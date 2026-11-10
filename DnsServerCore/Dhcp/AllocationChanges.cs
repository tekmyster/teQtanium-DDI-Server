// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DnsServerCore.Dhcp
{
    public sealed record AllocationFrozenOwner(string Node, AllocationPlan Plan, AllocationReplica Replica,
        AllocationBootstrapRecord Bootstrap = null, AllocationNativeHold[] NativeHolds = null, DistributedScopeConfiguration Configuration = null, string NativeConfiguration = null);
    public sealed record AllocationChangeInput(string Id, string Source, AllocationPlan Plan, AllocationFrozenOwner[] Frozen, DateTime CapturedUtc);
    public sealed record AllocationChangeRecord(string Id, string Scope, string FromEpoch, string Phase, string Frozen,
        string Payload = null, string Hash = null, string[] PreparedNodes = null);

    // All old and new owners must cooperate. There is deliberately no timeout, forced
    // unfreeze or rollback to old authority: those would resurrect a stale allocator.
    public sealed partial class DistributedAllocation
    {
        static byte[] ChangeSafety(AllocationState state) => (state.Changes?.Length ?? 0) == 0 ? [] : JsonSerializer.SerializeToUtf8Bytes(state.Changes, JsonOptions);
        static string Encode<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);
        public static string ChangeHash(AllocationChangeInput input) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(input, JsonOptions)));
        public AllocationChangeRecord Change(string scope)
        { lock (_sync) { var record = _state.Changes?.LastOrDefault(c => c.Scope == scope); return record is null ? null : record with { PreparedNodes = record.PreparedNodes?.ToArray() }; } }
        public bool ChangePending(string scope) => Change(scope) is { Phase: not "Committed" };
        static string[] Participants(AllocationChangeInput input) => input.Frozen[0].Plan.Owners.Concat(input.Plan.Owners).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        void EnsureChangesFrozen(AllocationState next)
        {
            DateTime now = DateTime.UtcNow;
            foreach (var record in _state.Changes ?? [])
                if (record.Phase != "Committed" &&
                    (Encode(_state.Plans.Where(p => p.Scope == record.Scope)) != Encode(next.Plans.Where(p => p.Scope == record.Scope)) ||
                     Encode(_state.Replicas.Where(r => r.Scope == record.Scope)) != Encode(next.Replicas.Where(r => r.Scope == record.Scope)) ||
                     Encode((_state.Configurations ?? []).Where(c => c.Scope == record.Scope)) != Encode((next.Configurations ?? []).Where(c => c.Scope == record.Scope)) ||
                     Encode((_state.NativeHolds ?? []).Where(h => h.Scope == record.Scope && h.Entry.Expires > now)) != Encode((next.NativeHolds ?? []).Where(h => h.Scope == record.Scope && h.Entry.Expires > now))))
                    throw new InvalidOperationException("Ownership change is frozen; resume the exact saved change before serving or accepting authority updates.");
        }
        static void ValidateChanges(AllocationState state)
        {
            if (state.Changes is null) return;
            if (state.Changes.Length > 256 || state.Changes.Any(c => c is null) || state.Changes.Select(c => c.Id).Distinct().Count() != state.Changes.Length) throw new ArgumentException("Invalid ownership change journal.");
            foreach (var record in state.Changes)
            {
                if (!Guid.TryParseExact(record.Id, "N", out _) || record.Phase != "Frozen" && record.Phase != "Prepared" && record.Phase != "Committed" || record.Frozen is null || record.Frozen.Length > 8 * 1024 * 1024) throw new ArgumentException("Invalid ownership change phase.");
                var frozen = JsonSerializer.Deserialize<AllocationFrozenOwner>(record.Frozen, JsonOptions);
                if (frozen?.Plan?.Scope != record.Scope || frozen.Plan.Epoch != record.FromEpoch || frozen.Replica?.Scope != record.Scope || frozen.Replica.Epoch != record.FromEpoch || frozen.Replica.Node != frozen.Node) throw new ArgumentException("Invalid frozen authority.");
                if (record.Phase == "Frozen") { if (record.Payload is not null || record.Hash is not null || record.PreparedNodes is not null) throw new ArgumentException("Frozen change has unexpected preparation."); continue; }
                if (record.Payload is null || record.Payload.Length > 8 * 1024 * 1024) throw new ArgumentException("Invalid ownership payload.");
                var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload, JsonOptions);
                var built = BuildChange(input.Id, input.Source, input.Plan with { Pins = null }, input.Frozen, input.CapturedUtc);
                if (input.Id != record.Id || input.Plan.Scope != record.Scope || input.Frozen[0].Plan.Epoch != record.FromEpoch ||
                    Encode(input) != Encode(built) || record.Hash != ChangeHash(input) || !input.Frozen.Any(f => Encode(f) == record.Frozen) ||
                    record.PreparedNodes is null || !record.PreparedNodes.SequenceEqual(record.PreparedNodes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) || record.PreparedNodes.Any(n => !Participants(input).Contains(n))) throw new ArgumentException("Ownership review or receipts changed.");
                if (record.Phase == "Committed" && !record.PreparedNodes.SequenceEqual(Participants(input))) throw new ArgumentException("Committed ownership lacks every participant receipt.");
            }
            foreach (var scope in state.Changes.Select(c => c.Scope).Distinct())
            {
                var records = state.Changes.Where(c => c.Scope == scope).ToArray();
                if (records.SkipLast(1).Any(c => c.Phase != "Committed")) throw new ArgumentException("An earlier ownership change remains pending.");
                var last = records[^1]; var plan = state.Plans.SingleOrDefault(p => p.Scope == scope);
                if (last.Phase == "Frozen" ? plan is not null && !Same(plan, JsonSerializer.Deserialize<AllocationFrozenOwner>(last.Frozen, JsonOptions).Plan) : !Same(plan, JsonSerializer.Deserialize<AllocationChangeInput>(last.Payload, JsonOptions).Plan)) throw new ArgumentException("Current plan differs from ownership journal.");
            }
        }
        public AllocationFrozenOwner FreezeChange(string id, AllocationPlan expected, AllocationEntry[] native = null, string nativeConfiguration = null)
        {
            if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("Use a stable ownership change identifier.");
            _ = new AllocationSequence(expected);
            lock (_sync)
            {
                EnsureLocalAuthority();
                var previous = Change(expected.Scope);
                if (previous?.Id == id)
                {
                    var saved = JsonSerializer.Deserialize<AllocationFrozenOwner>(previous.Frozen, JsonOptions);
                    if (!Same(saved.Plan, expected)) throw new InvalidOperationException("Frozen epoch changed.");
                    return saved;
                }
                if (previous is { Phase: not "Committed" } || Bootstrap(expected.Scope)?.Phase == "Prepared") throw new InvalidOperationException("Resume the pending ownership migration.");
                if ((_state.Changes?.Length ?? 0) >= 256 || _state.Changes?.Any(c => c.Id == id) == true) throw new InvalidOperationException("Ownership journal limit or reused identifier.");
                var localPlan = Plan(expected.Scope);
                if (localPlan is not null ? !Same(localPlan, expected) : expected.Owners.Contains(NodeName())) throw new InvalidOperationException("Expected current epoch does not match local authority.");
                foreach (var entry in (native ?? []).Where(e => e.Expires > DateTime.UtcNow))
                {
                    var own = localPlan is null ? null : Local(expected.Scope, expected).Entries.SingleOrDefault(e => e.Address == entry.Address);
                    bool Matches(AllocationEntry e) => e.Address == entry.Address && e.Client == entry.Client && string.Equals(e.Hardware, entry.Hardware, StringComparison.OrdinalIgnoreCase) &&
                        (e.State == entry.State || entry.State == "Offer" && e.State == "Lease");
                    if (own is not null && Matches(own) && own.Expires < entry.Expires)
                        Mutate(expected.Scope, own with { Expires = entry.Expires }); // protect the exact native ACK/offer lifetime before freezing
                    if (!_state.Replicas.Where(r => r.Scope == expected.Scope).SelectMany(r => r.Entries).Any(e => Matches(e) && e.Expires >= entry.Expires ||
                        e.Address == entry.Address && e.Client == entry.Client && string.Equals(e.Hardware, entry.Hardware, StringComparison.OrdinalIgnoreCase) && e.State == "Grant" &&
                        (e.Protection?.State == entry.State || entry.State == "Offer" && e.Protection?.State == "Lease") && e.Protection.Expires >= entry.Expires))
                        throw new InvalidOperationException("Native protection has no corresponding current authority; reconcile its original owner first.");
                }
                var frozen = new AllocationFrozenOwner(NodeName(), Copy(expected), localPlan is null ? new(expected.Scope, expected.Epoch, NodeName(), 0, []) : Copy(Local(expected.Scope, expected)),
                    Bootstrap(expected.Scope), _state.NativeHolds?.Where(h => h.Scope == expected.Scope).ToArray(), _state.Configurations?.SingleOrDefault(c => c.Scope == expected.Scope), nativeConfiguration);
                var next = _state with { Changes = (_state.Changes ?? []).Append(new AllocationChangeRecord(id, expected.Scope, expected.Epoch, "Frozen", Encode(frozen))).ToArray() };
                Validate(next); Save(next, true); return frozen;
            }
        }
        static bool PreserveGrantLifecycle(AllocationFrozenOwner[] frozen)
        {
            var replicas = frozen.Select(f => f.Replica).ToArray();
            return replicas.Any(r => (r.BorrowRequests?.Length ?? 0) > 0 ||
                (r.GrantReturns ?? []).Any(receipt => replicas.SingleOrDefault(d => d.Node == receipt.Owner)?.GrantReclaims?.Contains(receipt) != true) ||
                (r.UnusedRecoveries ?? []).Any(d => d.Addresses.Any(a => (r.GrantReclaims ?? []).Any(x => x.Grant.Address == a))));
        }
        public static AllocationChangeInput BuildChange(string id, string source, AllocationPlan desired, AllocationFrozenOwner[] frozen, DateTime? capturedUtc = null)
        {
            if (!Guid.TryParseExact(id, "N", out _) || desired is null || desired.Epoch != id || desired.Pins is not null || frozen is null || frozen.Length < 1 || frozen.Length > 128 || frozen.Any(f => f?.Plan is null || f.Replica is null) || frozen.Select(f => f.Node).Distinct().Count() != frozen.Length) throw new ArgumentException("Invalid ownership change input.");
            var old = frozen[0].Plan; _ = new AllocationSequence(old); var sequence = new AllocationSequence(desired);
            DateTime now = capturedUtc ?? DateTime.UtcNow;
            if (now.Kind != DateTimeKind.Utc || now > DateTime.UtcNow || old.Scope != desired.Scope || old.Epoch == desired.Epoch || old.Mask != desired.Mask || !old.Owners.Contains(source) || !desired.Owners.Contains(source) ||
                desired.Owners.Concat(old.Owners).Distinct().Order(StringComparer.Ordinal).SequenceEqual(frozen.Select(f => f.Node).Order(StringComparer.Ordinal)) == false ||
                frozen.Any(f => !Same(f.Plan, old) || f.Replica.Node != f.Node || f.Replica.Scope != old.Scope || f.Replica.Epoch != old.Epoch || !old.Owners.Contains(f.Node) && (f.Replica.Sequence != 0 || f.Replica.Entries.Length != 0))) throw new ArgumentException("Ownership participants, source, subnet mask or epoch changed.");
            if ((old.First & old.Mask) != (desired.First & desired.Mask) || (old.First & old.Mask) != (desired.Last & desired.Mask)) throw new ArgumentException("Move between subnets using a separate scope migration.");
            if ((desired.Reservations ?? []).Select(r => r.Client).Distinct().Count() != (desired.Reservations?.Length ?? 0) || (desired.Reservations ?? []).Any(r => desired.Excluded.Count(e => r.Address >= e.First && r.Address <= e.Last) > 1 || desired.Excluded.Any(e => r.Address >= e.First && r.Address <= e.Last && (e.First != r.Address || e.Last != r.Address)))) throw new ArgumentException("Reservations require unique clients and cannot overlap explicit exclusions.");
            var originals = frozen.Where(f => old.Owners.Contains(f.Node)).Select(f => f.Replica).ToArray();
            bool preserveLifecycle = PreserveGrantLifecycle(frozen);
            bool returnedDivision = originals.Any(r => (r.UnusedRecoveries ?? []).Any(d => d.Addresses.Any(a => (r.GrantReclaims ?? []).Any(x => x.Grant.Address == a))));
            if (returnedDivision && !Same(desired with { Epoch = old.Epoch, Seed = old.Seed, Configuration = old.Configuration, Pins = old.Pins }, old))
                throw new InvalidOperationException("Returned offline recovery divisions require unchanged ownership eligibility; retain their journals and original receivers.");
            Validate(new(1, [old], originals));
            var pins = new Dictionary<uint, AllocationPin>();
            if (preserveLifecycle)
                foreach (var original in originals)
                {
                    foreach (var request in original.BorrowRequests ?? [])
                        if (!desired.Owners.Contains(original.Node) || !desired.Owners.Contains(request.Donor)) throw new InvalidOperationException("Resolve pending requests before removing their original participants.");
                    foreach (var receipt in (original.GrantReturns ?? []).Concat(original.GrantReclaims ?? []))
                    {
                        if (!desired.Owners.Contains(receipt.Owner) || !desired.Owners.Contains(receipt.Grant.Borrower) || sequence.Owner(receipt.Grant.Address) is null || (desired.Reservations ?? []).Any(r => r.Address == receipt.Grant.Address && r.Client != receipt.Grant.Client))
                            throw new InvalidOperationException("Complete pending returns before removing lifecycle participants or address eligibility.");
                        pins[receipt.Grant.Address] = new(receipt.Grant.Address, receipt.Owner);
                    }
                }
            foreach (var original in originals)
                foreach (var grant in original.Entries.Where(e => e.State == "Grant"))
                {
                    if (!desired.Owners.Contains(original.Node) || !desired.Owners.Contains(grant.Borrower) || sequence.Owner(grant.Address) is null || (desired.Reservations ?? []).Any(r => r.Address == grant.Address && r.Client != grant.Client)) throw new InvalidOperationException("Return permanent grants before removing their participants or address eligibility.");
                    pins[grant.Address] = new(grant.Address, original.Node);
                }
            foreach (var original in originals)
                foreach (var entry in original.Entries.Where(e => e.State != "Grant" && e.State != "Released" && e.Expires > now && e.GrantId is null))
                {
                    if (sequence.Owner(entry.Address) is null || (desired.Reservations ?? []).Any(r => r.Address == entry.Address && r.Client != entry.Client || r.Client == entry.Client && r.Address != entry.Address))
                    {
                        string owner = sequence.Owner(entry.Address) ?? desired.Owners.Order(StringComparer.Ordinal).ElementAt((int)(entry.Address % (uint)desired.Owners.Length));
                        pins[entry.Address] = new(entry.Address, owner, entry.Client);
                    }
                }
            var plan = Copy(desired with { Pins = pins.Count == 0 ? null : pins.Values.OrderBy(p => p.Address).ToArray() });
            var result = new AllocationChangeInput(id, source, plan, frozen.OrderBy(f => f.Node, StringComparer.Ordinal).Select(f => f with { Plan = Copy(f.Plan), Replica = Copy(f.Replica) }).ToArray(), now);
            Validate(new(1, [plan], ChangeReplicas(result))); return result;
        }
        static AllocationReplica[] ChangeReplicas(AllocationChangeInput input)
        {
            var old = input.Frozen[0].Plan; var sequence = new AllocationSequence(input.Plan);
            var buckets = input.Plan.Owners.ToDictionary(n => n, _ => new Dictionary<uint, AllocationEntry>());
            foreach (var frozen in input.Frozen.Where(f => old.Owners.Contains(f.Node)))
                foreach (var entry in frozen.Replica.Entries.Where(e => e.State == "Grant" || e.State != "Released" && e.Expires > input.CapturedUtc))
                {
                    string node = entry.State == "Grant" || entry.GrantId is not null ? frozen.Node : sequence.Owner(entry.Address);
                    if (node is null || !buckets.ContainsKey(node) || !buckets[node].TryAdd(entry.Address, entry)) throw new InvalidOperationException("Conflicting protected authority in successor.");
                }
            long priorSequence = input.Frozen.Max(f => f.Replica.Sequence);
            return input.Plan.Owners.Select(n =>
            {
                long sequenceNumber = checked(priorSequence + 1);
                var entries = buckets[n].Values.OrderBy(e => e.Address).ToArray();
                var history = entries.Select(e => new AllocationEvent(checked(++sequenceNumber), input.CapturedUtc, null, e)).TakeLast(2000).ToArray();
                return new AllocationReplica(input.Plan.Scope, input.Plan.Epoch, n, sequenceNumber, entries, history,
                    UnusedRecoveries: input.Frozen.SingleOrDefault(f => f.Node == n)?.Replica.UnusedRecoveries,
                    GrantReturns: PreserveGrantLifecycle(input.Frozen) ? input.Frozen.SingleOrDefault(f => f.Node == n)?.Replica.GrantReturns : null,
                    GrantReclaims: PreserveGrantLifecycle(input.Frozen) ? input.Frozen.SingleOrDefault(f => f.Node == n)?.Replica.GrantReclaims : null,
                    BorrowRequests: PreserveGrantLifecycle(input.Frozen) ? input.Frozen.SingleOrDefault(f => f.Node == n)?.Replica.BorrowRequests : null);
            }).ToArray();
        }
        public void PrepareChange(AllocationChangeInput input)
        {
            if (input is null || JsonSerializer.SerializeToUtf8Bytes(input, JsonOptions).Length > 8 * 1024 * 1024) throw new ArgumentException("Ownership review exceeds 8 MiB.");
            var rebuilt = BuildChange(input.Id, input.Source, input.Plan with { Pins = null }, input.Frozen, input.CapturedUtc);
            if (Encode(rebuilt) != Encode(input)) throw new ArgumentException("Reviewed authority changed.");
            lock (_sync)
            {
                var record = Change(input.Plan.Scope) ?? throw new InvalidOperationException("Freeze each participant before preparing ownership.");
                string hash = ChangeHash(input);
                if (record.Id != input.Id || record.FromEpoch != input.Frozen[0].Plan.Epoch || !input.Frozen.Any(f => f.Node == NodeName() && Encode(f) == record.Frozen)) throw new InvalidOperationException("Local frozen authority differs from review.");
                if (record.Phase != "Frozen") { if (record.Hash != hash) throw new InvalidOperationException("Prepared ownership review changed."); return; }
                var localFrozen = JsonSerializer.Deserialize<AllocationFrozenOwner>(record.Frozen, JsonOptions);
                if (Plan(record.Scope) is { } localPlan && (!Same(localPlan, localFrozen.Plan) || Encode(Local(record.Scope, localPlan)) != Encode(localFrozen.Replica))) throw new InvalidOperationException("Local authority changed after freezing.");
                var originalByNode = input.Frozen.ToDictionary(f => f.Node, f => f.Replica);
                foreach (var known in _state.Replicas.Where(r => r.Scope == record.Scope))
                    if (!originalByNode.TryGetValue(known.Node, out var captured) || captured.Sequence < known.Sequence || captured.Sequence == known.Sequence && Encode(captured) != Encode(known) ||
                        known.Entries.Where(e => e.State == "Grant").Any(grant => !captured.Entries.Contains(grant) && !(captured.GrantReclaims ?? []).Any(x => x.Grant == grant)) ||
                        (known.GrantReturns ?? []).Any(receipt => !(captured.GrantReturns ?? []).Contains(receipt)) ||
                        (known.GrantReclaims ?? []).Any(receipt => !(captured.GrantReclaims ?? []).Contains(receipt)) ||
                        (known.UnusedRecoveries ?? []).Any(recovery => !originalByNode.TryGetValue(known.Node, out var original) || !(original.UnusedRecoveries ?? []).Any(r => Encode(r) == Encode(recovery))))
                        throw new InvalidOperationException("Frozen original owner omits previously observed permanent authority; recover its latest journal.");
                var records = _state.Changes.Select(c => c.Id == input.Id ? c with { Phase = "Prepared", Payload = Encode(input), Hash = hash, PreparedNodes = Array.Empty<string>() } : c).ToArray();
                var next = _state with { Plans = _state.Plans.Where(p => p.Scope != record.Scope).Append(Copy(input.Plan)).ToArray(), Replicas = _state.Replicas.Where(r => r.Scope != record.Scope).Concat(ChangeReplicas(input)).ToArray(),
                    Configurations = _state.Configurations?.Where(c => c.Scope != record.Scope).ToArray(), Bootstraps = _state.Bootstraps?.Where(b => b.Scope != record.Scope).ToArray(), Changes = records };
                Validate(next); Save(next, true);
            }
        }
        AllocationReplica[] HistoricalReplicas(DateTime timestamp)
        {
            var replicas = _state.Replicas.ToDictionary(r => (r.Scope, r.Node));
            foreach (var record in (_state.Changes ?? []).Reverse())
            {
                if (record.Payload is null) continue;
                var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload, JsonOptions);
                if (timestamp >= input.CapturedUtc) continue;
                foreach (var key in replicas.Keys.Where(k => k.Scope == record.Scope).ToArray()) replicas.Remove(key);
                foreach (var original in input.Frozen.Where(f => f.Plan.Owners.Contains(f.Node))) replicas[(record.Scope, original.Node)] = original.Replica;
            }
            return replicas.Values.ToArray();
        }
        // Called by the native API only after strict scope save/readback. Journal
        // preparation alone is not a configuration durability acknowledgement.
        public void ConfirmChangeConfiguration(string scope, string id, string hash)
        {
            lock (_sync)
            {
                var record = Change(scope) ?? throw new InvalidOperationException("Missing ownership preparation.");
                if (record.Id != id || record.Hash != hash || record.Phase == "Frozen") throw new InvalidOperationException("Configuration receipt differs from ownership review.");
                if (record.PreparedNodes.Contains(NodeName())) return;
                Save(_state with { Changes = _state.Changes.Select(c => c.Id == id ? c with { PreparedNodes = c.PreparedNodes.Append(NodeName()).Order(StringComparer.Ordinal).ToArray() } : c).ToArray() }, true);
            }
        }
        public void AcknowledgeChange(string scope, string id, string hash, string node)
        {
            lock (_sync)
            {
                var record = Change(scope) ?? throw new InvalidOperationException("Missing ownership change.");
                if (record.Phase != "Prepared" || record.Id != id || record.Hash != hash) throw new InvalidOperationException("Ownership receipt changed.");
                var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload, JsonOptions);
                if (input.Source != NodeName() || !record.PreparedNodes.Contains(NodeName()) || !Participants(input).Contains(node)) throw new InvalidOperationException("Invalid ownership receipt source.");
                if (record.PreparedNodes.Contains(node)) return;
                Save(_state with { Changes = _state.Changes.Select(c => c.Id == id ? c with { PreparedNodes = c.PreparedNodes.Append(node).Order(StringComparer.Ordinal).ToArray() } : c).ToArray() }, true);
            }
        }
        public void CommitChange(string scope, string id, string hash, string[] preparedNodes = null)
        {
            lock (_sync)
            {
                var record = Change(scope) ?? throw new InvalidOperationException("Missing ownership change.");
                if (record.Id != id || record.Hash != hash || record.Phase == "Frozen") throw new InvalidOperationException("Prepare the exact ownership review first.");
                if (record.Phase == "Committed") return;
                var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload, JsonOptions);
                var receipts = NodeName() == input.Source ? record.PreparedNodes : preparedNodes;
                if (!record.PreparedNodes.Contains(NodeName()) || receipts is null || !receipts.SequenceEqual(Participants(input))) throw new InvalidOperationException("Every participant must acknowledge durable preparation.");
                var next = _state with { Changes = _state.Changes.Select(c => c.Id == id ? c with { Phase = "Committed", PreparedNodes = receipts.ToArray() } : c).ToArray() };
                Validate(next); Save(next, true);
            }
        }
    }
}
