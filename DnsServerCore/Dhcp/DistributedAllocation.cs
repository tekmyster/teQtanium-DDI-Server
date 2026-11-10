using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Dhcp
{
    public sealed record AllocationRange(uint First, uint Last);
    public sealed record AllocationReservation(uint Address, string Client);
    public sealed record DhcpHaGroup(string Name, string Region, string Primary, string Secondary);
    public sealed record AllocationPlan(string Scope, string Epoch, uint First, uint Last, string Seed, string[] Owners, AllocationRange[] Excluded, uint Mask = 0, AllocationReservation[] Reservations = null, string Configuration = null, DhcpHaGroup[] HaGroups = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string Algorithm = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationPin[] Pins = null);
    public sealed record AllocationPin(uint Address, string Owner, string Client = null);
    public sealed record AllocationProtection(string State, DateTime Expires);
    public sealed record AllocationEntry(uint Address, string Client, string Hardware, string Host, string State, DateTime Expires, string GrantId = null, string Borrower = null, string AuthorityOwner = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationProtection Protection = null);
    public sealed record AllocationEvent(long Sequence, DateTime Timestamp, AllocationEntry Before, AllocationEntry After);
    public sealed record AllocationGrantReturn(string Id, string Owner, AllocationEntry Grant, long BorrowerSequence);
    public sealed record AllocationBorrowRequest(string Donor, string Id);
    public sealed record AllocationUnusedRecovery(string Id, string[] Receivers, uint[] Addresses);
    public sealed record AllocationReplica(string Scope, string Epoch, string Node, long Sequence, AllocationEntry[] Entries, AllocationEvent[] History = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationUnusedRecovery[] UnusedRecoveries = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationGrantReturn[] GrantReturns = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationGrantReturn[] GrantReclaims = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationBorrowRequest[] BorrowRequests = null);
    public sealed record AllocationDevice(string Scope, string Node, AllocationEntry Lease);
    public sealed record DistributedScopeConfiguration(string Scope, long Revision, string Hash, string Data);
    public sealed record AllocationNativeSnapshot(string Node, string Scope, string Configuration, AllocationEntry[] Entries);
    public sealed record AllocationBootstrapInput(string Id, string Source, AllocationPlan Plan, AllocationNativeSnapshot[] Native, AllocationReplica[] Seeds, DateTime CapturedUtc);
    public sealed record AllocationBootstrapRecord(string Id, string Scope, string Hash, string Phase, string Payload, string[] PreparedNodes = null);
    public sealed record AllocationNativeHold(string Scope, AllocationEntry Entry);
    public sealed record AllocationState(int Version, AllocationPlan[] Plans, AllocationReplica[] Replicas, DistributedScopeConfiguration[] Configurations = null,
        AllocationBootstrapRecord[] Bootstraps = null, AllocationNativeHold[] NativeHolds = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AllocationChangeRecord[] Changes = null);
    public sealed record AllocationWatermark(string Node, AllocationWatermarkScope[] Scopes, string SafetyHash = null);
    public sealed record AllocationWatermarkScope(string Scope, string Epoch, long Sequence, string Hash);

    // A bijection, not hash modulo pool size: every eligible address has exactly one owner.
    public sealed class AllocationSequence
    {
        readonly AllocationRange[] _ranges;
        readonly string[] _owners;
        readonly ulong _multiplier, _offset, _inverse;
        readonly Dictionary<uint, string> _reserved = [];
        readonly Dictionary<uint, string> _pins = [];
        public ulong Count { get; }
        public AllocationSequence(AllocationPlan plan)
        {
            if (plan?.Algorithm is not null && plan.Algorithm != "interleaved-v1") throw new ArgumentException("Unknown allocation algorithm.");
            if (plan is null || string.IsNullOrWhiteSpace(plan.Scope) || plan.Scope.Length > 255 || !Guid.TryParseExact(plan.Epoch, "N", out _) || string.IsNullOrEmpty(plan.Seed) || plan.Seed.Length > 255 || plan.First > plan.Last || plan.Owners is null || plan.Owners.Length < 1 || plan.Owners.Length > 128 || plan.Owners.Any(n => string.IsNullOrWhiteSpace(n) || n.Length > 255) || plan.Owners.Distinct(StringComparer.Ordinal).Count() != plan.Owners.Length || plan.Excluded is null || plan.Excluded.Length > 10000)
                throw new ArgumentException("Invalid allocation plan.");
            _owners = plan.Owners.Order(StringComparer.Ordinal).ToArray();
            if (plan.Pins?.Length > 100000 || plan.Pins?.Any(p => p is null || !_owners.Contains(p.Owner) || p.Client?.Length > 1024) == true || plan.Pins?.Select(p => p.Address).Distinct().Count() != plan.Pins?.Length) throw new ArgumentException("Invalid retained allocation authority.");
            foreach (var pin in plan.Pins ?? []) _pins.Add(pin.Address, pin.Owner);
            if (plan.HaGroups is not null && (plan.HaGroups.Length > 64 || plan.HaGroups.Any(g => g is null || string.IsNullOrWhiteSpace(g.Name) || g.Name.Length > 255 || string.IsNullOrWhiteSpace(g.Region) || g.Region.Length > 255 || g.Primary == g.Secondary || !_owners.Contains(g.Primary) || !_owners.Contains(g.Secondary)) || plan.HaGroups.Select(g => g.Name).Distinct().Count() != plan.HaGroups.Length || plan.HaGroups.SelectMany(g => new[] { g.Primary, g.Secondary }).Distinct().Count() != plan.HaGroups.Length * 2)) throw new ArgumentException("HA groups require distinct enrolled primary/secondary pairs; array order defines local then regional preference.");
            foreach (var reservation in plan.Reservations ?? [])
            {
                if (reservation.Address < plan.First || reservation.Address > plan.Last || string.IsNullOrWhiteSpace(reservation.Client) || reservation.Client.Length > 1024 || _reserved.ContainsKey(reservation.Address)) throw new ArgumentException("Invalid reservation.");
                byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(plan.Seed + ":" + reservation.Address));
                _reserved[reservation.Address] = _owners[System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(key) % _owners.Length];
            }
            List<AllocationRange> ranges = []; ulong cursor = plan.First;
            foreach (var excluded in plan.Excluded.Concat((plan.Reservations ?? []).Select(r => new AllocationRange(r.Address, r.Address))).OrderBy(r => r.First))
            {
                if (excluded.First > excluded.Last) throw new ArgumentException("Invalid exclusion.");
                if (excluded.Last < cursor || excluded.First > plan.Last) continue;
                if (excluded.First > cursor) ranges.Add(new((uint)cursor, excluded.First - 1));
                cursor = Math.Max(cursor, (ulong)excluded.Last + 1);
            }
            if (cursor <= plan.Last) ranges.Add(new((uint)cursor, plan.Last));
            _ranges = ranges.ToArray(); Count = _ranges.Aggregate(0UL, (n, r) => n + (ulong)r.Last - r.First + 1);
            if (Count == 0 && _reserved.Count > 0) { _multiplier = 1; _offset = 0; _inverse = 0; return; }
            if (Count < (ulong)_owners.Length) throw new ArgumentException("The pool needs at least one eligible address per owner.");
            // Eligible ranks 0,N,2N... belong to the first sorted owner. Membership
            // stays immutable during an outage. Missing Algorithm retains legacy maps.
            if (plan.Algorithm == "interleaved-v1") { _multiplier = 1; _offset = 0; _inverse = Count == 1 ? 0UL : 1UL; return; }
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(plan.Seed));
            _offset = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(0, 8)) % Count;
            ulong multiplier = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(8, 8)) % Count;
            if (multiplier == 0) multiplier = 1;
            while (BigInteger.GreatestCommonDivisor(multiplier, Count) != 1) multiplier = multiplier == Count - 1 ? 1 : multiplier + 1;
            _multiplier = multiplier;
            if (Count == 1) { _inverse = 0; return; }
            BigInteger oldR = Count, r = multiplier, oldT = 0, t = 1;
            while (r != 0) { BigInteger q = oldR / r; (oldR, r) = (r, oldR - q * r); (oldT, t) = (t, oldT - q * t); }
            _inverse = (ulong)((oldT % Count + Count) % Count);
        }
        uint At(ulong index)
        {
            // Product is at most (2^32-1)^2 and fits UInt64, but offset addition may overflow.
            ulong rank = (ulong)(((BigInteger)_multiplier * index + _offset) % Count);
            foreach (var range in _ranges)
            { ulong size = (ulong)range.Last - range.First + 1; if (rank < size) return (uint)(range.First + rank); rank -= size; }
            throw new InvalidOperationException("Invalid allocation rank.");
        }
        public string Owner(uint address)
        {
            if (_pins.TryGetValue(address, out var pinnedOwner)) return pinnedOwner;
            if (_reserved.TryGetValue(address, out var reservedOwner)) return reservedOwner;
            ulong rank = 0;
            foreach (var range in _ranges)
            {
                if (address >= range.First && address <= range.Last)
                { rank += address - range.First; ulong input = Count == 1 ? 0 : (ulong)(((BigInteger)((rank + Count - _offset) % Count) * _inverse) % Count); return _owners[input % (ulong)_owners.Length]; }
                rank += (ulong)range.Last - range.First + 1;
            }
            return null;
        }
        public IEnumerable<uint> Candidates(string node)
        {
            int owner = Array.IndexOf(_owners, node); if (owner < 0) yield break;
            for (ulong index = (ulong)owner; index < Count; index += (ulong)_owners.Length) { uint address = At(index); if (Owner(address) == node) yield return address; }
        }
        public static uint Number(IPAddress address)
        { if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) throw new ArgumentException("DHCPv4 requires IPv4."); return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()); }
        public static IPAddress Address(uint number)
        { byte[] bytes = new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, number); return new(bytes); }
    }

    // Immutable ownership epochs allow independent service during partitions. Only the
    // separate cooperative change journal may install a successor after every owner freezes.
    public sealed partial class DistributedAllocation : IAsyncDisposable
    {
        public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        readonly object _sync = new(); readonly string _path;
        readonly FileStream _writerLock;
        int _disposed;
        bool _recoveryRequired;
        public bool RecoveryRequired { get { lock (_sync) return _recoveryRequired; } }
        AllocationState _state;
        Dictionary<uint, AllocationDevice[]> _leaseIndex = [];
        Dictionary<string, AllocationSequence> _sequences = [];
        AllocationWatermark _watermark;
        AllocationState _verifiedAuthorityState;
        string _verifiedAuthorityNode;
        public string PersistedNode => Volatile.Read(ref _watermark)?.Node;
        readonly CancellationTokenSource _stop = new(); Task _worker;
        string _health = "Not started";
        public string Health { get { lock (_sync) return _recoveryRequired ? "Authoritative state requires offline recovery; DHCP service withheld" : _health; } }
        public Func<string> NodeName { get; set; } = () => "localhost";
        public DistributedAllocation(string path)
        {
            _path = path;
            if (!File.Exists(path) && File.Exists(path + ".required") && !File.Exists(path + ".tmp")) throw new InvalidDataException("Authoritative DHCP state is missing. Recover it before serving clients.");
            if (File.Exists(path + ".recovery-required")) throw new InvalidDataException("Peer evidence showed newer authoritative DHCP state. Offline recovery is required before serving.");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
            _writerLock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                _state = File.Exists(path) ? JsonSerializer.Deserialize<AllocationState>(File.ReadAllBytes(path), JsonOptions) : new(1, [], []); Validate(_state);
                if (File.Exists(path + ".required"))
                {
                    _watermark = JsonSerializer.Deserialize<AllocationWatermark>(File.ReadAllBytes(path + ".required"), JsonOptions) ?? throw new InvalidDataException("Invalid authoritative watermark.");
                    try { ValidateWatermark(_state, _watermark); }
                    catch (InvalidDataException) when (File.Exists(path + ".tmp"))
                    {
                        // A crash after the durable barrier may precede the snapshot rename.
                        // Complete only the staged generation cryptographically bound to that barrier.
                        var staged = JsonSerializer.Deserialize<AllocationState>(File.ReadAllBytes(path + ".tmp"), JsonOptions);
                        Validate(staged); ValidateWatermark(staged, _watermark);
                        File.Move(path + ".tmp", path, true);
                        AllocationDurability.SyncDirectory(path);
                        _state = staged;
                    }
                }
                else if (_state.Plans.Length > 0 || (_state.NativeHolds?.Length ?? 0) > 0 || (_state.Changes?.Length ?? 0) > 0) throw new InvalidDataException("Authoritative watermark is missing; offline recovery is required.");
                RebuildLeaseIndex(); _sequences = _state.Plans.ToDictionary(p => p.Scope, p => new AllocationSequence(p));
            }
            catch { _writerLock.Dispose(); throw; }
        }
        static AllocationPlan Copy(AllocationPlan p) => p with { Owners = p.Owners.ToArray(), Excluded = p.Excluded.ToArray(), Reservations = p.Reservations?.ToArray(), HaGroups = p.HaGroups?.ToArray(), Pins = p.Pins?.ToArray() };
        static AllocationReplica Copy(AllocationReplica r) => r with { Entries = r.Entries.ToArray(), GrantReturns = r.GrantReturns?.ToArray(), GrantReclaims = r.GrantReclaims?.ToArray(), BorrowRequests = r.BorrowRequests?.ToArray(), History = r.History?.ToArray(), UnusedRecoveries = r.UnusedRecoveries?.Select(x => x with { Receivers = x.Receivers.ToArray(), Addresses = x.Addresses.ToArray() }).ToArray() };
        static AllocationBootstrapRecord Copy(AllocationBootstrapRecord record) => record with { PreparedNodes = record.PreparedNodes?.ToArray() };
        public AllocationState Snapshot() { lock (_sync) return _state with { Plans = _state.Plans.Select(Copy).ToArray(), Replicas = _state.Replicas.Select(Copy).ToArray(), Configurations = _state.Configurations?.ToArray(), Bootstraps = _state.Bootstraps?.Select(Copy).ToArray(), NativeHolds = _state.NativeHolds?.ToArray(), Changes = _state.Changes?.Select(c => c with { PreparedNodes = c.PreparedNodes?.ToArray() }).ToArray() }; }
        public AllocationPlan Plan(string scope) { lock (_sync) { var p = _state.Plans.SingleOrDefault(p => p.Scope == scope); return p is null ? null : Copy(p); } }
        public bool ProtectedByOtherPlan(string scope, uint first, uint last)
        { lock (_sync) return _state.Plans.Any(p => p.Scope != scope && (first <= p.Last && p.First <= last || (p.Pins ?? []).Any(pin => pin.Address >= first && pin.Address <= last))); }
        public byte[] Export() => JsonSerializer.SerializeToUtf8Bytes(Snapshot(), JsonOptions);
        static bool Same(AllocationPlan a, AllocationPlan b) => JsonSerializer.Serialize(a, JsonOptions) == JsonSerializer.Serialize(b, JsonOptions);
        static string AuthorityHash(AllocationPlan plan, AllocationReplica replica)
            => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { plan, replica }, JsonOptions)));
        static AllocationWatermark MakeWatermark(AllocationState state, string node)
            => new(node, state.Plans.Where(p => p.Owners.Contains(node)).Select(p =>
            {
                var replica = state.Replicas.SingleOrDefault(r => r.Scope == p.Scope && r.Node == node) ?? new(p.Scope, p.Epoch, node, 0, []);
                return new AllocationWatermarkScope(p.Scope, p.Epoch, replica.Sequence, AuthorityHash(p, replica));
            }).ToArray(), Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
                bootstraps = (state.Bootstraps ?? []).OrderBy(b => b.Scope, StringComparer.Ordinal).ToArray(),
                nativeHolds = (state.NativeHolds ?? []).OrderBy(h => h.Scope, StringComparer.Ordinal).ThenBy(h => h.Entry.Address).ToArray()
            }, JsonOptions).Concat(ChangeSafety(state)).ToArray())));
        static void ValidateWatermark(AllocationState state, AllocationWatermark watermark)
        {
            if (watermark.Node is null || watermark.Scopes is null) throw new InvalidDataException("Invalid authoritative watermark.");
            var actual = MakeWatermark(state, watermark.Node);
            if (state.Changes?.Any(c => JsonSerializer.Deserialize<AllocationFrozenOwner>(c.Frozen, JsonOptions).Node != watermark.Node) == true) throw new InvalidDataException("Ownership barrier belongs to another node.");
            if (watermark.SafetyHash is null && ((state.Bootstraps?.Length ?? 0) > 0 || (state.NativeHolds?.Length ?? 0) > 0 || (state.Changes?.Length ?? 0) > 0)) throw new InvalidDataException("Migration protections require a safety-bound durable watermark.");
            foreach (var record in state.Bootstraps ?? [])
            {
                var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(record.Payload, JsonOptions);
                if (input.Plan.Owners.Contains(watermark.Node) && !record.PreparedNodes.Contains(watermark.Node) ||
                    input.Source == watermark.Node && record.Phase == "Committed" && !record.PreparedNodes.Order(StringComparer.Ordinal).SequenceEqual(input.Plan.Owners.Order(StringComparer.Ordinal)))
                    throw new InvalidDataException("Local migration acknowledgements do not prove durable preparation.");
            }
            if (watermark.SafetyHash is not null && watermark.SafetyHash != actual.SafetyHash) throw new InvalidDataException("Native protections or migration journal differ from the durable barrier.");
            foreach (var known in watermark.Scopes)
            {
                var present = actual.Scopes.SingleOrDefault(s => s.Scope == known.Scope);
                if (present is null || present.Epoch != known.Epoch || present.Sequence != known.Sequence || present.Hash != known.Hash) throw new InvalidDataException("Authoritative allocation state disagrees with its durable watermark; offline recovery required.");
            }
            if (actual.Scopes.Length != watermark.Scopes.Length) throw new InvalidDataException("Ownership differs from the durable watermark.");
        }
        void EnsureLocalAuthority()
        {
            if (_recoveryRequired) throw new InvalidOperationException("Authoritative DHCP state requires offline recovery.");
            if (_watermark is not null && (_watermark.Scopes.Length > 0 || (_state.NativeHolds?.Length ?? 0) > 0 || (_state.Changes?.Length ?? 0) > 0) && _watermark.Node != NodeName()) throw new InvalidOperationException("Allocation node identity changed; fenced migration is required.");
            if (ReferenceEquals(_verifiedAuthorityState, _state) && _verifiedAuthorityNode == NodeName()) return;
            if (_watermark is not null) ValidateWatermark(_state, _watermark);
            _verifiedAuthorityState = _state; _verifiedAuthorityNode = NodeName();
        }
        static void Validate(AllocationState state)
        {
            if (state is null || state.Version != 1 || state.Plans is null || state.Replicas is null || state.Plans.Length > 1000 || state.Replicas.Length > 128000 || state.Plans.Select(p => p.Scope).Distinct().Count() != state.Plans.Length) throw new ArgumentException("Invalid distributed state.");
            foreach (var p in state.Plans) _ = new AllocationSequence(p);
            ValidateChanges(state);
            if (state.Bootstraps?.Any(b => b is null) == true || state.Bootstraps?.Length > 1000 || state.Bootstraps?.Select(b => b.Scope).Distinct().Count() != state.Bootstraps?.Length ||
                state.Bootstraps?.Any(b => b is null || !Guid.TryParseExact(b.Id, "N", out _) || b.Phase != "Prepared" && b.Phase != "Committed" ||
                    b.Payload is null || b.Payload.Length > 8 * 1024 * 1024 || !state.Plans.Any(p => p.Scope == b.Scope) ||
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(b.Payload))) != b.Hash) == true) throw new ArgumentException("Invalid migration journal.");
            foreach (var record in state.Bootstraps ?? [])
            {
                var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(record.Payload, JsonOptions);
                var plan = state.Plans.Single(p => p.Scope == record.Scope);
                if (input is null || input.Id != record.Id || input.Plan is null || !Same(input.Plan, plan) || !plan.Owners.Contains(input.Source) ||
                    record.PreparedNodes is null || record.PreparedNodes.Length == 0 || record.PreparedNodes.Length > plan.Owners.Length ||
                    record.PreparedNodes.Distinct(StringComparer.Ordinal).Count() != record.PreparedNodes.Length || record.PreparedNodes.Any(n => !plan.Owners.Contains(n)))
                    throw new ArgumentException("Invalid migration acknowledgements or payload.");
                var rebuilt = BuildBootstrap(input.Id, input.Source, input.Plan, input.Native, input.CapturedUtc);
                if (JsonSerializer.Serialize(rebuilt, JsonOptions) != record.Payload) throw new ArgumentException("Migration payload does not match native evidence.");
            }
            if (state.NativeHolds?.Length > 100000 || state.NativeHolds?.Any(h => h is null || string.IsNullOrEmpty(h.Scope) || h.Scope.Length > 255 || h.Entry is null || h.Entry.Expires.Kind != DateTimeKind.Utc ||
                h.Entry.State != "Offer" && h.Entry.State != "Lease" && h.Entry.State != "Declined" || string.IsNullOrEmpty(h.Entry.Client) || h.Entry.Client.Length > 1024 || string.IsNullOrEmpty(h.Entry.Hardware) || h.Entry.Hardware.Length > 255 || h.Entry.Host?.Length > 255 ||
                h.Entry.GrantId is not null || h.Entry.Borrower is not null || h.Entry.AuthorityOwner is not null || h.Entry.Protection is not null) == true ||
                state.NativeHolds?.Select(h => (h.Scope,h.Entry.Address)).Distinct().Count() != state.NativeHolds?.Length) throw new ArgumentException("Invalid native protections.");
            foreach (var hold in state.NativeHolds ?? []) ValidateNativeIdentity(hold.Entry);
            if (state.Configurations?.Length > 1000 || state.Configurations?.Select(c => c.Scope).Distinct().Count() != state.Configurations?.Length || state.Configurations?.Any(c => c is null || !state.Plans.Any(p => p.Scope == c.Scope) || c.Revision < 1 || c.Data is null || c.Data.Length > 1024 * 1024 || Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(c.Data))) != c.Hash) == true) throw new ArgumentException("Invalid scope configuration snapshots.");
            foreach (var p in state.Plans) if (state.Plans.Any(other => other.Scope != p.Scope && (p.First <= other.Last && other.First <= p.Last || (p.Pins ?? []).Any(pin => pin.Address >= other.First && pin.Address <= other.Last || (other.Pins ?? []).Any(op => op.Address == pin.Address))))) throw new ArgumentException("Distributed scopes cannot overlap retained authority.");
            ValidateGrantLifecycle(state);
            if (state.Replicas.Select(r => (r.Scope, r.Node)).Distinct().Count() != state.Replicas.Length) throw new ArgumentException("Duplicate replicas.");
            foreach (var r in state.Replicas)
            {
                var p = state.Plans.SingleOrDefault(p => p.Scope == r.Scope) ?? throw new ArgumentException("Unknown scope.");
                var sequence = new AllocationSequence(p);
                if (r.Epoch != p.Epoch || !p.Owners.Contains(r.Node) || r.Sequence < 0 || r.Entries is null || r.Entries.Length > 100000 || r.Entries.Select(e => e.Address).Distinct().Count() != r.Entries.Length) throw new ArgumentException("Invalid replica.");
                if (r.UnusedRecoveries is not null)
                {
                    var donorEntries = r.Entries.ToDictionary(e => e.Address);
                    var reservedAddresses = (p.Reservations ?? []).Select(x => x.Address).ToHashSet();
                    if (r.UnusedRecoveries.Length > 256 || r.UnusedRecoveries.Any(x => x is null) || r.UnusedRecoveries.Select(x => x.Id).Distinct().Count() != r.UnusedRecoveries.Length) throw new ArgumentException("Invalid unused-capacity recovery journal.");
                    foreach (var recovery in r.UnusedRecoveries)
                    {
                        if (!Guid.TryParseExact(recovery.Id, "N", out _) || recovery.Receivers is null || recovery.Receivers.Length == 0 || recovery.Receivers.Length >= p.Owners.Length ||
                            !recovery.Receivers.SequenceEqual(recovery.Receivers.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) || recovery.Receivers.Any(n => n == r.Node || !p.Owners.Contains(n)) ||
                            recovery.Addresses is null || recovery.Addresses.Length > 65536 || !recovery.Addresses.SequenceEqual(recovery.Addresses.Distinct().Order())) throw new ArgumentException("Invalid unused-capacity division.");
                        for (int i = 0; i < recovery.Addresses.Length; i++)
                        {
                            uint address = recovery.Addresses[i];
                            donorEntries.TryGetValue(address, out var grant);
                            grant = (r.GrantReclaims ?? []).SingleOrDefault(x => x.Grant.Address == address)?.Grant ?? grant;
                            if (sequence.Owner(address) != r.Node || reservedAddresses.Contains(address) || grant?.State != "Grant" ||
                                grant.GrantId != RecoveryGrantId(recovery.Id, address) || grant.Borrower != recovery.Receivers[i % recovery.Receivers.Length] || grant.Protection is not null)
                                throw new ArgumentException("Unused-capacity recovery differs from its permanent donor grants.");
                        }
                    }
                }
                if (r.History?.Length > 2000 || r.History?.Any(h => h is null || h.Sequence < 1 || h.Sequence > r.Sequence || h.Timestamp.Kind != DateTimeKind.Utc || h.After is null || h.After.Client?.Length > 1024 || h.After.Hardware?.Length > 255 || h.After.Host?.Length > 255 || h.After.Expires.Kind != DateTimeKind.Utc || h.After.State != "Offer" && h.After.State != "Lease" && h.After.State != "Grant" && h.After.State != "Released" && h.After.State != "Declined" || sequence.Owner(h.After.Address) != r.Node && h.After.AuthorityOwner != sequence.Owner(h.After.Address)) == true || r.History?.Select(h => h.Sequence).Distinct().Count() != r.History?.Length) throw new ArgumentException("Invalid lease history.");
                foreach (var e in r.Entries)
                {
                    if (e is null || e.Client?.Length > 1024 || e.Hardware?.Length > 255 || e.Host?.Length > 255 || e.Expires.Kind != DateTimeKind.Utc || e.State != "Offer" && e.State != "Lease" && e.State != "Grant" && e.State != "Released" && e.State != "Declined" || e.GrantId is not null && !Guid.TryParseExact(e.GrantId, "N", out _) || e.State == "Grant" && (e.GrantId is null || !p.Owners.Contains(e.Borrower) || e.Borrower == r.Node)) throw new ArgumentException("Invalid allocation entry.");
                    if (e.Protection is not null && (e.State != "Grant" || e.Protection.Expires.Kind != DateTimeKind.Utc || e.Protection.State != "Lease" && e.Protection.State != "Offer" && e.Protection.State != "Declined" || string.IsNullOrEmpty(e.Client))) throw new ArgumentException("Invalid handoff protection.");
                    if (sequence.Owner(e.Address) != r.Node)
                    {
                        var donor = state.Replicas.SingleOrDefault(d => d.Scope == r.Scope && d.Node == e.AuthorityOwner);
                        if (e.State == "Grant" || e.GrantId is null || e.AuthorityOwner != sequence.Owner(e.Address) || donor?.Entries.Concat((donor.GrantReclaims ?? []).Select(x => x.Grant)).Any(g => g.State == "Grant" && g.Address == e.Address && g.GrantId == e.GrantId && g.Borrower == r.Node) != true) throw new ArgumentException("Missing durable donor authority.");
                    }
                    if (e.State != "Released" && (p.Reservations ?? []).Any(a => a.Address == e.Address && a.Client != e.Client) && !(p.Pins ?? []).Any(pin => pin.Address == e.Address && pin.Client == e.Client)) throw new ArgumentException("Reserved address belongs to another client.");
                }
            }
        }
        static void ValidateNativeIdentity(AllocationEntry entry)
        {
            try
            {
                if (entry.Client.Split('-').Length != 2) throw new ArgumentException("Invalid native client identifier.");
                var client = Options.ClientIdentifierOption.Parse(entry.Client);
                var hardware = Lease.ParseHardwareAddress(entry.Hardware);
                if (client.Identifier.Length == 0 || client.Identifier.Length > 254 || hardware.Length == 0 || hardware.Length > 16) throw new ArgumentException("Invalid native client or hardware length.");
            }
            catch (Exception exception) when (exception is FormatException || exception is OverflowException || exception is IndexOutOfRangeException)
            { throw new ArgumentException("Invalid native client identifier or hardware address.", exception); }
        }
        void Save(AllocationState next, bool ownershipChange = false)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_recoveryRequired) throw new InvalidOperationException("Local authoritative state requires offline recovery.");
            EnsureLocalAuthority();
            if (!ownershipChange) EnsureChangesFrozen(next);
            try
            {
                string temporary = _path + ".tmp";
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path)));
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                { JsonSerializer.Serialize(stream, next, JsonOptions); stream.Flush(true); }
                if (next.Plans.Length > 0 || (next.NativeHolds?.Length ?? 0) > 0 || (next.Changes?.Length ?? 0) > 0 || _watermark?.SafetyHash is not null)
                {
                    var watermark = MakeWatermark(next, NodeName());
                    // Publish the barrier before the snapshot: a crash between these writes stops service,
                    // rather than allowing the previous snapshot to allocate an already-advertised address.
                    using (var marker = new FileStream(_path + ".required.tmp", FileMode.Create, FileAccess.Write, FileShare.None)) { JsonSerializer.Serialize(marker, watermark, JsonOptions); marker.Flush(true); }
                    File.Move(_path + ".required.tmp", _path + ".required", true);
                    _watermark = watermark; _verifiedAuthorityState = null;
                    AllocationDurability.SyncDirectory(_path);
                }
                File.Move(temporary, _path, true);
                AllocationDurability.SyncDirectory(_path);
                var previousPlans = _state.Plans.ToDictionary(p => p.Scope);
                _state = next;
                _verifiedAuthorityState = next; _verifiedAuthorityNode = NodeName();
                foreach (var plan in next.Plans)
                    if (!_sequences.ContainsKey(plan.Scope) || !previousPlans.TryGetValue(plan.Scope, out var previousPlan) || previousPlan.Epoch != plan.Epoch)
                        _sequences[plan.Scope] = new AllocationSequence(plan);
                RebuildLeaseIndex();
            }
            catch
            {
                _recoveryRequired = true;
                _health = "Durable allocation commit failed; DHCP service withheld until verified recovery.";
                throw;
            }
        }
        public void AddPlan(AllocationPlan plan)
        {
            plan = Copy(plan with { Owners = plan.Owners.Order(StringComparer.Ordinal).ToArray(), Excluded = plan.Excluded.OrderBy(r => r.First).ThenBy(r => r.Last).ToArray() }); _ = new AllocationSequence(plan);
            lock (_sync)
            {
                var current = _state.Plans.SingleOrDefault(p => p.Scope == plan.Scope);
                if (current is not null) { if (Same(current, plan)) return; throw new InvalidOperationException("Use a cooperative ownership change to install a successor epoch."); }
                if (NativeHolds(plan.Scope).Length > 0) throw new InvalidOperationException("Live native protections require reviewed ownership migration.");
                var next = _state with { Plans = _state.Plans.Append(plan).ToArray() }; Validate(next); Save(next);
            }
        }
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        // Bootstrap writes every initial owner snapshot exactly once while all native scopes are
        // quiescent. Ordinary replication must never acquire this initial-authority privilege.
        public static AllocationBootstrapInput BuildBootstrap(string id, string source, AllocationPlan plan, AllocationNativeSnapshot[] native, DateTime? capturedUtc = null)
        {
            if (!Guid.TryParseExact(id, "N", out _) || plan is null || plan.Owners is null || !plan.Owners.Contains(source) || native is null || native.Any(n => n is null) ||
                native.Length != plan.Owners.Length || native.Select(n => n.Node).Distinct().Count() != native.Length ||
                native.Any(n => n.Scope != plan.Scope || !plan.Owners.Contains(n.Node) || n.Entries is null || n.Entries.Length > 100000))
                throw new ArgumentException("Invalid native migration participants.");
            var sequence = new AllocationSequence(plan); var now = capturedUtc ?? DateTime.UtcNow;
            if (now.Kind != DateTimeKind.Utc || now > DateTime.UtcNow.AddMinutes(2)) throw new ArgumentException("Invalid migration capture timestamp.");
            if (native.Any(n => string.IsNullOrEmpty(n.Configuration) || n.Configuration.Length > 1024 * 1024 || n.Entries.Any(e => e is null || e.Expires.Kind != DateTimeKind.Utc ||
                e.State != "Lease" && e.State != "Offer" && e.State != "Declined" || string.IsNullOrEmpty(e.Client) || e.Client.Length > 1024 || string.IsNullOrEmpty(e.Hardware) || e.Hardware.Length > 255 || e.Host?.Length > 255 ||
                e.GrantId is not null || e.Borrower is not null || e.AuthorityOwner is not null || e.Protection is not null))) throw new ArgumentException("Invalid native migration evidence.");
            foreach (var snapshot in native)
            {
                _ = Convert.FromBase64String(snapshot.Configuration);
                foreach (var entry in snapshot.Entries) ValidateNativeIdentity(entry);
            }
            if (native.Single(n => n.Node == source).Configuration != plan.Configuration) throw new ArgumentException("Source configuration differs from the migration plan.");
            var live = native.SelectMany(n => n.Entries).Where(e => e.Expires > now).GroupBy(e => e.Address).Select(g =>
            {
                if (g.Any(e => e.State != "Lease" && e.State != "Offer" && e.State != "Declined" || string.IsNullOrEmpty(e.Client) || string.IsNullOrEmpty(e.Hardware)) ||
                    g.Select(e => e.Client).Distinct().Count() != 1 || g.Select(e => e.Hardware).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 1 ||
                    g.Any(e => e.State == "Declined") && g.Any(e => e.State != "Declined"))
                    throw new InvalidOperationException("Conflicting native lease or offer evidence; resolve it before migrating.");
                if (sequence.Owner(g.Key) is null) throw new InvalidOperationException("A live address is outside eligible ownership; migration is unavailable.");
                foreach (var e in g) { _ = Options.ClientIdentifierOption.Parse(e.Client); _ = Lease.ParseHardwareAddress(e.Hardware); }
                var selected = g.OrderByDescending(e => e.State == "Declined" ? 2 : e.State == "Lease" ? 1 : 0).ThenByDescending(e => e.Expires).First();
                return selected with { Expires = g.Max(e => e.Expires), GrantId = null, Borrower = null, AuthorityOwner = null, Protection = null };
            }).OrderBy(e => e.Address).ToArray();
            if (live.GroupBy(e => e.Client).Any(g => g.Count(e => e.State != "Declined") > 1)) throw new InvalidOperationException("A client has conflicting native addresses.");
            var entries = plan.Owners.ToDictionary(n => n, _ => new List<AllocationEntry>());
            foreach (var lease in live)
            {
                string owner = sequence.Owner(lease.Address);
                if (owner == source) { entries[source].Add(lease); continue; }
                string grantId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id + ":" + lease.Address))).Substring(0, 32).ToLowerInvariant();
                entries[owner].Add(lease with { State = "Grant", Expires = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc), GrantId = grantId,
                    Borrower = source, Protection = new(lease.State, lease.Expires) });
                entries[source].Add(lease with { GrantId = grantId, AuthorityOwner = owner });
            }
            var replicas = plan.Owners.Order(StringComparer.Ordinal).Select(n =>
            {
                var values = entries[n].OrderBy(e => e.Address).ToArray();
                var events = values.Select((e, i) => new AllocationEvent(i + 1, now, null, e)).TakeLast(2000).ToArray();
                return new AllocationReplica(plan.Scope, plan.Epoch, n, values.Length, values, events);
            }).ToArray();
            Validate(new(1, [plan], replicas));
            return new(id, source, Copy(plan), native.Select(n => n with { Entries = n.Entries.ToArray() }).ToArray(), replicas, now);
        }
        public AllocationBootstrapRecord Bootstrap(string scope)
        { lock (_sync) { var record = _state.Bootstraps?.SingleOrDefault(b => b.Scope == scope); return record is null ? null : Copy(record); } }
        public bool BootstrapPending(string scope) => Bootstrap(scope)?.Phase == "Prepared" || ChangePending(scope);
        public void PrepareBootstrap(AllocationBootstrapInput input)
        {
            byte[] encoded = JsonSerializer.SerializeToUtf8Bytes(input, JsonOptions);
            if (encoded.Length > 8 * 1024 * 1024) throw new ArgumentException("Migration exceeds 8 MiB.");
            if (input is null || input.Plan?.Owners is null || !Guid.TryParseExact(input.Id, "N", out _) || !input.Plan.Owners.Contains(NodeName()) ||
                !input.Plan.Owners.Contains(input.Source) || input.Native is null || input.Seeds is null) throw new ArgumentException("Invalid migration.");
            // Rebuild the seed against the review's complete protected evidence, not current wall time.
            Validate(new(1, [input.Plan], input.Seeds));
            var rebuilt = BuildBootstrap(input.Id, input.Source, input.Plan, input.Native, input.CapturedUtc);
            if (!encoded.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(rebuilt, JsonOptions))) throw new ArgumentException("Migration authority does not match captured native evidence.");
            DateTime observedUtc = DateTime.UtcNow;
            var protectedEntries = input.Seeds.Single(replica => replica.Node == input.Source).Entries;
            if (input.Native.SelectMany(snapshot => snapshot.Entries).Any(entry => entry.Expires > observedUtc && !protectedEntries.Any(protection => protection.Address == entry.Address && protection.Client == entry.Client && protection.Expires >= entry.Expires)))
                throw new ArgumentException("Migration omits still-active native evidence; capture a new review.");
            string hash = Convert.ToHexString(SHA256.HashData(encoded));
            lock (_sync)
            {
                var previous = Bootstrap(input.Plan.Scope);
                if (previous is not null)
                {
                    if (previous.Id != input.Id || previous.Hash != hash) throw new InvalidOperationException("A different immutable migration already owns this scope.");
                    return; // Never overwrite authority after a lost response or restart.
                }
                if (Plan(input.Plan.Scope) is not null) throw new InvalidOperationException("Scope already has allocation ownership.");
                var next = _state with { Plans = _state.Plans.Append(Copy(input.Plan)).ToArray(), Replicas = _state.Replicas.Concat(input.Seeds.Select(Copy)).ToArray(),
                    Bootstraps = (_state.Bootstraps ?? []).Append(new(input.Id, input.Plan.Scope, hash, "Prepared", Encoding.UTF8.GetString(encoded), [NodeName()])).ToArray() };
                Validate(next); Save(next);
            }
        }
        public void CommitBootstrap(string scope, string id, string hash)
        {
            lock (_sync)
            {
                var previous = Bootstrap(scope) ?? throw new InvalidOperationException("Prepare migration before committing ownership.");
                if (previous.Id != id || previous.Hash != hash) throw new InvalidOperationException("Migration review identity changed.");
                if (previous.Phase == "Committed") return;
                var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(previous.Payload, JsonOptions);
                if (NodeName() == input.Source && !(previous.PreparedNodes ?? []).Order(StringComparer.Ordinal).SequenceEqual(input.Plan.Owners.Order(StringComparer.Ordinal)))
                    throw new InvalidOperationException("Every owner must acknowledge durable preparation before the coordinator commits.");
                Save(_state with { Bootstraps = _state.Bootstraps.Select(b => b.Scope == scope ? b with { Phase = "Committed" } : b).ToArray() });
            }
        }
        public void AcknowledgeBootstrap(string scope, string id, string hash, string node)
        {
            lock (_sync)
            {
                var previous = Bootstrap(scope) ?? throw new InvalidOperationException("Missing prepared migration.");
                var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(previous.Payload, JsonOptions);
                if (previous.Id != id || previous.Hash != hash || input.Source != NodeName() || !input.Plan.Owners.Contains(node)) throw new InvalidOperationException("Invalid preparation acknowledgement.");
                if ((previous.PreparedNodes ?? []).Contains(node)) return;
                Save(_state with { Bootstraps = _state.Bootstraps.Select(b => b.Scope == scope ? b with { PreparedNodes = (b.PreparedNodes ?? []).Append(node).Order(StringComparer.Ordinal).ToArray() } : b).ToArray() });
            }
        }
        public AllocationEntry[] NativeHolds(string scope)
        { lock (_sync) return (_state.NativeHolds ?? []).Where(h => h.Scope == scope && h.Entry.Expires > DateTime.UtcNow).Select(h => h.Entry).ToArray(); }
        static AllocationEntry CombineNativeProtection(AllocationEntry previous, AllocationEntry observed, bool capturedOffer)
        {
            if (previous is null) return observed;
            if (previous.Client != observed.Client || !Lease.ParseHardwareAddress(previous.Hardware).SequenceEqual(Lease.ParseHardwareAddress(observed.Hardware)))
                throw new InvalidOperationException("Native client or hardware evidence conflicts with durable protection.");
            DateTime expires = previous.Expires > observed.Expires ? previous.Expires : observed.Expires;
            if (previous.State == "Declined")
            {
                if (observed.State != "Declined" && !capturedOffer) throw new InvalidOperationException("Native address remains quarantined; wait for its protection to expire.");
                return previous with { Expires = expires };
            }
            if (observed.State == "Declined") return observed;
            var retained = previous.State == "Lease" && observed.State == "Offer" ? previous : observed;
            return retained with { Expires = expires };
        }
        public void ProtectNative(string scope, AllocationEntry entry)
        {
            Validate(new(1, [], [], NativeHolds: [new(scope, entry)]));
            lock (_sync)
            {
                var previous = NativeHolds(scope).SingleOrDefault(e => e.Address == entry.Address);
                entry = CombineNativeProtection(previous, entry, false);
                var holds = (_state.NativeHolds ?? []).Where(h => h.Entry.Expires > DateTime.UtcNow && (h.Scope != scope || h.Entry.Address != entry.Address)).Append(new(scope, entry)).ToArray();
                var next = _state with { NativeHolds = holds }; Validate(next); Save(next);
            }
        }
        public void ReleaseNative(string scope, uint address, string client)
        {
            lock (_sync)
            {
                var holds = (_state.NativeHolds ?? []).Where(h => h.Scope != scope || h.Entry.Address != address || h.Entry.Client != client || h.Entry.State == "Declined").ToArray();
                if (holds.Length != (_state.NativeHolds?.Length ?? 0)) Save(_state with { NativeHolds = holds });
            }
        }
        public void ProtectNativeOffers(string scope, AllocationEntry[] entries)
        {
            if (entries is null || entries.Length > 100000 || entries.Any(entry => entry is null || entry.State != "Offer")) throw new ArgumentException("Invalid captured native offers.");
            foreach (var entry in entries) Validate(new(1, [], [], NativeHolds: [new(scope, entry)]));
            lock (_sync)
            {
                var holds = (_state.NativeHolds ?? []).Where(h => h.Entry.Expires > DateTime.UtcNow).ToList();
                foreach (var entry in entries.Where(e => e.State == "Offer" && e.Expires > DateTime.UtcNow))
                {
                    var previous = holds.SingleOrDefault(hold => hold.Scope == scope && hold.Entry.Address == entry.Address)?.Entry;
                    var retained = CombineNativeProtection(previous, entry, true);
                    holds.RemoveAll(h => h.Scope == scope && h.Entry.Address == entry.Address); holds.Add(new(scope, retained));
                }
                if (JsonSerializer.Serialize(holds, JsonOptions) == JsonSerializer.Serialize(_state.NativeHolds ?? [], JsonOptions)) return;
                var next = _state with { NativeHolds = holds.ToArray() }; Validate(next); Save(next);
            }
        }
        public bool NativeProtected(string scope, uint address, string client = null)
        {
            lock (_sync)
            {
                EnsureLocalAuthority();
                return NativeHolds(scope).Any(e => e.Address == address && (e.State == "Declined" || e.Client != client));
            }
        }
        public void Merge(byte[] bytes, bool importPlans = false)
        {
            var incoming = JsonSerializer.Deserialize<AllocationState>(bytes, JsonOptions); Validate(incoming);
            lock (_sync)
            {
                var plans = _state.Plans.ToDictionary(p => p.Scope);
                foreach (var p in incoming.Plans)
                {
                    if (plans.TryGetValue(p.Scope, out var existing)) { if (!Same(existing, p)) throw new InvalidOperationException("Conflicting ownership epoch."); }
                    else if (importPlans)
                    {
                        if (incoming.Bootstraps?.Any(b => b.Scope == p.Scope) == true || NativeHolds(p.Scope).Length > 0) throw new InvalidOperationException("Reviewed local preparation is required for live native authority.");
                        plans.Add(p.Scope, Copy(p));
                    }
                    else throw new InvalidOperationException("Install the allocation plan before accepting replicas.");
                }
                var replicas = _state.Replicas.ToDictionary(r => (r.Scope, r.Node));
                foreach (var r in incoming.Replicas)
                {
                    if (r.Node == NodeName())
                    {
                        if (replicas.TryGetValue((r.Scope, r.Node), out var own) ? r.Sequence > own.Sequence || r.Sequence == own.Sequence && JsonSerializer.Serialize(r, JsonOptions) != JsonSerializer.Serialize(own, JsonOptions) : r.Sequence > 0)
                        {
                            using var marker = new FileStream(_path + ".recovery-required", FileMode.Create, FileAccess.Write, FileShare.None); marker.WriteByte(1); marker.Flush(true);
                            _recoveryRequired = true; _health = "Local authoritative state is older than peer evidence; DHCP service withheld pending offline recovery";
                            throw new InvalidOperationException(_health);
                        }
                        continue; // remote state never silently overwrites local authoritative allocation state
                    }
                    if (!replicas.TryGetValue((r.Scope, r.Node), out var current)) replicas[(r.Scope, r.Node)] = Copy(r);
                    else if (r.Sequence > current.Sequence)
                    {
                        var incomingEntries = r.Entries.ToDictionary(e => e.Address);
                        // A restored donor may produce a numerically newer snapshot.
                        // Sequence ordering cannot revoke any permanent grant or saved
                        // recovery division that peers already accepted.
                        if (current.Entries.Where(e => e.State == "Grant").Any(grant => (!incomingEntries.TryGetValue(grant.Address, out var incoming) || incoming != grant) && !(r.GrantReclaims ?? []).Any(x => x.Grant == grant)) ||
                            (current.GrantReturns ?? []).Any(old => !(r.GrantReturns ?? []).Contains(old)) ||
                            (current.GrantReclaims ?? []).Any(old => !(r.GrantReclaims ?? []).Contains(old)) ||
                            (current.UnusedRecoveries ?? []).Any(old => !(r.UnusedRecoveries ?? []).Any(next => next.Id == old.Id && next.Receivers.SequenceEqual(old.Receivers) && next.Addresses.SequenceEqual(old.Addresses))))
                            throw new InvalidOperationException("Replica advance would revoke permanent donor authority; recover the latest original journal before rejoining.");
                        replicas[(r.Scope, r.Node)] = Copy(r);
                    }
                    else if (r.Sequence == current.Sequence && JsonSerializer.Serialize(r, JsonOptions) != JsonSerializer.Serialize(current, JsonOptions)) throw new InvalidOperationException("Conflicting replica sequence.");
                }
                var configurations = (_state.Configurations ?? []).ToDictionary(c => c.Scope);
                if (importPlans)
                    foreach (var configuration in incoming.Configurations ?? [])
                    {
                        if (!configurations.TryGetValue(configuration.Scope, out var current) || configuration.Revision > current.Revision) configurations[configuration.Scope] = configuration;
                        else if (configuration.Revision == current.Revision && configuration != current) throw new InvalidOperationException("Conflicting scope configuration revision.");
                    }
                var next = _state with { Plans = plans.Values.ToArray(), Replicas = replicas.Values.ToArray(), Configurations = configurations.Values.ToArray() };
                Validate(next);
                if (JsonSerializer.Serialize(next, JsonOptions) != JsonSerializer.Serialize(_state, JsonOptions)) Save(next);
            }
        }
        public AllocationState LocalSnapshot() => Snapshot(); // donor authorities accompany borrowed allocations
        public void PublishConfiguration(string scope, byte[] data)
        {
            if (data.Length > 768 * 1024) throw new ArgumentException("Scope configuration exceeds 768 KiB.");
            lock (_sync)
            {
                if (!_state.Plans.Any(p => p.Scope == scope)) throw new ArgumentException("Unknown distributed scope.");
                string hash = Convert.ToHexString(SHA256.HashData(data)); var current = (_state.Configurations ?? []).SingleOrDefault(c => c.Scope == scope);
                if (current?.Hash == hash) return;
                var next = new DistributedScopeConfiguration(scope, checked((current?.Revision ?? 0) + 1), hash, Convert.ToBase64String(data));
                Save(_state with { Configurations = (_state.Configurations ?? []).Where(c => c.Scope != scope).Append(next).ToArray() });
            }
        }
        AllocationReplica Local(string scope, AllocationPlan p) => _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == NodeName()) ?? new(scope, p.Epoch, NodeName(), 0, []);
        void Mutate(string scope, AllocationEntry entry)
        {
            var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
            if (!HasAuthority(scope, entry.Address)) throw new InvalidOperationException("Address belongs to a different owner.");
            // Released tombstones can be compacted: every replica is a complete snapshot and sequence is durable.
            var entries = local.Entries.Where(e => e.Address != entry.Address && (e.State == "Grant" || e.State != "Released" && e.Expires > DateTime.UtcNow || IncomingGrant(scope, e.Address)?.Protection?.Expires > DateTime.UtcNow)).Append(entry).ToArray();
            long number = checked(local.Sequence + 1);
            var history = (local.History ?? []).Append(new AllocationEvent(number, DateTime.UtcNow, local.Entries.SingleOrDefault(e => e.Address == entry.Address), entry)).TakeLast(2000).ToArray();
            var next = local with { Sequence = number, Entries = entries, History = history };
            Save(_state with { Replicas = _state.Replicas.Where(r => r.Scope != scope || r.Node != next.Node).Append(next).ToArray() });
        }
        public bool Available(string scope, uint address, string client = null)
        {
            lock (_sync)
            {
                if (_recoveryRequired) return false;
                EnsureLocalAuthority();
                var p = _state.Plans.Single(p => p.Scope == scope);
                var pin = (p.Pins ?? []).SingleOrDefault(pin => pin.Address == address && pin.Client is not null);
                var protectedEntry = Local(scope, p).Entries.SingleOrDefault(e => e.Address == address);
                if (pin is not null && (pin.Client != client || protectedEntry is null || protectedEntry.State == "Released" || protectedEntry.Expires <= DateTime.UtcNow)) return false;
                if ((p.Reservations ?? []).Any(r => r.Address == address && r.Client != client) && (pin is null || pin.Client != client)) return false;
                if (!HasAuthority(scope, address)) return false;
                var protection = IncomingGrant(scope, address);
                if (protection?.Protection?.Expires > DateTime.UtcNow && (protection.Protection.State == "Declined" || client is null || protection.Client != client)) return false;
                var entry = Local(scope, p).Entries.SingleOrDefault(e => e.Address == address);
                return entry is null || entry.State == "Released" || entry.State != "Grant" && (entry.Expires <= DateTime.UtcNow || entry.State != "Declined" && client is not null && entry.Client == client);
            }
        }
        public bool Hold(string scope, uint address, string client, string hardware, string host, DateTime expires)
        {
            lock (_sync)
            {
                if (!Available(scope, address, client)) return false;
                Mutate(scope, Entry(scope, address, client, hardware, host, "Offer", expires)); return true;
            }
        }
        public void Commit(string scope, uint address, string client, string hardware, string host, DateTime expires)
        {
            lock (_sync)
            {
                if (!Available(scope, address, client)) throw new InvalidOperationException("Allocation authority is unavailable.");
                var prior = Local(scope, _state.Plans.Single(p => p.Scope == scope)).Entries.SingleOrDefault(e => e.Address == address && e.State == "Lease" && e.Client == client);
                if (prior is not null && prior.Expires > expires) expires = prior.Expires; // a lost shorter renewal ACK cannot revoke the client's prior lifetime
                var inherited = IncomingGrant(scope, address);
                if (inherited?.Protection?.State == "Lease" && inherited.Protection.Expires > expires) expires = inherited.Protection.Expires;
                Mutate(scope, Entry(scope, address, client, hardware, host, "Lease", expires));
            }
        }
        public void Release(string scope, uint address, string client)
        {
            lock (_sync)
            {
                var p = _state.Plans.Single(p => p.Scope == scope); var entry = Local(scope, p).Entries.SingleOrDefault(e => e.Address == address);
                entry ??= InheritedEntries(scope, NodeName(), "Lease").Concat(InheritedEntries(scope, NodeName(), "Offer")).SingleOrDefault(e => e.Address == address);
                if (entry is null || entry.Client != client || entry.State == "Grant") return;
                Mutate(scope, entry with { State = "Released", Expires = DateTime.UtcNow });
            }
        }
        // A donor grant never expires on its own. A lost response leaves the address held; an idempotent
        // retry returns the same authority. Transfer back requires a future explicit drain/return protocol.
        public AllocationEntry Grant(string scope, uint address, string borrower, string requestId)
        {
            if (!Guid.TryParseExact(requestId, "N", out _)) throw new ArgumentException("Invalid grant request ID.");
            lock (_sync)
            {
                var p = _state.Plans.Single(p => p.Scope == scope);
                if (_sequences[scope].Owner(address) != NodeName()) throw new InvalidOperationException("Only the original owner can grant an address.");
                if ((p.Reservations ?? []).Any(r => r.Address == address)) throw new InvalidOperationException("Reserved addresses cannot be borrowed.");
                if (borrower == NodeName() || !p.Owners.Contains(borrower)) throw new ArgumentException("Unknown borrower.");
                if ((Local(scope, p).GrantReclaims ?? []).Any(x => x.Grant.GrantId == requestId)) throw new InvalidOperationException("Grant request was terminally returned; retain its original outcome.");
                var old = Local(scope, p).Entries.SingleOrDefault(e => e.GrantId == requestId);
                if (old is not null) { if (old.Address != address || old.Borrower != borrower) throw new InvalidOperationException("Grant request changed."); return old; }
                if (RetiredGrant(scope, address)) throw new InvalidOperationException("Returned capacity cannot be regranted in this epoch.");
                if (!Available(scope, address)) throw new InvalidOperationException("Donor address is already held.");
                var grant = new AllocationEntry(address, "", "", "", "Grant", DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc), requestId, borrower);
                Mutate(scope, grant); return grant;
            }
        }
        static string RecoveryGrantId(string id, uint address) => new Guid(SHA256.HashData(Encoding.UTF8.GetBytes("unused:" + id + ":" + address.ToString(System.Globalization.CultureInfo.InvariantCulture))).AsSpan(0, 16)).ToString("N");

        // Offline operation on the externally fenced owner's ORIGINAL store, never a
        // replica. The exclusive store lock excludes a running server. Its watermark
        // binds the original identity and all permanent grants before any import.
        public void RecoverUnusedCapacity(string scope, string[] receivers, string requestId, long expectedSequence)
        {
            if (!Guid.TryParseExact(requestId, "N", out _) || receivers is null || receivers.Length == 0 || receivers.Distinct(StringComparer.Ordinal).Count() != receivers.Length) throw new ArgumentException("Use a stable recovery ID and distinct surviving owners.");
            receivers = receivers.Order(StringComparer.Ordinal).ToArray();
            lock (_sync)
            {
                EnsureLocalAuthority();
                var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                if (BootstrapPending(scope) || !plan.Owners.Contains(NodeName()) || receivers.Any(n => n == NodeName() || !plan.Owners.Contains(n))) throw new InvalidOperationException("Recovery requires committed ownership and enrolled surviving receivers.");
                var previous = local.UnusedRecoveries?.SingleOrDefault(x => x.Id == requestId);
                if (previous is not null)
                {
                    if (!previous.Receivers.SequenceEqual(receivers)) throw new InvalidOperationException("Recovery receivers changed; retry the original division.");
                    return;
                }
                if (local.Sequence != expectedSequence) throw new InvalidOperationException("Owner state changed; read its current fenced journal before recovery.");
                if ((local.UnusedRecoveries?.Length ?? 0) >= 256) throw new InvalidOperationException("Recovery journal limit reached.");
                var entries = local.Entries.ToDictionary(e => e.Address);
                DateTime now = DateTime.UtcNow;
                var addresses = _sequences[scope].Candidates(NodeName()).Where(a => !RetiredGrant(scope, a) && (!entries.TryGetValue(a, out var e) || e.State != "Grant" && (e.State == "Released" || e.Expires <= now))).Take(65537).Order().ToArray();
                if (addresses.Length > 65536) throw new InvalidOperationException("Unused recovery exceeds 65536 addresses; no grants were written.");
                var history = (local.History ?? []).ToList(); long sequence = local.Sequence;
                for (int i = 0; i < addresses.Length; i++)
                {
                    uint address = addresses[i]; entries.TryGetValue(address, out var before);
                    var grant = new AllocationEntry(address, "", "", "", "Grant", DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc), RecoveryGrantId(requestId, address), receivers[i % receivers.Length]);
                    entries[address] = grant; history.Add(new(checked(++sequence), now, before, grant));
                }
                // Even an empty recovery advances the sequence so replicas carry the
                // immutable retry record; replay cannot silently choose new receivers.
                if (sequence == local.Sequence) sequence = checked(sequence + 1);
                var next = local with { Sequence = sequence, Entries = entries.Values.ToArray(), History = history.TakeLast(2000).ToArray(), UnusedRecoveries = (local.UnusedRecoveries ?? []).Append(new(requestId, receivers, addresses)).ToArray() };
                var state = _state with { Replicas = _state.Replicas.Where(r => r.Scope != scope || r.Node != next.Node).Append(next).ToArray() };
                Validate(state); Save(state);
            }
        }
        // Connected-owner surrender is atomic with the existing ACK lock. A lost reply must never
        // restore donor authority; retry the same operation or recover the published grant snapshot.
        public void Handoff(string scope, uint[] addresses, string borrower, string requestId, long expectedSequence)
        {
            if (!Guid.TryParseExact(requestId, "N", out _) || addresses is null || addresses.Length < 1 || addresses.Length > 256 || addresses.Distinct().Count() != addresses.Length) throw new ArgumentException("Use a stable request ID and 1–256 distinct addresses.");
            lock (_sync)
            {
                EnsureLocalAuthority();
                var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                if (borrower == NodeName() || !plan.Owners.Contains(borrower)) throw new ArgumentException("Receiver must be another enrolled owner.");
                string Id(uint address) => new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(requestId + ":" + address.ToString(System.Globalization.CultureInfo.InvariantCulture))).AsSpan(0, 16)).ToString("N");
                bool Retried(uint address) => local.Entries.Any(e => e.Address == address && e.State == "Grant" && e.GrantId == Id(address) && e.Borrower == borrower);
                if (addresses.All(Retried)) return;
                if (local.Sequence != expectedSequence) throw new InvalidOperationException("Owner state changed; review a fresh snapshot before handoff.");
                var entries = local.Entries.ToDictionary(e => e.Address); var history = (local.History ?? []).ToList(); long sequence = local.Sequence;
                foreach (uint address in addresses.Order())
                {
                    if (_sequences[scope].Owner(address) != NodeName()) throw new InvalidOperationException("Only the original owner can surrender an address.");
                    entries.TryGetValue(address, out var previous);
                    if (RetiredGrant(scope, address)) throw new InvalidOperationException("Returned capacity cannot be regranted in this epoch.");
                    if (previous?.State == "Grant") throw new InvalidOperationException("Address already has a permanent receiver.");
                    var reservation = (plan.Reservations ?? []).SingleOrDefault(r => r.Address == address);
                    var active = previous?.Expires > DateTime.UtcNow && previous.State != "Released";
                    var grant = new AllocationEntry(address, active ? previous.Client : reservation?.Client ?? "", active ? previous.Hardware : "", active ? previous.Host : "", "Grant", DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc), Id(address), borrower,
                        Protection: active ? new(previous.State, previous.Expires) : null);
                    entries[address] = grant; history.Add(new(checked(++sequence), DateTime.UtcNow, previous, grant));
                }
                var next = local with { Sequence = sequence, Entries = entries.Values.ToArray(), History = history.TakeLast(2000).ToArray() };
                var state = _state with { Replicas = _state.Replicas.Where(r => r.Scope != scope || r.Node != next.Node).Append(next).ToArray() };
                Validate(state); Save(state);
            }
        }
        AllocationEntry IncomingGrant(string scope, uint address)
        {
            string owner = _sequences[scope].Owner(address);
            return owner == NodeName() ? null : _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner)?.Entries.SingleOrDefault(e => e.Address == address && e.State == "Grant" && e.Borrower == NodeName());
        }
        AllocationEntry Entry(string scope, uint address, string client, string hardware, string host, string state, DateTime expires)
        {
            var p = _state.Plans.Single(p => p.Scope == scope); string owner = _sequences[scope].Owner(address);
            var grant = owner == NodeName() ? null : _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner)?.Entries.SingleOrDefault(e => e.Address == address && e.State == "Grant" && e.Borrower == NodeName());
            return new(address, client, hardware, host, state, expires, grant?.GrantId, null, grant is null ? null : owner);
        }
        public bool HasAuthority(string scope, uint address)
        {
            lock (_sync)
            {
                if (BootstrapPending(scope) || _recoveryRequired) return false;
                var p = _state.Plans.Single(p => p.Scope == scope); string owner = _sequences[scope].Owner(address);
                if (owner == NodeName()) return Local(scope, p).Entries.All(e => e.Address != address || e.State != "Grant");
                return owner is not null && !Relinquished(scope, address, NodeName()) && _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner)?.Entries.Any(e => e.Address == address && e.State == "Grant" && e.Borrower == NodeName()) == true;
            }
        }
        public bool EntireOwnerSurrendered(string scope, string owner, string receiver)
        {
            lock (_sync)
            {
                var plan = _state.Plans.Single(p => p.Scope == scope);
                int index = Array.IndexOf(plan.Owners.Order(StringComparer.Ordinal).ToArray(), owner);
                if (index < 0 || owner == receiver || !plan.Owners.Contains(receiver)) return false;
                ulong expected = (_sequences[scope].Count + (ulong)plan.Owners.Length - 1 - (ulong)index) / (ulong)plan.Owners.Length
                    + (ulong)(plan.Reservations ?? []).Count(r => _sequences[scope].Owner(r.Address) == owner);
                var entries = _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner)?.Entries ?? [];
                return (ulong)entries.Count(e => e.State == "Grant" && e.Borrower == receiver && _sequences[scope].Owner(e.Address) == owner) == expected;
            }
        }
        public uint[] OwnedAddresses(string scope, int maximum = 65536)
        {
            lock (_sync)
            {
                var plan = _state.Plans.Single(p => p.Scope == scope);
                var sequence = _sequences[scope];
                var addresses = sequence.Candidates(NodeName()).Concat((plan.Reservations ?? []).Where(r => sequence.Owner(r.Address) == NodeName()).Select(r => r.Address)).Take(maximum + 1).ToArray();
                if (addresses.Length > maximum) throw new InvalidOperationException("Owner capacity exceeds the configured recovery batch limit.");
                return addresses;
            }
        }
        public uint[] GrantedAddresses(string scope)
        {
            lock (_sync) return _state.Replicas.Where(r => r.Scope == scope && r.Node != NodeName()).SelectMany(r => r.Entries).Where(e => e.State == "Grant" && e.Borrower == NodeName()).Select(e => e.Address).ToArray();
        }
        public AllocationEntry FindLease(string scope, string client)
        {
            lock (_sync)
            {
                if (ChangePending(scope)) return null;
                var entries = _state.Replicas.Where(r => r.Scope == scope && r.Node == NodeName()).SelectMany(r => r.Entries).ToArray();
                return entries.Where(e => HasAuthority(scope, e.Address) && e.Client == client && e.State == "Lease" && e.Expires > DateTime.UtcNow)
                    .Concat(_state.Replicas.Where(r => r.Scope == scope && r.Node != NodeName()).SelectMany(r => r.Entries)
                        .Where(e => e.State == "Grant" && e.Borrower == NodeName() && !Relinquished(scope, e.Address, NodeName()) && e.Client == client && e.Protection?.State == "Lease" && e.Protection.Expires > DateTime.UtcNow && !entries.Any(l => l.Address == e.Address))
                        .Select(e => Entry(scope, e.Address, e.Client, e.Hardware, e.Host, "Lease", e.Protection.Expires)))
                    .OrderByDescending(e => e.Expires).FirstOrDefault();
            }
        }
        public AllocationEntry FindOffer(string scope, string client)
        { lock (_sync) return ChangePending(scope) ? null : _state.Replicas.Where(r => r.Scope == scope && r.Node == NodeName()).SelectMany(r => r.Entries).Concat(InheritedEntries(scope, NodeName(), "Offer")).Where(e => HasAuthority(scope, e.Address) && e.Client == client && e.State == "Offer" && e.Expires > DateTime.UtcNow).OrderByDescending(e => e.Expires).FirstOrDefault(); }
        public void ReleaseOffer(string scope, string client)
        { lock (_sync) { var offer = FindOffer(scope, client); if (offer is not null) Mutate(scope, offer with { State = "Released", Expires = DateTime.UtcNow }); } }
        public bool HasLiveOffer(string scope, uint address, string client)
        { lock (_sync) return FindOffer(scope, client)?.Address == address; }
        public void Decline(string scope, uint address, string client)
        {
            lock (_sync)
            {
                var p = _state.Plans.Single(p => p.Scope == scope); var entry = Local(scope, p).Entries.SingleOrDefault(e => e.Address == address && e.Client == client);
                entry ??= InheritedEntries(scope, NodeName(), "Lease").Concat(InheritedEntries(scope, NodeName(), "Offer")).SingleOrDefault(e => e.Address == address && e.Client == client);
                if (entry is not null && entry.State != "Grant") Mutate(scope, entry with { State = "Declined", Expires = DateTime.UtcNow.AddMinutes(10) });
            }
        }
        IEnumerable<AllocationEntry> InheritedEntries(string scope, string receiver, string state)
        {
            var local = _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == receiver);
            return _state.Replicas.Where(r => r.Scope == scope && r.Node != receiver).SelectMany(r => r.Entries
                .Where(e => e.State == "Grant" && e.Borrower == receiver && !Relinquished(scope, e.Address, receiver) && e.Protection?.State == state && local?.Entries.Any(l => l.Address == e.Address) != true)
                .Select(e => e with { State = state, Expires = e.Protection.Expires, Borrower = null, AuthorityOwner = r.Node, Protection = null }));
        }
        void RebuildLeaseIndex()
        {
            var receivers = _state.Replicas.ToDictionary(r => (r.Scope, r.Node), r => r.Entries.Select(e => e.Address).ToHashSet());
            var leases = _state.Replicas.SelectMany(r => r.Entries.Where(e => e.State == "Lease").Select(e => new AllocationDevice(r.Scope, r.Node, e)))
                .Concat(_state.Replicas.SelectMany(r => r.Entries.Where(e => e.State == "Grant" && e.Protection?.State == "Lease" && (!receivers.TryGetValue((r.Scope, e.Borrower), out var known) || !known.Contains(e.Address)))
                    .Select(e => new AllocationDevice(r.Scope, e.Borrower, e with { State = "Lease", Expires = e.Protection.Expires, Borrower = null, AuthorityOwner = r.Node, Protection = null }))));
            Volatile.Write(ref _leaseIndex, leases.GroupBy(d => d.Lease.Address).ToDictionary(g => g.Key, g => g.ToArray()));
        }
        public AllocationDevice ResolveLive(uint address)
        {
            if (!Volatile.Read(ref _leaseIndex).TryGetValue(address, out var values)) return null;
            var active = values.Where(d => d.Lease.Expires > DateTime.UtcNow).ToArray();
            return active.Length == 1 ? active[0] : null; // immutable index lookup never waits for replication/disk writes
        }
        public AllocationDevice[] LiveLeases(string scope)
            => Volatile.Read(ref _leaseIndex).Values.SelectMany(d => d).Where(d => d.Scope == scope && d.Lease.Expires > DateTime.UtcNow).ToArray();
        public bool HasLiveConflict(uint address, string client, string hardware)
        { return Volatile.Read(ref _leaseIndex).TryGetValue(address, out var values) && values.Any(d => d.Lease.Expires > DateTime.UtcNow && (d.Lease.Client != client || !string.Equals(d.Lease.Hardware, hardware, StringComparison.OrdinalIgnoreCase))); }
        public AllocationDevice ResolveAt(uint address, DateTime timestamp)
        {
            lock (_sync)
            {
                var latest = HistoricalReplicas(timestamp).Select(r => (r, history: (r.History ?? []).Where(h => h.After.Address == address && h.Timestamp <= timestamp).OrderByDescending(h => h.Sequence).FirstOrDefault())).Where(x => x.history is not null).ToArray();
                var observations = latest.Where(x => x.history.After.State == "Lease" && x.history.After.Expires > timestamp).Select(x => new AllocationDevice(x.r.Scope, x.r.Node, x.history.After))
                    .Concat(latest.Where(x => x.history.After.State == "Grant" && x.history.After.Protection?.State == "Lease" && x.history.After.Protection.Expires > timestamp && !latest.Any(other => other.r.Scope == x.r.Scope && other.r.Node == x.history.After.Borrower && other.history.Timestamp >= x.history.Timestamp))
                        .Select(x => new AllocationDevice(x.r.Scope, x.history.After.Borrower, x.history.After with { State = "Lease", Expires = x.history.After.Protection.Expires, Borrower = null, AuthorityOwner = x.r.Node, Protection = null }))).ToArray();
                return observations.Length == 1 ? observations[0] : null;
            }
        }
        public void Start(Func<CancellationToken, Task> synchronize)
        {
            lock (_sync) _worker ??= Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    try { await synchronize(_stop.Token); lock (_sync) _health = "Synchronization pass completed; inspect per-owner sequences for applied state"; }
                    catch (OperationCanceledException) when (_stop.IsCancellationRequested) { break; }
                    catch (Exception) { lock (_sync) _health = "Synchronization failed; authoritative local allocations retained, retry scheduled"; }
                    try { await Task.Delay(TimeSpan.FromSeconds(5), _stop.Token); } catch (OperationCanceledException) { break; }
                }
            });
        }
        public async ValueTask DisposeAsync()
        { if (Interlocked.Exchange(ref _disposed, 1) != 0) return; _stop.Cancel(); try { if (_worker is not null) await _worker; } finally { _stop.Dispose(); _writerLock.Dispose(); } }
    }
}
