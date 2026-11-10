// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace DnsServerCore.Dhcp
{
    public sealed partial class DistributedAllocation
    {
        public static string GrantReviewHash(string scope, string epoch, string owner, AllocationEntry grant)
            => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { scope, epoch, owner, grant }, JsonOptions)));
        public static string GrantReturnHash(string scope, string epoch, AllocationGrantReturn receipt)
            => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { scope, epoch, receipt }, JsonOptions)));
        // Receipts are epoch-local, append-only, bounded, and watermark-bound as part
        // of the issuing owner's replica. A timeout never cancels a surrender.
        static void ValidateGrantLifecycle(AllocationState state)
        {
            foreach (var replica in state.Replicas)
            {
                var plan = state.Plans.Single(p => p.Scope == replica.Scope);
                foreach (var receipts in new[] { replica.GrantReturns, replica.GrantReclaims })
                {
                    if (receipts is null) continue;
                    if (receipts.Length > 256 || receipts.Any(x => x is null) || receipts.Select(x => x.Id).Distinct().Count() != receipts.Length || receipts.Select(x => x.Grant?.Address).Distinct().Count() != receipts.Length)
                        throw new ArgumentException("Invalid grant lifecycle journal.");
                    foreach (var receipt in receipts)
                    {
                        var grant = receipt.Grant;
                        if (!Guid.TryParseExact(receipt.Id, "N", out _) || grant is null || grant.State != "Grant" || !Guid.TryParseExact(grant.GrantId, "N", out _) ||
                            !plan.Owners.Contains(receipt.Owner) || !plan.Owners.Contains(grant.Borrower) || receipt.Owner == grant.Borrower ||
                            new AllocationSequence(plan).Owner(grant.Address) != receipt.Owner || receipt.BorrowerSequence < 1 || grant.Expires.Kind != DateTimeKind.Utc || grant.Expires != DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc) ||
                            grant.AuthorityOwner is not null || (grant.Protection is not null && (grant.Protection.Expires.Kind != DateTimeKind.Utc || grant.Protection.State != "Offer" && grant.Protection.State != "Lease" && grant.Protection.State != "Declined" || string.IsNullOrEmpty(grant.Client))) || grant.Client?.Length > 1024 || grant.Hardware?.Length > 255 || grant.Host?.Length > 255)
                            throw new ArgumentException("Invalid grant relinquishment identity.");
                        bool surrender = ReferenceEquals(receipts, replica.GrantReturns);
                        if (replica.Node != (surrender ? grant.Borrower : receipt.Owner) || surrender && receipt.BorrowerSequence > replica.Sequence)
                            throw new ArgumentException("Receipt was not issued by its authority.");
                        var donor = state.Replicas.SingleOrDefault(r => r.Scope == replica.Scope && r.Node == receipt.Owner);
                        if (donor is null || !donor.Entries.Contains(grant) && !(donor.GrantReclaims ?? []).Contains(receipt))
                            throw new ArgumentException("Receipt lacks the exact durable original grant.");
                        if (!surrender && state.Replicas.SingleOrDefault(r => r.Scope == replica.Scope && r.Node == grant.Borrower)?.GrantReturns?.Contains(receipt) != true)
                            throw new ArgumentException("Reclamation lacks durable borrower surrender.");
                        if (!surrender && replica.Entries.Any(e => e.Address == grant.Address && e.State == "Grant")) throw new ArgumentException("Reclaimed capacity still carries an active donor grant.");
                        if (surrender && replica.Entries.Any(e => e.Address == grant.Address)) throw new ArgumentException("Relinquished grant still has borrower bindings.");
                    }
                }
                var requests = replica.BorrowRequests;
                if (requests is not null && (requests.Length > 127 || requests.Any(x => x is null || !Guid.TryParseExact(x.Id, "N", out _) || x.Donor == replica.Node || !plan.Owners.Contains(x.Donor)) || requests.Select(x => x.Donor).Distinct().Count() != requests.Length || requests.Select(x => x.Id).Distinct().Count() != requests.Length))
                    throw new ArgumentException("Invalid pending capacity requests.");
            }
        }
        bool Relinquished(string scope, uint address, string borrower) => _state.Replicas.Any(r => r.Scope == scope &&
            ((r.GrantReturns ?? []).Any(x => x.Grant.Address == address && x.Grant.Borrower == borrower) || (r.GrantReclaims ?? []).Any(x => x.Grant.Address == address && x.Grant.Borrower == borrower)));
        public bool IsRetiredGrant(string scope, uint address) { lock (_sync) return RetiredGrant(scope, address); }
        bool RetiredGrant(string scope, uint address) => _state.Replicas.Any(r => r.Scope == scope && (r.GrantReclaims ?? []).Any(x => x.Grant.Address == address));
        void SaveReplica(AllocationReplica replica)
        {
            var next = _state with { Replicas = _state.Replicas.Where(r => r.Scope != replica.Scope || r.Node != replica.Node).Append(replica).ToArray() };
            Validate(next); Save(next);
        }
        public string CapacityRequest(string scope, string donor)
        {
            lock (_sync)
            {
                EnsureLocalAuthority();
                var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                if (BootstrapPending(scope) || donor == NodeName() || !plan.Owners.Contains(donor)) throw new InvalidOperationException("A current committed donor is required.");
                var pending = local.BorrowRequests?.SingleOrDefault(x => x.Donor == donor);
                if (pending is not null) return pending.Id;
                string id = Guid.NewGuid().ToString("N");
                SaveReplica(local with { Sequence = checked(local.Sequence + 1), BorrowRequests = (local.BorrowRequests ?? []).Append(new(donor, id)).ToArray() });
                return id;
            }
        }
        public void CompleteCapacityRequest(string scope, string donor, string id)
        {
            lock (_sync)
            {
                EnsureLocalAuthority(); var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                var pending = local.BorrowRequests?.SingleOrDefault(x => x.Donor == donor);
                if (pending is null) return;
                if (pending.Id != id || !_state.Replicas.Any(r => r.Scope == scope && r.Node == donor && (r.Entries.Any(e => e.GrantId == id && e.Borrower == NodeName()) || (r.GrantReclaims ?? []).Any(x => x.Grant.GrantId == id && x.Grant.Borrower == NodeName()))))
                    throw new InvalidOperationException("The exact capacity request has no durable donor outcome.");
                SaveReplica(local with { Sequence = checked(local.Sequence + 1), BorrowRequests = local.BorrowRequests.Where(x => x.Donor != donor).ToArray() });
            }
        }
        public AllocationGrantReturn RelinquishGrant(string scope, string epoch, string owner, uint address, string grantId, string id, long expectedSequence)
        {
            if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("Use a stable return request ID.");
            lock (_sync)
            {
                EnsureLocalAuthority(); var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                if (plan.Epoch != epoch || BootstrapPending(scope)) throw new InvalidOperationException("Return requires the current committed epoch.");
                var prior = local.GrantReturns?.SingleOrDefault(x => x.Id == id);
                if (prior is not null)
                {
                    if (prior.Owner != owner || prior.Grant.Address != address || prior.Grant.GrantId != grantId) throw new InvalidOperationException("Return request content changed.");
                    return prior;
                }
                if (local.Sequence != expectedSequence) throw new InvalidOperationException("Borrower changed; review its current sequence before return.");
                if ((local.GrantReturns?.Length ?? 0) >= 256 || (local.GrantReturns ?? []).Any(x => x.Grant.Address == address)) throw new InvalidOperationException("Grant already returned or return journal is full.");
                var grant = _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner)?.Entries.SingleOrDefault(e => e.Address == address && e.State == "Grant" && e.GrantId == grantId && e.Borrower == NodeName())
                    ?? throw new InvalidOperationException("The exact current original donor grant is required.");
                DateTime now = DateTime.UtcNow;
                if (grant.Protection?.Expires > now || local.Entries.Any(e => e.Address == address && e.State != "Released" && e.Expires > now) || NativeHolds(scope).Any(e => e.Address == address && e.Expires > now))
                    throw new InvalidOperationException("Retain the grant until all leases, offers and protections have expired or been released.");
                var receipt = new AllocationGrantReturn(id, owner, grant, checked(local.Sequence + 1));
                SaveReplica(local with { Sequence = receipt.BorrowerSequence, Entries = local.Entries.Where(e => e.Address != address).ToArray(), GrantReturns = (local.GrantReturns ?? []).Append(receipt).ToArray() });
                return receipt;
            }
        }
        public AllocationGrantReturn ReclaimGrant(string scope, string epoch, string borrower, string id, long expectedSequence)
        {
            lock (_sync)
            {
                EnsureLocalAuthority(); var plan = _state.Plans.Single(p => p.Scope == scope); var local = Local(scope, plan);
                if (plan.Epoch != epoch || BootstrapPending(scope)) throw new InvalidOperationException("Reclaim requires the current committed epoch.");
                var prior = local.GrantReclaims?.SingleOrDefault(x => x.Id == id);
                if (prior is not null) { if (prior.Grant.Borrower != borrower) throw new InvalidOperationException("Reclaim borrower changed."); return prior; }
                if (local.Sequence != expectedSequence || (local.GrantReclaims?.Length ?? 0) >= 256) throw new InvalidOperationException("Review current donor sequence or retain capacity at the journal limit.");
                var receipt = _state.Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == borrower)?.GrantReturns?.SingleOrDefault(x => x.Id == id && x.Owner == NodeName())
                    ?? throw new InvalidOperationException("Missing durable borrower surrender; absence or a fence request is not proof.");
                if (!local.Entries.Contains(receipt.Grant)) throw new InvalidOperationException("Original donor grant differs from the surrender receipt.");
                if (NativeHolds(scope).Any(e => e.Address == receipt.Grant.Address && e.Expires > DateTime.UtcNow)) throw new InvalidOperationException("Native bindings still protect the returned address.");
                SaveReplica(local with { Sequence = checked(local.Sequence + 1), Entries = local.Entries.Where(e => e.Address != receipt.Grant.Address).ToArray(), GrantReclaims = (local.GrantReclaims ?? []).Append(receipt).ToArray() });
                return receipt;
            }
        }
    }
}
