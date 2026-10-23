// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        void RequireOwnershipCoordinator(HttpContext context)
        {
            if (!HasDirectTlsTransport(context)) throw new DnsWebServiceException("Use a direct HTTPS administrator connection."); RequireBootstrapCoordinator(context);
            if (_voting.Initialized) { RequireVotingAdmin(context); _voting.RequireLeader(); }
        }
        void RequireOwnershipPeer(HttpContext context)
        {
            if (!HasDirectTlsTransport(context)) throw new DnsWebServiceException("Use a direct HTTPS cluster connection."); RequireBootstrapPeer(context);
            if (_voting.Initialized)
            {
                VotingEnrollment();
                _voting.RequirePeerLeader(_clusterManager.GetPrimaryNode().Name, long.Parse(context.Request.GetQueryOrForm("votingTerm"), System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        void WriteOwnershipChange(HttpContext context, string scope)
        {
            context.GetCurrentJsonWriter().WritePropertyName("state");
            JsonSerializer.Serialize(context.GetCurrentJsonWriter(), _allocation.Change(scope), DistributedAllocation.JsonOptions);
        }
        void OwnershipChangeStatus(HttpContext context)
        { RequireOwnershipCoordinator(context); WriteOwnershipChange(context, context.Request.GetQueryOrForm("scope")); }
        void CheckOwnershipParticipants(AllocationPlan old, AllocationPlan desired)
        {
            if (old is null || desired is null || desired.Scope != old.Scope || desired.Pins is not null || !desired.Owners.Contains(_clusterManager.GetPrimaryNode().Name)) throw new ArgumentException("Keep the current primary in the successor ownership plan.");
            _ = new AllocationSequence(desired);
            if (old.Mask != desired.Mask || (old.First & old.Mask) != (desired.First & desired.Mask) || (old.First & old.Mask) != (desired.Last & desired.Mask)) throw new ArgumentException("Keep the same subnet and mask; migrate different subnets separately.");
            var enrolled = BootstrapOwners();
            if (old.Owners.Concat(desired.Owners).Any(n => !enrolled.Contains(n))) throw new InvalidOperationException("Every old and new owner must remain enrolled and unfenced until commit.");
        }
        async Task<JsonElement> OwnershipPeerCall(ClusterNode peer, string action, params (string Key, string Value)[] fields)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_allocationStop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(15));
            var values = fields.ToDictionary(f => f.Key, f => f.Value);
            if (_voting.Initialized) { _voting.RequireLeader(); values.Add("votingTerm", _voting.Status().State.Term.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
            using var json = JsonDocument.Parse(await peer.ChangeAllocationAsync(action, values, deadline.Token)); return json.RootElement.Clone();
        }
        AllocationPlan ReadOwnershipPlan(HttpContext context)
        {
            string json = context.Request.GetQueryOrForm("plan");
            if (Encoding.UTF8.GetByteCount(json) > 2 * 1024 * 1024) throw new ArgumentException("Scope plan exceeds 2 MiB.");
            return JsonSerializer.Deserialize<AllocationPlan>(json, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing successor plan.");
        }
        Scope ReadOwnershipConfiguration(AllocationPlan plan)
        {
            using var bytes = new MemoryStream(Convert.FromBase64String(plan.Configuration ?? throw new ArgumentException("Provide the reviewed paused native scope configuration.")));
            var source = new Scope(bytes, _log, _dhcpServer);
            if (source.Enabled || source.Name != plan.Scope || !source.MatchesAllocationPlan(plan)) { source.Dispose(); throw new ArgumentException("Native scope configuration differs from the reviewed plan or is enabled."); }
            return source;
        }
        static string OwnershipConfiguration(Scope scope)
        { using var bytes = new MemoryStream(); scope.WriteTo(bytes, false, false); return Convert.ToBase64String(bytes.ToArray()); }
        async Task<AllocationFrozenOwner> FreezeLocalOwnership(string id, AllocationPlan old, Action validate)
        {
            var scope = _dhcpServer.GetScope(old.Scope) ?? throw new ArgumentException("Configure this scope on every participant first.");
            if (scope.Enabled) throw new InvalidOperationException("Pause this scope on every participant before changing ownership.");
            if (_allocation.Change(old.Scope)?.Id == id)
            {
                AllocationFrozenOwner retry = null;
                _voting.GuardMutation(validate, () => retry = _allocation.FreezeChange(id, old)); return retry;
            }
            if (_allocation.Plan(old.Scope) is null && !scope.CanInitializeAllocation) throw new InvalidOperationException("A new owner must have an empty paused scope; migrate its native bindings separately.");
            AllocationFrozenOwner frozen = null;
            await scope.CaptureNativeAllocationAsync(_allocation.NodeName(), _allocationStop.Token, snapshot =>
            {
                if (!ReferenceEquals(scope, _dhcpServer.GetScope(old.Scope)) || old.Owners.Contains(_allocation.NodeName()) && !scope.MatchesAllocationPlan(old)) throw new InvalidOperationException("Current scope identity or eligibility changed.");
                _voting.GuardMutation(validate, () => frozen = _allocation.FreezeChange(id, old, snapshot.Entries, snapshot.Configuration)); return Task.CompletedTask;
            });
            return frozen;
        }
        async Task FreezeOwnershipChangePeer(HttpContext context)
        {
            RequireOwnershipPeer(context);
            var old = JsonSerializer.Deserialize<AllocationPlan>(context.Request.GetQueryOrForm("currentPlan"), DistributedAllocation.JsonOptions);
            var result = await FreezeLocalOwnership(context.Request.GetQueryOrForm("id"), old, () => RequireOwnershipPeer(context));
            RequireOwnershipPeer(context);
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), result, DistributedAllocation.JsonOptions);
        }
        async Task PreviewOwnershipChange(HttpContext context)
        {
            RequireOwnershipCoordinator(context);
            if (_voting.Initialized)
            {
                await _votingOperation.WaitAsync(context.RequestAborted);
                try
                {
                    RequireOwnershipCoordinator(context); long term = _voting.Status().State.Term;
                    int barrier = _voting.Add(Guid.NewGuid().ToString("N"), "Noop", "");
                    await ReplicateVoting(context, term); _voting.RequireCommitted(barrier); RequireOwnershipCoordinator(context);
                }
                finally { _votingOperation.Release(); }
            }
            var desired = ReadOwnershipPlan(context); var old = _allocation.Plan(desired.Scope) ?? throw new ArgumentException("This scope has no current allocation epoch.");
            string expected = context.Request.GetQueryOrForm("expectedEpoch");
            if (old.Epoch != expected) throw new InvalidOperationException("Current epoch changed; review the saved ownership status.");
            CheckOwnershipParticipants(old, desired); using var source = ReadOwnershipConfiguration(desired);
            var participants = old.Owners.Concat(desired.Owners).Distinct().Order(StringComparer.Ordinal).ToArray();
            var frozen = new System.Collections.Generic.List<AllocationFrozenOwner>();
            frozen.Add(await FreezeLocalOwnership(desired.Epoch, old, () => RequireOwnershipCoordinator(context)));
            RequireOwnershipCoordinator(context); CheckOwnershipParticipants(old, desired);
            foreach (string node in participants.Where(n => n != _allocation.NodeName()))
            {
                var peer = _clusterManager.ClusterNodes.Values.Single(n => n.Name == node);
                var reply = await OwnershipPeerCall(peer, "freezePeer", ("id", desired.Epoch), ("currentPlan", JsonSerializer.Serialize(old, DistributedAllocation.JsonOptions)));
                RequireOwnershipCoordinator(context); CheckOwnershipParticipants(old, desired);
                var snapshot = reply.Deserialize<AllocationFrozenOwner>(DistributedAllocation.JsonOptions);
                if (snapshot.Node != node) throw new InvalidOperationException("Peer freeze identity changed.");
                frozen.Add(snapshot);
            }
            var input = DistributedAllocation.BuildChange(desired.Epoch, _allocation.NodeName(), desired, frozen.ToArray());
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), input, DistributedAllocation.JsonOptions);
            context.GetCurrentJsonWriter().WriteString("hash", DistributedAllocation.ChangeHash(input));
        }
        AllocationChangeInput ReadOwnershipChange(HttpContext context)
        {
            string json = context.Request.GetQueryOrForm("change");
            if (Encoding.UTF8.GetByteCount(json) > 2 * 1024 * 1024) throw new ArgumentException("Native ownership review exceeds 2 MiB.");
            var input = JsonSerializer.Deserialize<AllocationChangeInput>(json, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing ownership review.");
            if (input.Source != _clusterManager.GetPrimaryNode().Name || input.Plan.Pins is { Length: > 100000 } || DistributedAllocation.ChangeHash(input) != context.Request.GetQueryOrForm("expectedHash")) throw new InvalidOperationException("Ownership source or review hash changed.");
            CheckOwnershipParticipants(input.Frozen[0].Plan, input.Plan with { Pins = null }); return input;
        }
        async Task PrepareLocalOwnership(AllocationChangeInput input, Action validate)
        {
            validate(); RequireVotingOwnership(input);
            var scope = _dhcpServer.GetScope(input.Plan.Scope) ?? throw new ArgumentException("Unknown scope.");
            if (scope.Enabled) throw new InvalidOperationException("Keep the scope paused until ownership commits.");
            using var source = ReadOwnershipConfiguration(input.Plan);
            _voting.GuardMutation(() => { validate(); RequireVotingOwnership(input); }, () => _allocation.PrepareChange(input));
            if (_allocation.Change(input.Plan.Scope).Phase == "Prepared")
            {
                await scope.ApplyOwnershipChangeAsync(source, input.Plan, () => { validate(); RequireVotingOwnership(input); }); validate(); RequireVotingOwnership(input);
                using var persisted = _dhcpServer.SaveProvisionedScope(scope.Name);
                if (!persisted.MatchesAllocationPlan(input.Plan) || persisted.Enabled || OwnershipConfiguration(persisted) != input.Plan.Configuration) throw new InvalidOperationException("Persisted native scope options differ from prepared ownership.");
                _voting.GuardMutation(() => { validate(); RequireVotingOwnership(input); }, () => _allocation.ConfirmChangeConfiguration(scope.Name, input.Id, DistributedAllocation.ChangeHash(input)));
            }
        }
        async Task StageOwnershipChangePeer(HttpContext context)
        {
            RequireOwnershipPeer(context); var input = ReadOwnershipChange(context);
            await PrepareLocalOwnership(input, () => RequireOwnershipPeer(context)); RequireOwnershipPeer(context); WriteOwnershipChange(context, input.Plan.Scope);
        }
        async Task PrepareOwnershipChange(HttpContext context)
        {
            RequireOwnershipCoordinator(context); var input = ReadOwnershipChange(context);
            await PrepareLocalOwnership(input, () => RequireOwnershipCoordinator(context)); RequireOwnershipCoordinator(context); CheckOwnershipParticipants(input.Frozen[0].Plan, input.Plan with { Pins = null });
            var current = _allocation.Change(input.Plan.Scope);
            if (current.Phase == "Committed") { WriteOwnershipChange(context, input.Plan.Scope); return; }
            foreach (string node in input.Frozen.Select(f => f.Node).Where(n => n != _allocation.NodeName()))
            {
                var reply = await OwnershipPeerCall(_clusterManager.ClusterNodes.Values.Single(n => n.Name == node), "stage", ("change", current.Payload), ("expectedHash", current.Hash));
                RequireOwnershipCoordinator(context); CheckOwnershipParticipants(input.Frozen[0].Plan, input.Plan with { Pins = null });
                if (reply.GetProperty("id").GetString() != current.Id || reply.GetProperty("hash").GetString() != current.Hash || !reply.GetProperty("preparedNodes").EnumerateArray().Any(n => n.GetString() == node)) throw new InvalidOperationException("Peer has not durably applied the reviewed native configuration.");
                _allocation.AcknowledgeChange(input.Plan.Scope, current.Id, current.Hash, node);
            }
            WriteOwnershipChange(context, input.Plan.Scope);
        }
        void ValidateOwnershipCommit(AllocationChangeRecord record)
        {
            var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload ?? throw new InvalidOperationException("Prepare ownership before commit."), DistributedAllocation.JsonOptions);
            RequireVotingOwnership(input);
            CheckOwnershipParticipants(input.Frozen[0].Plan, input.Plan with { Pins = null });
            if (input.Source != _clusterManager.GetPrimaryNode().Name || _dhcpServer.GetScope(record.Scope)?.MatchesAllocationPlan(input.Plan) != true) throw new InvalidOperationException("Primary or scope eligibility changed; resume the exact prepared change.");
            using var persisted = _dhcpServer.ReadPersistedAllocationScope(record.Scope);
            if (OwnershipConfiguration(persisted) != input.Plan.Configuration) throw new InvalidOperationException("Persisted native configuration is missing or differs from the reviewed successor.");
        }
        void RequireVotingOwnership(AllocationChangeInput input)
        {
            if (_voting.Initialized) _voting.RequireOwnership(new(input.Plan.Scope, input.Frozen[0].Plan.Epoch, input.Id, DistributedAllocation.ChangeHash(input)));
        }
        async Task CommitOwnershipChange(HttpContext context)
        {
            RequireOwnershipCoordinator(context); string scope = context.Request.GetQueryOrForm("scope");
            var record = _allocation.Change(scope) ?? throw new InvalidOperationException("Missing ownership change.");
            string id = context.Request.GetQueryOrForm("id"), hash = context.Request.GetQueryOrForm("expectedHash");
            if (record.Id != id || record.Hash != hash) throw new InvalidOperationException("Ownership commit identity changed.");
            ValidateOwnershipCommit(record);
            var input = JsonSerializer.Deserialize<AllocationChangeInput>(record.Payload, DistributedAllocation.JsonOptions);
            var participants = input.Frozen.Select(f => f.Node).Order(StringComparer.Ordinal).ToArray();
            if (!record.PreparedNodes.SequenceEqual(participants)) throw new InvalidOperationException("All participants must acknowledge preparation before commit.");
            foreach (string node in participants.Where(n => n != _allocation.NodeName()))
            {
                await OwnershipPeerCall(_clusterManager.ClusterNodes.Values.Single(n => n.Name == node), "commitPeer", ("scope", scope), ("id", id), ("expectedHash", hash), ("preparedNodes", JsonSerializer.Serialize(participants)));
                RequireOwnershipCoordinator(context); ValidateOwnershipCommit(record);
            }
            _voting.GuardMutation(() => { RequireOwnershipCoordinator(context); ValidateOwnershipCommit(record); }, () => _allocation.CommitChange(scope, id, hash)); WriteOwnershipChange(context, scope);
        }
        void CommitOwnershipChangePeer(HttpContext context)
        {
            RequireOwnershipPeer(context); string scope = context.Request.GetQueryOrForm("scope");
            var record = _allocation.Change(scope) ?? throw new InvalidOperationException("Missing ownership change."); ValidateOwnershipCommit(record);
            _voting.GuardMutation(() => { RequireOwnershipPeer(context); ValidateOwnershipCommit(record); }, () => _allocation.CommitChange(scope, context.Request.GetQueryOrForm("id"), context.Request.GetQueryOrForm("expectedHash"), JsonSerializer.Deserialize<string[]>(context.Request.GetQueryOrForm("preparedNodes"))));
            WriteOwnershipChange(context, scope);
        }
    }
}
