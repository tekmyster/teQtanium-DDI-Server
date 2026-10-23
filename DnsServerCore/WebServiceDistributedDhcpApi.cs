using DnsServerCore.Auth;
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
        readonly DistributedAllocation _allocation;
        readonly CancellationTokenSource _allocationStop = new();
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        void RequireBootstrapCoordinator(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (!context.Request.IsHttps || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken ||
                !_authManager.IsPermitted(PermissionSection.Administration, GetSessionUser(context), PermissionFlag.Delete))
                throw new DnsWebServiceException("Ownership migration requires a direct HTTPS administrator session.");
            if (!_clusterManager.ClusterInitialized || _clusterManager.GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsWebServiceException("Create live ownership migration on the cluster primary.");
        }
        void RequireBootstrapPeer(HttpContext context)
        {
            RequireAllocationService(context);
            var address = context.Connection.RemoteIpAddress;
            if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
            if (!_clusterManager.GetPrimaryNode().IPAddresses.Contains(address)) throw new DnsWebServiceException("Only the enrolled primary may prepare live migration.");
        }
        string[] BootstrapOwners()
        {
            if (_clusterManager.ClusterNodes.Values.Any(n => n.IsFenced)) throw new InvalidOperationException("Resolve fenced cluster members before initial migration.");
            return _clusterManager.ClusterNodes.Values.Select(n => n.Name).Order(StringComparer.Ordinal).ToArray();
        }
        AllocationPlan BootstrapPlan(string scope, string[] owners, string id, string seed, DhcpHaGroup[] groups = null)
        {
            var native = _dhcpServer.GetScope(scope) ?? throw new ArgumentException("Configure the scope on every owner before migration.");
            using var bytes = new MemoryStream(); native.WriteTo(bytes, false, false);
            var plan = native.BuildAllocationPlan(id, seed, owners) with { Configuration = Convert.ToBase64String(bytes.ToArray()), HaGroups = groups };
            _ = new AllocationSequence(plan); return plan;
        }
        async Task<JsonElement> BootstrapPeerCall(ClusterNode peer, string action, params (string Key, string Value)[] fields)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_allocationStop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(15));
            byte[] data = await peer.BootstrapAllocationAsync(action, fields.ToDictionary(f => f.Key, f => f.Value), deadline.Token);
            using var json = JsonDocument.Parse(data); return json.RootElement.Clone();
        }
        void WriteBootstrap(HttpContext context, string scope)
        {
            var record = _allocation.Bootstrap(scope);
            context.GetCurrentJsonWriter().WritePropertyName("state");
            JsonSerializer.Serialize(context.GetCurrentJsonWriter(), record is null ? null : new { record.Id, record.Scope, record.Hash, record.Phase, record.PreparedNodes }, DistributedAllocation.JsonOptions);
        }
        void GetLiveBootstrap(HttpContext context)
        {
            RequireBootstrapCoordinator(context);
            string scope = context.Request.GetQueryOrForm("scope");
            WriteBootstrap(context, scope);
            context.GetCurrentJsonWriter().WritePropertyName("migration");
            var record = _allocation.Bootstrap(scope);
            JsonSerializer.Serialize(context.GetCurrentJsonWriter(), record is null ? null : JsonSerializer.Deserialize<AllocationBootstrapInput>(record.Payload, DistributedAllocation.JsonOptions), DistributedAllocation.JsonOptions);
        }
        async Task CheckLiveBootstrap(HttpContext context)
        {
            RequireBootstrapCoordinator(context); string name = context.Request.GetQueryOrForm("scope"); var owners = BootstrapOwners();
            var plan = BootstrapPlan(name, owners, "00000000000000000000000000000000", "compatibility");
            foreach (var peer in _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id))
            {
                var reply = await BootstrapPeerCall(peer, "checkPeer", ("scope", name));
                var candidate = reply.Deserialize<AllocationPlan>(DistributedAllocation.JsonOptions);
                if (JsonSerializer.Serialize(candidate with { Configuration = null }, DistributedAllocation.JsonOptions) != JsonSerializer.Serialize(plan with { Configuration = null }, DistributedAllocation.JsonOptions))
                    throw new InvalidOperationException("Scope address eligibility differs between owners; resolve it before pausing DHCP.");
            }
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), new { scope = name, compatible = true, owners }, DistributedAllocation.JsonOptions);
        }
        void CheckLiveBootstrapPeer(HttpContext context)
        {
            RequireBootstrapPeer(context); var plan = BootstrapPlan(context.Request.GetQueryOrForm("scope"), BootstrapOwners(), "00000000000000000000000000000000", "compatibility");
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), plan, DistributedAllocation.JsonOptions);
        }
        async Task SnapshotLiveBootstrapPeer(HttpContext context)
        {
            RequireBootstrapPeer(context); var scope = _dhcpServer.GetScope(context.Request.GetQueryOrForm("scope")) ?? throw new ArgumentException("Unknown scope.");
            var snapshot = await scope.CaptureNativeAllocationAsync(_allocation.NodeName(), context.RequestAborted);
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), snapshot, DistributedAllocation.JsonOptions);
        }
        async Task PreviewLiveBootstrap(HttpContext context)
        {
            RequireBootstrapCoordinator(context); string name = context.Request.GetQueryOrForm("scope");
            if (_allocation.Plan(name) is not null) throw new InvalidOperationException("This scope already has ownership; resume its saved migration instead.");
            string id = context.Request.GetQueryOrForm("id"); if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("A stable 32-hex migration identifier is required.");
            var owners = BootstrapOwners(); var groups = JsonSerializer.Deserialize<DhcpHaGroup[]>(context.Request.GetQueryOrForm("haGroups", "[]"), DistributedAllocation.JsonOptions);
            var plan = BootstrapPlan(name, owners, id, id, groups);
            var snapshots = new System.Collections.Generic.List<AllocationNativeSnapshot>();
            snapshots.Add(await _dhcpServer.GetScope(name).CaptureNativeAllocationAsync(_allocation.NodeName(), context.RequestAborted));
            foreach (var peer in _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id).OrderBy(n => n.Name, StringComparer.Ordinal))
                snapshots.Add((await BootstrapPeerCall(peer, "snapshot", ("scope", name))).Deserialize<AllocationNativeSnapshot>(DistributedAllocation.JsonOptions));
            var input = DistributedAllocation.BuildBootstrap(id, _allocation.NodeName(), plan, snapshots.OrderBy(n => n.Node, StringComparer.Ordinal).ToArray());
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), input, DistributedAllocation.JsonOptions);
        }
        AllocationBootstrapInput ReadLiveBootstrap(HttpContext context)
        {
            string json = context.Request.GetQueryOrForm("migration");
            if (Encoding.UTF8.GetByteCount(json) > 8 * 1024 * 1024) throw new ArgumentException("Migration exceeds 8 MiB.");
            var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(json, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing migration.");
            if (input.Plan?.Owners is null || input.Source != _clusterManager.GetPrimaryNode().Name || !input.Plan.Owners.Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners()))
                throw new ArgumentException("Migration membership or primary identity changed.");
            string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(input, DistributedAllocation.JsonOptions)));
            if (hash != context.Request.GetQueryOrForm("expectedHash")) throw new InvalidOperationException("Migration review hash changed.");
            return input;
        }
        async Task PrepareLocalLiveBootstrap(AllocationBootstrapInput input, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var previous = _allocation.Bootstrap(input.Plan.Scope);
            var scope = _dhcpServer.GetScope(input.Plan.Scope) ?? throw new ArgumentException("Unknown scope.");
            using var bytes = new MemoryStream(Convert.FromBase64String(input.Plan.Configuration)); using var source = new Scope(bytes, _log, _dhcpServer);
            if (source.Enabled || source.Name != scope.Name || !source.MatchesAllocationPlan(input.Plan)) throw new ArgumentException("Reviewed source configuration changes ownership or listener enablement.");
            if (previous is not null)
            {
                _allocation.PrepareBootstrap(input);
                if (previous.Phase == "Prepared")
                {
                    await scope.ApplySharedOptionsAsync(source, input.Plan); _dhcpServer.SaveScope(scope.Name);
                }
                return;
            }
            await scope.CaptureNativeAllocationAsync(_allocation.NodeName(), cancellationToken, async actual =>
            {
                if (!ReferenceEquals(scope, _dhcpServer.GetScope(input.Plan.Scope))) throw new InvalidOperationException("Scope was replaced during capture; capture a new review before migration.");
                var expected = input.Native.Single(n => n.Node == actual.Node);
                DateTime observedUtc = DateTime.UtcNow;
                string Entries(AllocationEntry[] entries) => JsonSerializer.Serialize(entries.Where(e => e.Expires > observedUtc).Distinct().OrderBy(e => e.Address).ThenBy(e => e.Client, StringComparer.Ordinal).ThenBy(e => e.State, StringComparer.Ordinal), DistributedAllocation.JsonOptions);
                if (expected.Configuration != actual.Configuration || Entries(expected.Entries) != Entries(actual.Entries)) throw new InvalidOperationException("Native leases, offers, quarantine or options changed after review; capture a new review before migration.");
                if (!scope.MatchesAllocationPlan(input.Plan)) throw new InvalidOperationException("Scope eligibility differs from reviewed ownership.");
                _allocation.PrepareBootstrap(input); // Durable phase and initial authority precede admission reopening.
                await scope.ApplySharedOptionsAsync(source, input.Plan); _dhcpServer.SaveScope(scope.Name);
            });
        }
        async Task StageLiveBootstrapPeer(HttpContext context)
        {
            RequireBootstrapPeer(context); var input = ReadLiveBootstrap(context);
            await PrepareLocalLiveBootstrap(input, context.RequestAborted); WriteBootstrap(context, input.Plan.Scope);
        }
        async Task PrepareLiveBootstrap(HttpContext context)
        {
            RequireBootstrapCoordinator(context); var input = ReadLiveBootstrap(context);
            await PrepareLocalLiveBootstrap(input, context.RequestAborted);
            string payload = JsonSerializer.Serialize(input, DistributedAllocation.JsonOptions); var record = _allocation.Bootstrap(input.Plan.Scope);
            foreach (var peer in _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id))
            {
                var receipt = await BootstrapPeerCall(peer, "stage", ("migration", payload), ("expectedHash", record.Hash));
                if (receipt.GetProperty("hash").GetString() != record.Hash || receipt.GetProperty("id").GetString() != input.Id) throw new InvalidOperationException("Peer acknowledged a different migration.");
                _allocation.AcknowledgeBootstrap(input.Plan.Scope, input.Id, record.Hash, peer.Name);
            }
            if (!input.Plan.Owners.Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())) throw new InvalidOperationException("Migration membership changed during preparation; keep DHCP paused.");
            WriteBootstrap(context, input.Plan.Scope);
        }
        async Task CommitLiveBootstrap(HttpContext context)
        {
            RequireBootstrapCoordinator(context); string name = context.Request.GetQueryOrForm("scope"); string id = context.Request.GetQueryOrForm("id"); string hash = context.Request.GetQueryOrForm("expectedHash");
            var record = _allocation.Bootstrap(name) ?? throw new InvalidOperationException("Prepare migration before committing.");
            var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(record.Payload, DistributedAllocation.JsonOptions);
            if (input.Source != _allocation.NodeName() || !_dhcpServer.GetScope(name).MatchesAllocationPlan(input.Plan)) throw new InvalidOperationException("Migration source or eligibility changed; keep DHCP paused.");
            if (record.Id != id || record.Hash != hash || !(record.PreparedNodes ?? []).Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())) throw new InvalidOperationException("Every current owner must acknowledge this exact durable migration.");
            foreach (var peer in _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id))
                await BootstrapPeerCall(peer, "commitPeer", ("scope", name), ("id", id), ("expectedHash", hash));
            if (!input.Plan.Owners.Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())) throw new InvalidOperationException("Migration membership changed during commit; keep DHCP paused.");
            _allocation.CommitBootstrap(name, id, hash); WriteBootstrap(context, name);
        }
        void CommitLiveBootstrapPeer(HttpContext context)
        {
            RequireBootstrapPeer(context); string name = context.Request.GetQueryOrForm("scope");
            var record = _allocation.Bootstrap(name) ?? throw new InvalidOperationException("Prepare migration before committing.");
            var input = JsonSerializer.Deserialize<AllocationBootstrapInput>(record.Payload, DistributedAllocation.JsonOptions);
            if (input.Source != _clusterManager.GetPrimaryNode().Name || !input.Plan.Owners.Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())) throw new InvalidOperationException("Migration membership changed; keep DHCP paused.");
            if (!_dhcpServer.GetScope(name).MatchesAllocationPlan(input.Plan)) throw new InvalidOperationException("Scope eligibility changed; keep DHCP paused.");
            _allocation.CommitBootstrap(name, context.Request.GetQueryOrForm("id"), context.Request.GetQueryOrForm("expectedHash")); WriteBootstrap(context, name);
        }
        bool IsAllocationService(HttpContext context) => _clusterManager.ClusterInitialized && context.Request.IsHttps && context.GetCurrentSession().Type == UserSessionType.ClusterApiToken && context.Request.QueryOrForm("actingUser") is null;
        void RequireAllocationService(HttpContext context)
        { if (!IsAllocationService(context)) throw new DnsWebServiceException("A direct HTTPS cluster session is required."); }
        void RequireDhcpPermission(HttpContext context, PermissionFlag flag)
        { if (!_authManager.IsPermitted(PermissionSection.DhcpServer, GetSessionUser(context), flag)) throw new DnsWebServiceException("Access was denied."); }
        string AllocationNode(string name)
        {
            if (_clusterManager.ClusterInitialized)
            { if (_clusterManager.TryGetClusterNode(name, out var node)) return node.Name; }
            else if (string.Equals(name, _allocation.NodeName(), StringComparison.OrdinalIgnoreCase)) return _allocation.NodeName();
            throw new ArgumentException("Owner must be an enrolled node.");
        }
        void WriteAllocationState(HttpContext context)
        {
            context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), _allocation.Snapshot(), DistributedAllocation.JsonOptions);
            context.GetCurrentJsonWriter().WriteString("health", _allocation.Health);
            context.GetCurrentJsonWriter().WriteString("node", _allocation.NodeName());
            context.GetCurrentJsonWriter().WritePropertyName("nodes"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), _clusterManager.ClusterInitialized ? _clusterManager.ClusterNodes.Values.Select(n => n.Name).Order(StringComparer.Ordinal).ToArray() : [_allocation.NodeName()]);
            context.GetCurrentJsonWriter().WritePropertyName("scopeStatus"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), _allocation.Snapshot().Plans.Select(p => new { scope = p.Scope, exists = _dhcpServer.GetScope(p.Scope) is not null, matchesOwnership = _dhcpServer.GetScope(p.Scope)?.MatchesAllocationPlan(p) == true, enabled = _dhcpServer.GetScope(p.Scope)?.Enabled == true, overflowRequestedUtc = _dhcpServer.GetScope(p.Scope)?.OverflowRequestedUtc }).ToArray());
        }
        void GetAllocationState(HttpContext context)
        {
            if (context.GetCurrentSession().Type == UserSessionType.ClusterApiToken && context.Request.QueryOrForm("actingUser") is null) RequireAllocationService(context);
            else RequireDhcpPermission(context, PermissionFlag.View);
            WriteAllocationState(context);
        }
        void LookupAllocationHistory(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.View);
            uint address = AllocationSequence.Number(System.Net.IPAddress.Parse(context.Request.GetQueryOrForm("address")));
            DateTime timestamp = DateTimeOffset.Parse(context.Request.GetQueryOrForm("timestamp"), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime;
            var writer = context.GetCurrentJsonWriter(); writer.WritePropertyName("device"); JsonSerializer.Serialize(writer, _allocation.ResolveAt(address, timestamp), DistributedAllocation.JsonOptions);
            writer.WriteString("coverage", "Last 2000 durable changes per scope and owner; null means unknown or ambiguous, not proof of absence.");
        }
        async Task SetAllocationPlan(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (_clusterManager.ClusterInitialized && _clusterManager.GetSelfNode().Type != ClusterNodeType.Primary) throw new DnsWebServiceException("Create ownership on the primary.");
            string name = context.Request.GetQueryOrForm("scope"); var scope = _dhcpServer.GetScope(name) ?? throw new ArgumentException("Unknown scope.");
            if (!scope.CanInitializeAllocation) throw new InvalidOperationException("Bootstrap requires a disabled scope with no leases or offers on every owner.");
            string[] owners = context.Request.GetQueryOrForm("owners").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(AllocationNode).ToArray();
            var plan = _allocation.Plan(name);
            if (plan is null)
            {
                using MemoryStream bytes = new(); scope.WriteTo(bytes, false, false);
                var groups = JsonSerializer.Deserialize<DhcpHaGroup[]>(context.Request.GetQueryOrForm("haGroups", "[]"), DistributedAllocation.JsonOptions);
                if (groups is not null) groups = groups.Select(g => g with { Primary = AllocationNode(g.Primary), Secondary = AllocationNode(g.Secondary) }).ToArray();
                plan = scope.BuildAllocationPlan(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), owners) with { Configuration = Convert.ToBase64String(bytes.ToArray()), HaGroups = groups };
                _allocation.AddPlan(plan);
            }
            else if (!plan.Owners.SequenceEqual(owners.Order(StringComparer.Ordinal))) throw new InvalidOperationException("Existing ownership cannot be changed without fenced migration.");
            // Install the same immutable authority on all enrolled nodes while their scopes are drained.
            // A failed bootstrap retains the epoch for an idempotent retry, never repartitions it.
            if (_clusterManager.ClusterInitialized)
                foreach (var peer in _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id))
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted); deadline.CancelAfter(TimeSpan.FromSeconds(3));
                    await peer.PrepareAllocationAsync(Encoding.UTF8.GetString(_allocation.Export()), deadline.Token);
                }
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Created immutable DHCP allocation ownership for '" + name + "'.");
            WriteAllocationState(context);
        }
        void IngestAllocationState(HttpContext context)
        {
            RequireAllocationService(context);
            string state = context.Request.GetQueryOrForm("state");
            if (Encoding.UTF8.GetByteCount(state) > 8 * 1024 * 1024) throw new ArgumentException("Replication state exceeds 8 MiB.");
            var snapshot = JsonSerializer.Deserialize<AllocationState>(state, DistributedAllocation.JsonOptions);
            if (snapshot is null || snapshot.Replicas is null) throw new ArgumentException("Missing state.");
            foreach (var replica in snapshot.Replicas)
                if (!_clusterManager.TryGetClusterNode(replica.Node, out _)) throw new ArgumentException("Replica source is not enrolled.");
            _allocation.Merge(Encoding.UTF8.GetBytes(state)); WriteAllocationState(context);
        }
        async Task PrepareAllocation(HttpContext context)
        {
            RequireAllocationService(context);
            string state = context.Request.GetQueryOrForm("state");
            if (Encoding.UTF8.GetByteCount(state) > 8 * 1024 * 1024) throw new ArgumentException("Bootstrap exceeds 8 MiB.");
            var snapshot = JsonSerializer.Deserialize<AllocationState>(state, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing state.");
            foreach (var plan in snapshot.Plans)
                foreach (string node in plan.Owners) if (!_clusterManager.TryGetClusterNode(node, out _)) throw new ArgumentException("Owner is not enrolled.");
            await InstallAllocationPlans(snapshot); WriteAllocationState(context);
        }
        async Task GrantAllocation(HttpContext context)
        {
            RequireAllocationService(context);
            string borrower = context.Request.GetQueryOrForm("borrower");
            if (!_clusterManager.TryGetClusterNode(borrower, out _)) throw new ArgumentException("Borrower is not enrolled.");
            borrower = AllocationNode(borrower);
            var scope = _dhcpServer.GetScope(context.Request.GetQueryOrForm("scope")) ?? throw new ArgumentException("Unknown scope.");
            byte[] state = await scope.GrantCapacityAsync(borrower, context.Request.GetQueryOrForm("requestId"));
            var writer = context.GetCurrentJsonWriter(); writer.WritePropertyName("state");
            if (state is null) writer.WriteNullValue(); else writer.WriteRawValue(state);
        }
        async Task ReturnGrantAllocation(HttpContext context) => await ChangeGrantAllocation(context, false);
        async Task ReclaimGrantAllocation(HttpContext context) => await ChangeGrantAllocation(context, true);
        async Task ChangeGrantAllocation(HttpContext context, bool reclaim)
        {
            void Authorize()
            {
                RequireDhcpPermission(context, PermissionFlag.Modify);
                if (!HasDirectTlsTransport(context) || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken || context.Request.QueryOrForm("actingUser") is not null ||
                    !_authManager.IsPermitted(PermissionSection.Administration, GetSessionUser(context), PermissionFlag.Delete))
                    throw new DnsWebServiceException("Grant return requires a direct HTTPS administrator session.");
                if (!_clusterManager.ClusterInitialized || _clusterManager.GetSelfNode().IsFenced) throw new InvalidOperationException("Retain current authority while cluster membership is unavailable or fenced.");
            }
            Authorize();
            string name = context.Request.GetQueryOrForm("scope"), epoch = context.Request.GetQueryOrForm("epoch"), id = context.Request.GetQueryOrForm("requestId");
            string participant = AllocationNode(context.Request.GetQueryOrForm(reclaim ? "borrower" : "owner"));
            var scope = _dhcpServer.GetScope(name) ?? throw new ArgumentException("Unknown scope.");
            long expected = long.Parse(context.Request.GetQueryOrForm("expectedSequence"), System.Globalization.CultureInfo.InvariantCulture);
            uint address = reclaim ? 0 : AllocationSequence.Number(System.Net.IPAddress.Parse(context.Request.GetQueryOrForm("address")));
            string grantId = reclaim ? null : context.Request.GetQueryOrForm("grantId");
            string expectedHash = context.Request.GetQueryOrForm("expectedHash");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted); deadline.CancelAfter(TimeSpan.FromSeconds(10));
            await scope.CaptureNativeAllocationAsync(_allocation.NodeName(), deadline.Token, snapshot =>
            {
                Authorize();
                if (AllocationNode(participant) != participant || !scope.MatchesAllocationPlan(_allocation.Plan(name))) throw new InvalidOperationException("Current enrolled participants and matching native scope are required.");
                var current = _allocation.Snapshot();
                var receipt = reclaim ? current.Replicas.SingleOrDefault(r => r.Scope == name && r.Node == participant)?.GrantReturns?.SingleOrDefault(r => r.Id == id)
                    : current.Replicas.SingleOrDefault(r => r.Scope == name && r.Node == _allocation.NodeName())?.GrantReturns?.SingleOrDefault(r => r.Id == id);
                var grant = reclaim ? receipt?.Grant : receipt?.Grant ?? current.Replicas.SingleOrDefault(r => r.Scope == name && r.Node == participant)?.Entries.SingleOrDefault(e => e.State == "Grant" && e.Address == address && e.GrantId == grantId && e.Borrower == _allocation.NodeName());
                if (grant is null) throw new InvalidOperationException("Missing the original grant or surrender receipt; retain the original donor and request identity.");
                string actualHash = reclaim ? DistributedAllocation.GrantReturnHash(name, epoch, receipt) : DistributedAllocation.GrantReviewHash(name, epoch, participant, grant);
                if (actualHash != expectedHash) throw new InvalidOperationException("Grant review changed; read the exact current grant or surrender receipt before retrying.");
                uint target = grant.Address;
                if (snapshot.Entries.Any(e => e.Address == target && e.State != "Released" && e.Expires > DateTime.UtcNow)) throw new InvalidOperationException("Native leases or offers still protect this grant; retain its exact lifetime.");
                using var persisted = _dhcpServer.SaveProvisionedScope(name);
                string[] Bindings(Scope source) => source.Leases.Values.Select(lease =>
                {
                    using var bytes = new MemoryStream(); lease.WriteTo(new BinaryWriter(bytes));
                    return Convert.ToBase64String(bytes.ToArray());
                }).Order(StringComparer.Ordinal).ToArray();
                // Compare every native binding field byte-for-byte after independent
                // reopen. Dictionary enumeration order is not binding identity. Native
                // dates retain their existing format; JSON authority retains full ticks.
                if (persisted.Enabled || !Bindings(scope).SequenceEqual(Bindings(persisted)) || OwnershipConfiguration(persisted) != snapshot.Configuration)
                    throw new InvalidOperationException("Persisted native scope differs; retain capacity and reconcile original bindings.");
                Authorize();
                if (reclaim) _allocation.ReclaimGrant(name, epoch, participant, id, expected);
                else _allocation.RelinquishGrant(name, epoch, participant, address, grantId, id, expected);
                return Task.CompletedTask;
            });
            WriteAllocationState(context);
        }
        async Task HandoffAllocation(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (context.GetCurrentSession().Type == UserSessionType.ClusterApiToken) throw new DnsWebServiceException("Planned handoff requires an administrative user session.");
            string name = context.Request.GetQueryOrForm("scope");
            var scope = _dhcpServer.GetScope(name) ?? throw new ArgumentException("Unknown scope.");
            var plan = _allocation.Plan(name) ?? throw new ArgumentException("Scope has no allocation plan.");
            if (!scope.MatchesAllocationPlan(plan)) throw new InvalidOperationException("Scope differs from its ownership plan.");
            string borrower = AllocationNode(context.Request.GetQueryOrForm("receiver"));
            string input = context.Request.GetQueryOrForm("addresses");
            if (input.Length > 8192) throw new ArgumentException("Address selection is too large.");
            uint[] addresses = input.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(a => AllocationSequence.Number(System.Net.IPAddress.Parse(a))).ToArray();
            string requestId = context.Request.GetQueryOrForm("requestId");
            long sequence = long.Parse(context.Request.GetQueryOrForm("expectedSequence"), System.Globalization.CultureInfo.InvariantCulture);
            _allocation.Handoff(name, addresses, borrower, requestId, sequence);
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Persisted DHCP handoff '" + requestId + "' for " + addresses.Length + " addresses in '" + name + "' to '" + borrower + "'.");
            // Failure after surrender leaves the donor fenced for these addresses. The same request
            // returns the same grant state, and the normal mesh also retries its delivery.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted); deadline.CancelAfter(TimeSpan.FromSeconds(3));
            bool delivered = false;
            try { if (_clusterManager.TryGetClusterNode(borrower, out var peer)) { await peer.PushAllocationStateAsync(Encoding.UTF8.GetString(_allocation.Export()), deadline.Token); delivered = true; } }
            catch (Exception) when (!context.RequestAborted.IsCancellationRequested) { }
            context.GetCurrentJsonWriter().WriteBoolean("receiverAcknowledged", delivered);
            WriteAllocationState(context);
        }
        void GetOwnedAllocationAddresses(HttpContext context)
        {
            if (context.GetCurrentSession().Type == UserSessionType.ClusterApiToken) RequireAllocationService(context);
            RequireDhcpPermission(context, PermissionFlag.View);
            string name = context.Request.GetQueryOrForm("scope");
            context.GetCurrentJsonWriter().WriteStringArray("addresses", _allocation.OwnedAddresses(name).Select(a => AllocationSequence.Address(a).ToString()).ToArray());
        }
        void RecoverFencedAllocation(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (!context.Request.IsHttps || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken || context.Request.QueryOrForm("actingUser") is not null
                || !_authManager.IsPermitted(PermissionSection.Administration, GetSessionUser(context), PermissionFlag.Delete))
                throw new DnsWebServiceException("A direct HTTPS administrative recovery session is required.");
            string owner = AllocationNode(context.Request.GetQueryOrForm("owner"));
            string payload = context.Request.GetQueryOrForm("state");
            if (Encoding.UTF8.GetByteCount(payload) > 8 * 1024 * 1024) throw new ArgumentException("Recovery snapshot exceeds 8 MiB.");
            var state = JsonSerializer.Deserialize<AllocationState>(payload, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing recovery snapshot.");
            if (state.Replicas is null || state.Plans is null || state.Replicas.Any(r => r.Node != owner || r.Entries is null || r.Entries.Any(e => e.State != "Grant" || e.Borrower != _allocation.NodeName())))
                throw new ArgumentException("Recovery accepts only the fenced owner's complete exclusive grants to this receiver.");
            foreach (var plan in state.Plans)
            {
                var local = _allocation.Plan(plan.Scope) ?? throw new ArgumentException("Install the identical authority epoch before recovery.");
                if (JsonSerializer.Serialize(local, DistributedAllocation.JsonOptions) != JsonSerializer.Serialize(plan, DistributedAllocation.JsonOptions)) throw new ArgumentException("Recovery changes an authority epoch.");
                var sequence = new AllocationSequence(plan); int index = Array.IndexOf(plan.Owners.Order(StringComparer.Ordinal).ToArray(), owner);
                if (index < 0) throw new ArgumentException("Owner does not belong to this plan.");
                ulong count = (sequence.Count + (ulong)plan.Owners.Length - 1 - (ulong)index) / (ulong)plan.Owners.Length + (ulong)(plan.Reservations ?? []).Count(r => sequence.Owner(r.Address) == owner);
                var replica = state.Replicas.SingleOrDefault(r => r.Scope == plan.Scope);
                if (replica is null || (ulong)replica.Entries.Count(e => sequence.Owner(e.Address) == owner) != count) throw new ArgumentException("The original owner's complete capacity must be surrendered before recovery.");
            }
            _allocation.Merge(JsonSerializer.SerializeToUtf8Bytes(state, DistributedAllocation.JsonOptions));
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Imported durably surrendered capacity from externally fenced owner '" + owner + "'.");
            WriteAllocationState(context);
        }
        void RecoverUnusedAllocation(HttpContext context)
        {
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (!context.Request.IsHttps || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken || context.Request.QueryOrForm("actingUser") is not null ||
                !_authManager.IsPermitted(PermissionSection.Administration, GetSessionUser(context), PermissionFlag.Delete)) throw new DnsWebServiceException("A direct HTTPS administrative recovery session is required.");
            string owner = AllocationNode(context.Request.GetQueryOrForm("owner"));
            string scope = context.Request.GetQueryOrForm("scope"), id = context.Request.GetQueryOrForm("recoveryId");
            if (owner == _allocation.NodeName()) throw new InvalidOperationException("Import recovered grants on a surviving owner.");
            string payload = context.Request.GetQueryOrForm("state");
            if (Encoding.UTF8.GetByteCount(payload) > 8 * 1024 * 1024) throw new ArgumentException("Recovery snapshot exceeds 8 MiB.");
            var snapshot = JsonSerializer.Deserialize<AllocationState>(payload, DistributedAllocation.JsonOptions) ?? throw new ArgumentException("Missing original-owner recovery state.");
            var plan = snapshot.Plans?.SingleOrDefault(p => p.Scope == scope) ?? throw new ArgumentException("Missing recovered scope.");
            var local = _allocation.Plan(scope) ?? throw new ArgumentException("Install the identical ownership epoch first.");
            if (JsonSerializer.Serialize(plan, DistributedAllocation.JsonOptions) != JsonSerializer.Serialize(local, DistributedAllocation.JsonOptions)) throw new ArgumentException("Recovery changes the immutable ownership plan.");
            var donor = snapshot.Replicas?.SingleOrDefault(r => r.Scope == scope && r.Node == owner) ?? throw new ArgumentException("Missing original-owner replica.");
            var recovery = donor.UnusedRecoveries?.SingleOrDefault(r => r.Id == id);
            if (recovery is null || !recovery.Receivers.Contains(_allocation.NodeName())) throw new ArgumentException("This surviving owner is not a receiver in the saved recovery division.");
            var knownDonor = _allocation.Snapshot().Replicas.SingleOrDefault(r => r.Scope == scope && r.Node == owner);
            if (knownDonor is not null && donor.Sequence < knownDonor.Sequence) throw new InvalidOperationException("The fenced owner's journal is older than known peer evidence; retain its fence and recover the current original journal.");
            // Only the original donor replica changes. Local and other owners' current
            // authority must never be replaced by the failed server's older observations.
            var replicas = _allocation.Snapshot().Replicas.Where(r => r.Scope == scope && r.Node != owner).Append(donor).ToArray();
            _allocation.Merge(JsonSerializer.SerializeToUtf8Bytes(new AllocationState(1, [plan], replicas), DistributedAllocation.JsonOptions));
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Imported unused-capacity recovery '" + id + "' from externally fenced owner '" + owner + "' in '" + scope + "'.");
            WriteAllocationState(context);
        }
        async Task InstallAllocationPlans(AllocationState state)
        {
            if (state is null || state.Plans is null) throw new ArgumentException("Missing allocation plans.");
            foreach (var plan in state.Plans)
            {
                if (_allocation.Plan(plan.Scope) is not null) continue;
                if (state.Bootstraps?.Any(b => b.Scope == plan.Scope) == true) throw new InvalidOperationException("Live migration requires reviewed native preparation on this node.");
                var scope = _dhcpServer.GetScope(plan.Scope);
                if (scope is null)
                {
                    if (plan.Configuration is null || plan.Configuration.Length > 1024 * 1024) throw new ArgumentException("Missing bootstrap scope configuration.");
                    using var bytes = new MemoryStream(Convert.FromBase64String(plan.Configuration));
                    scope = new Scope(bytes, _log, _dhcpServer);
                    if (scope.Enabled || scope.Name != plan.Scope) throw new ArgumentException("Bootstrap scope must remain disabled.");
                    if (!scope.CanInitializeAllocation) throw new ArgumentException("Bootstrap cannot import active leases or offers.");
                    var candidate = scope.BuildAllocationPlan(plan.Epoch, plan.Seed, plan.Owners, plan.Algorithm) with { Configuration = plan.Configuration, HaGroups = plan.HaGroups };
                    if (JsonSerializer.Serialize(candidate, DistributedAllocation.JsonOptions) != JsonSerializer.Serialize(plan, DistributedAllocation.JsonOptions)) throw new InvalidOperationException("Bootstrap scope and ownership disagree.");
                    await _dhcpServer.AddScopeAsync(scope);
                }
                if (!scope.CanInitializeAllocation || _allocation.NativeHolds(scope.Name).Length > 0) throw new InvalidOperationException("Disable and drain the scope before joining allocation ownership.");
                var expected = scope.BuildAllocationPlan(plan.Epoch, plan.Seed, plan.Owners, plan.Algorithm) with { Configuration = plan.Configuration, HaGroups = plan.HaGroups };
                if (JsonSerializer.Serialize(expected, DistributedAllocation.JsonOptions) != JsonSerializer.Serialize(plan, DistributedAllocation.JsonOptions)) throw new InvalidOperationException("Scope addressing does not match coordinator ownership.");
            }
            var localConfigurations = (_allocation.Snapshot().Configurations ?? []).ToDictionary(c => c.Scope);
            foreach (var configuration in state.Configurations ?? [])
            {
                if (localConfigurations.TryGetValue(configuration.Scope, out var local) && local.Revision > configuration.Revision) continue;
                if (local is not null && local.Revision == configuration.Revision && local.Hash != configuration.Hash) throw new InvalidOperationException("Conflicting configuration revision.");
                if (configuration.Data.Length > 1024 * 1024 || Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(configuration.Data))) != configuration.Hash) throw new ArgumentException("Invalid configuration content hash.");
                var scope = _dhcpServer.GetScope(configuration.Scope) ?? throw new ArgumentException("Unknown configured scope.");
                using var administrativeChange = scope.BeginAdministrativeChange();
                using MemoryStream actual = new(); scope.WriteTo(actual, false, false);
                if (local?.Revision == configuration.Revision && Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(actual.ToArray())) == configuration.Hash) continue;
                var plan = state.Plans.Single(p => p.Scope == configuration.Scope);
                using var data = new MemoryStream(Convert.FromBase64String(configuration.Data)); using var source = new Scope(data, _log, _dhcpServer);
                if (source.Enabled || source.Name != scope.Name) throw new ArgumentException("Replicated configuration cannot activate a listener or rename a scope.");
                await scope.ApplySharedOptionsAsync(source, plan); _dhcpServer.SaveScope(scope.Name);
            }
            _allocation.Merge(JsonSerializer.SerializeToUtf8Bytes(state, DistributedAllocation.JsonOptions), true);
        }
        async Task SynchronizeAllocation(CancellationToken cancellationToken)
        {
            if (!_clusterManager.ClusterInitialized) return;
            bool coordinatorUnavailable = false;
            if (_clusterManager.GetSelfNode().Type == ClusterNodeType.Primary)
                foreach (var plan in _allocation.Snapshot().Plans)
                {
                    var scope = _dhcpServer.GetScope(plan.Scope) ?? throw new InvalidOperationException("A managed scope is missing.");
                    if (!scope.MatchesAllocationPlan(plan)) throw new InvalidOperationException("Scope drift changes ownership eligibility; migration is required.");
                    using MemoryStream configuration = new(); scope.WriteTo(configuration, false, false);
                    _allocation.PublishConfiguration(scope.Name, configuration.ToArray());
                }
            if (_clusterManager.GetSelfNode().Type != ClusterNodeType.Primary)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(3));
                try
                {
                    var state = await _clusterManager.GetPrimaryNode().GetAllocationStateAsync(deadline.Token);
                    await InstallAllocationPlans(JsonSerializer.Deserialize<AllocationState>(state, DistributedAllocation.JsonOptions));
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested) { coordinatorUnavailable = true; }
            }
            if (_allocation.Snapshot().Plans.Length == 0) return;
            string local = Encoding.UTF8.GetString(_allocation.Export());
            // Every enrolled node receives all owners' observations, independent of a fixed HA pair.
            var peers = _clusterManager.ClusterNodes.Values.Where(n => n.Id != _clusterManager.GetSelfNode().Id && !n.IsFenced).ToArray();
            var results = await Task.WhenAll(peers.Select(async peer =>
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(3));
                try { await peer.PushAllocationStateAsync(local, deadline.Token); return true; }
                catch (Exception) when (!cancellationToken.IsCancellationRequested) { return false; }
            }));
            if (coordinatorUnavailable || results.Any(success => !success)) throw new IOException("A coordinator or peer is unavailable; reachable peers received the publication attempt and local authority is retained.");
        }
        int _capacityDonorCursor;
        async Task<byte[]> BorrowAllocation(string scope, string borrower)
        {
            var plan = _allocation.Plan(scope);
            var candidates = plan.Owners.Where(n => n != borrower).ToArray();
            if (candidates.Length == 0) return null;
            int start = (int)((uint)Interlocked.Increment(ref _capacityDonorCursor) % (uint)candidates.Length);
            // At most three requests, each with a two-second deadline. Pending IDs
            // remain scoped to their original donor across later rotations/restarts.
            foreach (string owner in Enumerable.Range(0, Math.Min(3, candidates.Length)).Select(i => candidates[(start + i) % candidates.Length]))
            {
                if (!_clusterManager.ClusterInitialized || !_clusterManager.TryGetClusterNode(owner, out var donor)) continue;
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_allocationStop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    string requestId = _allocation.CapacityRequest(scope, owner);
                    var state = await donor.GrantAllocationAsync(scope, borrower, requestId, deadline.Token);
                    if (state is null) continue;
                    _allocation.Merge(state);
                    _allocation.CompleteCapacityRequest(scope, owner, requestId);
                    return _allocation.Export();
                }
                catch (Exception) when (!_allocationStop.IsCancellationRequested) { }
            }
            return null;
        }
    }
}
