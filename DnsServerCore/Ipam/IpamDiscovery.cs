// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Ipam
{
    public sealed record IpamDiscoverySource(string Id, string Name, string Kind, string SubnetId, string Targets, int Port,
        string CredentialReference, string Subscription, string ResourceGroup, int MaxResults, int TimeoutMs,
        int FreshSeconds, string ApprovalReference, bool Enabled = false);
    public sealed record IpamDiscoveryEvidence(string Address, string SourceId, string Source, string ObjectId,
        string HostName, string ClientIdentifier, string Confidence, DateTime ObservedAt, DateTime Expires, bool Present = true);
    public sealed record IpamDiscoveryRun(string SourceId, string Configuration, string Actor, DateTime AttemptedAt,
        DateTime? LastSuccess, string Status, string Detail, IpamDiscoveryEvidence[] Evidence, string OutcomeReason = "", bool Truncated = false);

    public sealed partial class IpamManager
    {
        readonly SemaphoreSlim _activeDiscoveryGate = new(1, 1);
        sealed class DiscoveryJob
        {
            public CancellationTokenSource Cancellation { get; } = new();
            public IpamDiscoveryRun PendingResult { get; set; }
        }
        readonly Dictionary<string, DiscoveryJob> _activeDiscoveryJobs = new();
        public string[] ActiveDiscoveryIds() { lock (_sync) return _activeDiscoveryJobs.Keys.ToArray(); }
        public string[] PendingDiscoveryPersistenceIds() { lock (_sync) return _activeDiscoveryJobs.Where(p => p.Value.PendingResult is not null).Select(p => p.Key).ToArray(); }
        void ReleaseDiscoveryJob(string id)
        {
            if (_activeDiscoveryJobs.Remove(id, out var job)) { job.Cancellation.Dispose(); _activeDiscoveryGate.Release(); }
        }
        bool PersistDiscoveryResult(string id, DiscoveryJob job)
        {
            if (job.PendingResult is null) return false;
            try
            {
                var result = job.PendingResult;
                Mutate(_state.Revision, result.Actor, "discovery.run", state => (state with { DiscoveryRuns = (state.DiscoveryRuns ?? []).Where(r => r.SourceId != id).Append(result).ToArray() }, true, id));
                ReleaseDiscoveryJob(id);
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidOperationException || ex is InvalidDataException || ex is JsonException)
            {
                // Keep the real pending job and admission claim until a terminal result is durable.
                // Status/cancel/new-run retries only this save, never the collector transport.
                return false;
            }
        }
        public void RetryDiscoveryPersistence()
        {
            lock (_sync) foreach (var item in _activeDiscoveryJobs.Where(p => p.Value.PendingResult is not null).ToArray()) PersistDiscoveryResult(item.Key, item.Value);
        }
        public bool CancelDiscovery(string id)
        {
            lock (_sync)
            {
                if (!_activeDiscoveryJobs.TryGetValue(id, out var job)) return false;
                job.Cancellation.Cancel();
                if (job.PendingResult is not null)
                {
                    var previous = (_state.DiscoveryRuns ?? []).Single(r => r.SourceId == id);
                    job.PendingResult = job.PendingResult with { Status = "Cancelled", OutcomeReason = "OperatorCancelled", Detail = "Collection cancelled by an operator. Last-known evidence retained.", LastSuccess = previous.LastSuccess, Evidence = previous.Evidence, Truncated = false };
                    PersistDiscoveryResult(id, job);
                }
                return true;
            }
        }
        void RetireInterruptedDiscovery()
        {
            lock (_sync) if ((_state.DiscoveryRuns ?? []).Any(r => r.Status == "Running"))
                Mutate(_state.Revision, "Startup", "discovery.interrupted", state => (state with { DiscoveryRuns = state.DiscoveryRuns.Select(r => r.Status == "Running" ? r with { Status = "Interrupted", OutcomeReason = "Restart", Detail = "Collection was interrupted by restart. Last-known evidence retained; run again explicitly." } : r).ToArray() }, true, ""));
            var reviewed = RequireDiscoveryScopeReview(_state);
            if (!ReferenceEquals(reviewed, _state)) Mutate(_state.Revision, "Startup", "discovery.scope.review", _ => (reviewed, true, ""));
        }
        static string LegacyDiscoveryConfiguration(IpamDiscoverySource source) => JsonSerializer.Serialize(source with { Enabled = false }, JsonOptions);
        static string DiscoveryConfiguration(IpamDiscoverySource source, IpamSubnet subnet) => JsonSerializer.Serialize(new { source = source with { Enabled = false }, parent = new { subnet.Id, subnet.Prefix, subnet.ViewId, subnet.Container } }, JsonOptions);
        public static bool DiscoveryScopeCurrent(IpamSnapshot state, IpamDiscoveryRun run)
        {
            var source = (state.DiscoverySources ?? []).SingleOrDefault(s => s.Id == run.SourceId);
            var parent = source is null ? null : state.Subnets.SingleOrDefault(s => s.Id == source.SubnetId);
            return parent is not null && run.Configuration == DiscoveryConfiguration(source, parent);
        }
        static IpamSnapshot RequireDiscoveryScopeReview(IpamSnapshot state)
        {
            var unbound = (state.DiscoveryRuns ?? []).Where(r => !DiscoveryScopeCurrent(state, r)).Select(r => r.SourceId).ToHashSet();
            if (unbound.Count == 0 || !(state.DiscoverySources ?? []).Any(s => unbound.Contains(s.Id) && s.Enabled) && !(state.DiscoveryRuns ?? []).Any(r => unbound.Contains(r.SourceId) && r.OutcomeReason != "ScopeReviewRequired")) return state;
            return state with { DiscoverySources = (state.DiscoverySources ?? []).Select(s => unbound.Contains(s.Id) ? s with { Enabled = false } : s).ToArray(), DiscoveryRuns = (state.DiscoveryRuns ?? []).Select(r => unbound.Contains(r.SourceId) ? r with { Status = "Interrupted", OutcomeReason = "ScopeReviewRequired", Detail = "Previous qualification did not bind the parent subnet scope. Evidence is historical only; qualify the current prefix and view before enabling." } : r).ToArray() };
        }
        static void GuardDiscoveryParents(IpamSnapshot previous, IpamSnapshot next)
        {
            foreach (var source in previous.DiscoverySources ?? [])
            {
                if (!(next.DiscoverySources ?? []).Any(s => s.Id == source.Id && s.SubnetId == source.SubnetId)) continue;
                var before = previous.Subnets.Single(s => s.Id == source.SubnetId);
                var after = next.Subnets.SingleOrDefault(s => s.Id == source.SubnetId);
                if (after is null || before.Prefix != after.Prefix || before.ViewId != after.ViewId || before.Container != after.Container)
                    throw new InvalidOperationException("Remove the subnet's discovery sources before changing its prefix, network view or container status, or deleting it. Then configure and qualify sources for the new scope.");
            }
        }
        static void ValidateActiveDiscovery(IpamSnapshot state)
        {
            var sources = state.DiscoverySources ?? [];
            var runs = state.DiscoveryRuns ?? [];
            if (sources.Any(s => s is null) || runs.Any(r => r is null) || sources.Length > 32 || sources.Select(s => s.Id).Distinct().Count() != sources.Length || runs.Length > 32 || runs.Select(r => r.SourceId).Distinct().Count() != runs.Length)
                throw new ArgumentException("At most 32 unique discovery sources are supported.");
            foreach (var source in sources)
            {
                if (source is null || !Guid.TryParseExact(source.Id, "N", out _) || string.IsNullOrWhiteSpace(source.Name) || source.Name.Length > 128 || source.ApprovalReference is null || source.ApprovalReference.Length > 512)
                    throw new ArgumentException("A discovery name and approval reference of at most 512 characters are required.");
                var subnet = state.Subnets.SingleOrDefault(s => s.Id == source.SubnetId && !s.Container) ?? throw new ArgumentException("Select an existing leaf subnet for discovery.");
                var network = new IpamNetwork(subnet.Prefix);
                if (source.Kind != "TcpConnect" && source.Kind != "SnmpArp" && source.Kind != "AzureNic") throw new ArgumentException("Select TCP, SNMP or Azure NIC discovery.");
                if (source.MaxResults < 1 || source.MaxResults > 256 || source.TimeoutMs < 100 || source.TimeoutMs > 5000 || source.FreshSeconds < 60 || source.FreshSeconds > 86400 || source.Port < 1 || source.Port > 65535)
                    throw new ArgumentException("Use 1–256 results, a 100–5000 ms request timeout, 60–86400 seconds of freshness and a valid port.");
                if (source.Targets is null || source.Targets.Length > 4096 || source.CredentialReference is null || source.Subscription is null || source.ResourceGroup is null) throw new ArgumentException("Discovery configuration is incomplete.");
                if (source.Kind == "AzureNic")
                {
                    if (!Guid.TryParseExact(source.Subscription, "D", out _) || !Regex.IsMatch(source.ResourceGroup, @"\A[A-Za-z0-9_.()-]{1,90}\z") || source.ResourceGroup.EndsWith('.')) throw new ArgumentException("Azure requires a subscription UUID and resource group name.");
                    if (source.Targets.Length != 0) throw new ArgumentException("Azure targets its resource group; do not specify probe addresses.");
                }
                else
                {
                    var targets = IpamDiscoveryCollector.Targets(source);
                    if (targets.Length < 1 || targets.Length > 64 || targets.Distinct().Count() != targets.Length || source.Kind == "SnmpArp" && targets.Length != 1)
                        throw new ArgumentException("Enter 1–64 unique literal IP targets; SNMP requires exactly one device.");
                    foreach (string target in targets)
                    {
                        var ip = Address(target);
                        if (target != ip.ToString() || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast || ip.GetAddressBytes()[0] >= 224 && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) throw new ArgumentException("Use canonical unicast IP targets.");
                        if (source.Kind == "TcpConnect" && (!network.Contains(ip) || IpamNetwork.Number(ip) < network.FirstUsable || IpamNetwork.Number(ip) > network.LastUsable)) throw new ArgumentException("Every TCP target must be a usable address in the selected subnet.");
                    }
                }
                if (source.Kind != "TcpConnect" && !Regex.IsMatch(source.CredentialReference, @"\ADDI_DISCOVERY_[A-Z0-9_]{1,80}\z")) throw new ArgumentException("Use a DDI_DISCOVERY_ environment credential reference.");
                if (source.Kind == "TcpConnect" && source.CredentialReference.Length != 0) throw new ArgumentException("TCP discovery does not use credentials.");
                if (source.Enabled && string.IsNullOrWhiteSpace(source.ApprovalReference)) throw new ArgumentException("Record approved target scope before enabling discovery.");
            }
            foreach (var run in runs)
            {
                if (run is null) throw new ArgumentException("Invalid discovery run.");
                var source = sources.SingleOrDefault(s => s.Id == run.SourceId) ?? throw new ArgumentException("Unknown discovery source in evidence.");
                if (run is null || string.IsNullOrWhiteSpace(run.Actor) || run.Actor.Length > 255 || run.Evidence is null || run.Evidence.Any(e => e is null) || run.Evidence.Select(e => e.ObjectId + "|" + e.Address).Distinct().Count() != run.Evidence.Length || run.AttemptedAt > DateTime.UtcNow.AddMinutes(5) || run.LastSuccess > DateTime.UtcNow.AddMinutes(5) || run.Status == "Complete" && run.LastSuccess is null || run.Evidence.Length > source.MaxResults || run.Configuration != DiscoveryConfiguration(source, state.Subnets.Single(s => s.Id == source.SubnetId)) && run.Configuration != LegacyDiscoveryConfiguration(source) || run.AttemptedAt.Kind != DateTimeKind.Utc || run.LastSuccess?.Kind != DateTimeKind.Utc && run.LastSuccess is not null || run.Detail is null || run.Detail.Length > 512 || run.Status != "Complete" && run.Status != "Failed" && run.Status != "Cancelled" && run.Status != "Running" && run.Status != "Interrupted") throw new ArgumentException("Invalid discovery run.");
                var subnet = state.Subnets.Single(s => s.Id == source.SubnetId);
                var network = new IpamNetwork(subnet.Prefix);
                foreach (var e in run.Evidence)
                    if (e.SourceId != source.Id || e.Source != source.Kind || (DiscoveryScopeCurrent(state, run) && !network.Contains(Address(e.Address))) || e.ObservedAt.Kind != DateTimeKind.Utc || e.Expires.Kind != DateTimeKind.Utc || e.Expires < e.ObservedAt || e.ObservedAt > DateTime.UtcNow.AddMinutes(5) || e.Expires > e.ObservedAt.AddSeconds(source.FreshSeconds) || e.ObjectId?.Length > 2048 || e.HostName?.Length > 255 || e.ClientIdentifier?.Length > 256 || e.Confidence != "ConnectionConfirmed" && e.Confidence != "DeviceReported" && e.Confidence != "ProviderReported") throw new ArgumentException("Invalid discovery evidence.");
            }
        }
        public IpamDiscoverySource PutDiscoverySource(long revision, string actor, IpamDiscoverySource input) => Mutate(revision, actor, "discovery.source.set", state =>
        {
            if ((_state.DiscoveryRuns ?? []).Any(r => r.SourceId == input.Id && r.Status == "Running")) throw new InvalidOperationException("Cancel the active collection and wait for its final outcome before editing this source.");
            var source = input with { Id = string.IsNullOrEmpty(input.Id) ? Guid.NewGuid().ToString("N") : input.Id, Name = input.Name?.Trim() };
            var old = (state.DiscoverySources ?? []).SingleOrDefault(s => s.Id == source.Id);
            if (!string.IsNullOrEmpty(input.Id) && old is null) throw new ArgumentException("Unknown discovery source.");
            var run = (state.DiscoveryRuns ?? []).SingleOrDefault(r => r.SourceId == source.Id);
            if (source.Enabled && (old is null || run?.Status != "Complete" || run.LastSuccess < DateTime.UtcNow.AddSeconds(-source.FreshSeconds) || run.Configuration != DiscoveryConfiguration(source, state.Subnets.Single(s => s.Id == source.SubnetId)))) throw new InvalidOperationException("Save disabled, then qualify the approved scope successfully before enabling. Configuration changes require qualification again.");
            bool same = old is not null && LegacyDiscoveryConfiguration(old) == LegacyDiscoveryConfiguration(source);
            return (state with { DiscoverySources = (state.DiscoverySources ?? []).Where(s => s.Id != source.Id).Append(source).ToArray(), DiscoveryRuns = (state.DiscoveryRuns ?? []).Where(r => r.SourceId != source.Id || same).ToArray() }, source, source.Id);
        });
        public void DeleteDiscoverySource(long revision, string actor, string id) => Mutate(revision, actor, "discovery.source.delete", state =>
        {
            if ((state.DiscoveryRuns ?? []).Any(r => r.SourceId == id && r.Status == "Running")) throw new InvalidOperationException("Cancel the active collection and wait for its final outcome before removing this source.");
            if (!(state.DiscoverySources ?? []).Any(s => s.Id == id)) throw new ArgumentException("Unknown discovery source.");
            return (state with { DiscoverySources = state.DiscoverySources.Where(s => s.Id != id).ToArray(), DiscoveryRuns = (state.DiscoveryRuns ?? []).Where(r => r.SourceId != id).ToArray() }, true, id);
        });
        public IpamDiscoveryEvidence[] DiscoveryEvidence(string subnetId, bool includeStale)
        {
            lock (_sync)
            {
                var ids = (_state.DiscoverySources ?? []).Where(s => s.SubnetId == subnetId).Select(s => s.Id).ToHashSet();
                return (_state.DiscoveryRuns ?? []).Where(r => ids.Contains(r.SourceId) && DiscoveryScopeCurrent(_state, r)).SelectMany(r => r.Evidence).Where(e => includeStale || e.Present && e.Expires > DateTime.UtcNow).ToArray();
            }
        }
        public async Task<IpamDiscoveryRun> RunDiscovery(string id, string actor, bool qualify, CancellationToken cancellationToken, Action authorize = null)
        {
            RetryDiscoveryPersistence();
            if (!await _activeDiscoveryGate.WaitAsync(0, cancellationToken)) throw new InvalidOperationException("Another discovery run or unsaved outcome is active. Reload source status before retrying.");
            DiscoveryJob job = null;
            IpamDiscoverySource source;
            IpamSubnet parent;
            string configuration;
            try
            {
                authorize?.Invoke();
                lock (_sync)
                {
                    source = (_state.DiscoverySources ?? []).SingleOrDefault(s => s.Id == id) ?? throw new ArgumentException("Unknown discovery source.");
                    parent = _state.Subnets.Single(s => s.Id == source.SubnetId);
                    configuration = DiscoveryConfiguration(source, parent);
                    var previous = (_state.DiscoveryRuns ?? []).SingleOrDefault(r => r.SourceId == id);
                    if (!qualify && (!source.Enabled || previous is null || previous.LastSuccess is null || !DiscoveryScopeCurrent(_state, previous))) throw new InvalidOperationException("Source is disabled or its parent scope needs review. Qualify the current prefix and view first.");
                    if (string.IsNullOrWhiteSpace(source.ApprovalReference)) throw new InvalidOperationException("Record an approval reference for the exact target scope before collection.");
                    bool previousBound = previous is not null && DiscoveryScopeCurrent(_state, previous);
                    var running = new IpamDiscoveryRun(id, configuration, actor, DateTime.UtcNow, previousBound ? previous.LastSuccess : null, "Running", "Collecting the approved scope; last-known evidence remains available.", previousBound ? previous.Evidence : []);
                    Mutate(_state.Revision, actor, "discovery.started", state => (state with { DiscoveryRuns = (state.DiscoveryRuns ?? []).Where(r => r.SourceId != id).Append(running).ToArray() }, true, id));
                    job = new DiscoveryJob(); _activeDiscoveryJobs.Add(id, job);
                }
            }
            catch { _activeDiscoveryGate.Release(); throw; }
            IpamDiscoveryEvidence[] collected = null;
            string status = "Complete", reason = "Complete", detail = "Collection completed. Missing replies do not prove addresses are unused.";
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, job.Cancellation.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                collected = await IpamDiscoveryCollector.Collect(source, new IpamNetwork(parent.Prefix), deadline.Token);
                if (collected.Length > source.MaxResults) throw new IpamDiscoveryLimitException("Excessive discovery results.");
                if (collected.Select(e => e.ObjectId + "|" + e.Address).Distinct().Count() != collected.Length) throw new InvalidDataException("Duplicate discovery results.");
            }
            catch (OperationCanceledException)
            {
                reason = job.Cancellation.IsCancellationRequested ? "OperatorCancelled" : cancellationToken.IsCancellationRequested ? "RequestCancelled" : deadline.IsCancellationRequested ? "RunTimeout" : "RequestTimeout";
                collected = null; status = cancellationToken.IsCancellationRequested || job.Cancellation.IsCancellationRequested ? "Cancelled" : "Failed";
                detail = (job.Cancellation.IsCancellationRequested ? "Collection cancelled by an operator." : cancellationToken.IsCancellationRequested ? "Collection cancelled when its request ended." : "Collection exceeded a request or 30-second run deadline.") + " Last-known evidence retained; review the target and retry.";
            }
            catch (Exception ex)
            {
                collected = null; status = "Failed"; reason = ex is IpamDiscoveryLimitException ? "LimitExceeded" : ex is InvalidDataException || ex is JsonException || ex is System.Formats.Asn1.AsnContentException ? "InvalidResponse" : ex is InvalidOperationException ? "UnavailableConfiguration" : "TransportFailure";
                detail = (ex is IpamDiscoveryLimitException ? "Source exceeded the configured response, row, object or page limit. Collection is incomplete." : ex is InvalidDataException || ex is JsonException || ex is System.Formats.Asn1.AsnContentException ? "Source returned an invalid, incomplete or over-limit response." : ex is InvalidOperationException ? "Source credentials or configuration are unavailable." : "Source connection failed.") + " Last-known evidence retained. Check scope, credentials, limits and source availability, then retry.";
            }
            Exception revoked = null;
            try { authorize?.Invoke(); } catch (Exception ex) { revoked = ex; collected = null; status = "Cancelled"; reason = "AccessChanged"; detail = "Collection access changed. Last-known evidence retained."; }
            lock (_sync)
            {
                var current = (_state.DiscoverySources ?? []).SingleOrDefault(s => s.Id == id);
                if (current is null) { ReleaseDiscoveryJob(id); throw new InvalidOperationException("Discovery source was removed. Collection stopped and no source was recreated."); }
                var currentParent = _state.Subnets.Single(s => s.Id == current.SubnetId);
                var previous = (_state.DiscoveryRuns ?? []).Single(r => r.SourceId == id);
                bool scopeChanged = current != source || DiscoveryConfiguration(current, currentParent) != configuration;
                var evidence = scopeChanged ? [] : previous.Evidence;
                if (scopeChanged) { collected = null; status = "Cancelled"; reason = "ScopeChanged"; detail = "Collection scope changed. Results discarded; qualify the current prefix and view."; }
                if (collected is not null)
                {
                    var keys = collected.Select(e => e.ObjectId + "|" + e.Address).ToHashSet();
                    evidence = collected.Concat(evidence.Where(e => !keys.Contains(e.ObjectId + "|" + e.Address)).Select(e => e with { Present = false })).Take(source.MaxResults).ToArray();
                }
                if (job.Cancellation.IsCancellationRequested) { collected = null; status = "Cancelled"; reason = "OperatorCancelled"; detail = "Collection cancelled by an operator. Last-known evidence retained."; evidence = previous.Evidence; }
                var result = new IpamDiscoveryRun(id, DiscoveryConfiguration(current, currentParent), actor, previous.AttemptedAt, scopeChanged ? null : collected is null ? previous.LastSuccess : DateTime.UtcNow, status, detail, evidence, reason, reason == "LimitExceeded");
                job.PendingResult = result;
                if (!PersistDiscoveryResult(id, job)) throw new InvalidOperationException("Collection stopped, but its outcome could not be saved. Restore inventory storage and reload sources to finish saving; collection will not run again.");
                if (revoked is not null) throw revoked;
                return result;
            }
        }
    }
}
