using DnsServerCore.ApplicationCommon;
using DnsServerCore.Ipam;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Security
{
    public sealed partial class DdiSecurityManager : IAsyncDisposable
    {
        sealed record Rule(ThreatIndicator Indicator, IpamNetwork Client);
        sealed class Index
        {
            public readonly Dictionary<string, List<Rule>> Domains = new(StringComparer.Ordinal);
            public readonly Dictionary<string, List<Rule>> Suffixes = new(StringComparer.Ordinal);
            public readonly Dictionary<string, List<Rule>> Networks = new(StringComparer.Ordinal);
            public readonly HashSet<(int Bits, int Prefix)> Prefixes = [];
            public readonly Dictionary<string, ThreatIndicator> Evidence = new(StringComparer.Ordinal);
            static void Add(Dictionary<string, List<Rule>> dictionary, string key, Rule rule)
            { if (!dictionary.TryGetValue(key, out var values)) dictionary[key] = values = []; values.Add(rule); }
            public Index(IEnumerable<ThreatIndicator> indicators, CancellationToken cancellationToken = default)
            {
                foreach (ThreatIndicator indicator in indicators)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (indicator.Kind == "MispUnsupportedUrl") continue; // quarantine is not active DNS/device evidence
                    Evidence[EvidenceKey(indicator)] = indicator;
                    Rule rule = new(indicator, string.IsNullOrEmpty(indicator.ClientNetwork) ? null : new IpamNetwork(indicator.ClientNetwork));
                    if (indicator.Kind == "Domain") Add(Domains, indicator.Value, rule);
                    else if (indicator.Kind == "DomainSuffix") Add(Suffixes, indicator.Value, rule);
                    else if (indicator.Kind == "Network")
                    {
                        IpamNetwork network = new(indicator.Value);
                        Prefixes.Add((network.Bits, network.PrefixLength)); Add(Networks, network.Prefix, rule);
                    }
                }
                foreach (var group in Domains.Values.Concat(Suffixes.Values).Concat(Networks.Values))
                { cancellationToken.ThrowIfCancellationRequested(); if (group.Count > 32) _summaries[group] = Summarize(group, cancellationToken); }
            }
            // Immutable summaries accelerate a single matching group (including repeated DNS targets).
            // Client-scoped or partially expired groups use the full evaluator instead.
            sealed record Summary(int Count, bool Block, ThreatIndicator[] Selected, ThreatIndicator[] Allows, ThreatIndicator[] RankedAllows, int AllowCount, DateTime Until);
            readonly Dictionary<List<Rule>, Summary> _summaries = new();
            Summary Summarize(List<Rule> rules, CancellationToken cancellationToken)
            {
                HashSet<(string Id, string Source)> seen = [];
                List<ThreatIndicator> selected = new(32), allows = new(32), rankedAllows = new(32);
                int count = 0, allowCount = 0; bool block = false; DateTime until = DateTime.MaxValue;
                static int Rank(ThreatIndicator i) => (i.Action == "Block" ? 101 : 0) + i.Confidence;
                static void Insert(List<ThreatIndicator> sample, ThreatIndicator item)
                {
                    if (sample.Count == 32 && Rank(item) <= Rank(sample[^1])) return;
                    int at = sample.FindIndex(i => Rank(i) < Rank(item));
                    if (at < 0) sample.Add(item); else sample.Insert(at, item);
                    if (sample.Count > 32) sample.RemoveAt(32);
                }
                foreach (Rule rule in rules)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (rule.Client is not null) return null;
                    ThreatIndicator item = rule.Indicator;
                    // Ambiguous cross-source identity collisions retain the full target/Allow evaluator.
                    if (!seen.Add((item.Id, item.Source))) return null;
                    count++; block |= item.Action == "Block";
                    if (item.Expires.HasValue && item.Expires.Value < until) until = item.Expires.Value;
                    Insert(selected, item);
                    if (item.Action == "Allow")
                    { allowCount++; if (allows.Count < 32) allows.Add(item); Insert(rankedAllows, item); }
                }
                return new(count, block, selected.ToArray(), allows.ToArray(), rankedAllows.ToArray(), allowCount, until);
            }
            IEnumerable<List<Rule>> DomainGroups(string name)
            {
                if (Domains.TryGetValue(name, out var exact)) yield return exact;
                while (true)
                {
                    if (Suffixes.TryGetValue(name, out var suffix)) yield return suffix;
                    int dot = name.IndexOf('.'); if (dot < 0) break; name = name[(dot + 1)..];
                }
            }
            IEnumerable<List<Rule>> AddressGroups(IPAddress address)
            {
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                int bits = address.GetAddressBytes().Length * 8;
                foreach (var prefix in Prefixes)
                {
                    if (prefix.Bits != bits) continue;
                    IpamNetwork network = new(address + "/" + prefix.Prefix);
                    if (Networks.TryGetValue(network.Prefix, out var rules)) yield return rules;
                }
            }
            public bool TrySingleGroup(string query, string[] cnames, IPAddress[] addresses, DateTime now,
                out ThreatIndicator[] selected, out int count, out bool block, out bool queryException)
            {
                selected = []; count = 0; block = false; queryException = false;
                List<Rule> group = null; bool queryGroup = false;
                foreach (var item in DomainGroups(query))
                { if (group is not null && !ReferenceEquals(group, item)) return false; group = item; queryGroup = true; }
                foreach (string name in cnames)
                    foreach (var item in DomainGroups(PublicSuffixes.Normalize(name)))
                    { if (group is not null && !ReferenceEquals(group, item)) return false; group = item; }
                foreach (IPAddress address in addresses)
                    foreach (var item in AddressGroups(address))
                    { if (group is not null && !ReferenceEquals(group, item)) return false; group = item; }
                if (group is null) return true;
                if (!_summaries.TryGetValue(group, out var summary) || summary is null || now >= summary.Until) return false;
                queryException = queryGroup && summary.AllowCount > 0;
                selected = queryException ? summary.Allows : summary.AllowCount > 0 ? summary.RankedAllows : summary.Selected;
                // Never expose the index-owned sample array to a caller.
                selected = selected.ToArray();
                count = summary.AllowCount > 0 ? summary.AllowCount : summary.Count;
                block = summary.AllowCount == 0 && summary.Block;
                return true;
            }
            static IEnumerable<ThreatIndicator> Active(IEnumerable<Rule> rules, IPAddress client, DateTime now) => rules.Where(r => (!r.Indicator.Expires.HasValue || r.Indicator.Expires > now) && (r.Client is null || r.Client.Contains(client))).Select(r => r.Indicator);
            public IEnumerable<ThreatIndicator> Domain(string name, IPAddress client, DateTime now)
            {
                if (Domains.TryGetValue(name, out var exact)) foreach (var rule in Active(exact, client, now)) yield return rule;
                string current = name;
                while (true)
                {
                    if (Suffixes.TryGetValue(current, out var suffix)) foreach (var rule in Active(suffix, client, now)) yield return rule;
                    int dot = current.IndexOf('.'); if (dot < 0) break; current = current[(dot + 1)..];
                }
            }
            public IEnumerable<ThreatIndicator> Address(IPAddress address, IPAddress client, DateTime now)
            {
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                int bits = address.GetAddressBytes().Length * 8;
                foreach (var prefix in Prefixes)
                {
                    if (prefix.Bits != bits) continue;
                    IpamNetwork network = new(address + "/" + prefix.Prefix);
                    if (Networks.TryGetValue(network.Prefix, out var rules)) foreach (var rule in Active(rules, client, now)) yield return rule;
                }
            }
        }

        public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };
        readonly object _sync = new();
        // All durable mutations share this gate; no gate owner calls another gate-taking method.
        sealed class CommitGate
        {
            readonly SemaphoreSlim _gate = new(1, 1);
            sealed class Lease(SemaphoreSlim gate) : IDisposable { public void Dispose() => gate.Release(); }
            public IDisposable Enter() { _gate.Wait(); return new Lease(_gate); }
            public async Task<IDisposable> EnterAsync(CancellationToken token)
            { await _gate.WaitAsync(token).ConfigureAwait(false); return new Lease(_gate); }
        }
        readonly CommitGate _persistence = new();
        readonly string _folder;
        readonly HttpClient _mispClient;
        readonly SemaphoreSlim _mispRefresh = new(1, 1);
        readonly CancellationTokenSource _stop = new();
        readonly Channel<SecurityEvent> _events = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(2048) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
        readonly Queue<SecurityEvent> _recent = new();
        readonly Dictionary<string, SecuritySignal> _signals = new(StringComparer.Ordinal);
        readonly Dictionary<(string Scope, string Client, string Hardware), List<SecuritySignal>> _deviceSignals = new();
        readonly Dictionary<string, (DateTime Start, int Count)> _dhcpRequests = new(StringComparer.Ordinal);
        readonly BehavioralAnalyzer _behavior;
        readonly SecurityLlm _llm = new();
        SecurityPolicy _policy;
        Index _index;
        ThreatIndicator[] _mispIndicators = [];
        long _mispEpoch;
        DateTime? _mispActiveFetchStartedAt;
        string _mispActiveFetchSourceUrl = "";
        string _mispSourceUrl = "";
        string _mispCacheOrigin = "None";
        DateTime? _mispCacheReceivedAt, _mispCacheFetchedAt, _mispCacheLastExpiry;
        string _mispLastSuccessSourceUrl = "";
        bool _mispCacheHadEntries;
        MispHealth _mispHealth = new(null, null, "Disabled", 0);
        SignalHealth _signalHealth = new(null, "Local signals; replication not attempted", 0);
        Task _worker;
        Task _refreshTask;
        long _dropped;
        public Func<IPAddress, SecurityDevice> DeviceResolver { get; set; }
        public Action DeviceContextChanged { get; set; }
        public Func<string> NodeName { get; set; } = () => Environment.MachineName.ToLowerInvariant();
        public Func<SecuritySignal[], CancellationToken, Task> PublishSignals { get; set; }
        public Action<SecurityEvent> EventRecorded { get; set; }
        public Func<string> PublicationDescription { get; set; }
        public Action SharedStateChanged { get; set; }

        public DdiSecurityManager(string folder, PublicSuffixes suffixes, HttpClient mispClient = null, Func<DateTime> feedClock = null, Action<string> feedCheckpoint = null)
        {
            _feedClock = feedClock; _feedCheckpoint = feedCheckpoint;
            _folder = folder; Directory.CreateDirectory(folder);
            _mispClient = mispClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(120) };
            string policyFile = Path.Combine(folder, "security.json");
            try { _policy = ParsePolicy(ReadPolicyFile(policyFile)); }
            catch (FileNotFoundException) { _policy = SecurityPolicy.Default; }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException || ex is FormatException || ex is IOException || ex is UnauthorizedAccessException || ex is OverflowException)
            {
                // Preserve the file for repair. Invalid optional protection must never stop DNS/DHCP.
                _policy = SecurityPolicy.Default;
                PolicyLoadWarning = "Saved security policy could not be loaded. Protection is disabled with default settings; review and save the policy to repair it. DNS and DHCP remain available.";
            }
            string cache = Path.Combine(folder, "security-misp.json");
            if (File.Exists(cache))
            {
                try
                {
                    if (new FileInfo(cache).Length > MispCacheByteLimit) throw new ArgumentException("MISP cache exceeds 64 MiB.");
                    MispCache stored = JsonSerializer.Deserialize<MispCache>(File.ReadAllBytes(cache), JsonOptions) ?? throw new ArgumentException("Invalid MISP cache.");
                    ThreatIndicator[] validated = ValidateEnrichment(stored);
                    _mispSourceUrl = stored.SourceUrl; _mispIndicators = validated.Where(i => i.Expires > DateTime.UtcNow).ToArray();
                    _mispCacheOrigin = "Persisted"; _mispCacheHadEntries = validated.Length > 0;
                    _mispCacheFetchedAt = PeerMispSnapshotStartedAt(stored);
                    _mispCacheLastExpiry = validated.Where(i => i.Kind != "MispUnsupportedUrl").Max(i => i.Expires);
                    _mispHealth = new(null, null, "Cached evidence; source refresh required", _mispIndicators.Length);
                }
                catch (Exception ex) when (ex is JsonException || ex is ArgumentException || ex is FormatException || ex is IOException || ex is UnauthorizedAccessException) { _mispIndicators = []; _mispSourceUrl = ""; _mispCacheOrigin = "Rejected"; _mispHealth = new(null, null, "Invalid cached indicators; refresh required", 0); }
            }
            LoadEdlCache(); LoadFeedSchedule();
            _index = BuildIndex(_policy);
            string signals = Path.Combine(folder, "security-signals.json");
            if (File.Exists(signals)) MergeSignals(JsonSerializer.Deserialize<SecuritySignal[]>(File.ReadAllBytes(signals), JsonOptions) ?? [], false);
            _behavior = new BehavioralAnalyzer(suffixes);
        }

        public string PolicyLoadWarning { get; private set; }
        public void Start() { lock (_sync) _worker ??= Task.Run(WorkerAsync); }
        public SecurityPolicy Policy { get { lock (_sync) return _policy with { Indicators = _policy.Indicators.ToArray(), EdlFeeds = _policy.EdlFeeds.ToArray(), EdlPublications = _policy.EdlPublications.Select(p => p with { Selected = p.Selected.ToArray() }).ToArray() }; } }
        SecurityPolicy ReadPolicy() { lock (_sync) return _policy; }
        IEnumerable<ThreatIndicator> EnrichmentFor(SecurityPolicy policy) => policy.Misp.Enabled && policy.Misp.Url.TrimEnd('/') == _mispSourceUrl.TrimEnd('/') ? _mispIndicators : [];
        public long DroppedEvents => Interlocked.Read(ref _dropped);
        public MispHealth MispStatus
        {
            get
            {
                lock (_sync)
                {
                    DateTime now = DateTime.UtcNow;
                    bool enabled = _policy.Misp.Enabled;
                    bool sourceMatches = _policy.Misp.Url.TrimEnd('/') == _mispSourceUrl.TrimEnd('/');
                    var active = EnrichmentFor(_policy).Where(i => i.Expires > now).ToArray();
                    int supported = active.Count(i => i.Kind != "MispUnsupportedUrl");
                    string cacheState = !enabled ? "Disabled" : !sourceMatches && _mispSourceUrl.Length > 0 ? "SourceChanged" :
                        _mispCacheOrigin == "Rejected" ? "Rejected" : supported > 0 ? "Usable" : active.Length > 0 ? "EvidenceOnly" :
                        _mispCacheHadEntries ? "Expired" : "Empty";
                    var unsupported = _mispIndicators.Where(i => i.Kind == "MispUnsupportedUrl").ToArray();
                    string status = _mispHealth.Status;
                    if (status == "Available" && _mispIndicators.Length > 0 && active.Length == 0) status = "Expired; evidence inactive";
                    if (unsupported.Length > 0)
                    {
                        string schemes = string.Join(", ", unsupported.GroupBy(i => new Uri(i.Value).Scheme).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => g.Key + " (" + g.Count() + ")"));
                        status += "; unsupported URL schemes retained as evidence only: " + schemes;
                    }
                    return _mispHealth with { Status = !enabled ? "Disabled" : cacheState == "SourceChanged" ? "Source changed; refresh required" : status, Indicators = supported,
                        CompleteSnapshot = enabled && sourceMatches && _mispHealth.CompleteSnapshot,
                        CacheState = cacheState, CacheSourceUrl = _mispSourceUrl, CacheOrigin = _mispCacheOrigin, CacheReceivedAt = _mispCacheReceivedAt,
                        CacheFetchedAt = _mispCacheFetchedAt,
                        CacheExpiresAt = active.Where(i => i.Kind != "MispUnsupportedUrl").Min(i => i.Expires),
                        CacheLastExpiresAt = _mispCacheLastExpiry,
                        LocalSuccessSourceMatches = _mispHealth.LastSuccess.HasValue && _policy.Misp.Url.TrimEnd('/') == _mispLastSuccessSourceUrl.TrimEnd('/'),
                        ActiveUnsupportedAttributes = active.Count(i => i.Kind == "MispUnsupportedUrl"),
                        LocalRefreshStale = _mispHealth.LastSuccess.HasValue && (now - _mispHealth.LastSuccess.Value).TotalSeconds > _policy.Misp.RefreshSeconds * 2L,
                        SnapshotEntries = _mispIndicators.Length, UnsupportedAttributes = unsupported.Length,
                        DnsMatchingIndicators = active.Count(i => i.Kind is "Domain" or "DomainSuffix" or "Network"),
                        UrlEvidenceOnly = active.Count(i => i.Kind == "Url") };
                }
            }
        }
        public SignalHealth SignalStatus { get { lock (_sync) return _signalHealth; } }
        public SecurityEvent[] RecentEvents() { lock (_sync) return _recent.ToArray(); }
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        public Task<LlmAnalysis> TestModelConnectionAsync(LlmSettings settings, CancellationToken cancellationToken)
            => _llm.TestConnectionAsync(settings, cancellationToken);

        public LlmMetrics ModelMetrics(int minutes) => _llm.Telemetry.Snapshot(ReadPolicy().Llm ?? new LlmSettings(), minutes);

        public Task<LlmAnalysis> AnalyzeEventAsync(string eventId, CancellationToken cancellationToken)
        {
            SecurityEvent evidence = RecentEvents().SingleOrDefault(e => e.Id == eventId) ?? throw new ArgumentException("This event is no longer available for model analysis. Select a recent event.");
            return _llm.AnalyzeAsync(ReadPolicy().Llm ?? new LlmSettings(), evidence, cancellationToken);
        }
        public SecuritySignal[] Signals() { lock (_sync) return _signals.Values.Where(s => s.Expires > DateTime.UtcNow && EvidenceActive(s, DateTime.UtcNow)).ToArray(); }
        static string EvidenceKey(ThreatIndicator indicator) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { indicator.Id, indicator.Source, indicator.Kind, indicator.Value, indicator.Action, indicator.ClientNetwork }, JsonOptions))).ToLowerInvariant();
        bool EvidenceActive(SecuritySignal signal, DateTime now) => signal.EvidenceKeys is null || signal.EvidenceKeys.Length == 0 || signal.EvidenceKeys.Any(k => _index.Evidence.TryGetValue(k, out var indicator) && (!indicator.Expires.HasValue || indicator.Expires > now));
        public byte[] ExportPolicy() => JsonSerializer.SerializeToUtf8Bytes(ReadPolicy(), JsonOptions);
        public byte[] ExportSignals() => JsonSerializer.SerializeToUtf8Bytes(Signals(), JsonOptions);
        public byte[] ExportEnrichment() { MispCache cache; lock (_sync) cache = new(_mispSourceUrl, _mispIndicators); return SerializeIntelligenceCache(cache); }
        public void RestoreEnrichment(byte[] data) => RestoreEnrichment(data, false);
        // Only authenticated cluster configuration transfer uses peer ordering. Manual restore
        // keeps unconditional epoch invalidation, even when it restores an older snapshot.
        internal void RestoreEnrichment(byte[] data, bool isConfigTransfer)
        {
            if (data.Length > MispCacheByteLimit) throw new ArgumentException("MISP cache exceeds 64 MiB.");
            MispCache cache = JsonSerializer.Deserialize<MispCache>(data, JsonOptions) ?? throw new ArgumentException("Invalid MISP cache.");
            ThreatIndicator[] indicators = ValidateEnrichment(cache).Where(i => i.Expires > DateTime.UtcNow).ToArray();
            DateTime? snapshotStartedAt = PeerMispSnapshotStartedAt(cache);
            DateTime? peerStartedAt = isConfigTransfer ? snapshotStartedAt : null;
            using (_persistence.Enter())
            {
                SecurityPolicy policy = ReadPolicy();
                Index index = BuildIndex(policy, policy.Misp.Enabled && policy.Misp.Url.TrimEnd('/') == cache.SourceUrl.TrimEnd('/') ? indicators : []);
                Save("security-misp.json", cache with { Indicators = indicators });
                lock (_sync)
                {
                    // A peer may deliver the previous complete snapshot while this node is
                    // traversing the same source. That older peer read must not starve
                    // the later complete local fetch. Newer/unknown peer snapshots and
                    // all explicit administrative restores still supersede the fetch.
                    bool olderPeerDuringFetch = isConfigTransfer && peerStartedAt.HasValue &&
                        _mispActiveFetchStartedAt.HasValue && peerStartedAt.Value <= _mispActiveFetchStartedAt.Value &&
                        cache.SourceUrl.TrimEnd('/') == _mispActiveFetchSourceUrl.TrimEnd('/');
                    if (!olderPeerDuringFetch) _mispEpoch++;
                    _mispIndicators = indicators; _mispSourceUrl = cache.SourceUrl; _index = index;
                    _mispCacheOrigin = isConfigTransfer ? "Peer" : "Restored";
                    _mispCacheReceivedAt = DateTime.UtcNow; _mispCacheFetchedAt = snapshotStartedAt;
                    _mispCacheHadEntries = cache.Indicators.Length > 0;
                    _mispCacheLastExpiry = cache.Indicators.Where(i => i.Kind != "MispUnsupportedUrl").Max(i => i.Expires);
                    _mispHealth = _mispHealth with { Status = "Replicated cache; source refresh status is local to each node", Indicators = indicators.Length, CompleteSnapshot = false };
                }
            }
        }
        static DateTime? PeerMispSnapshotStartedAt(MispCache cache)
        {
            // Legacy/empty/mixed/malformed provenance has no ordering proof: retain
            // the conservative restore-wins behavior rather than infer freshness.
            if (cache.Indicators.Length == 0) return null;
            DateTime? started = null;
            try
            {
                foreach (ThreatIndicator indicator in cache.Indicators)
                {
                    using JsonDocument json = JsonDocument.Parse(indicator.Evidence ?? "");
                    var evidence = json.RootElement;
                    if (!evidence.TryGetProperty("sourceUrl", out var source) || source.GetString() != cache.SourceUrl ||
                        !evidence.TryGetProperty("fetchedAt", out var fetched) || !fetched.TryGetDateTime(out DateTime at) ||
                        at.Kind != DateTimeKind.Utc || at > DateTime.UtcNow.AddMinutes(5) ||
                        started.HasValue && started.Value != at) return null;
                    started = at;
                }
                return started;
            }
            catch (Exception ex) when (ex is JsonException || ex is InvalidOperationException) { return null; }
        }
        static ThreatIndicator[] ValidateEnrichment(MispCache cache)
        {
            if (cache.SourceUrl is null || cache.SourceUrl.Length > 2048 || (cache.SourceUrl.Length > 0 && (!Uri.TryCreate(cache.SourceUrl, UriKind.Absolute, out Uri source) || source.Scheme != "https" || source.UserInfo.Length > 0 || source.Query.Length > 0 || source.Fragment.Length > 0))) throw new ArgumentException("Invalid enrichment source.");
            ThreatIndicator[] indicators = Normalize(cache.Indicators, MispIndicatorLimit);
            if (indicators.Any(i => cache.SourceUrl.Length == 0 || i.Source != "MISP" || i.Action != "Monitor" || !i.Id.StartsWith("misp:", StringComparison.Ordinal) || !i.Expires.HasValue || i.Expires.Value.Kind != DateTimeKind.Utc || i.Expires > DateTime.UtcNow.AddHours(168) || !string.IsNullOrEmpty(i.ClientNetwork))) throw new ArgumentException("Enrichment must be bounded, expiring MISP monitor evidence.");
            ValidateIntelligenceCache(cache with { Indicators = indicators });
            return indicators;
        }
        public void RestorePolicy(byte[] data)
        {
            SecurityPolicy policy = ParsePolicy(data);
            using (_persistence.Enter())
            {
                ThreatIndicator[] enrichment; lock (_sync) enrichment = EnrichmentFor(policy).ToArray();
                Index index = BuildIndex(policy, enrichment); SavePolicyHistory(policy); Save("security.json", policy);
                lock (_sync) { if (_policy.Misp != policy.Misp) _mispEpoch++; _policy = policy; PolicyLoadWarning = null; _index = index; _edlHealth.Clear(); _edlEpoch++; }
            }
        }
        public void SetPolicy(SecurityPolicy policy, long expectedRevision, Action authorizeCommit = null)
        {
            using (var counter = new IntelligenceCacheBuffer(2 * 1024 * 1024, default)) JsonSerializer.Serialize(counter, policy, JsonOptions);
            byte[] data = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
            ThreatIndicator[] proposedIndicators = JsonSerializer.Deserialize<SecurityPolicy>(data, JsonOptions).Indicators;
            policy = ParsePolicy(data);
            using (_persistence.Enter())
                CommitPolicy(policy, expectedRevision, authorizeCommit, validateEdits: true, proposedIndicators);
        }
        public void RollbackPolicy(long targetRevision, long expectedRevision, Action<SecurityPolicy> authorizeCommit = null)
        {
            using (_persistence.Enter())
            {
                SecurityPolicy retained = LoadRetainedPolicyHistory().SingleOrDefault(p => p.Revision == targetRevision) ?? throw new ArgumentException("Policy revision is not retained.");
                CommitPolicy(retained, expectedRevision, () => authorizeCommit?.Invoke(retained), validateEdits: false);
            }
        }
        void CommitPolicy(SecurityPolicy policy, long expectedRevision, Action authorizeCommit, bool validateEdits, ThreatIndicator[] proposedIndicators = null)
        {
            ThreatIndicator[] enrichment;
            ThreatIndicator[] existing;
            lock (_sync)
            {
                if (_policy.Revision != expectedRevision) throw new InvalidOperationException("Security policy changed; refresh and retry.");
                existing = _policy.Indicators;
                enrichment = EnrichmentFor(policy).ToArray();
            }
            authorizeCommit?.Invoke();
            if (validateEdits) policy = policy with { Indicators = NormalizeLocalIndicators(policy.Indicators, existing, proposedIndicators) };
            policy = policy with { Revision = checked(expectedRevision + 1) };
            Index index = BuildIndex(policy, enrichment); SavePolicyHistory(policy, authorizeCommit); Save("security.json", policy, authorizeCommit);
            lock (_sync) { if (_policy.Misp != policy.Misp) _mispEpoch++; _policy = policy; PolicyLoadWarning = null; _index = index; _edlHealth.Clear(); _edlEpoch++; }
        }
        static SecurityPolicy ParsePolicy(byte[] data)
        {
            if (data.Length > 2 * 1024 * 1024) throw new ArgumentException("Security policy exceeds 2 MiB. No changes were saved.");
            SecurityPolicy p = JsonSerializer.Deserialize<SecurityPolicy>(data, JsonOptions) ?? throw new ArgumentException("Missing policy.");
            if (p.Version != 1 || p.Revision < 0 || p.Mode != "Monitor" && p.Mode != "Block" || p.AlertThreshold < 1 || p.AlertThreshold > 100 || p.DeviceThreshold < 1 || p.DeviceThreshold > 100 || p.DeviceDnsResponse != "Monitor" && p.DeviceDnsResponse != "Block" || p.DhcpResponse != "Observe" && p.DhcpResponse != "DenyNewLeases") throw new ArgumentException("Invalid security policy settings.");
            if (p.Misp is null || p.Misp.RefreshSeconds < 60 || p.Misp.RefreshSeconds > 86400 || p.Misp.CacheLifetimeHours < 1 || p.Misp.CacheLifetimeHours > 168 || string.IsNullOrEmpty(p.Misp.ApiKeyEnvironment) || p.Misp.ApiKeyEnvironment.Length > 128 || !p.Misp.ApiKeyEnvironment.StartsWith("DDI_MISP_", StringComparison.Ordinal) || !p.Misp.ApiKeyEnvironment.EndsWith("_API_KEY", StringComparison.Ordinal) || p.Misp.ApiKeyEnvironment.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')) throw new ArgumentException("MISP credential references must use DDI_MISP_*_API_KEY environment variables.");
            if (p.Misp.Enabled && (!Uri.TryCreate(p.Misp.Url, UriKind.Absolute, out Uri url) || url.Scheme != "https" || url.UserInfo.Length > 0 || url.Query.Length > 0 || url.Fragment.Length > 0)) throw new ArgumentException("MISP requires an HTTPS base URL without credentials, query, or fragment.");
            ValidateEdlPolicy(p);
            if (p.Indicators?.Any(i => i?.Kind == "MispUnsupportedUrl") == true) throw new ArgumentException("Unsupported MISP source evidence cannot be configured as a local rule.");
            // Existing files, retained history and restores retain the predecessor's list contract.
            // Authoritative edits are validated against the current policy at the commit gate.
            p = p with { DnsTunneling = (p.DnsTunneling ?? throw new ArgumentException("DNS tunneling settings cannot be null; omit the field to use defaults.")).Validate(), Indicators = Normalize(p.Indicators), Llm = SecurityLlm.Validate(p.Llm ?? new LlmSettings()) };
            using (var counter = new IntelligenceCacheBuffer(2 * 1024 * 1024, default)) JsonSerializer.Serialize(counter, p, JsonOptions);
            return p;
        }
        static byte[] ReadPolicyFile(string path)
        {
            const int limit = 2 * 1024 * 1024;
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length > limit) throw new ArgumentException("Saved security policy exceeds 2 MiB.");
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[8192];
            while (buffer.Length <= limit)
            {
                int read = file.Read(chunk, 0, (int)Math.Min(chunk.Length, limit + 1 - buffer.Length));
                if (read == 0) return buffer.ToArray();
                buffer.Write(chunk, 0, read);
            }
            throw new ArgumentException("Saved security policy exceeds 2 MiB.");
        }
        static string LocalIndicatorKey(ThreatIndicator i) => JsonSerializer.Serialize(new[] { i.Kind, i.Value, i.Action, string.IsNullOrEmpty(i.ClientNetwork) ? null : new IpamNetwork(i.ClientNetwork).Prefix, i.Source });
        static ThreatIndicator[] NormalizeLocalIndicators(ThreatIndicator[] indicators, ThreatIndicator[] existing, ThreatIndicator[] proposed)
        {
            if (indicators is null || indicators.Length > 10000) throw new ArgumentException("Local lists support at most 10,000 indicators. No changes were saved.");
            var prior = existing.ToDictionary(i => i.Id, StringComparer.Ordinal);
            var counts = indicators.GroupBy(LocalIndicatorKey, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
            var result = new ThreatIndicator[indicators.Length];
            for (int row = 0; row < indicators.Length; row++)
            {
                try
                {
                    ThreatIndicator canonical = indicators[row];
                    ThreatIndicator i = proposed[row];
                    if (i is null) throw new ArgumentException("Indicator is missing.");
                    if (prior.TryGetValue(canonical.Id, out var old) && JsonSerializer.Serialize(old, JsonOptions) == JsonSerializer.Serialize(canonical, JsonOptions))
                    { result[row] = canonical; continue; }
                    if (string.IsNullOrWhiteSpace(i.Value) || i.Value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) throw new ArgumentException("Enter one value without spaces or control characters.");
                    if (i.Kind == "Url" && (!Uri.TryCreate(i.Value, UriKind.Absolute, out Uri inputUrl) || inputUrl.Scheme is not ("http" or "https") || inputUrl.UserInfo.Length > 0 || !i.Value.StartsWith(inputUrl.Scheme + "://", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(inputUrl.Host) || inputUrl.Host.Contains('*')))
                        throw new ArgumentException("URL evidence requires an HTTP or HTTPS URL with a host and no credentials.");
                    ThreatIndicator normalized = Normalize([i])[0];
                    if (i.Kind is "Domain" or "DomainSuffix")
                    {
                        if (normalized.Value.Split('.').Any(label => label.StartsWith('-') || label.EndsWith('-') || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')))
                            throw new ArgumentException("Use a DNS name, such as example.test; omit wildcards, schemes, paths and ports.");
                    }
                    normalized = normalized with { ClientNetwork = string.IsNullOrEmpty(i.ClientNetwork) ? null : new IpamNetwork(i.ClientNetwork).Prefix };
                    if (counts[LocalIndicatorKey(normalized)] > 1) throw new ArgumentException("This canonical value, action, source and client scope already appear in the list.");
                    result[row] = normalized;
                }
                catch (Exception ex) when (ex is ArgumentException || ex is FormatException || ex is OverflowException)
                { throw new ArgumentException($"Local indicator row {row + 1}: {ex.Message} No changes were saved."); }
            }
            // Keep IDs unique across the entire atomic batch as well as validating each row.
            return Normalize(result);
        }
        static ThreatIndicator[] Normalize(ThreatIndicator[] indicators, int limit = 10000)
        {
            if (indicators is null || indicators.Length > limit) throw new ArgumentException("Indicator count exceeds the source limit.");
            HashSet<string> ids = [];
            return indicators.Select(i =>
            {
                if (i is null || string.IsNullOrWhiteSpace(i.Id) || i.Id.Length > 255 || !ids.Add(i.Id) || string.IsNullOrWhiteSpace(i.Source) || i.Source.Length > 255 || i.Confidence < 0 || i.Confidence > 100 || i.Action != "Allow" && i.Action != "Monitor" && i.Action != "Block" || string.IsNullOrEmpty(i.Value) || i.Value.Length > 2048 || i.Evidence?.Length > 8192) throw new ArgumentException("Invalid indicator or duplicate ID.");
                if (!string.IsNullOrEmpty(i.ClientNetwork)) _ = new IpamNetwork(i.ClientNetwork);
                // Modified by Tekmyster Industries, LLC — remains GPL-3.0. Context is advisory metadata only.
                PredictiveProvenance.Validate(i.Provenance);
                string value = i.Kind switch
                {
                    "Domain" or "DomainSuffix" => PublicSuffixes.Normalize(i.Value),
                    "Network" => new IpamNetwork(i.Value.Contains('/') ? i.Value : i.Value + "/" + (IPAddress.Parse(i.Value).GetAddressBytes().Length * 8)).Prefix,
                    "MispUnsupportedUrl" when ValidUnsupportedMispUrl(i) => i.Value,
                    "Url" when Uri.TryCreate(i.Value, UriKind.Absolute, out Uri url) && (url.Scheme == "https" || url.Scheme == "http") && url.UserInfo.Length == 0 => url.AbsoluteUri,
                    _ => throw new ArgumentException("Indicator kind must be Domain, DomainSuffix, Network, or Url.")
                };
                return i with { Value = value };
            }).ToArray();
        }
        // This kind is retained source evidence, never a DNS rule or an EDL URL.
        static bool ValidUnsupportedMispUrl(ThreatIndicator indicator)
        {
            if (indicator.Source != "MISP" || indicator.Action != "Monitor" || !indicator.Expires.HasValue || !string.IsNullOrEmpty(indicator.ClientNetwork) ||
                indicator.Value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || !Uri.TryCreate(indicator.Value, UriKind.Absolute, out Uri uri) ||
                uri.Scheme is "http" or "https" || uri.Scheme.Length > 32) return false;
            try
            {
                using var json = JsonDocument.Parse(indicator.Evidence ?? ""); var e = json.RootElement;
                return e.GetProperty("sourceType").GetString() == "url" && e.GetProperty("sourceValue").GetString() == indicator.Value &&
                    e.GetProperty("unsupportedReason").GetString() == "Unsupported URL scheme" && e.GetProperty("uriScheme").GetString() == uri.Scheme &&
                    indicator.Id == "misp:" + e.GetProperty("attributeUuid").GetString();
            }
            catch (Exception ex) when (ex is JsonException || ex is KeyNotFoundException || ex is InvalidOperationException) { return false; }
        }
        static ThreatIndicator[] NormalizeMispAttribute(JsonElement attribute, MispSettings settings, DateTime attempt)
        {
            if (attribute.TryGetProperty("deleted", out var deleted))
            {
                string deletion = deleted.ToString().ToLowerInvariant();
                if (deletion is "true" or "1") return [];
                if (deletion is not ("false" or "0")) throw new InvalidOperationException("Invalid MISP deletion state");
            }
            if (attribute.TryGetProperty("timestamp", out var timestamp) && (!long.TryParse(timestamp.ToString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long seconds) || seconds < 0 || seconds > new DateTimeOffset(attempt.AddMinutes(5)).ToUnixTimeSeconds())) throw new InvalidOperationException("Invalid MISP modification timestamp");
            string type = attribute.GetProperty("type").GetString(), value = attribute.GetProperty("value").GetString();
            string uuid = MispIdentity(attribute), kind = type == "url" ? "Url" : null;
            Uri uri = null;
            if (type == "url")
            {
                if (string.IsNullOrEmpty(value) || value.Length > 2048 || value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || !Uri.TryCreate(value, UriKind.Absolute, out uri))
                    throw new InvalidOperationException("Invalid MISP URL syntax");
                if (uri.Scheme is "http" or "https")
                {
                    if (uri.UserInfo.Length > 0 || !value.StartsWith(uri.Scheme + "://", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(uri.Host) || uri.Host.Contains('*'))
                        throw new InvalidOperationException("Invalid MISP HTTP URL syntax");
                }
                else kind = "MispUnsupportedUrl";
            }
            var evidenceFields = new Dictionary<string, object> { ["sourceUrl"] = settings.Url, ["fetchedAt"] = attempt, ["attributeUuid"] = uuid,
                ["eventId"] = attribute.TryGetProperty("event_id", out var e) ? e.ToString() : "", ["toIds"] = attribute.TryGetProperty("to_ids", out var ids) ? ids.ToString() : "",
                ["timestamp"] = attribute.TryGetProperty("timestamp", out var t) ? t.ToString() : "", ["tags"] = attribute.TryGetProperty("Tag", out var tags) ? tags.ToString() : "" };
            if (type == "url")
            {
                evidenceFields["sourceType"] = type; evidenceFields["sourceValue"] = value; evidenceFields["uriScheme"] = uri.Scheme;
                if (kind == "MispUnsupportedUrl") evidenceFields["unsupportedReason"] = "Unsupported URL scheme";
            }
            string evidence = JsonSerializer.Serialize(evidenceFields);
            if (evidence.Length > 8192) throw new MispLimitException("MISP evidence size limit exceeded");
            ThreatIndicator Row(string rowKind, string rowValue, string suffix = "") => new("misp:" + uuid + suffix, rowKind, rowValue, "Monitor", "MISP", 50, attempt.AddHours(settings.CacheLifetimeHours), null, evidence);
            ThreatIndicator[] rows;
            if (type is "domain" or "hostname") rows = [Row("Domain", value)];
            else if (type == "ip-dst") rows = [Row("Network", value)];
            else if (type == "url") rows = [Row(kind, value)];
            else if (type == "domain|ip")
            { string[] parts = value.Split('|'); if (parts.Length != 2) throw new InvalidOperationException("Invalid composite MISP attribute"); rows = [Row("Domain", parts[0], ":domain"), Row("Network", parts[1], ":ip")]; }
            else throw new InvalidOperationException("Unexpected MISP attribute type");
            return Normalize(rows);
        }
        void Save<T>(string name, T value, Action authorizeCommit = null)
        {
            if (name is "security-misp.json" or "security-edl.json") { SaveBytes(name, SerializeIntelligenceCache(value)); return; }
            string target = Path.Combine(_folder, name), temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (FileStream file = new(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { JsonSerializer.Serialize(file, value, JsonOptions); file.Flush(true); } authorizeCommit?.Invoke(); File.Move(temp, target, true); }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        void SaveBytes(string name, byte[] data)
        {
            string target = Path.Combine(_folder, name), temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (FileStream file = new(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { file.Write(data); file.Flush(true); if (name == "security-edl.json") _feedCheckpoint?.Invoke("Flushed"); } File.Move(temp, target, true); }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }

        const int IntelligenceCacheByteLimit = 16 * 1024 * 1024; // all eight EDL sources together
        const int MispCacheByteLimit = 64 * 1024 * 1024;
        const int MispIndicatorLimit = 100000;
        const int MispPageLimit = 101; // includes final empty-page proof at the exact 100000 raw boundary
        sealed class MispLimitException(string message) : InvalidOperationException(message);
        sealed class IntelligenceCacheBuffer(int limit, CancellationToken cancellationToken, Stream destination = null) : Stream
        {
            long _count;
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => _count;
            public override long Position { get => _count; set => throw new NotSupportedException(); }
            public override void Flush() => destination?.Flush();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (_count + buffer.Length > limit) throw new ArgumentException("Serialized intelligence cache exceeds its source budget; previous complete cache retained.");
                destination?.Write(buffer); _count += buffer.Length;
            }
        }
        static int ValidateIntelligenceCache<T>(T value, CancellationToken cancellationToken = default)
        {
            using var counter = new IntelligenceCacheBuffer(value is MispCache ? MispCacheByteLimit : IntelligenceCacheByteLimit, cancellationToken);
            JsonSerializer.Serialize(counter, value, JsonOptions);
            return checked((int)counter.Length);
        }
        static byte[] SerializeIntelligenceCache<T>(T value, CancellationToken cancellationToken = default)
        {
            int length = ValidateIntelligenceCache(value, cancellationToken);
            byte[] data = GC.AllocateUninitializedArray<byte>(length);
            using var destination = new MemoryStream(data, true);
            using var writer = new IntelligenceCacheBuffer(length, cancellationToken, destination);
            JsonSerializer.Serialize(writer, value, JsonOptions);
            if (writer.Length != length) throw new InvalidOperationException("Cache changed during serialization.");
            return data;
        }
        static bool SafeOpaqueCredential(string key) => !string.IsNullOrEmpty(key) && key.Length <= 4096 && key.All(c => c >= '!' && c <= '~');
        static string MispIdentity(JsonElement attribute)
        {
            if (attribute.TryGetProperty("uuid", out var uuid))
            {
                string value = uuid.ValueKind == JsonValueKind.String ? uuid.GetString() : null;
                if (value?.Length != 36 || !Guid.TryParseExact(value, "D", out Guid parsed) || parsed == Guid.Empty) throw new InvalidOperationException("Invalid MISP attribute UUID.");
                return parsed.ToString("D");
            }
            string id = attribute.GetProperty("id").ToString();
            if (id.Length == 0 || id[0] == '0' || !id.All(char.IsAsciiDigit) || !ulong.TryParse(id, out _)) throw new InvalidOperationException("Invalid MISP numeric attribute identity.");
            return id;
        }

        public SecurityDecision Evaluate(IPAddress client, string query, IEnumerable<string> cnames, IEnumerable<IPAddress> addresses, BehavioralScore behavior = null)
        {
            SecurityPolicy policy; Index index; lock (_sync) { policy = _policy; index = _index; }
            return EvaluateSnapshot(policy, index, client, query, cnames, addresses, behavior);
        }
        SecurityDecision EvaluateSnapshot(SecurityPolicy policy, Index index, IPAddress client, string query, IEnumerable<string> cnames, IEnumerable<IPAddress> addresses, BehavioralScore behavior = null)
        {
            if (client.IsIPv4MappedToIPv6) client = client.MapToIPv4();
            if (!policy.Enabled) return new("Allow", [], behavior, "Security module disabled.");
            DateTime now = DateTime.UtcNow;
            string normalizedQuery = string.IsNullOrEmpty(query) ? "" : PublicSuffixes.Normalize(query);
            string[] cnameTargets = cnames.ToArray(); IPAddress[] addressTargets = addresses.ToArray();
            if (index.TrySingleGroup(normalizedQuery, cnameTargets, addressTargets, now, out var sample, out int total, out bool blocked, out bool exception))
            {
                if (exception) return new("Allow", sample, behavior, "Explicit query exception for this module; other blocking systems still apply.", Math.Max(0, total - 32));
                return new(blocked && policy.Mode == "Block" ? "Block" : total > 0 || behavior?.Score >= policy.AlertThreshold ? "Monitor" : "Allow", sample, behavior,
                    blocked ? "Threat indicator matched." : behavior?.Score >= policy.AlertThreshold ? "Behavioral risk threshold reached; score is uncalibrated." : total > 0 ? "Threat enrichment matched." : "No configured threat match.", Math.Max(0, total - 32));
            }
            ThreatIndicator[] queryMatches = normalizedQuery.Length == 0 ? [] : index.Domain(normalizedQuery, client, now).ToArray();
            if (queryMatches.Any(m => m.Action == "Allow"))
            {
                var exceptions = queryMatches.Where(m => m.Action == "Allow").ToArray();
                return new("Allow", exceptions.Take(32).ToArray(), behavior, "Explicit query exception for this module; other blocking systems still apply.", Math.Max(0, exceptions.Length - 32));
            }
            static IEnumerable<ThreatIndicator> Target(IEnumerable<ThreatIndicator> values) { var entries = values.ToArray(); return entries.Any(i => i.Action == "Allow") ? entries.Where(i => i.Action == "Allow") : entries; }
            // Keep the existing stable Block/confidence order, without sorting/materializing every matched attribute.
            HashSet<(string Id, string Source)> seen = [];
            List<ThreatIndicator> selected = new(32); int matchCount = 0; bool indicatorBlock = false;
            static int Rank(ThreatIndicator indicator) => (indicator.Action == "Block" ? 101 : 0) + indicator.Confidence;
            foreach (var indicator in queryMatches.Concat(cnameTargets.SelectMany(n => Target(index.Domain(PublicSuffixes.Normalize(n), client, now)))).Concat(addressTargets.SelectMany(a => Target(index.Address(a, client, now)))))
            {
                if (!seen.Add((indicator.Id, indicator.Source))) continue;
                matchCount++; indicatorBlock |= indicator.Action == "Block";
                int rank = Rank(indicator);
                if (selected.Count == 32 && rank <= Rank(selected[^1])) continue;
                int position = selected.FindIndex(i => Rank(i) < rank);
                if (position < 0) selected.Add(indicator); else selected.Insert(position, indicator);
                if (selected.Count > 32) selected.RemoveAt(32);
            }
            // Target-specific allow rules suppress only that target's matching evidence.
            bool deny = indicatorBlock;
            return new(deny && policy.Mode == "Block" ? "Block" : matchCount > 0 || behavior?.Score >= policy.AlertThreshold ? "Monitor" : "Allow", selected.ToArray(), behavior, deny ? "Threat indicator matched." : behavior?.Score >= policy.AlertThreshold ? "Behavioral risk threshold reached; score is uncalibrated." : matchCount > 0 ? "Threat enrichment matched." : "No configured threat match.", Math.Max(0, matchCount - 32));
        }

        public DnsDatagram BlockResponse(DnsDatagram request, bool recursionAvailable, string reason)
        {
            EDnsOption[] options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, reason))];
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, recursionAvailable, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : request.EDNS.UdpPayloadSize, EDnsHeaderFlags.None, request.EDNS is null ? null : options) { Tag = DnsServerResponseType.Blocked };
        }
        public DnsDatagram CheckQuery(DnsDatagram request, IPEndPoint client)
        {
            if (string.IsNullOrEmpty(request.Question[0].Name)) return null;
            SecurityPolicy policy; Index index; lock (_sync) { policy = _policy; index = _index; }
            SecurityDecision decision = EvaluateSnapshot(policy, index, client.Address, request.Question[0].Name, [], []);
            if (decision.Action == "Block") return BlockResponse(request, true, "DDI threat policy");
            if (policy.Enabled && policy.Mode == "Block" && policy.DeviceDnsResponse == "Block" && !decision.Reason.StartsWith("Explicit query exception", StringComparison.Ordinal))
            {
                SecurityDevice device = DeviceResolver?.Invoke(client.Address.IsIPv4MappedToIPv6 ? client.Address.MapToIPv4() : client.Address);
                if (device is not null && DeviceSignal(device.Scope, device.ClientIdentifier, device.HardwareAddress, policy.DeviceThreshold, true) is not null)
                    return BlockResponse(request, true, "DDI device policy");
            }
            return null;
        }
        public DnsDatagram InspectResponse(DnsDatagram request, IPEndPoint client, DnsDatagram response)
        {
            SecurityPolicy policy; Index index; lock (_sync) { policy = _policy; index = _index; }
            if (!policy.Enabled || request.OPCODE != DnsOpcode.StandardQuery || request.Question.Count != 1 || string.IsNullOrEmpty(request.Question[0].Name) || response.NextDatagram is not null || request.Question[0].Type == DnsResourceRecordType.AXFR || request.Question[0].Type == DnsResourceRecordType.IXFR || response.AuthoritativeAnswer && !policy.InspectAuthoritative) return response;
            string query = PublicSuffixes.Normalize(request.Question[0].Name);
            HashSet<string> reachable = new(StringComparer.Ordinal) { query };
            for (int pass = 0; pass < 16; pass++)
            {
                bool changed = false;
                foreach (DnsResourceRecord record in response.Answer)
                    if (record.RDATA is DnsCNAMERecordData cname && reachable.Contains(PublicSuffixes.Normalize(record.Name))) changed |= reachable.Add(PublicSuffixes.Normalize(cname.Domain));
                if (!changed) break;
            }
            List<IPAddress> addresses = [];
            foreach (DnsResourceRecord record in response.Answer)
                if (reachable.Contains(PublicSuffixes.Normalize(record.Name)))
                { if (record.RDATA is DnsARecordData a) addresses.Add(a.Address); else if (record.RDATA is DnsAAAARecordData aaaa) addresses.Add(aaaa.Address); }
            SecurityDevice device = DeviceResolver?.Invoke(client.Address.IsIPv4MappedToIPv6 ? client.Address.MapToIPv4() : client.Address);
            string identity = device is null ? client.Address.ToString() : device.Scope + "|" + device.ClientIdentifier + "|" + device.HardwareAddress;
            SecurityDecision baseDecision = EvaluateSnapshot(policy, index, client.Address, query, reachable.Where(n => n != query), addresses);
            bool queryException = baseDecision.Reason.StartsWith("Explicit query exception", StringComparison.Ordinal);
            BehavioralScore behavior = queryException ? null : _behavior.Observe(identity, query, request.Question[0].Type.ToString(), response.RCODE == DnsResponseCode.NxDomain, DateTime.UtcNow, policy.DnsTunneling, policy.Revision);
            SecurityDecision decision = EvaluateSnapshot(policy, index, client.Address, query, reachable.Where(n => n != query), addresses, behavior);
            SecuritySignal signal = device is null ? null : DeviceSignal(device.Scope, device.ClientIdentifier, device.HardwareAddress, 1);
            if (signal is not null && DeviceSignal(device.Scope, device.ClientIdentifier, device.HardwareAddress, policy.DeviceThreshold, true) is not null && policy.Mode == "Block" && policy.DeviceDnsResponse == "Block" && !queryException) decision = decision with { Action = "Block", Reason = "Shared device security signal: " + signal.Reason };
            else if (signal is not null && decision.Action == "Allow" && !queryException) decision = decision with { Action = "Monitor", Reason = "Related device security evidence: " + signal.Reason };
            if (decision.Matches.Length > 0 || behavior?.Score >= policy.AlertThreshold || signal is not null)
            {
                SecurityEvent item = new(Guid.NewGuid().ToString("N"), DateTime.UtcNow, NodeName(), "DNS", client.Address.ToString(), query, request.Question[0].Type.ToString(), decision.Action == "Block" ? DnsResponseCode.Refused.ToString() : response.RCODE.ToString(), decision.Action, policy.Revision, device, decision.Matches, behavior, decision.Reason, decision.AdditionalMatches);
                Record(item);
                int reputation = decision.Matches.Where(i => i.Action != "Allow").Select(i => i.Confidence).DefaultIfEmpty(0).Max();
                int risk = decision.Matches.Any(i => i.Action == "Block") ? 100 : Math.Max(reputation, behavior?.Score ?? 0);
                if (device is not null && (risk >= policy.AlertThreshold || decision.Matches.Any(i => i.Action != "Allow")))
                {
                    string summary = decision.Reason + " Query: " + query + "; sources: " + string.Join(",", decision.Matches.Select(i => i.Source).Distinct());
                    PublishDeviceSignal("DNS", device, risk, summary.Length > 1024 ? summary[..1024] : summary, decision.Matches.Where(i => i.Action != "Allow").Select(EvidenceKey).Take(32).ToArray());
                }
            }
            return decision.Action == "Block" ? BlockResponse(request, response.RecursionAvailable, "DDI security policy") : response;
        }
        void Record(SecurityEvent item)
        {
            lock (_sync) { _recent.Enqueue(item); while (_recent.Count > 1000) _recent.Dequeue(); }
            EventRecorded?.Invoke(item);
            if (!_events.Writer.TryWrite(item)) Interlocked.Increment(ref _dropped);
        }
        void PublishDeviceSignal(string service, SecurityDevice device, int score, string reason, string[] evidenceKeys = null)
        {
            DateTime now = DateTime.UtcNow;
            string id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(NodeName() + "|" + service + "|" + device.Scope + "|" + device.ClientIdentifier + "|" + device.HardwareAddress))).ToLowerInvariant();
            lock (_sync)
            {
                if (_signals.TryGetValue(id, out var previous) && previous.Expires > now && EvidenceActive(previous, now))
                {
                    if (previous.Score > score) return;
                    if (now - previous.Timestamp < TimeSpan.FromSeconds(30) && previous.Score == score && (previous.EvidenceKeys ?? []).SequenceEqual(evidenceKeys ?? [])) return;
                }
                _signals[id] = new SecuritySignal(id, now, now.AddMinutes(10), NodeName(), service, device.Scope, device.ClientIdentifier, device.HardwareAddress, score, reason, evidenceKeys);
                TrimSignals(now);
            }
        }
        void TrimSignals(DateTime now)
        {
            foreach (string id in _signals.Where(p => p.Value.Expires <= now).Select(p => p.Key).ToArray()) _signals.Remove(id);
            while (_signals.Count > 4096) _signals.Remove(_signals.MinBy(p => p.Value.Timestamp).Key);
            _deviceSignals.Clear();
            foreach (SecuritySignal signal in _signals.Values)
            {
                var key = (signal.Scope, signal.ClientIdentifier, signal.HardwareAddress?.ToUpperInvariant());
                if (!_deviceSignals.TryGetValue(key, out var signals)) _deviceSignals[key] = signals = [];
                signals.Add(signal);
            }
        }
        public int MergeSignals(SecuritySignal[] signals, bool notify = true)
        {
            if (signals is null || signals.Length > 4096) throw new ArgumentException("Invalid security signal batch.");
            DateTime now = DateTime.UtcNow; int changed = 0;
            foreach (var signal in signals)
                if (signal is null || signal.Id?.Length != 64 || signal.Id.Any(c => !Uri.IsHexDigit(c)) || string.IsNullOrWhiteSpace(signal.Node) || signal.Node.Length > 255 || signal.Score < 0 || signal.Score > 100 || signal.Service != "DNS" && signal.Service != "DHCP" || signal.Scope?.Length > 255 || signal.ClientIdentifier?.Length > 1024 || signal.HardwareAddress?.Length > 255 || signal.Reason?.Length > 1024 || signal.Timestamp > now.AddMinutes(1) || signal.Expires > signal.Timestamp.AddMinutes(10) || signal.EvidenceKeys?.Length > 32 || signal.EvidenceKeys?.Any(k => k is null || k.Length != 64 || k.Any(c => !Uri.IsHexDigit(c))) == true) throw new ArgumentException("Invalid or future-dated security signal.");
            using (_persistence.Enter())
            {
                Dictionary<string, SecuritySignal> merged;
                lock (_sync) merged = new(_signals);
                foreach (var signal in signals)
                    if (signal.Expires > now && (!merged.TryGetValue(signal.Id, out var current) || signal.Timestamp > current.Timestamp)) { merged[signal.Id] = signal with { EvidenceKeys = signal.EvidenceKeys?.ToArray() }; changed++; }
                if (changed > 0)
                {
                    var snapshot = merged.Values.Where(s => s.Expires > now).OrderByDescending(s => s.Timestamp).Take(4096).ToArray();
                    Save("security-signals.json", snapshot);
                    lock (_sync)
                    {
                        foreach (var signal in snapshot)
                            if (!_signals.TryGetValue(signal.Id, out var current) || signal.Timestamp > current.Timestamp) _signals[signal.Id] = signal;
                        TrimSignals(now);
                    }
                }
            }
            if (changed > 0 && notify) SharedStateChanged?.Invoke();
            return changed;
        }
        public SecuritySignal DeviceRisk(string scope, string clientIdentifier, string hardwareAddress)
        {
            return DeviceSignal(scope, clientIdentifier, hardwareAddress, ReadPolicy().DeviceThreshold);
        }
        SecuritySignal DeviceSignal(string scope, string clientIdentifier, string hardwareAddress, int threshold, bool enforcementOnly = false)
        {
            lock (_sync)
            {
                if (!_deviceSignals.TryGetValue((scope, clientIdentifier, hardwareAddress?.ToUpperInvariant()), out var signals)) return null;
                DateTime now = DateTime.UtcNow;
                return signals.Where(s => s.Expires > now && s.Score >= threshold && EvidenceActive(s, now) && (!enforcementOnly || s.EvidenceKeys is not { Length: > 0 } || s.EvidenceKeys.Any(k => _index.Evidence.TryGetValue(k, out var indicator) && indicator.Action == "Block" && indicator.Source != "MISP" && (!indicator.Expires.HasValue || indicator.Expires > now)))).OrderByDescending(s => s.Score).FirstOrDefault();
            }
        }
        public bool ObserveDhcp(string scope, string clientIdentifier, string hardwareAddress, string hostName, bool existingLease)
        {
            SecurityPolicy policy = ReadPolicy(); if (!policy.Enabled) return false;
            DateTime now = DateTime.UtcNow; string key = scope + "|" + clientIdentifier + "|" + hardwareAddress;
            bool anomaly = false;
            lock (_sync)
            {
                if (!_dhcpRequests.TryGetValue(key, out var value) || now - value.Start >= TimeSpan.FromMinutes(1)) value = (now, 0);
                value.Count++; _dhcpRequests[key] = value; anomaly = value.Count == 100;
                if (_dhcpRequests.Count > 2048) _dhcpRequests.Remove(_dhcpRequests.MinBy(p => p.Value.Start).Key);
            }
            SecurityDevice device = new(scope, clientIdentifier, hardwareAddress, hostName, "", "", null);
            if (anomaly) PublishDeviceSignal("DHCP", device, 70, "100 DHCP offer requests from one observed client identity in one minute; uncalibrated anomaly.");
            SecuritySignal risk = DeviceSignal(scope, clientIdentifier, hardwareAddress, 1);
            bool deny = !existingLease && risk is not null && DeviceSignal(scope, clientIdentifier, hardwareAddress, policy.DeviceThreshold, true) is not null && policy.Mode == "Block" && policy.DhcpResponse == "DenyNewLeases";
            if (anomaly || risk is not null) Record(new(Guid.NewGuid().ToString("N"), now, NodeName(), "DHCP", "", "", "Offer", "", deny ? "DenyNewLease" : "Monitor", policy.Revision, device, [], null, risk?.Reason ?? "DHCP request-rate anomaly."));
            return deny;
        }
        public void ObserveDhcpConflict(string scope, string clientIdentifier, string hardwareAddress, string hostName, string address)
        {
            SecurityPolicy policy = ReadPolicy(); if (!policy.Enabled) return;
            var device = new SecurityDevice(scope, clientIdentifier, hardwareAddress, hostName, "", "", null);
            string reason = "Client reports an address conflict for " + address + "; unverified DHCP observation.";
            PublishDeviceSignal("DHCP", device, 80, reason);
            Record(new(Guid.NewGuid().ToString("N"), DateTime.UtcNow, NodeName(), "DHCP", address, "", "Decline", "", "Monitor", policy.Revision, device, [], null, reason));
        }
        public bool DenyDhcpCommit(string scope, string clientIdentifier, string hardwareAddress, string hostName, bool existingLease)
        {
            var policy = ReadPolicy();
            if (!policy.Enabled || existingLease || policy.Mode != "Block" || policy.DhcpResponse != "DenyNewLeases") return false;
            var signal = DeviceSignal(scope, clientIdentifier, hardwareAddress, policy.DeviceThreshold, true); if (signal is null) return false;
            var device = new SecurityDevice(scope, clientIdentifier, hardwareAddress, hostName, "", "", null);
            Record(new(Guid.NewGuid().ToString("N"), DateTime.UtcNow, NodeName(), "DHCP", "", "", "Request", "", "DenyNewLease", policy.Revision, device, [], null, signal.Reason)); return true;
        }

        async Task WorkerAsync()
        {
            DateTime nextRefresh = DateTime.MinValue, lastSignalFlush = DateTime.MinValue, lastCleanup = DateTime.MinValue;
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    DateTime now = DateTime.UtcNow;
                    for (int eventCount = 0; eventCount < 128 && _events.Reader.TryRead(out var item); eventCount++)
                    {
                        try
                        {
                            string file = Path.Combine(_folder, "security-events-" + now.ToString("yyyyMMdd") + ".jsonl");
                            string line = JsonSerializer.Serialize(item, JsonOptions) + "\n";
                            if ((File.Exists(file) ? new FileInfo(file).Length : 0) + Encoding.UTF8.GetByteCount(line) > 10 * 1024 * 1024) { Interlocked.Increment(ref _dropped); continue; }
                            await File.AppendAllTextAsync(file, line, _stop.Token);
                        }
                        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { Interlocked.Increment(ref _dropped); }
                    }
                    if (now - lastSignalFlush >= TimeSpan.FromSeconds(10))
                    {
                        try
                        {
                            SecuritySignal[] local;
                            using (_persistence.Enter())
                            {
                                SecuritySignal[] snapshot;
                                lock (_sync) { TrimSignals(now); snapshot = _signals.Values.ToArray(); }
                                if (snapshot.Length > 0) Save("security-signals.json", snapshot);
                                local = snapshot.Where(s => s.Node == NodeName()).ToArray();
                            }
                            if (local.Length > 0)
                            {
                                if (PublishSignals is not null)
                                { foreach (var batch in local.Chunk(100)) await PublishSignals(batch, _stop.Token); }
                                else SharedStateChanged?.Invoke();
                                lock (_sync) _signalHealth = _signalHealth with { LastSuccess = now, Status = PublicationDescription?.Invoke() ?? "Stored locally; publication callback completed" };
                            }
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        { lock (_sync) _signalHealth = _signalHealth with { Status = "Signal publication failed; local evidence retained for retry", DeliveryErrors = _signalHealth.DeliveryErrors + 1 }; }
                        lastSignalFlush = now;
                    }
                    SecurityPolicy policy = ReadPolicy();
                    if (policy.Enabled && policy.Misp.Enabled && now >= nextRefresh && (_refreshTask is null || _refreshTask.IsCompleted))
                    { _refreshTask = RefreshMispAsync(_stop.Token); nextRefresh = now.AddSeconds(policy.Misp.RefreshSeconds); }
                    if (policy.Enabled && policy.EdlFeeds.Any(f => f.Enabled) && (_edlRefreshTask is null || _edlRefreshTask.IsCompleted))
                        _edlRefreshTask = RefreshEdlAsync(_stop.Token, scheduled: true);
                    if (now - lastCleanup >= TimeSpan.FromHours(1))
                    {
                        try
                        {
                            foreach (string old in Directory.GetFiles(_folder, "security-events-*.jsonl"))
                                if (File.GetLastWriteTimeUtc(old) < now.AddDays(-7)) File.Delete(old);
                        }
                        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { Interlocked.Increment(ref _dropped); }
                        lastCleanup = now;
                    }
                    await Task.Delay(250, _stop.Token);
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }

        public async Task RefreshMispAsync(CancellationToken cancellationToken = default)
        {
            if (!await _mispRefresh.WaitAsync(0, cancellationToken)) return;
            try { await Task.Yield(); await RefreshMispCoreAsync(cancellationToken); }
            finally { lock (_sync) { _mispActiveFetchStartedAt = null; _mispActiveFetchSourceUrl = ""; } _mispRefresh.Release(); }
        }

        async Task RefreshMispCoreAsync(CancellationToken cancellationToken)
        {
            MispSettings settings; long epoch;
            DateTime attempt = DateTime.UtcNow;
            lock (_sync)
            {
                settings = _policy.Misp; epoch = _mispEpoch;
                _mispActiveFetchStartedAt = settings.Enabled ? attempt : null;
                _mispActiveFetchSourceUrl = settings.Url;
                if (settings.Enabled) _mispHealth = _mispHealth with { LastAttempt = attempt, LocalRefreshState = "Fetching" };
            }
            if (!settings.Enabled) { lock (_sync) _mispHealth = _mispHealth with { Status = "Disabled" }; return; }
            string key = Environment.GetEnvironmentVariable(settings.ApiKeyEnvironment);
            if (!SafeOpaqueCredential(key)) { lock (_sync) _mispHealth = _mispHealth with { LastAttempt = attempt, LastFailure = DateTime.UtcNow, LocalRefreshState = "Failed", Status = "API key environment variable is missing or invalid" }; return; }
            // HttpClient's timeout ends at response headers with ResponseHeadersRead.
            // Bound the complete refresh, including all pages and response bodies.
            using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(120));
            CancellationToken refreshToken = deadline.Token;
            try
            {
                List<ThreatIndicator> indicators = [];
                HashSet<string> attributeIds = new(StringComparer.Ordinal);
                int rawCount = 0;
                long serializedCount = SerializeIntelligenceCache(new MispCache(settings.Url, [])).Length;
                for (int page = 1; page <= MispPageLimit; page++)
                {
                    using HttpRequestMessage request = new(HttpMethod.Post, new Uri(new Uri(settings.Url.TrimEnd('/') + "/"), "attributes/restSearch"));
                    request.Headers.TryAddWithoutValidation("Authorization", key); // validated visible ASCII opaque key, never CR/LF or whitespace
                    request.Headers.Accept.ParseAdd("application/json");
                    request.Content = new StringContent(JsonSerializer.Serialize(new { returnFormat = "json", type = new[] { "domain", "hostname", "ip-dst", "domain|ip", "url" }, limit = 1000, page }), Encoding.UTF8, "application/json");
                    using var response = await _mispClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, refreshToken);
                    if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentRange is not null) throw new InvalidOperationException("MISP did not return a complete HTTP 200 response");
                    await using Stream stream = await response.Content.ReadAsStreamAsync(refreshToken);
                    using MemoryStream bytes = new(); byte[] buffer = new byte[8192]; int read;
                    while ((read = await stream.ReadAsync(buffer, refreshToken)) > 0) { if (bytes.Length + read > 8 * 1024 * 1024) throw new MispLimitException("MISP response size limit exceeded"); bytes.Write(buffer, 0, read); }
                    using JsonDocument json = JsonDocument.Parse(bytes.ToArray());
                    if (!json.RootElement.TryGetProperty("response", out var result) || !result.TryGetProperty("Attribute", out var attributes) || attributes.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Unexpected MISP response shape");
                    if (attributes.GetArrayLength() > 1000) throw new MispLimitException("MISP page size limit exceeded");
                    rawCount += attributes.GetArrayLength();
                    if (rawCount > MispIndicatorLimit) throw new MispLimitException("MISP raw attribute capacity exceeded");
                    foreach (var attribute in attributes.EnumerateArray())
                    {
                        refreshToken.ThrowIfCancellationRequested();
                        // Identity uniqueness is checked even for deleted records; no source row disappears silently.
                        string uuid = MispIdentity(attribute);
                        if (!attributeIds.Add(uuid)) throw new InvalidOperationException("MISP attribute identity is repeated");
                        foreach (ThreatIndicator entry in NormalizeMispAttribute(attribute, settings, attempt))
                        {
                            if (indicators.Count >= MispIndicatorLimit) throw new MispLimitException("MISP normalized indicator capacity exceeded");
                            serializedCount += JsonSerializer.SerializeToUtf8Bytes(entry, JsonOptions).Length + (indicators.Count > 0 ? 1 : 0);
                            if (serializedCount > MispCacheByteLimit) throw new MispLimitException("MISP serialized cache capacity exceeded");
                            indicators.Add(entry);
                        }

                    }
                    if (attributes.GetArrayLength() < 1000) break;
                    if (page == MispPageLimit) throw new MispLimitException("MISP complete pagination capacity exceeded");
                }
                ThreatIndicator[] complete = Normalize(indicators.ToArray(), MispIndicatorLimit); // derived IDs must also be unique; never silently discard collisions
                using (await _persistence.EnterAsync(refreshToken))
                {
                    SecurityPolicy policy = ReadPolicy();
                    if (policy.Misp != settings || _mispEpoch != epoch)
                    {
                        lock (_sync) _mispHealth = _mispHealth with { LastAttempt = attempt, LocalRefreshState = "Superseded", Status = "Refresh superseded by newer settings or cache; last complete cache retained" };
                        return;
                    }
                    Index index = BuildIndex(policy, complete, cancellationToken: refreshToken);
                    byte[] serialized = SerializeIntelligenceCache(new MispCache(settings.Url, complete), refreshToken);
                    refreshToken.ThrowIfCancellationRequested();
                    // Final durability boundary: cancellation is honored up to this checkpoint.
                    // Flush/atomic replacement and matching in-memory publication must complete together;
                    // they are deliberately noninterruptible and may exceed the traversal deadline on slow disk.
                    SaveBytes("security-misp.json", serialized);
                    lock (_sync) { _mispSourceUrl = settings.Url; _mispIndicators = complete; _index = index; _mispLastSuccessSourceUrl = settings.Url; _mispCacheLastExpiry = complete.Where(i => i.Kind != "MispUnsupportedUrl").Max(i => i.Expires); _mispCacheOrigin = "Local"; _mispCacheReceivedAt = DateTime.UtcNow; _mispCacheFetchedAt = attempt; _mispCacheHadEntries = complete.Length > 0; _mispHealth = new(attempt, attempt, "Available", complete.Length) { CompleteSnapshot = true, LocalRefreshState = "Succeeded", LastFailure = _mispHealth.LastFailure }; }
                }
                SharedStateChanged?.Invoke();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            { lock (_sync) _mispHealth = _mispHealth with { LocalRefreshState = "Canceled", Status = "Refresh canceled; last complete cache retained" }; throw; }
            catch (Exception ex) when (ex is HttpRequestException || ex is JsonException || ex is InvalidOperationException || ex is IOException || ex is OperationCanceledException || ex is KeyNotFoundException || ex is ArgumentException || ex is FormatException || ex is UnauthorizedAccessException)
            { lock (_sync) _mispHealth = _mispHealth with { LastAttempt = attempt, LastFailure = DateTime.UtcNow, LocalRefreshState = ex is OperationCanceledException ? "TimedOut" : "Failed", Status = ex is MispLimitException ? "Capacity exceeded; last complete cache retained" : ex is OperationCanceledException ? "Refresh timed out; last complete cache retained" : "Refresh failed; last complete cache retained", Indicators = _mispIndicators.Length }; }
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); if (_worker is not null) await _worker;
            if (_refreshTask is not null) { try { await _refreshTask; } catch (OperationCanceledException) when (_stop.IsCancellationRequested) { } }
            if (_edlRefreshTask is not null) { try { await _edlRefreshTask; } catch (OperationCanceledException) when (_stop.IsCancellationRequested) { } }
            await _edlRefresh.WaitAsync(); _edlRefresh.Release(); // include caller-started refreshes before disposing transport
            Interlocked.Add(ref _dropped, _events.Reader.Count);
            using (_persistence.Enter())
            {
                SecuritySignal[] snapshot; lock (_sync) { TrimSignals(DateTime.UtcNow); snapshot = _signals.Values.ToArray(); }
                Save("security-signals.json", snapshot);
            }
            _llm.Dispose(); _mispClient.Dispose(); _stop.Dispose();
        }
    }
}
