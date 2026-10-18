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
            public Index(IEnumerable<ThreatIndicator> indicators)
            {
                foreach (ThreatIndicator indicator in indicators)
                {
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
        readonly object _persistence = new();
        readonly string _folder;
        readonly HttpClient _mispClient;
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
        string _mispSourceUrl = "";
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

        public DdiSecurityManager(string folder, PublicSuffixes suffixes, HttpClient mispClient = null)
        {
            _folder = folder; Directory.CreateDirectory(folder);
            _mispClient = mispClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
            string policyFile = Path.Combine(folder, "security.json");
            _policy = File.Exists(policyFile) ? ParsePolicy(File.ReadAllBytes(policyFile)) : SecurityPolicy.Default;
            string cache = Path.Combine(folder, "security-misp.json");
            if (File.Exists(cache))
            {
                try
                {
                    MispCache stored = JsonSerializer.Deserialize<MispCache>(File.ReadAllBytes(cache), JsonOptions) ?? throw new ArgumentException("Invalid MISP cache.");
                    if (stored.SourceUrl is null || stored.SourceUrl.Length > 2048) throw new ArgumentException("Invalid MISP source binding.");
                    _mispSourceUrl = stored.SourceUrl; _mispIndicators = Normalize(stored.Indicators).Where(i => i.Expires > DateTime.UtcNow).ToArray();
                    if (_mispIndicators.Any(i => i.Source != "MISP" || i.Action != "Monitor" || !i.Expires.HasValue)) throw new ArgumentException("Invalid cached MISP evidence.");
                }
                catch (Exception ex) when (ex is JsonException || ex is ArgumentException) { _mispIndicators = []; _mispSourceUrl = ""; _mispHealth = new(null, null, "Invalid cached indicators; refresh required", 0); }
            }
            _index = new Index(_policy.Indicators.Concat(EnrichmentFor(_policy)));
            string signals = Path.Combine(folder, "security-signals.json");
            if (File.Exists(signals)) MergeSignals(JsonSerializer.Deserialize<SecuritySignal[]>(File.ReadAllBytes(signals), JsonOptions) ?? [], false);
            _behavior = new BehavioralAnalyzer(suffixes);
        }

        public void Start() { lock (_sync) _worker ??= Task.Run(WorkerAsync); }
        public SecurityPolicy Policy { get { lock (_sync) return _policy with { Indicators = _policy.Indicators.ToArray() }; } }
        SecurityPolicy ReadPolicy() { lock (_sync) return _policy; }
        IEnumerable<ThreatIndicator> EnrichmentFor(SecurityPolicy policy) => policy.Misp.Enabled && policy.Misp.Url.TrimEnd('/') == _mispSourceUrl.TrimEnd('/') ? _mispIndicators : [];
        public long DroppedEvents => Interlocked.Read(ref _dropped);
        public MispHealth MispStatus { get { lock (_sync) return !_policy.Misp.Enabled ? _mispHealth with { Status = "Disabled", Indicators = 0 } : _mispHealth with { Indicators = EnrichmentFor(_policy).Count(i => i.Expires > DateTime.UtcNow) }; } }
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
        public byte[] ExportEnrichment() { MispCache cache; lock (_sync) cache = new(_mispSourceUrl, _mispIndicators); return JsonSerializer.SerializeToUtf8Bytes(cache, JsonOptions); }
        public void RestoreEnrichment(byte[] data)
        {
            MispCache cache = JsonSerializer.Deserialize<MispCache>(data, JsonOptions) ?? throw new ArgumentException("Invalid MISP cache.");
            ThreatIndicator[] indicators = Normalize(cache.Indicators);
            if (cache.SourceUrl is null || cache.SourceUrl.Length > 2048) throw new ArgumentException("Invalid enrichment source.");
            if (indicators.Any(i => i.Source != "MISP" || i.Action != "Monitor" || !i.Expires.HasValue)) throw new ArgumentException("Enrichment must be expiring MISP monitor evidence.");
            lock (_persistence)
            {
                SecurityPolicy policy = ReadPolicy();
                Index index = new(policy.Indicators.Concat(policy.Misp.Enabled && policy.Misp.Url.TrimEnd('/') == cache.SourceUrl.TrimEnd('/') ? indicators : []));
                Save("security-misp.json", cache with { Indicators = indicators });
                lock (_sync)
                {
                    _mispIndicators = indicators; _mispSourceUrl = cache.SourceUrl; _index = index;
                    _mispHealth = _mispHealth with { Status = "Replicated cache; source refresh status is local to each node", Indicators = indicators.Length };
                }
            }
        }
        public void RestorePolicy(byte[] data)
        {
            SecurityPolicy policy = ParsePolicy(data);
            lock (_persistence)
            {
                ThreatIndicator[] enrichment; lock (_sync) enrichment = EnrichmentFor(policy).ToArray();
                Index index = new(policy.Indicators.Concat(enrichment)); SavePolicyHistory(policy); Save("security.json", policy);
                lock (_sync) { _policy = policy; _index = index; }
            }
        }
        public void SetPolicy(SecurityPolicy policy, long expectedRevision)
        {
            policy = ParsePolicy(JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions));
            lock (_persistence)
            {
                ThreatIndicator[] enrichment;
                lock (_sync)
                {
                    if (_policy.Revision != expectedRevision) throw new InvalidOperationException("Security policy changed; refresh and retry.");
                    enrichment = EnrichmentFor(policy).ToArray();
                }
                policy = policy with { Revision = checked(expectedRevision + 1) };
                Index index = new(policy.Indicators.Concat(enrichment)); SavePolicyHistory(policy); Save("security.json", policy);
                lock (_sync) { _policy = policy; _index = index; }
            }
        }
        static SecurityPolicy ParsePolicy(byte[] data)
        {
            SecurityPolicy p = JsonSerializer.Deserialize<SecurityPolicy>(data, JsonOptions) ?? throw new ArgumentException("Missing policy.");
            if (p.Version != 1 || p.Revision < 0 || p.Mode != "Monitor" && p.Mode != "Block" || p.AlertThreshold < 1 || p.AlertThreshold > 100 || p.DeviceThreshold < 1 || p.DeviceThreshold > 100 || p.DeviceDnsResponse != "Monitor" && p.DeviceDnsResponse != "Block" || p.DhcpResponse != "Observe" && p.DhcpResponse != "DenyNewLeases") throw new ArgumentException("Invalid security policy settings.");
            if (p.Misp is null || p.Misp.RefreshSeconds < 60 || p.Misp.RefreshSeconds > 86400 || p.Misp.CacheLifetimeHours < 1 || p.Misp.CacheLifetimeHours > 168 || string.IsNullOrEmpty(p.Misp.ApiKeyEnvironment) || p.Misp.ApiKeyEnvironment.Length > 128 || !p.Misp.ApiKeyEnvironment.StartsWith("DDI_MISP_", StringComparison.Ordinal) || !p.Misp.ApiKeyEnvironment.EndsWith("_API_KEY", StringComparison.Ordinal) || p.Misp.ApiKeyEnvironment.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')) throw new ArgumentException("MISP credential references must use DDI_MISP_*_API_KEY environment variables.");
            if (p.Misp.Enabled && (!Uri.TryCreate(p.Misp.Url, UriKind.Absolute, out Uri url) || url.Scheme != "https" || url.UserInfo.Length > 0 || url.Query.Length > 0 || url.Fragment.Length > 0)) throw new ArgumentException("MISP requires an HTTPS base URL without credentials, query, or fragment.");
            return p with { Indicators = Normalize(p.Indicators), Llm = SecurityLlm.Validate(p.Llm ?? new LlmSettings()) };
        }
        static ThreatIndicator[] Normalize(ThreatIndicator[] indicators)
        {
            if (indicators is null || indicators.Length > 10000) throw new ArgumentException("At most 10000 indicators are supported per source.");
            HashSet<string> ids = [];
            return indicators.Select(i =>
            {
                if (i is null || string.IsNullOrWhiteSpace(i.Id) || i.Id.Length > 255 || !ids.Add(i.Id) || string.IsNullOrWhiteSpace(i.Source) || i.Source.Length > 255 || i.Confidence < 0 || i.Confidence > 100 || i.Action != "Allow" && i.Action != "Monitor" && i.Action != "Block" || string.IsNullOrEmpty(i.Value) || i.Value.Length > 2048 || i.Evidence?.Length > 8192) throw new ArgumentException("Invalid indicator or duplicate ID.");
                if (!string.IsNullOrEmpty(i.ClientNetwork)) _ = new IpamNetwork(i.ClientNetwork);
                string value = i.Kind switch
                {
                    "Domain" or "DomainSuffix" => PublicSuffixes.Normalize(i.Value),
                    "Network" => new IpamNetwork(i.Value.Contains('/') ? i.Value : i.Value + "/" + (IPAddress.Parse(i.Value).GetAddressBytes().Length * 8)).Prefix,
                    "Url" when Uri.TryCreate(i.Value, UriKind.Absolute, out Uri url) && (url.Scheme == "https" || url.Scheme == "http") && url.UserInfo.Length == 0 => url.AbsoluteUri,
                    _ => throw new ArgumentException("Indicator kind must be Domain, DomainSuffix, Network, or Url.")
                };
                return i with { Value = value };
            }).ToArray();
        }
        void Save<T>(string name, T value)
        {
            string target = Path.Combine(_folder, name), temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (FileStream file = new(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { JsonSerializer.Serialize(file, value, JsonOptions); file.Flush(true); } File.Move(temp, target, true); }
            finally { if (File.Exists(temp)) File.Delete(temp); }
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
            ThreatIndicator[] queryMatches = string.IsNullOrEmpty(query) ? [] : index.Domain(PublicSuffixes.Normalize(query), client, now).ToArray();
            if (queryMatches.Any(m => m.Action == "Allow"))
            {
                var exceptions = queryMatches.Where(m => m.Action == "Allow").ToArray();
                return new("Allow", exceptions.Take(32).ToArray(), behavior, "Explicit query exception for this module; other blocking systems still apply.", Math.Max(0, exceptions.Length - 32));
            }
            static IEnumerable<ThreatIndicator> Target(IEnumerable<ThreatIndicator> values) { var entries = values.ToArray(); return entries.Any(i => i.Action == "Allow") ? entries.Where(i => i.Action == "Allow") : entries; }
            ThreatIndicator[] matches = queryMatches.Concat(cnames.SelectMany(n => Target(index.Domain(PublicSuffixes.Normalize(n), client, now)))).Concat(addresses.SelectMany(a => Target(index.Address(a, client, now)))).DistinctBy(i => i.Id + "|" + i.Source).ToArray();
            // Target-specific allow rules suppress only that target's matching evidence.
            bool deny = matches.Any(m => m.Action == "Block");
            return new(deny && policy.Mode == "Block" ? "Block" : matches.Length > 0 || behavior?.Score >= policy.AlertThreshold ? "Monitor" : "Allow", matches.OrderByDescending(m => m.Action == "Block").ThenByDescending(m => m.Confidence).Take(32).ToArray(), behavior, deny ? "Threat indicator matched." : behavior?.Score >= policy.AlertThreshold ? "Behavioral risk threshold reached; score is uncalibrated." : matches.Length > 0 ? "Threat enrichment matched." : "No configured threat match.", Math.Max(0, matches.Length - 32));
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
                if (device is not null && DeviceSignal(device.Scope, device.ClientIdentifier, device.HardwareAddress, policy.DeviceThreshold) is not null)
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
            BehavioralScore behavior = queryException ? null : _behavior.Observe(identity, query, request.Question[0].Type.ToString(), response.RCODE == DnsResponseCode.NxDomain, DateTime.UtcNow);
            SecurityDecision decision = EvaluateSnapshot(policy, index, client.Address, query, reachable.Where(n => n != query), addresses, behavior);
            SecuritySignal signal = device is null ? null : DeviceSignal(device.Scope, device.ClientIdentifier, device.HardwareAddress, 1);
            if (signal is not null && signal.Score >= policy.DeviceThreshold && policy.Mode == "Block" && policy.DeviceDnsResponse == "Block" && !queryException) decision = decision with { Action = "Block", Reason = "Shared device security signal: " + signal.Reason };
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
            lock (_persistence)
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
        SecuritySignal DeviceSignal(string scope, string clientIdentifier, string hardwareAddress, int threshold)
        {
            lock (_sync)
            {
                if (!_deviceSignals.TryGetValue((scope, clientIdentifier, hardwareAddress?.ToUpperInvariant()), out var signals)) return null;
                DateTime now = DateTime.UtcNow;
                return signals.Where(s => s.Expires > now && s.Score >= threshold && EvidenceActive(s, now)).OrderByDescending(s => s.Score).FirstOrDefault();
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
            bool deny = !existingLease && risk is not null && risk.Score >= policy.DeviceThreshold && policy.Mode == "Block" && policy.DhcpResponse == "DenyNewLeases";
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
            var signal = DeviceSignal(scope, clientIdentifier, hardwareAddress, policy.DeviceThreshold); if (signal is null) return false;
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
                            lock (_persistence)
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
            MispSettings settings = ReadPolicy().Misp;
            DateTime attempt = DateTime.UtcNow;
            if (!settings.Enabled) { lock (_sync) _mispHealth = _mispHealth with { Status = "Disabled" }; return; }
            string key = Environment.GetEnvironmentVariable(settings.ApiKeyEnvironment);
            if (string.IsNullOrEmpty(key)) { lock (_sync) _mispHealth = _mispHealth with { LastAttempt = attempt, Status = "API key environment variable is missing" }; return; }
            try
            {
                List<ThreatIndicator> indicators = [];
                for (int page = 1; page <= 11; page++)
                {
                    using HttpRequestMessage request = new(HttpMethod.Post, new Uri(new Uri(settings.Url.TrimEnd('/') + "/"), "attributes/restSearch"));
                    request.Headers.TryAddWithoutValidation("Authorization", key);
                    request.Content = new StringContent(JsonSerializer.Serialize(new { returnFormat = "json", type = new[] { "domain", "hostname", "ip-dst", "domain|ip", "url" }, limit = 1000, page }), Encoding.UTF8, "application/json");
                    using var response = await _mispClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    if (!response.IsSuccessStatusCode) throw new InvalidOperationException("MISP returned HTTP " + (int)response.StatusCode);
                    await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                    using MemoryStream bytes = new(); byte[] buffer = new byte[8192]; int read;
                    while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0) { if (bytes.Length + read > 8 * 1024 * 1024) throw new InvalidOperationException("MISP response size limit exceeded"); bytes.Write(buffer, 0, read); }
                    using JsonDocument json = JsonDocument.Parse(bytes.ToArray());
                    if (!json.RootElement.TryGetProperty("response", out var result) || !result.TryGetProperty("Attribute", out var attributes) || attributes.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Unexpected MISP response shape");
                    foreach (var attribute in attributes.EnumerateArray())
                    {
                        if (attribute.TryGetProperty("deleted", out var deleted) && (deleted.ToString().Equals("true", StringComparison.OrdinalIgnoreCase) || deleted.ToString() == "1")) continue;
                        string type = attribute.GetProperty("type").GetString(), value = attribute.GetProperty("value").GetString();
                        string uuid = attribute.TryGetProperty("uuid", out var u) ? u.GetString() : attribute.GetProperty("id").ToString();
                        string evidence = JsonSerializer.Serialize(new { attributeUuid = uuid, eventId = attribute.TryGetProperty("event_id", out var e) ? e.ToString() : "", toIds = attribute.TryGetProperty("to_ids", out var ids) ? ids.ToString() : "", timestamp = attribute.TryGetProperty("timestamp", out var t) ? t.ToString() : "", tags = attribute.TryGetProperty("Tag", out var tags) ? tags.ToString() : "" });
                        if (evidence.Length > 8192) throw new InvalidOperationException("MISP evidence size limit exceeded");
                        void Add(string kind, string indicator, string suffix)
                        { try { indicators.AddRange(Normalize([new("misp:" + uuid + suffix, kind, indicator, "Monitor", "MISP", 50, attempt.AddHours(settings.CacheLifetimeHours), null, evidence)])); } catch (ArgumentException) { } catch (FormatException) { } }
                        if (type == "domain" || type == "hostname") Add("Domain", value, "");
                        else if (type == "ip-dst") Add("Network", value, "");
                        else if (type == "url") Add("Url", value, "");
                        else if (type == "domain|ip") { string[] parts = value.Split('|'); if (parts.Length == 2) { Add("Domain", parts[0], ":domain"); Add("Network", parts[1], ":ip"); } }
                        if (indicators.Count > 10000) throw new InvalidOperationException("MISP indicator limit exceeded; previous complete cache retained");
                    }
                    if (attributes.GetArrayLength() < 1000) break;
                    if (page == 11) throw new InvalidOperationException("MISP page limit exceeded; previous complete cache retained");
                }
                ThreatIndicator[] complete = Normalize(indicators.DistinctBy(i => i.Id).ToArray());
                lock (_persistence)
                {
                    SecurityPolicy policy = ReadPolicy();
                    if (policy.Misp != settings) return; // do not publish results from a superseded source configuration
                    Index index = new(policy.Indicators.Concat(complete));
                    Save("security-misp.json", new MispCache(settings.Url, complete));
                    lock (_sync) { _mispSourceUrl = settings.Url; _mispIndicators = complete; _index = index; _mispHealth = new(attempt, attempt, "Available", complete.Length); }
                }
                SharedStateChanged?.Invoke();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is HttpRequestException || ex is JsonException || ex is InvalidOperationException || ex is IOException || ex is TaskCanceledException || ex is KeyNotFoundException)
            { lock (_sync) _mispHealth = _mispHealth with { LastAttempt = attempt, Status = "Refresh failed; last complete cache retained", Indicators = _mispIndicators.Length }; }
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); if (_worker is not null) await _worker;
            if (_refreshTask is not null) { try { await _refreshTask; } catch (OperationCanceledException) when (_stop.IsCancellationRequested) { } }
            Interlocked.Add(ref _dropped, _events.Reader.Count);
            lock (_persistence)
            {
                SecuritySignal[] snapshot; lock (_sync) { TrimSignals(DateTime.UtcNow); snapshot = _signals.Values.ToArray(); }
                Save("security-signals.json", snapshot);
            }
            _llm.Dispose(); _mispClient.Dispose(); _stop.Dispose();
        }
    }
}
