// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

// Ordinary, synthetic capacity fixtures only. No live node/provider or security-review replay.
static class MispCapacityChecks
{
    sealed class Provider : HttpMessageHandler
    {
        public int Count = 1, Calls, TagSize, DelayMilliseconds;
        public string Shape = "network";
        public bool Duplicate, Stall;
        public int EdlCalls;
        public int EdlWidth = 180;
        public bool EdlSmall;
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Method == HttpMethod.Get)
            {
                EdlCalls++;
                string text = EdlSmall ? "https://edl.example/previous\n" : string.Join('\n', Enumerable.Range(0, 10000).Select(i => ("https://edl.example/" + i.ToString("D5") + "/").PadRight(EdlWidth, 'a'))) + "\n";
                return new(HttpStatusCode.OK) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };
            }
            if (request.Headers.GetValues("Authorization").Single() != "capacity-fixture") throw new Exception("Fixture authorization missing");
            using var json = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token));
            int page = json.RootElement.GetProperty("page").GetInt32(); Calls++;
            if (json.RootElement.GetProperty("limit").GetInt32() != 1000) throw new Exception("Unbounded page request");
            if (Stall && page == 2) { Entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            if (DelayMilliseconds > 0) await Task.Delay(DelayMilliseconds, token);
            int start = (page - 1) * 1000, take = Math.Min(1000, Math.Max(0, Count - start));
            using var bytes = new MemoryStream();
            using (var writer = new Utf8JsonWriter(bytes))
            {
                writer.WriteStartObject(); writer.WritePropertyName("response"); writer.WriteStartObject(); writer.WritePropertyName("Attribute"); writer.WriteStartArray();
                for (int i = start; i < start + take; i++)
                {
                    int identity = Duplicate && i == 1000 ? 0 : i;
                    string type = Shape == "composite" ? "domain|ip" : Shape == "observed" ? i < 46133 ? "ip-dst" : i < 53098 ? "domain" : i < 54415 ? "url" : "hostname" : "ip-dst";
                    string ip = "2001:db8::" + (i >> 16).ToString("x") + ":" + (i & 65535).ToString("x"), domain = "host" + i + ".example";
                    if (Shape == "dense") ip = "2001:db8::1";
                    string value = type == "domain|ip" ? domain + "|" + ip : type == "ip-dst" ? ip : type == "url" ? "https://" + domain + "/path" : domain;
                    writer.WriteStartObject(); writer.WriteString("uuid", new Guid(identity + 1, 0, 0, new byte[8]).ToString("D")); writer.WriteString("type", type); writer.WriteString("value", value);
                    writer.WriteString("timestamp", "1720000000"); writer.WriteString("event_id", "fixture"); writer.WriteBoolean("to_ids", i < 10064);
                    if (TagSize > 0) { writer.WritePropertyName("Tag"); writer.WriteStartArray(); writer.WriteStartObject(); writer.WriteString("name", new string('é', TagSize) + " reviewed"); writer.WriteEndObject(); writer.WriteEndArray(); }
                    writer.WriteEndObject();
                }
                writer.WriteEndArray(); writer.WriteEndObject(); writer.WriteEndObject();
            }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes.ToArray()) };
        }
    }
    public static async Task Run(string profile)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-capacity-" + Guid.NewGuid().ToString("N"));
        var provider = new Provider(); var suffixes = new PublicSuffixes(["example"]);
        int checks = 0; void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        Environment.SetEnvironmentVariable("DDI_MISP_CAPACITY_API_KEY", "capacity-fixture");
        long allocatedBefore = GC.GetTotalAllocatedBytes(); var total = Stopwatch.StartNew();
        double refreshSeconds = 0, restoreSeconds = 0, restartSeconds = 0;
        int expected = 0, sourceRows = 0; long cacheBytes = 0; var queryTimes = new List<double>();
        try
        {
            await using var manager = new DdiSecurityManager(folder, suffixes, new HttpClient(provider) { Timeout = TimeSpan.FromSeconds(120) });
            manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, Misp = new(true, "https://misp.capacity.test", "DDI_MISP_CAPACITY_API_KEY") }, 0);
            await manager.RefreshMispAsync(); Check(manager.MispStatus.Indicators == 1, "Nonempty initial cache was not accepted");
            byte[] initial = manager.ExportEnrichment();
            provider.Calls = 0;
            if (profile is "observed" or "observed-slow" or "boundary" or "expansion" or "edl" or "dense" or "slow-header")
            {
                provider.Count = profile == "slow-header" ? 2 : profile.StartsWith("observed") ? 54506 : profile == "expansion" ? 50000 : 100000;
                provider.Shape = profile.StartsWith("observed") ? "observed" : profile == "expansion" ? "composite" : profile == "dense" ? "dense" : "network";
                provider.DelayMilliseconds = profile == "slow-header" ? 16000 : profile == "observed-slow" ? 1300 : 0;
                var refresh = Stopwatch.StartNew(); await manager.RefreshMispAsync(); refreshSeconds = refresh.Elapsed.TotalSeconds;
                expected = profile == "expansion" ? 100000 : provider.Count; sourceRows = provider.Count;
                Check(manager.MispStatus.Status == "Available" && manager.MispStatus.Indicators == expected, "Complete capacity profile was not accepted");
                Check(provider.Calls == provider.Count / 1000 + 1, "Final short/empty completeness proof was not requested");
                byte[] cache = manager.ExportEnrichment(); cacheBytes = cache.Length;
                Check(cache.Length <= 64 * 1024 * 1024 && cache.Length >= initial.Length, "Accepted cache violates serialized envelope");
                var decoded = JsonSerializer.Deserialize<MispCache>(cache, DdiSecurityManager.JsonOptions);
                Check(decoded.Indicators.Length == expected && decoded.Indicators.Select(i => i.Id).Distinct().Count() == expected && decoded.Indicators.All(i => i.Source == "MISP" && i.Action == "Monitor" && i.Expires > DateTime.UtcNow.AddHours(23)), "Normalization, uniqueness, Monitor or expiry changed");
                using (var provenance = JsonDocument.Parse(decoded.Indicators[0].Evidence)) Check(provenance.RootElement.GetProperty("timestamp").GetString() == "1720000000" && provenance.RootElement.GetProperty("fetchedAt").GetDateTime().Kind == DateTimeKind.Utc, "Source/fetch provenance lost");
                decoded = null;
                int beforeQueries = provider.Calls;
                for (int i = 0; i < (profile == "dense" ? 20 : 1000); i++)
                {
                    var watch = Stopwatch.StartNew(); var decision = manager.Evaluate(IPAddress.Loopback, profile == "expansion" ? "host1.example" : "ordinary.example", [], [IPAddress.Parse("2001:db8::1")]);
                    queryTimes.Add(watch.Elapsed.TotalMilliseconds); if (profile == "dense" && (decision.Matches.Length != 32 || decision.AdditionalMatches != 99968)) throw new Exception("Dense evidence count/sample changed");
                    if (decision.Action != "Monitor") throw new Exception("Cached query outcome changed");
                }
                Check(beforeQueries == provider.Calls, "Cached reads performed provider work");
                if (profile == "dense")
                {
                    manager.SetPolicy(manager.Policy with { Indicators = [new("local-priority", "Network", "2001:db8::1", "Monitor", "Local", 90)] }, manager.Policy.Revision);
                    var ranked = manager.Evaluate(IPAddress.Loopback, "ordinary.example", [], [IPAddress.Parse("2001:db8::1"), IPAddress.Parse("2001:db8::1")]);
                    Check(ranked.Action == "Monitor" && ranked.Matches[0].Id == "local-priority" && ranked.Matches.Length == 32 && ranked.AdditionalMatches == 99969, "Stable ranking or duplicate-target counting changed");
                }
                var clock = Stopwatch.StartNew(); await PeerRoundtrip(Path.Combine(folder, "peer"), manager.ExportPolicy(), cache, suffixes, expected); restoreSeconds = clock.Elapsed.TotalSeconds;
                clock.Restart(); await PeerRestart(folder, cache, suffixes, expected); restartSeconds = clock.Elapsed.TotalSeconds;
                if (profile is "boundary" or "expansion")
                {
                    provider.Count++; provider.Calls = 0; await manager.RefreshMispAsync();
                    Check(manager.MispStatus.Status.Contains("Capacity") && cache.SequenceEqual(manager.ExportEnrichment()) && cache.SequenceEqual(File.ReadAllBytes(Path.Combine(folder, "security-misp.json"))), "Count overflow committed a partial cache");
                    Check(provider.Calls == (profile == "boundary" ? 101 : 51), "Overflow was not bounded at the raw/expanded boundary");
                }
                if (profile == "edl")
                {
                    manager.SetPolicy(manager.Policy with { EdlFeeds = Enumerable.Range(0, 8).Select(i => new EdlFeed("f" + i, "Url", "https://edl.capacity.test/" + i, true)).ToArray() }, manager.Policy.Revision);
                    await manager.RefreshEdlAsync(); Check(manager.EdlStatus().Sum(h => h.Entries) == 80000 && provider.EdlCalls == 8 && manager.MispStatus.Indicators == 100000, "EDL aggregate and MISP do not coexist");
                    byte[] edl = manager.ExportEdl(); Check(edl.Length <= 16 * 1024 * 1024, "EDL aggregate budget changed");
                    await EdlRoundtrip(Path.Combine(folder, "both-peer"), manager.ExportPolicy(), cache, edl, suffixes);
                }
            }
            else if (profile == "empty")
            {
                provider.Count = 0; await manager.RefreshMispAsync(); byte[] cache = manager.ExportEnrichment();
                Check(manager.MispStatus.Status == "Available" && manager.MispStatus.Indicators == 0 && JsonSerializer.Deserialize<MispCache>(cache, DdiSecurityManager.JsonOptions).Indicators.Length == 0, "Complete empty 200 did not retract");
                await PeerRoundtrip(Path.Combine(folder, "empty-peer"), manager.ExportPolicy(), cache, suffixes, 0);
                await PeerRestart(folder, cache, suffixes, 0); cacheBytes = cache.Length;
            }
            else if (profile == "budget")
            {
                provider.Count = 20000; provider.TagSize = 800;
                await manager.RefreshMispAsync(); Check(manager.MispStatus.Status.Contains("Capacity") && manager.ExportEnrichment().SequenceEqual(initial) && File.ReadAllBytes(Path.Combine(folder, "security-misp.json")).SequenceEqual(initial), "Expanded metadata overflow replaced complete cache");
                Check(provider.Calls > 1 && provider.Calls < 21, "Aggregate overflow accumulated the entire oversized feed"); sourceRows = provider.Count; cacheBytes = initial.Length;
            }
            else if (profile == "edl-budget")
            {
                provider.EdlSmall = true;
                manager.SetPolicy(manager.Policy with { EdlFeeds = Enumerable.Range(0, 8).Select(i => new EdlFeed("f" + i, "Url", "https://edl.capacity.test/" + i, true)).ToArray() }, manager.Policy.Revision);
                await manager.RefreshEdlAsync(); Check(manager.EdlStatus().Sum(h => h.Entries) == 8, "EDL seeds absent");
                provider.EdlSmall = false; provider.EdlWidth = 208; manager.SetPolicy(manager.Policy, manager.Policy.Revision);
                await manager.RefreshEdlAsync(); byte[] edl = manager.ExportEdl();
                Check(edl.Length <= 16 * 1024 * 1024 && manager.EdlStatus().Sum(h => h.Entries) == 70001 && manager.EdlStatus()[7].Status.Contains("failed"), "EDL aggregate overflow did not retain previous source");
                await EdlRoundtrip(Path.Combine(folder, "budget-peer"), manager.ExportPolicy(), initial, edl, suffixes, 1, 70001);
                cacheBytes = edl.Length;
            }
            else if (profile is "cancel" or "timeout")
            {
                provider.Count = 2000; provider.Stall = true;
                using var cancel = new CancellationTokenSource(); var elapsed = Stopwatch.StartNew(); Task refresh = manager.RefreshMispAsync(cancel.Token);
                await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                int calls = provider.Calls; await manager.RefreshMispAsync(); Check(provider.Calls == calls, "Multiple refreshes entered provider");
                Check(manager.Evaluate(IPAddress.Loopback, "ordinary.example", [], [IPAddress.Parse("2001:db8::0")]).Action == "Monitor", "Pending refresh prevents cached use");
                if (profile == "cancel") { cancel.Cancel(); try { await refresh; throw new Exception("Cancellation ignored"); } catch (OperationCanceledException) { checks++; } }
                else { await refresh.WaitAsync(TimeSpan.FromSeconds(135)); Check(elapsed.Elapsed.TotalSeconds is >= 115 and < 135 && manager.MispStatus.Status.Contains("timed out"), "Whole-refresh 120s deadline not enforced"); }
                refreshSeconds = elapsed.Elapsed.TotalSeconds; Check(initial.SequenceEqual(manager.ExportEnrichment()), "Interrupted refresh replaced complete cache"); cacheBytes = initial.Length;
            }
            else if (profile == "duplicate")
            {
                provider.Count = 2000; provider.Duplicate = true; await manager.RefreshMispAsync();
                Check(initial.SequenceEqual(manager.ExportEnrichment()) && manager.MispStatus.Status.Contains("failed"), "Repeated ordinary attribute identity was silently dropped");
            }
            else throw new ArgumentException("Unknown ordinary capacity profile");
            Check(manager.Policy.Misp.RefreshSeconds == 300 && manager.Policy.Misp.CacheLifetimeHours == 24, "Existing refresh/lifetime changed");
            GC.Collect(); GC.WaitForPendingFinalizers();
            queryTimes.Sort(); var process = Process.GetCurrentProcess();
            Console.WriteLine(JsonSerializer.Serialize(new { profile, checks, sourceRows, expectedNormalized = expected, requests = provider.Calls, cacheBytes, refreshSeconds, restoreSeconds, restartSeconds, elapsedSeconds = total.Elapsed.TotalSeconds, managedRetainedMiB = GC.GetTotalMemory(false) / 1048576.0, peakWorkingSetMiB = process.PeakWorkingSet64 / 1048576.0, allocatedMiB = (GC.GetTotalAllocatedBytes() - allocatedBefore) / 1048576.0, queryP95Milliseconds = queryTimes.Count == 0 ? (double?)null : queryTimes[(int)(queryTimes.Count * .95) - 1], queryMaxMilliseconds = queryTimes.Count == 0 ? (double?)null : queryTimes[^1] }));
            Console.WriteLine("PASS: ordinary MISP capacity profile " + profile);
        }
        finally { Environment.SetEnvironmentVariable("DDI_MISP_CAPACITY_API_KEY", null); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
    static async Task PeerRoundtrip(string folder, byte[] policy, byte[] cache, PublicSuffixes suffixes, int count)
    { await using var peer = new DdiSecurityManager(folder, suffixes); peer.RestorePolicy(policy); peer.RestoreEnrichment(cache); if (peer.MispStatus.Indicators != count || !peer.ExportEnrichment().SequenceEqual(cache)) throw new Exception("Accepted cache failed peer roundtrip"); }
    static async Task PeerRestart(string folder, byte[] cache, PublicSuffixes suffixes, int count)
    { await using var peer = new DdiSecurityManager(folder, suffixes); if (peer.MispStatus.Indicators != count || !peer.ExportEnrichment().SequenceEqual(cache)) throw new Exception("Accepted cache failed restart"); }
    static async Task EdlRoundtrip(string folder, byte[] policy, byte[] misp, byte[] edl, PublicSuffixes suffixes, int mispCount = 100000, int edlCount = 80000)
    { await using var peer = new DdiSecurityManager(folder, suffixes); peer.RestorePolicy(policy); peer.RestoreEnrichment(misp); peer.RestoreEdl(edl); if (peer.MispStatus.Indicators != mispCount || peer.EdlStatus().Sum(h => h.Entries) != edlCount) throw new Exception("Combined peer cache unreadable"); }
}
