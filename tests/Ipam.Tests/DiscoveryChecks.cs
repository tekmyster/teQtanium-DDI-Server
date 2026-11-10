// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Ipam;
using DnsServerCore.Dns;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class DiscoveryChecks
{
    // Private qualification harness: explicit previously approved management hosts only, no store/service writes.
    public static async Task QualifiedRead(string configurationPath)
    {
        var sources = JsonSerializer.Deserialize<IpamDiscoverySource[]>(File.ReadAllBytes(configurationPath), JsonOptions);
        var allowed = new HashSet<string> { "10.0.0.2", "10.81.5.13", "10.81.5.14" };
        var receipt = new List<object>();
        foreach (var source in sources)
        {
            if (source.Kind != "SnmpArp" || !allowed.Contains(source.Targets) || source.Port != 161 || source.MaxResults != 128 || source.TimeoutMs != 1000 || source.ApprovalReference != "manager-retained-approved-switch-read-only-access") throw new InvalidOperationException("Live qualification requires the exact approved bounded source configuration.");
            using var route = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); route.Connect(IPAddress.Parse(source.Targets), 161);
            var localSource = ((IPEndPoint)route.LocalEndPoint).Address.ToString();
            var at = DateTime.UtcNow; using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                var evidence = await IpamDiscoveryCollector.Collect(source, new IpamNetwork(source.Targets + "/32"), deadline.Token);
                receipt.Add(new { target = source.Targets, localSourceAddress = localSource, targetSeenSourceUnverified = true, atUtc = at, completedUtc = DateTime.UtcNow, outcome = "Complete", observedDeviceRows = evidence.Length, confidence = "DeviceReported", ipScope = source.Targets + "/32", tableRowLimit = source.MaxResults, requestTimeoutMs = source.TimeoutMs, wholeRunSeconds = 30, evidenceRetained = "counts only; no ARP inventory or credential export", sourceReference = source.CredentialReference, nativeCoreSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(IpamManager).Assembly.Location))).ToLowerInvariant() });
            }
            catch (Exception ex)
            { receipt.Add(new { target = source.Targets, localSourceAddress = localSource, targetSeenSourceUnverified = true, atUtc = at, completedUtc = DateTime.UtcNow, outcome = "Failed", category = ex is OperationCanceledException ? "Timeout" : ex is InvalidDataException ? "ResponseOrBound" : "TransportOrCredential", sourceReference = source.CredentialReference, tableRowLimit = source.MaxResults, noProductionMutation = true, nativeCoreSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(IpamManager).Assembly.Location))).ToLowerInvariant() }); }
        }
        File.WriteAllText(Path.ChangeExtension(configurationPath, ".result.json"), JsonSerializer.Serialize(receipt, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Qualified read receipts saved privately; " + receipt.Count + " exact sources attempted; no service, device or intent writes.");
    }
    static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    static int Port() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    internal sealed class SnmpFixture : IAsyncDisposable
    {
        readonly UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        readonly CancellationTokenSource stop = new();
        readonly Task loop;
        public string Mode = "normal";
        public string ArpAddress = "127.0.0.2";
        public string ControlFile;
        public int ResponseDelayMs;
        public int Requests, Sets;
        public int Port => ((IPEndPoint)udp.Client.LocalEndPoint).Port;
        public SnmpFixture() { loop = Run(); }
        async Task Run()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult request;
                    try { request = await udp.ReceiveAsync(stop.Token); } catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }
                    Requests++;
                    if (ControlFile is not null && File.Exists(ControlFile)) Mode = File.ReadAllText(ControlFile).Trim();
                    var root = new AsnReader(request.Buffer, AsnEncodingRules.BER).ReadSequence(); root.ReadInteger(); var community = root.ReadOctetString();
                    var tag = root.PeekTag(); if (tag.TagValue == 3) Sets++;
                    var pdu = root.ReadSequence(tag); int id = (int)pdu.ReadInteger(); pdu.ReadInteger(); pdu.ReadInteger();
                    string oid = pdu.ReadSequence().ReadSequence().ReadObjectIdentifier();
                    if (Mode == "silent" || Encoding.UTF8.GetString(community) != "fixture-read-only") continue;
                    if (Mode == "malformed") { await udp.SendAsync(new byte[] { 1, 2, 3 }, request.RemoteEndPoint, stop.Token); continue; }
                    if (Mode == "wrong-id") id++;
                    string nameOid = "1.3.6.1.2.1.1.5.0", arp = "1.3.6.1.2.1.4.22.1.2";
                    byte[] value; bool end = false;
                    if (tag.TagValue == 0) { oid = nameOid; value = Encoding.UTF8.GetBytes("fixture-switch"); }
                    else if (Mode == "empty") { oid = "1.3.6.1.2.1.5.1.0"; value = []; end = true; }
                    else if (Mode == "nonadvance") { value = new byte[] { 2, 0, 0, 0, 0, 2 }; }
                    else if (oid == arp) { oid = arp + ".1." + ArpAddress; value = new byte[] { 2, 0, 0, 0, 0, 2 }; }
                    else if (Mode == "partial") continue;
                    else if (Mode == "limit" || Mode == "slowlimit") { oid = arp + ".1.127.0.0." + (int.Parse(oid.Split('.').Last()) + 1); value = new byte[] { 2, 0, 0, 0, 0, 3 }; }
                    else { oid = "1.3.6.1.2.1.4.22.1.3.1.127.0.0.2"; value = new byte[] { 127, 0, 0, 2 }; }
                    if (Mode == "slowlimit") await Task.Delay(1100, stop.Token);
                    if (ResponseDelayMs > 0) await Task.Delay(ResponseDelayMs, stop.Token);
                    var w = new AsnWriter(AsnEncodingRules.BER); w.PushSequence(); w.WriteInteger(1); w.WriteOctetString(community);
                    var responseTag = new Asn1Tag(TagClass.ContextSpecific, 2, true); w.PushSequence(responseTag); w.WriteInteger(id); w.WriteInteger(0); w.WriteInteger(0);
                    w.PushSequence(); w.PushSequence(); w.WriteObjectIdentifier(oid);
                    if (end) w.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 2));
                    else if (oid.StartsWith("1.3.6.1.2.1.4.22.1.3.", StringComparison.Ordinal)) w.WriteOctetString(value, new Asn1Tag(TagClass.Application, 0));
                    else w.WriteOctetString(value);
                    w.PopSequence(); w.PopSequence(); w.PopSequence(responseTag); w.PopSequence();
                    await udp.SendAsync(w.Encode(), request.RemoteEndPoint, stop.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); udp.Dispose(); await loop; stop.Dispose(); }
    }
    sealed class AzureTransport : DelegatingHandler
    {
        readonly Uri origin;
        public readonly List<string> Requests = [];
        public AzureTransport(Uri uri, X509Certificate2 certificate) : base(new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.GetCertHashString() == certificate.GetCertHashString() }) { origin = uri; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.Method + " " + request.RequestUri.AbsoluteUri);
            if (request.RequestUri.Host != "management.azure.com" || request.Method != HttpMethod.Get) throw new Exception("Fixture attempted an unauthorized cloud request");
            request.RequestUri = new Uri(origin, request.RequestUri.PathAndQuery);
            return base.SendAsync(request, cancellationToken);
        }
    }
    public static async Task Run(bool serve)
    {
        string root = Path.Combine(Path.GetTempPath(), "ipam-discovery-native-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        int webPort = Port(), dnsPort = Port(), checks = 0;
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
        void Reject(Action action, string message) { try { action(); } catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException || ex is IOException) { Check(true, message); return; } throw new Exception(message); }
        var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start(); int tcpPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource(); int connections = 0;
        var accepts = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { using var c = await tcp.AcceptTcpClientAsync(stop.Token); Interlocked.Increment(ref connections); } } catch (OperationCanceledException) { } });
        await using var snmp = new SnmpFixture();
        Environment.SetEnvironmentVariable("DDI_DISCOVERY_FIXTURE_SNMP", "fixture-read-only");
        string password = Guid.NewGuid().ToString("N") + "Aa9!";
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", webPort.ToString());
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
        await using (var log = new LogManager(true, root))
        using (var dns = new DnsServer(root, Path.Combine(repository, "DnsServerCore/dohwww"), log))
        { dns.LoadConfigFile(); dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
        var service = new DnsWebService(true, root);
        using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + webPort), Timeout = TimeSpan.FromSeconds(40) };
        async Task<JsonElement> Call(HttpClient c, string path, params (string Key, string Value)[] values)
        {
            using var body = new FormUrlEncodedContent(values.Select(v => new KeyValuePair<string, string>(v.Key, v.Value)));
            using var response = await c.PostAsync("/api/" + path, body);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
        }
        bool Ok(JsonElement result) => result.GetProperty("status").GetString() == "ok";
        async Task<JsonElement> Inventory() => (await Call(client, "ipam/list")).GetProperty("response").GetProperty("inventory");
        async Task<string> Revision() => (await Inventory()).GetProperty("revision").GetInt64().ToString();
        async Task<JsonElement> Save(IpamDiscoverySource source) => await Call(client, "ipam/discovery/sources/set", ("revision", await Revision()), ("source", JsonSerializer.Serialize(source, JsonOptions)));
        async Task<JsonElement> Collect(string id, bool qualify = true) => await Call(client, "ipam/discovery/run", ("sourceId", id), ("qualify", qualify.ToString()));
        IpamDiscoverySource Source(JsonElement result) { Check(Ok(result), "native source save acknowledged"); return result.GetProperty("response").GetProperty("source").Deserialize<IpamDiscoverySource>(JsonOptions); }
        IpamDiscoveryRun Result(JsonElement result) { Check(Ok(result), "native run response acknowledged"); return result.GetProperty("response").GetProperty("run").Deserialize<IpamDiscoveryRun>(JsonOptions); }
        try
        {
            await service.StartAsync(true);
            using var anonymous = new HttpClient { BaseAddress = client.BaseAddress };
            foreach (string path in new[] { "status", "run", "cancel", "sources/set", "sources/delete" }) Check(!Ok(await Call(anonymous, "ipam/discovery/" + path)), "anonymous discovery " + path + " denied");
            var login = await Call(client, "user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true")); Check(Ok(login), "native admin authenticated");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
            var mgr = (IpamManager)typeof(DnsWebService).GetField("_ipam", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            var auth = (AuthManager)typeof(DnsWebService).GetField("_authManager", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            var subnetReply = await Call(client, "ipam/subnets/set", ("revision", await Revision()), ("prefix", "127.0.0.0/24"), ("name", "Isolated loopback discovery")); Check(Ok(subnetReply), "explicit loopback inventory subnet created");
            string subnetId = subnetReply.GetProperty("response").GetProperty("subnet").GetProperty("id").GetString();
            var tcpSource = new IpamDiscoverySource("", "Loopback TCP fixture", "TcpConnect", subnetId, "127.0.0.1", tcpPort, "", "", "", 16, 300, 60, "isolated-loopback-fixture-only");
            Check(!Ok(await Save(tcpSource with { Targets = "127.0.1.1" })), "outside-subnet target rejected before transport");
            Check(!Ok(await Save(tcpSource with { Targets = "localhost" })), "hostname target rejected; no DNS expansion");
            Check(!Ok(await Save(tcpSource with { Targets = "127.0.0.1 127.0.0.1" })), "duplicate targets rejected");
            Check(!Ok(await Save(tcpSource with { MaxResults = 257 })), "result-limit overflow rejected");
            Check(!Ok(await Save(tcpSource with { TimeoutMs = 99999 })), "unbounded request timeout rejected");
            Check(!Ok(await Save(tcpSource with { Enabled = true })), "new source cannot bypass qualification");
            var noApproval = Source(await Save(tcpSource with { ApprovalReference = "" }));
            int before = connections; Check(!Ok(await Collect(noApproval.Id)), "unapproved qualification refused"); Check(connections == before, "approval denial sent no target probe");
            tcpSource = Source(await Save(noApproval with { ApprovalReference = "isolated-loopback-fixture-only" }));
            Check(!Ok(await Collect(tcpSource.Id, false)), "disabled source does not collect without explicit qualification");
            var assignmentsBefore = JsonSerializer.Serialize(mgr.Snapshot().Assignments, JsonOptions);
            var tcpRun = Result(await Collect(tcpSource.Id));
            Check(tcpRun.Status == "Complete" && tcpRun.Evidence.Length == 1 && tcpRun.Evidence[0].Confidence == "ConnectionConfirmed", "actual native TCP positive stores connection-only confidence");
            Check(tcpRun.Evidence[0].ObservedAt.Kind == DateTimeKind.Utc && tcpRun.Evidence[0].Expires > tcpRun.Evidence[0].ObservedAt && tcpRun.LastSuccess >= tcpRun.AttemptedAt, "local observed and collection clocks persisted separately");
            Check(JsonSerializer.Serialize(mgr.Snapshot().Assignments, JsonOptions) == assignmentsBefore, "active TCP observation preserves all original assignments without creating static intent");
            var inspection = await Call(client, "ipam/subnets/inspect", ("subnetId", subnetId));
            Check(inspection.GetProperty("response").GetProperty("findings").EnumerateArray().Any(f => f.GetProperty("kind").GetString() == "Unmanaged" && f.GetProperty("address").GetString() == "127.0.0.1"), "native inspection reports unmanaged discovered address");
            Check((await Call(client, "ipam/addresses/nextAvailable", ("subnetId", subnetId))).GetProperty("response").GetProperty("address").GetString() == "127.0.0.2", "native suggestion skips current active evidence");
            tcpSource = Source(await Save(tcpSource with { Enabled = true }));
            Check(Result(await Collect(tcpSource.Id, false)).Status == "Complete", "qualified source enabled for explicit manual collection");
            Check(!Ok(await Save(tcpSource with { Port = tcpPort + 1 })), "enabled scope edit requires new qualification");
            var snmpSource = Source(await Save(new IpamDiscoverySource("", "Loopback device fixture", "SnmpArp", subnetId, "127.0.0.1", snmp.Port, "DDI_DISCOVERY_FIXTURE_SNMP", "", "", 16, 300, 60, "isolated-SNMP-fixture-only")));
            var good = Result(await Collect(snmpSource.Id));
            Check(good.Status == "Complete" && good.Evidence.Any(e => e.Address == "127.0.0.2" && e.ClientIdentifier == "020000000002" && e.Confidence == "DeviceReported"), "real UDP SNMP device/ARP collection with next-column IpAddress boundary persists provenance");
            var stamp = good.Evidence.Single(e => e.Address == "127.0.0.2").ObservedAt;
            foreach (string mode in new[] { "malformed", "wrong-id", "nonadvance", "partial" })
            {
                snmp.Mode = mode;
                var failed = Result(await Collect(snmpSource.Id));
                Check(failed.Status == "Failed" && failed.LastSuccess == good.LastSuccess && failed.Evidence.Single(e => e.Address == "127.0.0.2").ObservedAt == stamp, "SNMP " + mode + " preserves complete last-known evidence and timestamp");
            }
            Check(snmp.Sets == 0, "captured SNMP traffic contains no SET mutation");
            snmp.Mode = "silent";
            var running = Collect(snmpSource.Id);
            for (int i = 0; i < 100 && mgr.ActiveDiscoveryIds().Length == 0; i++) await Task.Delay(10);
            Check(mgr.ActiveDiscoveryIds().Contains(snmpSource.Id), "native collector remains in-flight during source stall");
            Reject(() => mgr.Restore(mgr.Export()), "inventory restore cannot race an active collector or reuse its source identity");
            var liveInventory = await Inventory(); Check(liveInventory.GetProperty("subnets").GetArrayLength() > 0, "stalled collector does not hold inventory read lock");
            Check(!Ok(await Collect(tcpSource.Id, false)), "concurrent run rejected without queue or overlap");
            Check(!Ok(await Save(snmpSource with { Name = "edited while collecting" })), "source edit cannot race an active run");
            Check(!Ok(await Call(client, "ipam/discovery/sources/delete", ("revision", await Revision()), ("sourceId", snmpSource.Id))), "source deletion cannot race an active run");
            Check(Ok(await Call(client, "ipam/discovery/cancel", ("sourceId", snmpSource.Id))), "native explicit cancellation requested");
            var cancelled = Result(await running);
            Check(cancelled.Status == "Cancelled" && cancelled.Detail.Contains("operator") && cancelled.LastSuccess == good.LastSuccess && cancelled.Evidence.Any(e => e.ObservedAt == stamp), "operator cancellation is distinct from deadline and retains last good");
            Check(mgr.ActiveDiscoveryIds().Length == 0, "cancellation releases run admission");
            snmp.Mode = "normal"; good = Result(await Collect(snmpSource.Id));
            snmp.Mode = "empty"; var absent = Result(await Collect(snmpSource.Id));
            Check(absent.Status == "Complete" && absent.Evidence.Any(e => e.Address == "127.0.0.2" && !e.Present) && !mgr.DiscoveryEvidence(subnetId, false).Any(e => e.Address == "127.0.0.2"), "complete empty ARP table keeps missing historical row without current occupancy");
            snmp.Mode = "normal"; good = Result(await Collect(snmpSource.Id));
            var staleSnapshot = mgr.Snapshot();
            var expired = staleSnapshot with { DiscoveryRuns = staleSnapshot.DiscoveryRuns.Select(r => r.SourceId == snmpSource.Id ? r with { Evidence = r.Evidence.Select(e => e with { ObservedAt = DateTime.UtcNow.AddHours(-1).AddSeconds(-60), Expires = DateTime.UtcNow.AddHours(-1).AddSeconds(-1) }).ToArray() } : r).ToArray() };
            string expiredFile = Path.Combine(root, "expired.json"); File.WriteAllBytes(expiredFile, JsonSerializer.SerializeToUtf8Bytes(expired, JsonOptions));
            var staleManager = new IpamManager(expiredFile);
            Check(staleManager.DiscoveryEvidence(subnetId, true).Any(e => e.SourceId == snmpSource.Id) && !staleManager.DiscoveryEvidence(subnetId, false).Any(e => e.SourceId == snmpSource.Id), "restart preserves expired evidence but excludes it from current occupancy");
            var interrupted = staleSnapshot with { DiscoveryRuns = staleSnapshot.DiscoveryRuns.Select(r => r.SourceId == snmpSource.Id ? r with { Status = "Running" } : r).ToArray() };
            string interruptedFile = Path.Combine(root, "interrupted.json"); File.WriteAllBytes(interruptedFile, JsonSerializer.SerializeToUtf8Bytes(interrupted, JsonOptions));
            int requests = snmp.Requests; var interruptedManager = new IpamManager(interruptedFile);
            Check(interruptedManager.Snapshot().DiscoveryRuns.Single(r => r.SourceId == snmpSource.Id).Status == "Interrupted" && snmp.Requests == requests, "restart retires persisted running attempt without automatic replay");
            interruptedManager.Restore(JsonSerializer.SerializeToUtf8Bytes(interrupted, JsonOptions));
            Check(interruptedManager.Snapshot().DiscoveryRuns.Single(r => r.SourceId == snmpSource.Id).Status == "Interrupted" && snmp.Requests == requests, "restored in-flight snapshot is retired without replay or a stuck source lock");
            using (var fileLock = new FileStream(Path.Combine(root, "ipam.json.write-lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                int oldRequests = snmp.Requests;
                Check(!Ok(await Collect(snmpSource.Id)), "real persistence failure rejects run before I/O");
                Check(snmp.Requests == oldRequests, "failed attempt persistence sent no SNMP request");
            }
            Check(Result(await Collect(snmpSource.Id)).Status == "Complete", "persistence failure releases admission for a new explicit run");
            var otherManager = new IpamManager(Path.Combine(root, "ipam.json"));
            await Collect(snmpSource.Id);
            Reject(() => otherManager.PutDiscoverySource(otherManager.Snapshot().Revision, "stale-process", tcpSource with { Enabled = false }), "stale manager cannot replace newer persisted discovery");
            var clone = mgr.Snapshot(); clone.DiscoveryRuns[0].Evidence[0] = clone.DiscoveryRuns[0].Evidence[0] with { Address = "127.0.0.200" };
            Check(!mgr.Snapshot().DiscoveryRuns[0].Evidence.Any(e => e.Address == "127.0.0.200"), "snapshot evidence arrays do not mutate live inventory");
            var inventoryText = (await Inventory()).GetRawText();
            Check(!inventoryText.Contains("DDI_DISCOVERY_") && !inventoryText.Contains("fixture-read-only") && !inventoryText.Contains("isolated-SNMP-fixture-only"), "ordinary Settings inventory excludes private source config/history");
            var removable = Source(await Save(tcpSource with { Id = "", Enabled = false, Name = "Source lifecycle fixture" }));
            await Collect(removable.Id);
            var otherRows = mgr.DiscoveryEvidence(subnetId, true).Where(e => e.SourceId != removable.Id).ToArray();
            var edited = Source(await Save(removable with { Name = "Changed explicit configuration" }));
            Check(!mgr.Snapshot().DiscoveryRuns.Any(r => r.SourceId == edited.Id) && mgr.DiscoveryEvidence(subnetId, true).SequenceEqual(otherRows), "explicit source edit clears only its own former configuration evidence");
            Check(Ok(await Call(client, "ipam/discovery/sources/delete", ("revision", await Revision()), ("sourceId", edited.Id))) && mgr.DiscoveryEvidence(subnetId, true).SequenceEqual(otherRows), "authorized source removal retains every other source observation");
            int beforeGet = snmp.Requests; var beforeGetAttempt = mgr.Snapshot().DiscoveryRuns.Single(r => r.SourceId == snmpSource.Id).AttemptedAt;
            using (var wrongMethod = await client.GetAsync("/api/ipam/discovery/run?sourceId=" + snmpSource.Id + "&qualify=true"))
            {
                bool denied = !wrongMethod.IsSuccessStatusCode;
                if (!denied) { using var wrongJson = JsonDocument.Parse(await wrongMethod.Content.ReadAsStringAsync()); denied = wrongJson.RootElement.GetProperty("status").GetString() != "ok"; }
                Check(denied && snmp.Requests == beforeGet && mgr.Snapshot().DiscoveryRuns.Single(r => r.SourceId == snmpSource.Id).AttemptedAt == beforeGetAttempt, "native GET mutation denied without target I/O or attempt changes (HTTP " + (int)wrongMethod.StatusCode + ")");
            }
            var invalidFuture = mgr.Snapshot() with { DiscoveryRuns = mgr.Snapshot().DiscoveryRuns.Select(r => r.SourceId == snmpSource.Id ? r with { AttemptedAt = DateTime.UtcNow.AddHours(1) } : r).ToArray() };
            Reject(() => mgr.Restore(JsonSerializer.SerializeToUtf8Bytes(invalidFuture, JsonOptions)), "restore rejects future local collection timestamps before replacing inventory");
            // Bounds apply to table traversal, not merely to matching subnet rows.
            var limited = Source(await Save(snmpSource with { Id = "", Name = "Small SNMP bound", MaxResults = 2 }));
            snmp.Mode = "normal"; var limitedGood = Result(await Collect(limited.Id));
            snmp.Mode = "limit"; var truncated = Result(await Collect(limited.Id));
            Check(truncated.Status == "Failed" && truncated.Truncated && truncated.OutcomeReason == "LimitExceeded" && truncated.LastSuccess == limitedGood.LastSuccess && truncated.Evidence.SequenceEqual(limitedGood.Evidence), "actual over-limit SNMP walk cannot promote a truncated snapshot");
            snmp.Mode = "normal";
            var whole = Source(await Save(snmpSource with { Id = "", Name = "Whole-run deadline fixture", MaxResults = 64, TimeoutMs = 5000 }));
            var wholeGood = Result(await Collect(whole.Id));
            snmp.Mode = "slowlimit"; var watch = System.Diagnostics.Stopwatch.StartNew(); var wholeFailure = Result(await Collect(whole.Id)); watch.Stop();
            Check(wholeFailure.Status == "Failed" && wholeFailure.OutcomeReason == "RunTimeout" && wholeFailure.LastSuccess == wholeGood.LastSuccess && watch.Elapsed.TotalSeconds >= 29 && watch.Elapsed.TotalSeconds < 36, "30-second whole-run deadline bounds individually responsive SNMP requests and retains last complete evidence");
            snmp.Mode = "silent";
            using (var abort = new CancellationTokenSource())
            {
                using var body = new FormUrlEncodedContent(new Dictionary<string, string> { ["sourceId"] = whole.Id, ["qualify"] = "true" });
                var request = client.PostAsync("/api/ipam/discovery/run", body, abort.Token);
                for (int i = 0; i < 100 && mgr.ActiveDiscoveryIds().Length == 0; i++) await Task.Delay(10);
                abort.Cancel(); try { await request; } catch (OperationCanceledException) { }
                for (int i = 0; i < 100 && mgr.ActiveDiscoveryIds().Length != 0; i++) await Task.Delay(10);
                Check(mgr.Snapshot().DiscoveryRuns.Single(r => r.SourceId == whole.Id).Status == "Cancelled", "actual client request abort persists cancelled attempt and releases admission");
            }
            snmp.Mode = "normal";
            // Large prefixes do not expand targets; selected literals remain the only transport destinations.
            var huge = await Call(client, "ipam/subnets/set", ("revision", await Revision()), ("prefix", "2001:db8::/32"), ("name", "Large IPv6 bound"));
            Check(Ok(huge), "large IPv6 inventory prefix created without enumeration");
            var hugeId = huge.GetProperty("response").GetProperty("subnet").GetProperty("id").GetString();
            Check(!Ok(await Save(tcpSource with { Id = "", Enabled = false, SubnetId = hugeId, Targets = "2001:db8::/64" })), "large IPv6 CIDR expansion rejected before network I/O");
            var overlapView = mgr.PutView(mgr.Snapshot().Revision, "fixture", "", "Independent discovery view", "");
            var overlapSubnet = mgr.PutSubnet(mgr.Snapshot().Revision, "fixture", "", overlapView.Id, "127.0.0.0/24", "Overlapping view", "", null, "", "");
            var overlapSource = Source(await Save(tcpSource with { Id = "", Enabled = false, SubnetId = overlapSubnet.Id, Name = "Independent view TCP" }));
            await Collect(overlapSource.Id);
            Check(mgr.DiscoveryEvidence(overlapSubnet.Id, false).All(e => e.SourceId == overlapSource.Id) && !mgr.DiscoveryEvidence(subnetId, false).Any(e => e.SourceId == overlapSource.Id), "overlapping views preserve separate source identity and occupancy");
            await PreservationChecks(client, service, mgr, snmp, dnsPort, Call, Revision, Save, Collect, Check);
            await PermissionChecks(client, service, auth, snmpSource, tcpSource, Call, Save, Collect, Check, snmp);
            await AzureChecks(snmpSource with { Kind = "AzureNic", Targets = "", Port = 443, Subscription = "00000000-0000-0000-0000-000000000001", ResourceGroup = "fixture-group", CredentialReference = "DDI_DISCOVERY_FIXTURE_AZURE" }, Check);
            using (var fresh = new HttpClient { BaseAddress = client.BaseAddress })
            {
                var freshLogin = await Call(fresh, "user/login", ("user", "admin"), ("pass", password)); Check(Ok(freshLogin), "fresh affected-source admin authentication succeeds while original remains open");
                fresh.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", freshLogin.GetProperty("token").GetString());
                Check(Ok(await Call(fresh, "ipam/discovery/status")), "fresh admin reads actual discovery results");
                Check(Ok(await Call(fresh, "ipam/views/set", ("revision", await Revision()), ("name", "Fresh discovery administration"))), "fresh admin performs required native modification");
                var sessions = await Call(fresh, "admin/sessions/list");
                Check(sessions.GetProperty("response").GetProperty("sessions").EnumerateArray().Single(s => s.GetProperty("isCurrentSession").GetBoolean()).GetProperty("lastSeenRemoteAddress").GetString() == "127.0.0.1", "target records affected source as loopback");
                Check(Ok(await Call(client, "ipam/discovery/status")), "original working administrative session remains usable after fresh proof");
            }
            var persisted = mgr.Snapshot(); int snmpBeforeRestart = snmp.Requests, tcpBeforeRestart = connections;
            await service.DisposeAsync(); service = new DnsWebService(true, root); await service.StartAsync(true);
            var restartLogin = await Call(client, "user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true")); Check(Ok(restartLogin), "fresh native admin authentication after complete service restart");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", restartLogin.GetProperty("token").GetString());
            var restartedMgr = (IpamManager)typeof(DnsWebService).GetField("_ipam", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            Check(JsonSerializer.Serialize(restartedMgr.Snapshot().DiscoverySources, JsonOptions) == JsonSerializer.Serialize(persisted.DiscoverySources, JsonOptions) && JsonSerializer.Serialize(restartedMgr.Snapshot().DiscoveryRuns, JsonOptions) == JsonSerializer.Serialize(persisted.DiscoveryRuns, JsonOptions), "actual native service restart reloads exact source configuration and last-good/error evidence");
            Check(Ok(await Call(client, "ipam/discovery/status")) && snmp.Requests == snmpBeforeRestart && connections == tcpBeforeRestart, "native status after restart sends no automatic network or device probes");
            Check(Ok(await Call(client, "ipam/views/set", ("revision", await Revision()), ("name", "Post-restart administration"))), "fresh post-restart admin performs actual modification before final fixture use");
            // Retain the configured independent fixture for actual browser inspection when requested.
            if (serve)
            {
                string sessionFile = Path.Combine(repository, "../discovery-ui-session.json");
                snmp.ControlFile = Path.Combine(root, "snmp-mode.txt"); File.WriteAllText(snmp.ControlFile, "normal");
                File.WriteAllText(sessionFile, JsonSerializer.Serialize(new { snmpControlFile = snmp.ControlFile, url = client.BaseAddress.AbsoluteUri, user = "admin", password, actorPassword = Environment.GetEnvironmentVariable("DDI_DISCOVERY_UI_ACTOR_PASSWORD"), tcpPort, snmpPort = snmp.Port, root }, JsonOptions));
                Console.WriteLine("SERVING isolated discovery UI; private session file created. Type ENTER to stop."); Console.ReadLine();
                File.Delete(sessionFile);
            }
            Console.WriteLine("PASS " + checks + " discovery native checks; no production source activated.");
        }
        finally { await service.DisposeAsync(); stop.Cancel(); tcp.Stop(); await accepts; Environment.SetEnvironmentVariable("DDI_DISCOVERY_FIXTURE_SNMP", null); }
    }
    static async Task PreservationChecks(HttpClient client, DnsWebService service, IpamManager mgr, SnmpFixture snmp, int dnsPort,
        Func<HttpClient, string, (string Key, string Value)[], Task<JsonElement>> call, Func<Task<string>> revision,
        Func<IpamDiscoverySource, Task<JsonElement>> save, Func<string, bool, Task<JsonElement>> collect, Action<bool, string> check)
    {
        bool Ok(JsonElement r) => r.GetProperty("status").GetString() == "ok";
        var dhcp = (DnsServerCore.Dhcp.DhcpServer)typeof(DnsWebService).GetField("_dhcpServer", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        var log = (LogManager)typeof(DnsWebService).GetField("_log", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        var scope = new DnsServerCore.Dhcp.Scope("discovery-preservation", false, IPAddress.Parse("198.18.32.10"), IPAddress.Parse("198.18.32.30"), IPAddress.Parse("255.255.255.0"), log, dhcp) { DnsUpdates = false, PingCheckEnabled = false };
        await dhcp.AddScopeAsync(scope);
        check(Ok(await call(client, "zones/create", [("zone", "discovery.test"), ("type", "Primary")])), "native preservation DNS zone created");
        var inventory = (await call(client, "ipam/list", [])).GetProperty("response").GetProperty("inventory");
        string subnetId = inventory.GetProperty("subnets").EnumerateArray().Single(s => s.GetProperty("dhcpScope").GetString() == scope.Name).GetProperty("id").GetString();
        check(Ok(await call(client, "ipam/subnets/set", [("revision", await revision()), ("id", subnetId), ("name", "Discovery preservation"), ("prefix", "198.18.32.0/24"), ("dhcpScope", scope.Name), ("dnsZone", "discovery.test")])), "native preservation service links saved");
        check(Ok(await call(client, "ipam/assignments/set", [("revision", await revision()), ("subnetId", subnetId), ("address", "198.18.32.21"), ("hostName", "operator.discovery.test"), ("owner", "Original operator"), ("description", "Preserve this metadata")])), "operator assignment established before active collection");
        string operationId = Guid.NewGuid().ToString("N");
        var preview = await call(client, "ipam/provisioning/preview", [("revision", await revision()), ("operationId", operationId), ("subnetId", subnetId), ("address", "198.18.32.22"), ("hostName", "held.discovery.test"), ("hardwareAddress", "02-00-00-00-00-22")]);
        check(Ok(preview), "native provisioning preview predates active observation");
        string digest = preview.GetProperty("response").GetProperty("operation").GetProperty("digest").GetString();
        check(Ok(await call(client, "ipam/provisioning/approve", [("operationId", operationId), ("digest", digest)])), "native approved transaction hold established before discovery");
        var originalOperation = JsonSerializer.Serialize(mgr.ProvisioningResult(operationId), JsonOptions);
        var assignments = JsonSerializer.Serialize(mgr.Snapshot().Assignments, JsonOptions);
        var reservations = JsonSerializer.Serialize(scope.ReservedLeases.Select(l => l.Address.ToString()).ToArray());
        var candidate = new IpamDiscoverySource("", "Scoped device occupancy", "SnmpArp", subnetId, "127.0.0.1", snmp.Port, "DDI_DISCOVERY_FIXTURE_SNMP", "", "", 16, 1000, 60, "isolated-fixture-synthetic-ARP-only");
        var saved = await save(candidate); check(Ok(saved), "scoped independent device source saved");
        var source = saved.GetProperty("response").GetProperty("source").Deserialize<IpamDiscoverySource>(JsonOptions);
        snmp.ArpAddress = "198.18.32.20";
        check(Ok(await collect(source.Id, true)), "native device source collected unmanaged address in linked scope");
        var denied = await call(client, "ipam/provisioning/preview", [("revision", await revision()), ("operationId", Guid.NewGuid().ToString("N")), ("subnetId", subnetId), ("address", "198.18.32.20"), ("hostName", "occupied.discovery.test"), ("hardwareAddress", "02-00-00-00-00-20")]);
        check(!Ok(denied), "native provisioning refuses current active unmanaged occupancy");
        snmp.ArpAddress = "198.18.32.22"; await collect(source.Id, true);
        check(mgr.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.22")) && JsonSerializer.Serialize(mgr.ProvisioningResult(operationId), JsonOptions) == originalOperation, "collecting a held address preserves exact provisioning journal and hold");
        snmp.ArpAddress = "198.18.32.21"; await collect(source.Id, true);
        check(JsonSerializer.Serialize(mgr.Snapshot().Assignments, JsonOptions) == assignments, "device evidence does not replace operator identity or unrelated DDI assignments");
        check(JsonSerializer.Serialize(scope.ReservedLeases.Select(l => l.Address.ToString()).ToArray()) == reservations && service.DnsServer.AuthZoneManager.GetRecords("discovery.test", "held.discovery.test", DnsResourceRecordType.A).Count == 0, "active collection never writes native reservations or DNS configuration");
        snmp.Mode = "silent";
        var pending = collect(source.Id, true);
        for (int i = 0; i < 100 && mgr.ActiveDiscoveryIds().Length == 0; i++) await Task.Delay(10);
        service.DnsServer.AuthZoneManager.SetRecords("discovery.test", [new DnsResourceRecord("health.discovery.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("198.18.32.25")))]);
        using (var udp = new UdpClient(AddressFamily.InterNetwork))
        {
            var query = new DnsDatagram(21, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [new DnsQuestionRecord("health.discovery.test", DnsResourceRecordType.A, DnsClass.IN)]);
            using var wire = new MemoryStream(); query.WriteTo(wire); await udp.SendAsync(wire.ToArray(), new IPEndPoint(IPAddress.Loopback, dnsPort));
            using var timeout = new CancellationTokenSource(3000); var reply = await udp.ReceiveAsync(timeout.Token); var response = DnsDatagram.ReadFrom(new MemoryStream(reply.Buffer));
            check(response.RCODE == DnsResponseCode.NoError && response.Answer.Any(r => r.RDATA is DnsARecordData a && a.Address.ToString() == "198.18.32.25"), "actual DNS UDP resolution succeeds during collector stall");
        }
        byte[] discover = new byte[244]; discover[0] = 1; discover[1] = 1; discover[2] = 6; new byte[] { 2, 0, 0, 0, 0, 10 }.CopyTo(discover, 28); new byte[] { 99, 130, 83, 99, 53, 1, 1, 255 }.CopyTo(discover, 236);
        var message = new DnsServerCore.Dhcp.DhcpMessage(new MemoryStream(discover));
        var offerMethod = typeof(DnsServerCore.Dhcp.Scope).GetMethod("GetOfferAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        var offer = await (Task<DnsServerCore.Dhcp.Lease>)offerMethod.Invoke(scope, [message]);
        check(offer is not null && offer.Address.ToString() != "198.18.32.22", "actual native allocator remains responsive and respects held address during collector stall");
        var failed = await pending; check(failed.GetProperty("response").GetProperty("run").GetProperty("status").GetString() == "Failed", "native stalled source times out without changing service authority");
        check(mgr.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.22")), "source timeout retains transaction hold");
        check(Ok(await call(client, "ipam/provisioning/cancel", [("operationId", operationId)])), "only explicit authorized provisioning cancellation releases its unsubmitted hold");
        snmp.Mode = "normal"; snmp.ArpAddress = "127.0.0.2";
    }
    static async Task PermissionChecks(HttpClient original, DnsWebService service, AuthManager auth, IpamDiscoverySource source, IpamDiscoverySource tcp,
        Func<HttpClient, string, (string Key, string Value)[], Task<JsonElement>> call,
        Func<IpamDiscoverySource, Task<JsonElement>> save, Func<string, bool, Task<JsonElement>> collect, Action<bool, string> check, SnmpFixture fixture)
    {
        var everyone = auth.GetGroup(Group.EVERYONE);
        auth.SetPermission(PermissionSection.Settings, everyone, (PermissionFlag)0);
        auth.SetPermission(PermissionSection.Administration, everyone, (PermissionFlag)0);
        string password = Guid.NewGuid().ToString("N") + "Aa9!";
        var actor = auth.CreateUser("Discovery role fixture", "discovery-actor", password);
        var retained = new List<HttpClient>();
        bool Ok(JsonElement r) => r.GetProperty("status").GetString() == "ok";
        async Task<HttpClient> Fresh()
        {
            var c = new HttpClient { BaseAddress = original.BaseAddress }; retained.Add(c);
            var login = await call(c, "user/login", [("user", actor.Username), ("pass", password), ("includeInfo", "true")]); check(Ok(login), "fresh affected-role authentication");
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
            return c;
        }
        var full = PermissionFlag.View | PermissionFlag.Modify;
        try
        {
            foreach (var rights in new[] { (full, PermissionFlag.Modify), (PermissionFlag.Modify, full), (full, PermissionFlag.View), (PermissionFlag.View, full), (full, (PermissionFlag)0) })
            {
                auth.SetPermission(PermissionSection.Settings, actor, rights.Item1); auth.SetPermission(PermissionSection.Administration, actor, rights.Item2); auth.SaveConfigFile(true);
                var c = await Fresh(); int requests = fixture.Requests;
                foreach (var path in new[] { "run", "cancel", "sources/set", "sources/delete" })
                {
                    var denied = await call(c, "ipam/discovery/" + path, [("sourceId", source.Id), ("qualify", "true"), ("revision", "0"), ("source", JsonSerializer.Serialize(source, JsonOptions))]);
                    check(!Ok(denied) && !denied.TryGetProperty("response", out _), "effective view + modify required for " + path + " (" + rights + ")");
                }
                check(fixture.Requests == requests, "denied actor sent no SNMP request");
                if (!rights.Item1.HasFlag(PermissionFlag.View) || !rights.Item2.HasFlag(PermissionFlag.View)) check(!Ok(await call(c, "ipam/discovery/status", [])), "current view revocation hides discovery configuration/results");
                check(Ok(await call(original, "ipam/discovery/status", [])), "original administrative source session remains usable during role checks");
            }
            auth.SetPermission(PermissionSection.Settings, everyone, PermissionFlag.View); auth.SetPermission(PermissionSection.Administration, everyone, PermissionFlag.View);
            auth.SetPermission(PermissionSection.Settings, actor, PermissionFlag.Modify); auth.SetPermission(PermissionSection.Administration, actor, PermissionFlag.Modify); auth.SaveConfigFile(true);
            var split = await Fresh();
            check(Ok(await call(split, "ipam/discovery/status", [])), "group View and user Modify compose for discovery reads");
            fixture.Mode = "normal";
            check(Ok(await call(split, "ipam/discovery/run", [("sourceId", source.Id), ("qualify", "true")])), "group View and user Modify compose for collection actions");
            fixture.Mode = "silent";
            var pending = call(split, "ipam/discovery/run", [("sourceId", source.Id), ("qualify", "true")]);
            var mgr = (IpamManager)typeof(DnsWebService).GetField("_ipam", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            for (int i = 0; i < 100 && mgr.ActiveDiscoveryIds().Length == 0; i++) await Task.Delay(10);
            auth.SetPermission(PermissionSection.Administration, everyone, (PermissionFlag)0); auth.SaveConfigFile(true);
            var revoked = await Fresh(); check(!Ok(await call(revoked, "ipam/discovery/status", [])), "fresh actor sees current revoked source access");
            var late = await pending;
            check(!Ok(late) && !late.TryGetProperty("response", out _), "revocation during native I/O suppresses source result response");
            check(mgr.Snapshot().DiscoveryRuns.Single(r => r.SourceId == source.Id).Status == "Cancelled", "revoked in-flight run retains truthful cancelled last-known state");
            auth.SetPermission(PermissionSection.Settings, actor, full); auth.SetPermission(PermissionSection.Administration, actor, full); auth.SaveConfigFile(true);
            var restored = await Fresh(); fixture.Mode = "normal";
            check(Ok(await call(restored, "ipam/discovery/run", [("sourceId", source.Id), ("qualify", "true")])), "fresh restored actor performs original-scope collection");
            var inventory = await call(restored, "ipam/list", []);
            check(Ok(await call(restored, "ipam/views/set", [("revision", inventory.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64().ToString()), ("name", "Restored discovery role proof")])), "fresh restored actor has required administrative modification privileges");
            var loginInfo = auth.GetUser(actor.Username);
            check(loginInfo.RecentSessionRemoteAddress.Equals(IPAddress.Loopback), "target records fresh affected-role source as loopback");
            check(Ok(await call(original, "ipam/discovery/status", [])), "original admin retained after role restoration and outcome proof");
            // A Settings reader has no entitlement to private discovery, even after previously privileged actors used it.
            var reader = auth.CreateUser("Discovery reader fixture", "discovery-reader", password);
            auth.SetPermission(PermissionSection.Settings, reader, PermissionFlag.View);
            auth.SetPermission(PermissionSection.Administration, reader, (PermissionFlag)0); auth.SaveConfigFile(true);
            using var creader = new HttpClient { BaseAddress = original.BaseAddress };
            var readLogin = await call(creader, "user/login", [("user", reader.Username), ("pass", password)]); check(Ok(readLogin), "fresh reader authenticates after scoped grants");
            creader.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", readLogin.GetProperty("token").GetString());
            check(!Ok(await call(creader, "ipam/discovery/status", [])), "fresh Settings reader denied private source/results");
            var readInventory = await call(creader, "ipam/list", []);
            check(Ok(readInventory) && !readInventory.GetRawText().Contains("DDI_DISCOVERY_"), "Settings reader receives ordinary inventory without collector metadata");
            var actorProof = await Fresh();
            check(Ok(await call(actorProof, "ipam/discovery/status", [])) && Ok(await call(original, "ipam/discovery/status", [])), "fresh affected admin plus original retain discovery privileges before session cleanup");
            // UI fixture uses these disposable roles with the same private generated password.
            Environment.SetEnvironmentVariable("DDI_DISCOVERY_UI_ACTOR_PASSWORD", password);
        }
        finally { foreach (var c in retained) c.Dispose(); }
    }
    static async Task AzureChecks(IpamDiscoverySource source, Action<bool, string> check)
    {
        using var key = RSA.Create(2048);
        var certRequest = new CertificateRequest("CN=localhost", key, System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certRequest.CertificateExtensions.Add(san.Build());
        using var generated = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        int port = Port(); string mode = "normal"; int requests = 0, writes = 0; bool authSeen = false;
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port, l => l.UseHttps(cert)));
        await using var app = builder.Build();
        string path = IpamDiscoveryCollector.AzurePath(source);
        string Nic(string address = "127.0.0.3", string id = null) => JsonSerializer.Serialize(new { id = id ?? path + "/fixture-nic", properties = new { ipConfigurations = new[] { new { name = "primary", properties = new { privateIPAddress = address } } } } });
        app.Run(async context =>
        {
            requests++; if (context.Request.Method != "GET") writes++;
            authSeen |= context.Request.Headers.Authorization == "Bearer fixture-not-a-real-cloud-token";
            context.Response.ContentType = "application/json";
            if (mode == "unauthorized") { context.Response.StatusCode = 401; await context.Response.WriteAsync("{\"error\":\"fixture unauthorized\"}"); return; }
            if (mode == "redirect") { context.Response.StatusCode = 302; context.Response.Headers.Location = "https://outside.invalid/"; return; }
            if (mode == "slow") { try { await Task.Delay(2000, context.RequestAborted); } catch (OperationCanceledException) { } return; }
            if (mode == "malformed") { await context.Response.WriteAsync("{bad json"); return; }
            if (mode == "oversized") { await context.Response.WriteAsync(new string('x', 1024 * 1024 + 1)); return; }
            if (mode == "empty") { await context.Response.WriteAsync("{\"value\":[]}"); return; }
            if (mode == "missing") { await context.Response.WriteAsync("{}"); return; }
            if (mode == "outside-object") { await context.Response.WriteAsync("{\"value\":[" + Nic(id: path.Replace("fixture-group", "outside-group") + "/nic") + "]}"); return; }
            if (mode == "duplicate") { await context.Response.WriteAsync("{\"value\":[" + Nic() + "," + Nic() + "]}"); return; }
            if (mode == "limit") { await context.Response.WriteAsync("{\"value\":[" + string.Join(',', Enumerable.Range(0, source.MaxResults + 1).Select(i => Nic(id: path + "/nic" + i))) + "]}"); return; }
            if (mode == "outside-page" || mode == "cycle")
            { await context.Response.WriteAsync("{\"value\":[" + Nic() + "],\"nextLink\":\"" + (mode == "outside-page" ? "https://outside.invalid/stolen" : "https://management.azure.com" + path + "?api-version=2024-07-01") + "\"}"); return; }
            if (mode == "pages" && !context.Request.Query.ContainsKey("skip"))
            { await context.Response.WriteAsync("{\"value\":[" + Nic() + "],\"nextLink\":\"https://management.azure.com" + path + "?api-version=2024-07-01&skip=2\"}"); return; }
            await context.Response.WriteAsync("{\"value\":[" + Nic(address: mode == "pages" ? "127.0.0.4" : "127.0.0.3", id: mode == "pages" ? path + "/fixture-nic-2" : null) + "]}");
        });
        await app.StartAsync();
        using var transport = new AzureTransport(new Uri("https://127.0.0.1:" + port), cert);
        using var http = new HttpClient(transport) { Timeout = Timeout.InfiniteTimeSpan };
        async Task<IpamDiscoveryEvidence[]> Collect() => await IpamDiscoveryCollector.Azure(source, new IpamNetwork("127.0.0.0/24"), "fixture-not-a-real-cloud-token", http, CancellationToken.None);
        var good = await Collect(); check(good.Length == 1 && good[0].Address == "127.0.0.3" && good[0].Confidence == "ProviderReported", "actual loopback TLS Azure-shaped inventory read returns provider configuration evidence");
        check(authSeen && writes == 0, "native TLS fixture sees read token with GET only");
        mode = "pages"; check((await Collect()).Length == 2, "same-scope native HTTPS pagination completes");
        foreach (string failure in new[] { "unauthorized", "redirect", "malformed", "oversized", "missing", "outside-object", "duplicate", "limit", "outside-page", "cycle", "slow" })
        {
            mode = failure; int before = requests; bool denied = false;
            try { await Collect(); } catch (Exception ex) when (ex is IpamDiscoveryLimitException || ex is InvalidDataException || ex is IOException || ex is HttpRequestException || ex is JsonException || ex is OperationCanceledException) { denied = true; }
            check(denied, "actual TLS Azure " + failure + " rejects an incomplete/untrusted snapshot");
            if (failure == "outside-page" || failure == "redirect" || failure == "cycle") check(requests == before + 1, "Azure " + failure + " sends no second target request");
        }
        mode = "empty"; check((await Collect()).Length == 0, "valid provider value array distinguishes an explicit empty inventory from missing/error");
        check(transport.Requests.All(r => r.StartsWith("GET https://management.azure.com" + path, StringComparison.OrdinalIgnoreCase)) && writes == 0, "all Azure requests retain selected subscription/resource-group path and GET method");
        await app.StopAsync();
    }
}

