// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class FeedNativeBoundaryChecks
{
    static readonly BindingFlags Flags = BindingFlags.Instance | BindingFlags.NonPublic;
    static T Field<T>(object o, string name) => (T)o.GetType().GetField(name, Flags).GetValue(o);
    static void Set(object o, string name, object value) => o.GetType().GetField(name, Flags).SetValue(o, value);
    static int Port() { using var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start(); return ((IPEndPoint)socket.LocalEndpoint).Port; }
    static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, DdiSecurityManager.JsonOptions))).ToLowerInvariant();
    static HttpClient Pinned(string pin) => new(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.GetCertHashString(HashAlgorithmName.SHA256) == pin });

    // A complete native service, isolated from production. Parent owns all stdin commands and ports.
    public static async Task Child(string folder)
    {
        string feedUrl = Environment.GetEnvironmentVariable("FEED_BOUNDARY_URL"), pin = Environment.GetEnvironmentVariable("FEED_BOUNDARY_PIN");
        int dnsPort = int.Parse(Environment.GetEnvironmentVariable("FEED_BOUNDARY_DNS_PORT"));
        Directory.CreateDirectory(Path.Combine(folder, "scopes"));
        await using (var log = new LogManager(true, folder))
        using (var dns = new DnsServer(folder, Path.Combine(AppContext.BaseDirectory, "dohwww"), log))
        { dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback, dnsPort)]; dns.Recursion = DnsServerRecursion.Deny; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
        await using var service = new DnsWebService(true, folder);
        var security = Field<DdiSecurityManager>(service, "_security");
        Field<HttpClient>(security, "_mispClient").Dispose(); Set(security, "_mispClient", Pinned(pin));
        var requestScope = new AsyncLocal<bool>(); DateTime manualNow = DateTime.UtcNow; bool pause = false;
        using var release = new ManualResetEventSlim();
        Set(security, "_feedClock", (Func<DateTime>)(() => requestScope.Value ? manualNow : DateTime.UtcNow));
        Set(security, "_feedCheckpoint", (Action<string>)(phase =>
        {
            if (phase == "Activated" && pause && requestScope.Value)
            {
                var health = security.EdlStatus()[0];
                Console.WriteLine("COMMITTED " + JsonSerializer.Serialize(new { health.AttemptId, health.SnapshotGeneration, revision = security.EdlRevision }));
                if (!release.Wait(TimeSpan.FromSeconds(15))) throw new Exception("Owned post-commit release timed out");
            }
        }));
        await service.StartAsync(true);
        if (service.DnsServer.AuthZoneManager.GetAuthZoneInfo("boundary.test") is null)
        {
            service.DnsServer.AuthZoneManager.CreatePrimaryZone("boundary.test");
            service.DnsServer.AuthZoneManager.SetRecord("boundary.test", new DnsResourceRecord("answer.boundary.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.71"))));
            service.DnsServer.AuthZoneManager.SaveZoneFile("boundary.test");
        }
        if (security.Policy.Revision == 0)
            security.SetPolicy(SecurityPolicy.Default with { Enabled = true, InspectAuthoritative = true, EdlFeeds = [new("native", "Domain", feedUrl, true, RefreshSeconds: 60)] }, 0);
        using var rsa = RSA.Create(2048); var certRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certRequest.CertificateExtensions.Add(san.Build());
        using var generated = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(cert)));
        await using var bridge = builder.Build();
        bridge.UseExceptionHandler(app => typeof(DnsWebService).GetMethod("WebServiceExceptionHandler", Flags).Invoke(service, [app]));
        bridge.MapPost("/api/security/feeds/refresh", async ctx =>
        {
            requestScope.Value = true;
            using var disconnected = ctx.RequestAborted.Register(() => Console.WriteLine("DISCONNECTED"));
            try
            {
                object api = Field<object>(service, "_securityApi");
                RequestDelegate endpoint = c => (Task)api.GetType().GetMethod("RefreshFeed").Invoke(api, [c]);
                RequestDelegate middleware = c => (Task)typeof(DnsWebService).GetMethod("WebServiceApiMiddleware", Flags).Invoke(service, [c, endpoint]);
                await (Task)typeof(DnsWebService).GetMethod("WebServiceDirectTransportMiddleware", Flags).Invoke(service, [ctx, middleware]);
            }
            finally { requestScope.Value = false; }
        });
        await bridge.StartAsync(); byte[] heldCache = null; string cache = Path.Combine(folder, "security-edl.json");
        Console.WriteLine("READY " + JsonSerializer.Serialize(new { pid = Environment.ProcessId, bridge = bridge.Urls.Single(), bridgePin = cert.GetCertHashString(HashAlgorithmName.SHA256) }));
        while (true)
        {
            string command = await Console.In.ReadLineAsync();
            switch (command)
            {
                case "arm": manualNow = security.EdlStatus()[0].NextAttempt.Value; pause = true; Console.WriteLine("ARMED"); break;
                case "release": pause = false; release.Set(); Console.WriteLine("RELEASED"); break;
                case "block-cache": heldCache = File.ReadAllBytes(cache); File.Delete(cache); Directory.CreateDirectory(cache); Console.WriteLine("CACHE-BLOCKED"); break;
                case "restore-cache": Directory.Delete(cache); File.WriteAllBytes(cache, heldCache); heldCache = null; Console.WriteLine("CACHE-RESTORED"); break;
                case "disk": Console.WriteLine("DISK " + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(cache))).ToLowerInvariant()); break;
                case "exit": Console.WriteLine("EXITING " + Environment.ProcessId); Console.Out.Flush(); Environment.Exit(73); return;
                case null: return;
                default: throw new Exception("Unknown owned child command");
            }
        }
    }

    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "feed-native-boundary-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
        int http = Port(), dns = Port(), checks = 0, calls = 0;
        string password = Guid.NewGuid().ToString("N") + "Aa!9";
        Process child = null; var children = new List<int>();
        void Check(bool okay, string why) { if (!okay) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
        async Task<string> Line(string prefix)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (true)
            {
                string line = await child.StandardOutput.ReadLineAsync(timeout.Token);
                if (line is null) throw new Exception("Native child ended before " + prefix + ": " + await child.StandardError.ReadToEndAsync());
                if (line.StartsWith(prefix, StringComparison.Ordinal)) return line[prefix.Length..];
                Console.WriteLine("Child observation: " + line);
            }
        }
        async Task Command(string command, string response) { await child.StandardInput.WriteLineAsync(command); await child.StandardInput.FlushAsync(); await Line(response); }
        using var rsa = RSA.Create(2048); var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); req.CertificateExtensions.Add(san.Build());
        using var generated = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(cert)));
        await using var provider = builder.Build();
        provider.MapGet("/feed", async ctx => { Interlocked.Increment(ref calls); ctx.Response.ContentType = "text/plain"; await ctx.Response.WriteAsync("answer.boundary.test\n"); });
        string[] BulkValues(int source, string marker) => Enumerable.Range(source * 2000, 2000)
            .Select(i => "https://item" + i.ToString("D5") + ".fixture.test/" + marker + new string('x', 770)).Order(StringComparer.Ordinal).ToArray();
        provider.MapGet("/bulk/{id}", async ctx =>
        {
            Interlocked.Increment(ref calls); ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync(string.Join('\n', BulkValues(int.Parse(ctx.Request.RouteValues["id"].ToString()), "a")) + "\n");
        });
        await provider.StartAsync();
        using var admin = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + http), Timeout = TimeSpan.FromSeconds(30) };
        async Task<JsonElement> Call(HttpClient client, string path, params (string, string)[] values)
        {
            using var content = new FormUrlEncodedContent(values.Select(v => new KeyValuePair<string, string>(v.Item1, v.Item2)));
            using var response = await client.PostAsync(path, content); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
        }
        async Task Login(HttpClient client)
        { var r = await Call(client, "/api/user/login", ("user", "admin"), ("pass", password)); Check(r.GetProperty("status").GetString() == "ok", "fresh native process authentication from loopback"); client.DefaultRequestHeaders.Authorization = new("Bearer", r.GetProperty("token").GetString()); }
        async Task<JsonElement> Read() => (await Call(admin, "/api/security/policy/get")).GetProperty("response");
        async Task<JsonElement> Terminal()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (true) { var r = await Read(); var h = r.GetProperty("edlHealth")[0]; if (h.GetProperty("attemptOutcome").GetString() == "Succeeded" && h.GetProperty("attemptCompletedAt").ValueKind == JsonValueKind.String) return r; await Task.Delay(30, timeout.Token); }
        }
        async Task Answer()
        {
            using var socket = new UdpClient(); socket.Connect(IPAddress.Loopback, dns);
            var query = new DnsDatagram(9, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("answer.boundary.test", DnsResourceRecordType.A, DnsClass.IN)]);
            using var bytes = new MemoryStream(); query.WriteTo(bytes); await socket.SendAsync(bytes.ToArray()); var packet = await socket.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5)); using var wire = new MemoryStream(packet.Buffer); var response = DnsDatagram.ReadFrom(wire);
            Check(response.RCODE == DnsResponseCode.NoError && response.Answer.Count == 1 && ((DnsARecordData)response.Answer[0].RDATA).Address.Equals(IPAddress.Parse("192.0.2.71")), "real authoritative synthetic answer remains unchanged");
        }
        async Task<JsonElement> Start()
        {
            var info = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            info.ArgumentList.Add(typeof(FeedNativeBoundaryChecks).Assembly.Location); info.ArgumentList.Add("--feed-service-child"); info.ArgumentList.Add(folder);
            info.Environment["DNS_SERVER_ADMIN_PASSWORD"] = password; info.Environment["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] = "127.0.0.1"; info.Environment["DNS_SERVER_WEB_SERVICE_HTTP_PORT"] = http.ToString();
            info.Environment["FEED_BOUNDARY_DNS_PORT"] = dns.ToString(); info.Environment["FEED_BOUNDARY_URL"] = provider.Urls.Single() + "/feed"; info.Environment["FEED_BOUNDARY_PIN"] = cert.GetCertHashString(HashAlgorithmName.SHA256);
            child = Process.Start(info); children.Add(child.Id); string ready = await Line("READY "); using var json = JsonDocument.Parse(ready); return json.RootElement.Clone();
        }
        async Task Exit()
        {
            int pid = child.Id; await Command("exit", "EXITING "); await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); Check(child.ExitCode == 73, "complete native OS process exited with owned code73 PID=" + pid); child.Dispose(); child = null;
        }
        async Task ModifyCurrent(JsonElement read)
        {
            var p = read.GetProperty("policy"); var r = await Call(admin, "/api/security/policy/set", ("policy", p.GetRawText()), ("revision", p.GetProperty("revision").GetInt64().ToString())); Check(r.GetProperty("status").GetString() == "ok", "fresh native administrative session has required modify privilege");
        }
        try
        {
            await Start(); await Login(admin); var first = await Terminal(); await Answer();
            string firstId = first.GetProperty("edlHealth")[0].GetProperty("attemptId").GetString(), firstGeneration = first.GetProperty("edlHealth")[0].GetProperty("snapshotGeneration").GetString();
            string due = first.GetProperty("edlHealth")[0].GetProperty("nextAttempt").GetString(); int before = calls; Check(before == 1, "first native process automatically fetched once");
            await Exit(); var secondReady = await Start();
            using var fresh = new HttpClient { BaseAddress = admin.BaseAddress }; await Login(fresh); admin.DefaultRequestHeaders.Authorization = fresh.DefaultRequestHeaders.Authorization;
            var cold = await Terminal();
            Check(cold.GetProperty("edlHealth")[0].GetProperty("attemptId").GetString() == firstId && cold.GetProperty("edlHealth")[0].GetProperty("snapshotGeneration").GetString() == firstGeneration && cold.GetProperty("edlHealth")[0].GetProperty("nextAttempt").GetString() == due && calls == before, "SEPARATE native process cold-loads exact attempt/generation/due without duplicate fetch");
            await ModifyCurrent(cold); await Answer();
            var events = await Call(admin, "/api/security/events/list");
            Check(events.GetProperty("response").GetProperty("events").EnumerateArray().Any(e => e.GetProperty("query").GetString() == "answer.boundary.test" && e.GetProperty("action").GetString() == "Monitor"), "separate native process consumes Monitor evidence on real DNS socket");
            var preLost = await Read(); await Command("arm", "ARMED");
            using var lostClient = Pinned(secondReady.GetProperty("bridgePin").GetString()); lostClient.DefaultRequestHeaders.Authorization = admin.DefaultRequestHeaders.Authorization;
            using var cancel = new CancellationTokenSource();
            using var refreshBody = new FormUrlEncodedContent(new Dictionary<string, string> { ["feedId"] = "native", ["revision"] = preLost.GetProperty("policy").GetProperty("revision").GetInt64().ToString(), ["snapshotRevision"] = preLost.GetProperty("snapshotRevision").GetString() });
            Task<HttpResponseMessage> lost = lostClient.PostAsync(secondReady.GetProperty("bridge").GetString() + "/api/security/feeds/refresh", refreshBody, cancel.Token);
            string committed = await Line("COMMITTED "); using var committedJson = JsonDocument.Parse(committed); cancel.Cancel();
            bool disconnected = false; try { using var ignored = await lost; } catch (OperationCanceledException) { disconnected = true; }
            await Line("DISCONNECTED"); Check(disconnected, "actual HTTP connection disconnected AFTER native snapshot commit before response"); await Command("release", "RELEASED");
            var afterLost = await Terminal(); var h = afterLost.GetProperty("edlHealth")[0];
            string lostId = h.GetProperty("attemptId").GetString(), lostGeneration = h.GetProperty("snapshotGeneration").GetString(), lostRevision = afterLost.GetProperty("snapshotRevision").GetString();
            Check(lostId == committedJson.RootElement.GetProperty("AttemptId").GetString() && lostGeneration == committedJson.RootElement.GetProperty("SnapshotGeneration").GetString() && lostRevision == committedJson.RootElement.GetProperty("revision").GetString() && h.GetProperty("attemptOutcome").GetString() == "Succeeded", "lost response readback reconciles same committed attempt/generation as Succeeded, never Cancelled");
            var stale = await Call(admin, "/api/security/feeds/refresh", ("feedId", "native"), ("revision", preLost.GetProperty("policy").GetProperty("revision").GetInt64().ToString()), ("snapshotRevision", preLost.GetProperty("snapshotRevision").GetString()));
            Check(stale.GetProperty("status").GetString() == "error", "lost-reply retry with old snapshot token reports stale state");
            var retry = await Call(admin, "/api/security/feeds/refresh", ("feedId", "native"), ("revision", afterLost.GetProperty("policy").GetProperty("revision").GetInt64().ToString()), ("snapshotRevision", lostRevision));
            Check(retry.GetProperty("status").GetString() == "ok" && retry.GetProperty("response").GetProperty("attempt").GetProperty("attemptId").GetString() == lostId && calls == before + 1, "actual retry using readback preserves same successful attempt without refetch before due"); await Answer();
            await Exit(); await Start(); await Login(admin); var third = await Terminal();
            Check(third.GetProperty("edlHealth")[0].GetProperty("attemptId").GetString() == lostId && third.GetProperty("snapshotRevision").GetString() == lostRevision && calls == before + 1, "third complete native process preserves lost-reply committed receipt and nonoverlap reservation"); await ModifyCurrent(third); await Answer();
            var bulkFeeds = Enumerable.Range(0, 4).Select(i => new EdlFeed("bulk" + i, "Url", provider.Urls.Single() + "/bulk/" + i, false)).ToArray();
            var policy = JsonSerializer.Deserialize<SecurityPolicy>((await Read()).GetProperty("policy"), DdiSecurityManager.JsonOptions) with { EdlFeeds = bulkFeeds };
            Check((await Call(admin, "/api/security/policy/set", ("policy", JsonSerializer.Serialize(policy, DdiSecurityManager.JsonOptions)), ("revision", policy.Revision.ToString()))).GetProperty("status").GetString() == "ok", "native current rights configure explicit bulk backup source");
            byte[] Payload(string marker)
            {
                DateTime now = DateTime.UtcNow;
                var snapshots = bulkFeeds.Select((bulkFeed, i) =>
                {
                    var values = BulkValues(i, marker);
                    if (Encoding.UTF8.GetByteCount(string.Join('\n', values) + "\n") > 2 * 1024 * 1024) throw new Exception("Owned bulk source exceeds per-feed response bound");
                    var snapshot = new EdlSnapshot(bulkFeed.Id, bulkFeed.Kind, bulkFeed.Url, now, now.AddHours(24), values)
                    { CommitId = Guid.NewGuid().ToString("N"), SourceConfiguration = Hash(new { bulkFeed.Id, bulkFeed.Kind, bulkFeed.Url, bulkFeed.Format, bulkFeed.RpzZone, bulkFeed.ApiKeyEnvironment, bulkFeed.AuthScheme }), Provenance = "Owned synthetic large validated-backup fixture", ValidatedAt = now };
                    return snapshot with { ContentSha256 = Hash(new { snapshot.FeedId, snapshot.Kind, snapshot.SourceUrl, snapshot.FetchedAt, snapshot.Expires, snapshot.Values, snapshot.Format, snapshot.RpzZone, snapshot.SourceConfiguration, snapshot.Provenance, snapshot.ValidatedAt }) };
                }).ToArray();
                return JsonSerializer.SerializeToUtf8Bytes(snapshots, DdiSecurityManager.JsonOptions);
            }
            async Task<JsonElement> Rollback(byte[] bytes, JsonElement read)
            {
                using var body = new ByteArrayContent(bytes); body.Headers.ContentType = new("application/json");
                using var response = await admin.PostAsync("/api/security/feeds/rollback?revision=" + read.GetProperty("policy").GetProperty("revision").GetInt64() + "&snapshotRevision=" + read.GetProperty("snapshotRevision").GetString(), body);
                using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return result.RootElement.Clone();
            }
            byte[] bulk = Payload("a"); Check(bulk.Length > 4 * 1024 * 1024 && bulk.Length < 16 * 1024 * 1024, "raw JSON payload exceeds ordinary 4MiB form capacity and remains below 16MiB");
            Console.WriteLine("RAW-JSON-LENGTH " + bulk.Length);
            Check((await Rollback(bulk, await Read())).GetProperty("status").GetString() == "ok", "real native raw JSON rollback above form capacity commits");
            var bulkState = await Read(); string bulkRevision = bulkState.GetProperty("snapshotRevision").GetString();
            Check(bulkState.GetProperty("edlHealth").EnumerateArray().Sum(h => h.GetProperty("retainedEntries").GetInt32()) == 8000 && bulkState.GetProperty("edlHealth").EnumerateArray().All(h => h.GetProperty("integrityState").GetString() == "VerifiedSha256"), "native large snapshot readback has exact entry count and verified integrity");
            await child.StandardInput.WriteLineAsync("disk"); await child.StandardInput.FlushAsync(); Check(await Line("DISK ") == bulkRevision, "native persisted large snapshot SHA256 matches current generation revision");
            byte[] over = Enumerable.Repeat((byte)' ', 16 * 1024 * 1024 + 1).ToArray(); var overResult = await Rollback(over, bulkState);
            Check(overResult.GetProperty("status").GetString() == "error" && overResult.GetProperty("errorMessage").GetString().Contains("exceeds 16 MiB") && (await Read()).GetProperty("snapshotRevision").GetString() == bulkRevision, "ordinary raw JSON overlimit refuses exact 16777217 bytes without generation change");
            await Command("block-cache", "CACHE-BLOCKED");
            try { Check((await Rollback(Payload("b"), await Read())).GetProperty("status").GetString() == "error" && (await Read()).GetProperty("snapshotRevision").GetString() == bulkRevision, "owned unavailable destination keeps native large current generation on write failure"); }
            finally { await Command("restore-cache", "CACHE-RESTORED"); }
            await child.StandardInput.WriteLineAsync("disk"); await child.StandardInput.FlushAsync(); Check(await Line("DISK ") == bulkRevision, "failed native write retains exact persisted complete large snapshot"); await Answer();
            await Exit(); await Start(); await Login(admin); var largeCold = await Read();
            Check(largeCold.GetProperty("snapshotRevision").GetString() == bulkRevision && largeCold.GetProperty("edlHealth").EnumerateArray().Sum(h => h.GetProperty("retainedEntries").GetInt32()) == 8000 && calls == before + 1, "separate complete native process cold-validates large persisted snapshot without feed activation"); await Answer(); await Exit();
            Console.WriteLine($"PASS: {checks} full native process/lost HTTP reply/large raw rollback boundary checks. ParentPID={Environment.ProcessId}; children={string.Join(',', children)}; HTTP={http}; DNS={dns}; TLS={new Uri(provider.Urls.Single()).Port}; config={folder}; nativeRAWJSONBytes={bulk.Length}; overlimitBytes={over.Length}; bulkSources=4x2000URLs, each source text under2MiB. No production target or external recursion. Lost-reply API alone uses explicit clock seam to reach the retained due time; real HTTP transport and native handler remain in use.");
        }
        finally
        {
            if (child is not null)
            {
                if (!child.HasExited) { await child.StandardInput.WriteLineAsync("release"); await child.StandardInput.WriteLineAsync("exit"); await child.StandardInput.FlushAsync(); await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
                Console.WriteLine("Owned remaining native child exit=" + child.ExitCode); child.Dispose();
            }
            await provider.StopAsync();
            string path = Path.GetFullPath(folder); if (!path.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(path).StartsWith("feed-native-boundary-")) throw new Exception("Unexpected native boundary cleanup path");
            if (Directory.Exists(path)) Directory.Delete(path, true); Console.WriteLine("Owned native boundary config removed=" + !Directory.Exists(path));
        }
    }
}
