// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class FeedNativeChecks
{
    static int Port() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
    static T Field<T>(object value, string name) => (T)value.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(value);
    static async Task Until(Func<bool> ready) { using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); while (!ready()) await Task.Delay(25, timeout.Token); }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "feed-native-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder); Directory.CreateDirectory(Path.Combine(folder, "scopes"));
        int httpPort = Port(), dnsPort = Port(), checks = 0, calls = 0;
        string password = Guid.NewGuid().ToString("N") + "Aa!9", restrictedPassword = Guid.NewGuid().ToString("N") + "Bb!9";
        var env = new Dictionary<string, string> { ["DNS_SERVER_ADMIN_PASSWORD"] = password, ["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] = "127.0.0.1", ["DNS_SERVER_WEB_SERVICE_HTTP_PORT"] = httpPort.ToString() };
        var oldEnv = env.Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable); foreach (var e in env) Environment.SetEnvironmentVariable(e.Key, e.Value);
        void Check(bool okay, string why) { if (!okay) throw new Exception(why); checks++; }
        using var rsa = RSA.Create(2048); var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); req.CertificateExtensions.Add(san.Build());
        using var generated = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
        await using var feedServer = builder.Build();
        string text = "answer.feed.test\n"; int status = 200; TaskCompletionSource entered = null, release = null;
        feedServer.MapGet("/feed", async ctx => { Interlocked.Increment(ref calls); entered?.TrySetResult(); if (release is not null) await release.Task.WaitAsync(ctx.RequestAborted); ctx.Response.StatusCode = status; ctx.Response.ContentType = "text/plain"; await ctx.Response.WriteAsync(text); });
        DnsWebService activeService = null;
        feedServer.MapGet("/api/security/edl/export", async ctx =>
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            object api = Field<object>(activeService, "_securityApi");
            RequestDelegate endpoint = c => (Task)api.GetType().GetMethod("ExportEdl").Invoke(api, [c]);
            RequestDelegate middleware = c => (Task)typeof(DnsWebService).GetMethod("WebServiceApiMiddleware", flags).Invoke(activeService, [c, endpoint]);
            await (Task)typeof(DnsWebService).GetMethod("WebServiceDirectTransportMiddleware", flags).Invoke(activeService, [ctx, middleware]);
        });
        await feedServer.StartAsync();
        HttpClient FeedClient() => new(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, remote, _, _) => remote?.GetCertHashString(HashAlgorithmName.SHA256) == certificate.GetCertHashString(HashAlgorithmName.SHA256) });
        using var original = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + httpPort) };
        async Task<JsonElement> Call(HttpClient client, string path, params (string, string)[] values)
        {
            using var content = new FormUrlEncodedContent(values.Select(p => new KeyValuePair<string, string>(p.Item1, p.Item2)));
            using var response = await client.PostAsync(path, content); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
        }
        async Task Login(HttpClient client, string user, string secret)
        { var result = await Call(client, "/api/user/login", ("user", user), ("pass", secret)); Check(result.GetProperty("status").GetString() == "ok", "Native login failed"); client.DefaultRequestHeaders.Authorization = new("Bearer", result.GetProperty("token").GetString()); }
        string Json(object o) => JsonSerializer.Serialize(o, DdiSecurityManager.JsonOptions);
        try
        {
            await using (var log = new LogManager(true, folder))
            using (var dns = new DnsServer(folder, Path.Combine(AppContext.BaseDirectory, "dohwww"), log))
            { dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback, dnsPort)]; dns.Recursion = DnsServerRecursion.Deny; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
            DnsWebService service = null;
            try
            {
                service = new DnsWebService(true, folder); activeService = service; var security = Field<DdiSecurityManager>(service, "_security");
                Field<HttpClient>(security, "_mispClient").Dispose(); typeof(DdiSecurityManager).GetField("_mispClient", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(security, FeedClient());
                await service.StartAsync(true);
                var zone = service.DnsServer.AuthZoneManager.CreatePrimaryZone("feed.test");
                service.DnsServer.AuthZoneManager.SetRecord("feed.test", new DnsResourceRecord("answer.feed.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.42"))));
                service.DnsServer.AuthZoneManager.SaveZoneFile("feed.test");
                async Task Answer()
                {
                    using var socket = new UdpClient(); socket.Connect(IPAddress.Loopback, dnsPort);
                    var query = new DnsDatagram(7, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("answer.feed.test", DnsResourceRecordType.A, DnsClass.IN)]);
                    using var wire = new MemoryStream(); query.WriteTo(wire); await socket.SendAsync(wire.ToArray());
                    var packet = await socket.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5)); using var input = new MemoryStream(packet.Buffer); var answer = DnsDatagram.ReadFrom(input);
                    Check(answer.RCODE == DnsResponseCode.NoError && answer.Answer.Count == 1 && ((DnsARecordData)answer.Answer[0].RDATA).Address.Equals(IPAddress.Parse("192.0.2.42")), "Synthetic authoritative Monitor answer changed");
                }
                await Answer();
                Check((await Call(original, "/api/security/feeds/refresh")).GetProperty("status").GetString() == "invalid-token", "Unauthenticated native refresh accepted");
                await Login(original, "admin", password);
                var auth = Field<AuthManager>(service, "_authManager");
                var reader = auth.CreateUser("Feed fixture", "feed-fixture", restrictedPassword); reader.SyncGroups(new Dictionary<string, Group> { ["dns administrators"] = auth.GetGroup("DNS Administrators") });
                using var restricted = new HttpClient { BaseAddress = original.BaseAddress }; await Login(restricted, "feed-fixture", restrictedPassword);
                using var fresh = new HttpClient { BaseAddress = original.BaseAddress }; await Login(fresh, "admin", password);
                Check(auth.GetSession(fresh.DefaultRequestHeaders.Authorization.Parameter).LastSeenRemoteAddress.Equals(IPAddress.Loopback), "Fresh fixture session source is not loopback");
                var feed = new EdlFeed("native", "Domain", feedServer.Urls.Single() + "/feed", true, RefreshSeconds: 60);
                var policy = security.Policy with { Enabled = true, InspectAuthoritative = true, EdlFeeds = [feed] };
                Check((await Call(fresh, "/api/security/policy/set", ("policy", Json(policy)), ("revision", security.Policy.Revision.ToString()))).GetProperty("status").GetString() == "ok", "Fresh fixture administrator cannot configure feed");
                await Until(() => security.EdlStatus()[0].AttemptOutcome == "Succeeded");
                Check(calls == 1 && security.EdlStatus()[0].Entries == 1, "Real native scheduled worker did not fetch once");
                byte[] first = security.ExportEdl(); string initialAttempt = security.EdlStatus()[0].AttemptId;
                // Committed success may precede the separate terminal schedule write. Wait
                // for this exact attempt/timestamp on disk; retain the assertion of persistence.
                bool MatchingTerminalPersisted()
                {
                    var health = security.EdlStatus()[0];
                    if (health.AttemptId != initialAttempt || health.AttemptOutcome != "Succeeded" || !health.AttemptCompletedAt.HasValue) return false;
                    using var stream = new FileStream(Path.Combine(folder, "security-feed-schedule.json"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var terminal = JsonDocument.Parse(stream);
                    var record = terminal.RootElement.GetProperty("native");
                    return record.GetProperty("attemptId").GetString() == initialAttempt && record.GetProperty("outcome").GetString() == "Succeeded" &&
                        record.GetProperty("completedAt").GetDateTime() == health.AttemptCompletedAt.Value;
                }
                await Until(MatchingTerminalPersisted);
                Check(MatchingTerminalPersisted(), "Matching terminal scheduled attempt and completion timestamp not persisted");
                await Answer(); await Until(() => security.RecentEvents().Any(e => e.Query == "answer.feed.test" && e.Action == "Monitor" && e.Matches.Any(i => i.Source == "EDL:native")));
                Check(security.Policy.Mode == "Monitor" && security.Policy.DeviceDnsResponse == "Monitor" && security.Policy.DhcpResponse == "Observe" && Field<DnsServerCore.Dhcp.DhcpServer>(service, "_dhcpServer").Scopes.Count == 0, "Native fixture modes or DHCP changed");
                string revision = security.Policy.Revision.ToString(), snapshotRevision = security.EdlRevision;
                var args = new[] { ("feedId", "native"), ("revision", revision), ("snapshotRevision", snapshotRevision) };
                var duplicate = await Call(original, "/api/security/feeds/refresh", args);
                Check(duplicate.GetProperty("status").GetString() == "ok" && duplicate.GetProperty("response").GetProperty("attempt").GetProperty("attemptId").GetString() == initialAttempt && calls == 1, "Native duplicate request changed durable attempt");
                Check((await Call(restricted, "/api/security/feeds/refresh", args)).GetProperty("status").GetString() == "error", "Settings-only user refreshed feed");
                Check((await Call(restricted, "/api/security/feeds/rollback", ("snapshot", Encoding.UTF8.GetString(first)), ("revision", revision), ("snapshotRevision", snapshotRevision))).GetProperty("status").GetString() == "error", "Settings-only rollback accepted");
                Check((await Call(original, "/api/security/feeds/attempt", ("attemptId", "missing"))).GetProperty("status").GetString() == "error", "Missing attempt was invented");
                Check((await Call(original, "/api/security/feeds/refresh", ("feedId", "native"), ("revision", "0"), ("snapshotRevision", snapshotRevision))).GetProperty("status").GetString() == "error", "Stale native revision accepted");
                Check((await Call(original, "/api/security/feeds/attempt", ("attemptId", initialAttempt))).GetProperty("response").GetProperty("attempt").GetProperty("attemptOutcome").GetString() == "Succeeded", "Native attempt readback failed");
                // A configuration change makes a new due schedule. Hold the native scheduled fetch for concurrent API/cancel/DNS checks.
                entered = new(TaskCreationOptions.RunContinuationsAsynchronously); release = new(TaskCreationOptions.RunContinuationsAsynchronously);
                security.SetPolicy(security.Policy with { EdlFeeds = [feed with { Provenance = "Second owned fixture generation" }] }, security.Policy.Revision);
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)); string running = security.EdlStatus()[0].AttemptId; await Answer();
                int before = calls;
                duplicate = await Call(original, "/api/security/feeds/refresh", ("feedId", "native"), ("revision", security.Policy.Revision.ToString()), ("snapshotRevision", security.EdlRevision));
                Check(calls == before && duplicate.GetProperty("response").GetProperty("attempt").GetProperty("attemptId").GetString() == running, "Manual/scheduled race duplicated fetch");
                Check((await Call(original, "/api/security/feeds/cancel", ("attemptId", running))).GetProperty("status").GetString() == "ok", "Native cancel rejected");
                await Until(() => security.EdlStatus()[0].AttemptOutcome == "Cancelled");
                Check(first.SequenceEqual(security.ExportEdl()), "Cancelled native attempt changed durable snapshot"); release.TrySetResult(); entered = release = null; await Answer();
                status = 503; string failedGeneration = security.EdlRevision; await security.RefreshEdlAsync();
                Check(security.EdlRevision == failedGeneration && security.EdlStatus()[0].AttemptOutcome == "Failed", "Native HTTP failure replaced generation or lost terminal outcome"); await Answer(); status = 200;
                // Direct local refresh is a fixture trigger; normal native scheduling is already independently proven above.
                text = "second.feed.test"; await security.RefreshEdlAsync(); string second = security.EdlRevision;
                Check(second != snapshotRevision, "Native manager replacement missing");
                using var rollbackBody = new ByteArrayContent(first); rollbackBody.Headers.ContentType = new("application/json");
                using var rollbackResponse = await original.PostAsync("/api/security/feeds/rollback?revision=" + security.Policy.Revision + "&snapshotRevision=" + second, rollbackBody);
                using var rolledJson = JsonDocument.Parse(await rollbackResponse.Content.ReadAsStringAsync()); var rolled = rolledJson.RootElement;
                Check(rolled.GetProperty("status").GetString() == "ok" && security.EdlStatus()[0].Entries == 1, "Native rollback failed"); await Answer();
                Check((await Call(original, "/api/security/feeds/rollback", ("snapshot", Encoding.UTF8.GetString(first)), ("revision", security.Policy.Revision.ToString()), ("snapshotRevision", second))).GetProperty("status").GetString() == "error", "Native rollback replay accepted");
                byte[] rolledBytes = security.ExportEdl();
                await using (var readback = new DdiSecurityManager(folder, new PublicSuffixes(["test"]), FeedClient()))
                    Check(readback.ExportEdl().SequenceEqual(rolledBytes) && readback.Evaluate(IPAddress.Loopback, "answer.feed.test", [], []).Matches.Length == 1, "Native rollback persisted readback/cold eligibility failed");
                var selected = security.Evaluate(IPAddress.Loopback, "answer.feed.test", [], []).Matches.Single();
                security.SetPolicy(security.Policy with { EdlPublications = [new("selected", "Domain", [new(selected.Source, selected.Id)], true, "Block")] }, security.Policy.Revision);
                using (var exportedClient = FeedClient())
                {
                    exportedClient.DefaultRequestHeaders.Authorization = original.DefaultRequestHeaders.Authorization;
                    string output = await exportedClient.GetStringAsync(feedServer.Urls.Single() + "/api/security/edl/export?list=selected&format=rpz&zone=policy.test");
                    Check(output == "$ORIGIN policy.test.\nanswer.feed.test CNAME .\n", "Native TLS RPZ selected export differs from declared fragment");
                }
                await Answer();
                // Post-await reauthorization uses a separate expendable fixture session; original and fresh admin sessions stay open.
                using var temporary = new HttpClient { BaseAddress = original.BaseAddress }; await Login(temporary, "admin", password);
                entered = new(TaskCreationOptions.RunContinuationsAsynchronously); release = new(TaskCreationOptions.RunContinuationsAsynchronously);
                var changedFeed = feed with { Provenance = "Reauthorization owned fixture" };
                // Disable background scheduling only for this race, then use the actual HTTP refresh handler.
                security.SetPolicy(security.Policy with { Enabled = false, EdlFeeds = [changedFeed] }, security.Policy.Revision);
                security.SetPolicy(security.Policy with { Enabled = true }, security.Policy.Revision);
                Task<JsonElement> pending = Call(temporary, "/api/security/feeds/refresh", ("feedId", "native"), ("revision", security.Policy.Revision.ToString()), ("snapshotRevision", security.EdlRevision));
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                string oldRevision = security.EdlRevision;
                auth.DeleteSession(temporary.DefaultRequestHeaders.Authorization.Parameter); release.TrySetResult(); await pending;
                await Until(() => security.EdlStatus()[0].AttemptOutcome != "Running");
                Check(security.EdlRevision == oldRevision && security.EdlStatus()[0].AttemptOutcome == "Superseded", "Revoked fixture session committed after await"); entered = release = null;
                Check((await Call(fresh, "/api/security/policy/get")).GetProperty("status").GetString() == "ok", "Fresh fixture admin access lost");
                string retainedAttempt = security.EdlStatus()[0].AttemptId; before = calls;
                await service.DisposeAsync(); service = null;
                service = new DnsWebService(true, folder); security = Field<DdiSecurityManager>(service, "_security"); Field<HttpClient>(security, "_mispClient").Dispose(); typeof(DdiSecurityManager).GetField("_mispClient", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(security, FeedClient()); await service.StartAsync(true);
                await Task.Delay(750);
                Check(calls == before && security.EdlStatus()[0].AttemptId == retainedAttempt && security.EdlStatus()[0].AttemptOutcome == "Superseded", "Native same-process service reload duplicated pending/backoff work or invented success");
                await Answer();
                // Zone records were persisted explicitly for restart availability.
                Console.WriteLine($"PASS: {checks} native feed API/scheduler/TLS/authoritative DNS checks. PID={Environment.ProcessId}; HTTP={httpPort}; DNS={dnsPort}; TLS={new Uri(feedServer.Urls.Single()).Port}; config={folder}. Fresh fixture admin authentication and modify privileges verified from target-observed 127.0.0.1; no production access/session/ACL changes. Service reload is disposal/recreation in the same process; store child exits are separate.");
            }
            finally { if (service is not null) await service.DisposeAsync(); }
        }
        finally { release?.TrySetResult(); await feedServer.StopAsync(); foreach (var e in oldEnv) Environment.SetEnvironmentVariable(e.Key, e.Value); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
