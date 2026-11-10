// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

static class MispEdlRepairChecks
{
    const int Budget = 16 * 1024 * 1024;
    sealed class Provider : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Reply;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Reply(request, token);
    }
    static string Uuid(int n) => new Guid(n, 0, 0, new byte[8]).ToString("D");
    static string Attribute(int n, string type = "domain", string value = "fixture.example", string tags = "") => JsonSerializer.Serialize(new { uuid = Uuid(n), type, value, Tag = tags });
    static string Page(params string[] attributes) => "{\"response\":{\"Attribute\":[" + string.Join(',', attributes) + "]}}";
    static HttpResponseMessage Json(string text, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
    static HttpResponseMessage Text(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };
    static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, DdiSecurityManager.JsonOptions);
    public static async Task Run()
    {
        int checks = 0;
        void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; }
        void Reject(Action action, string message) { try { action(); } catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException) { checks++; return; } throw new Exception(message); }
        string root = Path.Combine(Path.GetTempPath(), "ddi-repair-002-" + Guid.NewGuid().ToString("N"));
        var suffixes = new PublicSuffixes(["example"]);
        Environment.SetEnvironmentVariable("DDI_MISP_REPAIR_API_KEY", "fixture");
        var source = new Provider { Reply = (_, _) => Task.FromResult(Json(Page(Attribute(1)))) };
        try
        {
            await using (var manager = new DdiSecurityManager(Path.Combine(root, "misp"), suffixes, new HttpClient(source)))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, Misp = new(true, "https://misp.test", "DDI_MISP_REPAIR_API_KEY") }, 0);
                await manager.RefreshMispAsync(); byte[] before = manager.ExportEnrichment();
                Check(manager.MispStatus.Indicators == 1, "Valid UUID seed was not accepted");
                source.Reply = (_, _) => Task.FromResult(Json(Page(), HttpStatusCode.PartialContent)); await manager.RefreshMispAsync();
                Check(before.SequenceEqual(manager.ExportEnrichment()) && manager.MispStatus.Status.Contains("failed"), "206 empty JSON retracted complete evidence");
                source.Reply = (_, _) => { var response = Json(Page()); response.Content.Headers.ContentRange = new(0, 0, 100); return Task.FromResult(response); }; await manager.RefreshMispAsync();
                Check(before.SequenceEqual(manager.ExportEnrichment()), "200 with Content-Range was treated as complete");
                source.Reply = (_, _) => Task.FromResult(Json(Page(Attribute(2, "domain|ip", "composite.example|192.0.2.1"), JsonSerializer.Serialize(new { uuid = Uuid(2) + ":domain", type = "domain", value = "lost.example" })))); await manager.RefreshMispAsync();
                Check(before.SequenceEqual(manager.ExportEnrichment()), "Malformed derived-ID collision replaced complete evidence");
                source.Reply = (_, _) => Task.FromResult(Json(Page(Attribute(2, "domain|ip", "composite.example|192.0.2.1"), Attribute(3, value: "other.example")))); await manager.RefreshMispAsync();
                Check(manager.MispStatus.Indicators == 3 && JsonSerializer.Deserialize<MispCache>(manager.ExportEnrichment(), DdiSecurityManager.JsonOptions).Indicators.Select(i => i.Id).Distinct().Count() == 3, "Valid composite and UUID identities lost evidence");
                source.Reply = (_, _) => Task.FromResult(Json(Page("{\"id\":\"42\",\"type\":\"domain\",\"value\":\"fallback.example\"}", "{\"id\":43,\"type\":\"domain\",\"value\":\"second.example\"}"))); await manager.RefreshMispAsync();
                Check(manager.MispStatus.Indicators == 2 && JsonSerializer.Deserialize<MispCache>(manager.ExportEnrichment(), DdiSecurityManager.JsonOptions).Indicators.Any(i => i.Id == "misp:42"), "Valid numeric fallback rejected");
                before = manager.ExportEnrichment();
                foreach (var identity in new[] { "{\"uuid\":\"not-a-uuid\",\"id\":44", "{\"id\":\"4:domain\"", "{\"id\":0", "{\"id\":\"01\"", "{\"id\":1.5" })
                {
                    source.Reply = (_, _) => Task.FromResult(Json(Page(identity + ",\"type\":\"domain\",\"value\":\"invalid.example\"}"))); await manager.RefreshMispAsync();
                    Check(before.SequenceEqual(manager.ExportEnrichment()), "Invalid identity fell back or replaced evidence");
                }
                source.Reply = (_, _) => Task.FromResult(Json(Page(JsonSerializer.Serialize(new { uuid = " " + Uuid(5) + " ", type = "domain", value = "invalid.example" })))); await manager.RefreshMispAsync();
                Check(before.SequenceEqual(manager.ExportEnrichment()), "Whitespace-padded UUID accepted through parser normalization");
                DateTime? lastSuccess = manager.MispStatus.LastSuccess;
                source.Reply = async (request, token) => { using var json = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token)); int page = json.RootElement.GetProperty("page").GetInt32(); return Json(page <= 3 ? Page(Enumerable.Range(1, 1000).Select(i => Attribute(page * 1000 + i, tags: new string('t', 6000))).ToArray()) : Page()); };
                await manager.RefreshMispAsync();
                Check(before.SequenceEqual(manager.ExportEnrichment()) && File.ReadAllBytes(Path.Combine(root, "misp/security-misp.json")).SequenceEqual(before) && manager.MispStatus.LastSuccess == lastSuccess, "Over-budget MISP replaced last complete persisted/visible cache");

                // Build the exact writable boundary, then prove both peer and restart accept it.
                var cache = new MispCache("https://misp.test", Enumerable.Range(1, 2100).Select(i => new ThreatIndicator("misp:" + Uuid(i), "Domain", "boundary.example", "Monitor", "MISP", 50, DateTime.UtcNow.AddHours(1), Evidence: "")).ToArray());
                int remaining = Budget - Bytes(cache).Length;
                for (int i = 0; remaining > 0 && i < cache.Indicators.Length; i++) { int fill = Math.Min(8192, remaining); cache.Indicators[i] = cache.Indicators[i] with { Evidence = new string('x', fill) }; remaining -= fill; }
                Check(remaining == 0 && Bytes(cache).Length == Budget, "Boundary fixture did not reach exact canonical budget");
                byte[] boundary = Bytes(cache); manager.RestoreEnrichment(boundary);
                Check(manager.ExportEnrichment().SequenceEqual(boundary) && File.ReadAllBytes(Path.Combine(root, "misp/security-misp.json")).Length == Budget, "Exact budget was not writable");
                await using (var peer = new DdiSecurityManager(Path.Combine(root, "misp-peer"), suffixes)) { peer.RestorePolicy(manager.ExportPolicy()); peer.RestoreEnrichment(boundary); Check(peer.MispStatus.Indicators == 2100 && peer.ExportEnrichment().SequenceEqual(boundary), "Maximum MISP cache failed peer roundtrip"); }
                await using (var restart = new DdiSecurityManager(Path.Combine(root, "misp"), suffixes)) Check(restart.MispStatus.Indicators == 2100 && restart.ExportEnrichment().SequenceEqual(boundary), "Maximum MISP cache failed restart roundtrip");
                var overflowing = cache.Indicators.ToArray(); overflowing[0] = overflowing[0] with { Evidence = new string('é', 1000) + overflowing[0].Evidence[1000..] }; overflowing[1] = overflowing[1] with { Evidence = overflowing[1].Evidence[..^2500] };
                byte[] canonicalOverflow = Bytes(cache with { Indicators = overflowing });
                byte[] compactInput = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(canonicalOverflow).Replace("\\u00E9", "é"));
                Check(compactInput.Length < Budget && canonicalOverflow.Length > Budget, "Escaping fixture does not cross serialized boundary");
                Reject(() => manager.RestoreEnrichment(compactInput), "Compact input expanded beyond durable/peer budget");
                Check(boundary.SequenceEqual(manager.ExportEnrichment()), "Rejected canonical overflow changed cache");
                source.Reply = (_, _) => Task.FromResult(Json(Page())); await manager.RefreshMispAsync();
                Check(manager.MispStatus.Indicators == 0 && manager.MispStatus.Status == "Available", "Genuine 200 empty did not retract");
            }

            var edlProvider = new Provider { Reply = (_, _) => Task.FromResult(Text("https://small.example/path\n")) };
            EdlFeed[] feeds = Enumerable.Range(0, 8).Select(i => new EdlFeed("f" + i, "Url", "https://edl.test/" + i, true)).ToArray();
            await using (var manager = new DdiSecurityManager(Path.Combine(root, "edl"), suffixes, new HttpClient(edlProvider)))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = feeds }, 0); await manager.RefreshEdlAsync();
                var previous = JsonSerializer.Deserialize<EdlSnapshot[]>(manager.ExportEdl(), DdiSecurityManager.JsonOptions).Single(s => s.FeedId == "f7");
                string large = string.Join('\n', Enumerable.Range(0, 10000).Select(i => ("https://fixture.example/" + i.ToString("D5") + "/").PadRight(208, 'a'))) + "\n";
                Check(Encoding.UTF8.GetByteCount(large) < 2 * 1024 * 1024, "EDL aggregate fixture violates per-response limit");
                edlProvider.Reply = (_, _) => Task.FromResult(Text(large)); manager.SetPolicy(manager.Policy, manager.Policy.Revision); await manager.RefreshEdlAsync();
                byte[] complete = manager.ExportEdl(); var snapshots = JsonSerializer.Deserialize<EdlSnapshot[]>(complete, DdiSecurityManager.JsonOptions);
                Check(complete.Length <= Budget && manager.EdlStatus().Sum(h => h.Entries) == 70001 && snapshots.Single(s => s.FeedId == "f7").FetchedAt == previous.FetchedAt && manager.EdlStatus().Single(h => h.FeedId == "f7").Status.Contains("failed"), "Aggregate overflow did not retain previous source snapshot");
                await using (var peer = new DdiSecurityManager(Path.Combine(root, "edl-peer"), suffixes)) { peer.RestorePolicy(manager.ExportPolicy()); peer.RestoreEdl(complete); Check(peer.EdlStatus().Sum(h => h.Entries) == 70001, "Writable aggregate failed receiver"); }
                await using (var restart = new DdiSecurityManager(Path.Combine(root, "edl"), suffixes)) Check(restart.EdlStatus().Sum(h => h.Entries) == 70001, "Writable aggregate failed restart");
                // Equalize padding across feeds to make the exact 16 MiB canonical boundary writable.
                DateTime fetched = DateTime.UtcNow;
                snapshots = feeds.Select(f => new EdlSnapshot(f.Id, f.Kind, f.Url, fetched, fetched.AddHours(1), Enumerable.Range(0, 10000).Select(i => ("https://fixture.example/" + i.ToString("D5") + "/").PadRight(200, 'a')).ToArray())).ToArray();
                int remaining = Budget - Bytes(snapshots).Length;
                for (int row = 0; remaining > 0 && row < 10000; row++) foreach (var snapshot in snapshots) { int fill = Math.Min(16, remaining); snapshot.Values[row] += new string('x', fill); remaining -= fill; }
                Check(remaining == 0 && Bytes(snapshots).Length == Budget && snapshots.All(s => Encoding.UTF8.GetByteCount(string.Join('\n', s.Values) + "\n") <= 2 * 1024 * 1024), "EDL exact aggregate fixture is not fetchable within per-source limits");
                byte[] boundary = Bytes(snapshots); manager.RestoreEdl(boundary);
                Check(manager.ExportEdl().SequenceEqual(boundary), "Exact EDL aggregate budget rejected or changed");
                await using (var peer = new DdiSecurityManager(Path.Combine(root, "edl-max-peer"), suffixes)) { peer.RestorePolicy(manager.ExportPolicy()); peer.RestoreEdl(boundary); Check(peer.EdlStatus().Sum(h => h.Entries) == 80000, "Maximum EDL aggregate failed peer"); }
                await using (var restart = new DdiSecurityManager(Path.Combine(root, "edl"), suffixes)) Check(restart.EdlStatus().Sum(h => h.Entries) == 80000, "Maximum EDL aggregate failed restart");
                snapshots[0].Values[0] += "x"; Reject(() => manager.RestoreEdl(Bytes(snapshots)), "Over-budget EDL aggregate accepted");
                Check(manager.ExportEdl().SequenceEqual(boundary), "Rejected EDL overflow replaced maximum cache");
            }
            checks += await OpaqueHeaders(root, suffixes);
            Console.WriteLine($"PASS: {checks} QA02–QA05 repair checks: complete status, valid/invalid identity, exact 16 MiB roundtrips, escaped/aggregate overflow retention, actual TLS opaque headers.");
        }
        finally { Environment.SetEnvironmentVariable("DDI_MISP_REPAIR_API_KEY", null); Environment.SetEnvironmentVariable("DDI_EDL_REPAIR_API_KEY", null); if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
    static async Task<int> OpaqueHeaders(string root, PublicSuffixes suffixes)
    {
        int checks = 0, seen = 0; string expected = "";
        const string padded = "ZmFrZTprZXk=";
        Environment.SetEnvironmentVariable("DDI_EDL_REPAIR_API_KEY", padded); Environment.SetEnvironmentVariable("DDI_MISP_REPAIR_API_KEY", padded);
        using var rsa = RSA.Create(2048); var cr = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); cr.CertificateExtensions.Add(san.Build()); cr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var generated = cr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1)); using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(cert)));
        await using var server = builder.Build();
        server.MapGet("/feed", (HttpContext ctx) => { if (ctx.Request.Headers.Authorization != expected) { ctx.Response.StatusCode = 401; return Task.CompletedTask; } Interlocked.Increment(ref seen); ctx.Response.ContentType = "text/plain"; return ctx.Response.WriteAsync("opaque.example\n"); });
        server.MapPost("/attributes/restSearch", (HttpContext ctx) => { if (ctx.Request.Headers.Authorization != padded) { ctx.Response.StatusCode = 401; return Task.CompletedTask; } Interlocked.Increment(ref seen); return ctx.Response.WriteAsync(Page(Attribute(1))); });
        await server.StartAsync();
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        handler.ServerCertificateCustomValidationCallback = (_, remote, _, errors) => { if (remote is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false; using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(cert); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; return chain.Build(remote); };
        await using var manager = new DdiSecurityManager(Path.Combine(root, "opaque"), suffixes, new HttpClient(handler));
        foreach (string scheme in new[] { "Raw", "Basic", "Bearer" })
        {
            expected = scheme == "Raw" ? padded : scheme + " " + padded; int before = seen;
            manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [new("opaque", "Domain", server.Urls.Single() + "/feed", true, ApiKeyEnvironment: "DDI_EDL_REPAIR_API_KEY", AuthScheme: scheme)] }, manager.Policy.Revision);
            await manager.RefreshEdlAsync(); if (seen != before + 1 || manager.EdlStatus()[0].Entries != 1 || manager.EdlStatus()[0].Status != "Available") throw new Exception("Actual TLS header send failed for " + scheme); checks++;
        }
        foreach (string invalid in new[] { "key\r\nInjected: value", "two parts", "\t", "\u0080" })
        {
            Environment.SetEnvironmentVariable("DDI_EDL_REPAIR_API_KEY", invalid); int before = seen; byte[] cache = manager.ExportEdl();
            manager.SetPolicy(manager.Policy with { EdlFeeds = [manager.Policy.EdlFeeds[0] with { AuthScheme = "Raw" }] }, manager.Policy.Revision); await manager.RefreshEdlAsync();
            if (seen != before || !cache.SequenceEqual(manager.ExportEdl())) throw new Exception("Unsafe Raw header reached transport or replaced cache"); checks++;
        }
        manager.SetPolicy(manager.Policy with { Misp = new(true, server.Urls.Single(), "DDI_MISP_REPAIR_API_KEY") }, manager.Policy.Revision); await manager.RefreshMispAsync();
        if (manager.MispStatus.Indicators != 1) throw new Exception("MISP safe opaque key was reparsed as authentication scheme"); checks++;
        await server.StopAsync(); return checks;
    }
}
