// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

static class MispQualificationChecks
{
    sealed class Feed : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Reply;
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Interlocked.Increment(ref Calls);
            if (request.RequestUri != new Uri("https://misp.test/attributes/restSearch") || request.Headers.GetValues("Authorization").Single() != "fixture-key") throw new Exception("Unexpected endpoint or credential");
            return Reply(request, token);
        }
    }
    static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    static string Attribute(string id, string value = "fixture.example") => JsonSerializer.Serialize(new { uuid = id.Length == 0 ? "" : new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(id)).AsSpan(0, 16)).ToString("D"), type = "domain", value, timestamp = "1720000000", event_id = "fixture-event", to_ids = true });
    static string Page(params string[] attributes) => "{\"response\":{\"Attribute\":[" + string.Join(',', attributes) + "]}}";
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-misp-qualification-" + Guid.NewGuid().ToString("N"));
        const string credential = "DDI_MISP_QUALIFICATION_API_KEY";
        Environment.SetEnvironmentVariable(credential, "fixture-key");
        var suffixes = new PublicSuffixes(["example"]);
        var client = IPAddress.Parse("192.0.2.1");
        int checks = 0;
        void Check(bool condition, string reason) { if (!condition) throw new Exception(reason); checks++; }
        void Reject(Action action, string reason) { try { action(); } catch (Exception ex) when (ex is ArgumentException || ex is FormatException) { checks++; return; } throw new Exception(reason); }
        var feed = new Feed { Reply = (_, _) => Task.FromResult(Json(Page(Attribute("one")))) };
        try
        {
            await using var manager = new DdiSecurityManager(Path.Combine(folder, "source"), suffixes, new HttpClient(feed));
            manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, Mode = "Block", DeviceDnsResponse = "Block", DhcpResponse = "DenyNewLeases", DeviceThreshold = 1, Misp = new(true, "https://misp.test", credential) }, 0);
            await manager.RefreshMispAsync();
            byte[] complete = manager.ExportEnrichment();
            var cache = JsonSerializer.Deserialize<MispCache>(complete, DdiSecurityManager.JsonOptions);
            var indicator = cache.Indicators.Single();
            using (var evidence = JsonDocument.Parse(indicator.Evidence))
            {
                Check(evidence.RootElement.GetProperty("sourceUrl").GetString() == "https://misp.test", "Missing source provenance");
                Check(evidence.RootElement.GetProperty("timestamp").GetString() == "1720000000", "Source timestamp lost");
                Check(evidence.RootElement.GetProperty("fetchedAt").GetDateTime().Kind == DateTimeKind.Utc, "Fetch time not UTC");
            }
            Check(indicator.Expires > DateTime.UtcNow.AddHours(23) && indicator.Expires <= DateTime.UtcNow.AddHours(24), "Fetch lifetime incorrect");
            Check(manager.Evaluate(client, "fixture.example", [], []).Action == "Monitor", "MISP evidence enforces in Block policy");
            Check(!Encoding.UTF8.GetString(complete).Contains("fixture-key") && !Encoding.UTF8.GetString(manager.ExportPolicy()).Contains("fixture-key"), "Credential leaked to shared state");

            foreach (string malformed in new[] { "null", "[]", "{}", "{\"response\":null}", Page("null"), Page("{}"), Page(Attribute("")), Page(Attribute("one"), Attribute("one")), Page("{\"uuid\":\"broken\",\"type\":\"domain|ip\",\"value\":\"broken\"}"), Page("{\"uuid\":\"bad-ip\",\"type\":\"ip-dst\",\"value\":\"not-an-ip\"}"), Page("{\"uuid\":\"bad-type\",\"type\":\"domain\",\"value\":42}"), Page("{\"uuid\":\"bad-time\",\"type\":\"domain\",\"value\":\"fixture.example\",\"timestamp\":\"invalid\"}"), Page("{\"uuid\":\"bad-delete\",\"type\":\"domain\",\"value\":\"fixture.example\",\"deleted\":\"invalid\"}") })
            {
                feed.Reply = (_, _) => Task.FromResult(Json(malformed));
                await manager.RefreshMispAsync();
                Check(manager.ExportEnrichment().SequenceEqual(complete) && manager.MispStatus.Status.Contains("last complete"), "Malformed response replaced complete cache: " + malformed);
            }
            foreach (HttpStatusCode status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.ServiceUnavailable, HttpStatusCode.Redirect })
            {
                feed.Reply = (_, _) => Task.FromResult(Json("{}", status));
                await manager.RefreshMispAsync();
                Check(manager.ExportEnrichment().SequenceEqual(complete), "HTTP failure discarded cache");
            }
            feed.Reply = (_, _) => throw new HttpRequestException("TLS or network failure");
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Transport failure discarded cache");

            // A valid first page plus failed later page must not publish a partial snapshot.
            string fullPage = Page(Enumerable.Range(0, 1000).Select(i => Attribute("page-" + i)).ToArray());
            feed.Reply = async (request, token) => { using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token)); return body.RootElement.GetProperty("page").GetInt32() == 1 ? Json(fullPage) : Json("{}", HttpStatusCode.ServiceUnavailable); };
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Partial pagination published");
            feed.Reply = (_, _) => Task.FromResult(Json(fullPage));
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Repeated pagination published");
            feed.Reply = (_, _) => Task.FromResult(Json(Page(Enumerable.Range(0, 1001).Select(i => Attribute("large-" + i)).ToArray())));
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Oversized page published");
            feed.Reply = (_, _) => Task.FromResult(Json(new string(' ', 8 * 1024 * 1024 + 1)));
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Oversized body published");
            feed.Reply = async (request, token) => { using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token)); int page = body.RootElement.GetProperty("page").GetInt32(); return Json(Page(Enumerable.Range(0, page == 11 ? 1 : 1000).Select(i => Attribute("limit-" + page + "-" + i)).ToArray())); };
            await manager.RefreshMispAsync();
            Check(manager.ExportEnrichment().SequenceEqual(complete), "Indicator limit silently truncated snapshot");

            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            feed.Reply = async (_, token) => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json(Page()); };
            using (var cancel = new CancellationTokenSource())
            {
                Task refresh = manager.RefreshMispAsync(cancel.Token);
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                int before = feed.Calls;
                await manager.RefreshMispAsync();
                Check(feed.Calls == before, "Overlapping refresh reached network");
                Check(Enumerable.Range(0, 1000).All(_ => manager.Evaluate(client, "fixture.example", [], []).Action == "Monitor"), "Blocked network refresh blocked DNS evaluation");
                cancel.Cancel();
                try { await refresh; throw new Exception("Cancellation ignored"); } catch (OperationCanceledException) { checks++; }
                Check(manager.ExportEnrichment().SequenceEqual(complete), "Cancellation changed cache");
            }
            Environment.SetEnvironmentVariable(credential, "bad\r\nkey");
            int calls = feed.Calls;
            await manager.RefreshMispAsync();
            Check(feed.Calls == calls && manager.MispStatus.Status.Contains("invalid"), "Invalid credential reached transport");
            Environment.SetEnvironmentVariable(credential, "fixture-key");

            await using var peer = new DdiSecurityManager(Path.Combine(folder, "peer"), suffixes);
            peer.RestorePolicy(manager.ExportPolicy()); peer.RestoreEnrichment(complete);
            Check(peer.Evaluate(client, "fixture.example", [], []).Action == "Monitor", "Peer evidence missing");
            foreach (var invalid in new[] { indicator with { Action = "Block" }, indicator with { Source = "Local" }, indicator with { Expires = null }, indicator with { Expires = DateTime.UtcNow.AddDays(8) }, indicator with { ClientNetwork = "192.0.2.0/24" }, indicator with { Id = "local" } })
                Reject(() => peer.RestoreEnrichment(JsonSerializer.SerializeToUtf8Bytes(cache with { Indicators = [invalid] }, DdiSecurityManager.JsonOptions)), "Invalid replicated cache accepted");
            Check(peer.ExportEnrichment().SequenceEqual(complete), "Rejected cache changed persisted state");
            Reject(() => peer.RestoreEnrichment(JsonSerializer.SerializeToUtf8Bytes(cache with { SourceUrl = "http://misp.test" }, DdiSecurityManager.JsonOptions)), "Untrusted source accepted");
            await using (var restarted = new DdiSecurityManager(Path.Combine(folder, "peer"), suffixes))
                Check(restarted.Evaluate(client, "fixture.example", [], []).Action == "Monitor" && restarted.MispStatus.Status.Contains("refresh required"), "Restart cache state inaccurate");
            peer.RestoreEnrichment(JsonSerializer.SerializeToUtf8Bytes(cache with { Indicators = [indicator with { Expires = DateTime.UtcNow.AddSeconds(-1) }] }, DdiSecurityManager.JsonOptions));
            Check(peer.Evaluate(client, "fixture.example", [], []).Action == "Allow" && peer.MispStatus.Indicators == 0, "Expired peer evidence active");
            await using (var restarted = new DdiSecurityManager(Path.Combine(folder, "peer"), suffixes))
                Check(restarted.MispStatus.Indicators == 0, "Expired evidence revived on restart");
            string brokenFolder = Path.Combine(folder, "broken"); Directory.CreateDirectory(brokenFolder);
            File.WriteAllText(Path.Combine(brokenFolder, "security-misp.json"), JsonSerializer.Serialize(cache with { Indicators = [indicator with { Kind = "Network", Value = "not-an-ip" }] }, DdiSecurityManager.JsonOptions));
            await using (var restarted = new DdiSecurityManager(brokenFolder, suffixes))
                Check(restarted.MispStatus.Status == "Disabled", "Disabled integration state incorrect");
            feed.Reply = async (request, token) => { using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token)); return Json(body.RootElement.GetProperty("page").GetInt32() == 1 ? fullPage : Page(Attribute("last-page"))); };
            int paginatedBefore = feed.Calls; await manager.RefreshMispAsync();
            Check(manager.MispStatus.Indicators == 1001 && feed.Calls == paginatedBefore + 2, "Complete multi-page snapshot did not replace cache atomically");
            feed.Reply = (_, _) => Task.FromResult(Json(Page()));
            await manager.RefreshMispAsync();
            Check(manager.MispStatus.Indicators == 0 && manager.Evaluate(client, "fixture.example", [], []).Action == "Allow", "Successful empty feed failed to retract evidence");
            // Real loopback TLS: trust is fixture-local; no machine trust or production credentials change.
            using var rsa = RSA.Create(2048);
            var certificateRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certificateRequest.CertificateExtensions.Add(san.Build());
            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var generatedCertificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            using var certificate = X509CertificateLoader.LoadPkcs12(generatedCertificate.Export(X509ContentType.Pfx), null);
            var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(certificate)));
            await using var server = builder.Build();
            int authenticated = 0;
            server.MapPost("/attributes/restSearch", (HttpContext context) =>
            {
                if (context.Request.Headers.Authorization != "fixture-key") { context.Response.StatusCode = 401; return Task.CompletedTask; }
                Interlocked.Increment(ref authenticated);
                return context.Response.WriteAsync(Page(Attribute("tls")));
            });
            await server.StartAsync();
            var tlsPolicy = manager.Policy with { Misp = manager.Policy.Misp with { Url = server.Urls.Single() } };
            await using (var untrusted = new DdiSecurityManager(Path.Combine(folder, "untrusted"), suffixes))
            {
                untrusted.SetPolicy(tlsPolicy, 0); await untrusted.RefreshMispAsync();
                Check(untrusted.MispStatus.Indicators == 0 && authenticated == 0 && untrusted.MispStatus.Status.Contains("failed"), "Default client accepted untrusted TLS");
            }
            using var trustedHandler = new HttpClientHandler { AllowAutoRedirect = false };
            trustedHandler.ServerCertificateCustomValidationCallback = (_, remote, _, errors) =>
            {
                if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || remote is null) return false;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(certificate); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(remote);
            };
            await using (var trusted = new DdiSecurityManager(Path.Combine(folder, "trusted"), suffixes, new HttpClient(trustedHandler)))
            {
                trusted.SetPolicy(tlsPolicy, 0); await trusted.RefreshMispAsync();
                Check(trusted.MispStatus.Indicators == 1 && authenticated == 1, "Trusted TLS fixture failed authenticated refresh: " + trusted.MispStatus.Status + "; receipts=" + authenticated);
                Check(trusted.Evaluate(client, "fixture.example", [], []).Action == "Monitor", "TLS evidence became enforceable");
            }
            await server.StopAsync();
            Console.WriteLine($"PASS: {checks} MISP qualification assertions (isolated transport and loopback TLS; no live provider claim).");
        }
        finally { Environment.SetEnvironmentVariable(credential, null); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
