// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

static class FeedManagementChecks
{
    public static async Task Run(bool timeoutOnly = false)
    {
        string folder = Path.Combine(Path.GetTempPath(), "feed-management-" + Guid.NewGuid().ToString("N"));
        int checks = 0, calls = 0;
        void Check(bool result, string why) { if (!result) throw new Exception(why); checks++; }
        void Reject(Action action, string why) { try { action(); } catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { checks++; return; } throw new Exception(why); }
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
        await using var server = builder.Build();
        string text = "fixture.example\n"; int status = 200; bool stallBody = false;
        TaskCompletionSource entered = null, release = null;
        server.MapGet("/feed", async ctx => { Interlocked.Increment(ref calls); entered?.TrySetResult(); if (release is not null) await release.Task.WaitAsync(ctx.RequestAborted); ctx.Response.StatusCode = status; ctx.Response.ContentType = "text/plain"; if (stallBody) { ctx.Response.ContentLength = 100; await ctx.Response.StartAsync(); await ctx.Response.Body.FlushAsync(); await Task.Delay(TimeSpan.FromSeconds(90), ctx.RequestAborted); } else await ctx.Response.WriteAsync(text); });
        await server.StartAsync();
        HttpClient Client() => new(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.GetCertHashString(HashAlgorithmName.SHA256) == certificate.GetCertHashString(HashAlgorithmName.SHA256) });
        var suffixes = new PublicSuffixes(["example"]);
        var feed = new EdlFeed("fixture", "Domain", server.Urls.Single() + "/feed", true) { SourceConfidence = 62, MinimumConfidence = 60, MaximumAgeHours = 2, Provenance = "Synthetic local TLS fixture; operator assessment" };
        try
        {
            await using (var manager = new DdiSecurityManager(folder, suffixes, Client()))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [feed] }, 0);
                await manager.RefreshEdlAsync(scheduled: true);
                byte[] first = manager.ExportEdl(); string firstRevision = manager.EdlRevision;
                Check(manager.EdlStatus()[0].Entries == 1 && manager.EdlStatus()[0].SourceConfidence == 62, "Native TLS feed or confidence failed");
                Check(manager.EdlStatus()[0].ContentSha256?.Length == 64 && manager.EdlStatus()[0].NextAttempt > DateTime.UtcNow, "Integrity/schedule metadata missing");
                var matched = manager.Evaluate(IPAddress.Loopback, "fixture.example", [], []).Matches.Single();
                Check(matched.Confidence == 62 && matched.Evidence.Contains("accuracy unverified") && matched.Expires < DateTime.UtcNow.AddHours(3), "Confidence/age provenance misrepresented");
                if (timeoutOnly)
                {
                    stallBody = true; var elapsed = System.Diagnostics.Stopwatch.StartNew(); await manager.RefreshEdlAsync();
                    Check(elapsed.Elapsed > TimeSpan.FromSeconds(55) && elapsed.Elapsed < TimeSpan.FromSeconds(75), "Whole-body deadline not enforced");
                    Check(first.SequenceEqual(manager.ExportEdl()) && manager.EdlStatus()[0].AttemptOutcome == "TimedOut", "Timeout did not retain snapshot or truthful terminal outcome");
                    Console.WriteLine($"PASS: feed-only real loopback TLS stalled-body deadline {elapsed.Elapsed.TotalSeconds:F1}s, prior validated snapshot/generation retained, terminal TimedOut; no MISP or external target.");
                    return;
                }
                int before = calls; await manager.RefreshEdlAsync(scheduled: true); Check(calls == before, "Scheduled repeat overlapped reservation");
                manager.SetPolicy(manager.Policy with { AlertThreshold = 71 }, manager.Policy.Revision);
                await manager.RefreshEdlAsync(scheduled: true); Check(calls == before, "Unrelated policy update reset durable scheduling");
                await using (var restarted = new DdiSecurityManager(folder, suffixes, Client()))
                { await restarted.RefreshEdlAsync(scheduled: true); Check(calls == before && restarted.EdlStatus()[0].Entries == 1 && restarted.EdlStatus()[0].NextAttempt == manager.EdlStatus()[0].NextAttempt, "Restart lost snapshot or reservation"); }
                foreach (string bad in new[] { "good.example\nbad name.example", "*.fixture.example", "<html>login</html>" })
                { text = bad; await manager.RefreshEdlAsync(); Check(first.SequenceEqual(manager.ExportEdl()), "Partial invalid body replaced previous snapshot"); }
                Check(manager.EdlStatus()[0].ConsecutiveFailures == 3 && manager.EdlStatus()[0].NextAttempt > DateTime.UtcNow.AddSeconds(feed.RefreshSeconds * 3), "Failure backoff did not increase");
                text = "fixture.example"; status = 206; await manager.RefreshEdlAsync(); Check(first.SequenceEqual(manager.ExportEdl()), "Partial HTTP response accepted"); status = 200;
                entered = new(TaskCreationOptions.RunContinuationsAsynchronously); release = new(TaskCreationOptions.RunContinuationsAsynchronously);
                Task active = manager.RefreshEdlAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); before = calls;
                await manager.RefreshEdlAsync(); Check(calls == before, "Concurrent refresh reached transport");
                Check(Enumerable.Range(0, 1000).AsParallel().All(_ => manager.Evaluate(IPAddress.Loopback, "fixture.example", [], []).Matches.Length == 1), "Concurrent consumer snapshot unavailable");
                manager.SetPolicy(manager.Policy with { EdlFeeds = [] }, manager.Policy.Revision);
                manager.SetPolicy(manager.Policy with { EdlFeeds = [feed] }, manager.Policy.Revision);
                release.TrySetResult(); await active; entered = release = null;
                Check(first.SequenceEqual(manager.ExportEdl()), "Post-await ABA policy change committed stale body");
                text = "second.example"; await manager.RefreshEdlAsync(); string secondRevision = manager.EdlRevision;
                Check(secondRevision != firstRevision, "Successful replacement did not change snapshot revision");
                Reject(() => manager.RollbackEdl(first, manager.Policy.Revision - 1, secondRevision), "Stale policy rollback accepted");
                manager.RollbackEdl(first, manager.Policy.Revision, secondRevision); string rollbackRevision = manager.EdlRevision;
                Check(rollbackRevision != firstRevision && manager.Evaluate(IPAddress.Loopback, "fixture.example", [], []).Matches.Length == 1, "Explicit rollback failed or reused revision");
                Reject(() => manager.RollbackEdl(first, manager.Policy.Revision, secondRevision), "Rollback replay accepted");
                var tampered = JsonSerializer.Deserialize<EdlSnapshot[]>(first, DdiSecurityManager.JsonOptions)[0] with { Values = ["tampered.example"] };
                Reject(() => manager.RollbackEdl(JsonSerializer.SerializeToUtf8Bytes(new[] { tampered }, DdiSecurityManager.JsonOptions), manager.Policy.Revision, rollbackRevision), "Digest corruption accepted");
                byte[] current = manager.ExportEdl();
                string cachePath = Path.Combine(folder, "security-edl.json"); byte[] disk = File.ReadAllBytes(cachePath); File.Delete(cachePath); Directory.CreateDirectory(cachePath);
                text = "never-committed.example"; await manager.RefreshEdlAsync();
                Check(current.SequenceEqual(manager.ExportEdl()), "Failed snapshot persistence changed consumers");
                Directory.Delete(cachePath); File.WriteAllBytes(cachePath, disk);
                string schedulePath = Path.Combine(folder, "security-feed-schedule.json"); disk = File.ReadAllBytes(schedulePath); File.Delete(schedulePath); Directory.CreateDirectory(schedulePath); before = calls;
                await manager.RefreshEdlAsync(); Check(calls == before && current.SequenceEqual(manager.ExportEdl()), "Failed reservation persistence still fetched or replaced snapshot");
                Directory.Delete(schedulePath); File.WriteAllBytes(schedulePath, disk);
                manager.SetPolicy(manager.Policy with { EdlFeeds = [feed with { MinimumConfidence = 63 }] }, manager.Policy.Revision);
                Check(manager.EdlStatus()[0].Entries == 0 && manager.Evaluate(IPAddress.Loopback, "fixture.example", [], []).Matches.Length == 0, "Below-confidence evidence active");
                var rpz = feed with { Format = "RpzQnameNxdomain", RpzZone = "policy.example" };
                manager.SetPolicy(manager.Policy with { EdlFeeds = [rpz] }, manager.Policy.Revision);
                Check(manager.EdlStatus()[0].Entries == 0, "Format change reused plain snapshot");
                text = "$ORIGIN policy.example.\n$TTL 60\nfixture.example IN CNAME .\nsecond.example.policy.example. 60 IN CNAME . ; comment\n";
                await manager.RefreshEdlAsync(); Check(manager.EdlStatus()[0].Entries == 2, "RPZ relative/absolute QNAME fragment rejected"); current = manager.ExportEdl();
                foreach (string bad in new[] { "*.fixture.example CNAME .", "fixture.example CNAME rpz-passthru.", "24.0.2.0.192.rpz-ip CNAME .", "fixture.example A 192.0.2.1", "$INCLUDE other", "fixture.example.other.example. CNAME .", "@ SOA localhost. admin.example. 1 60 60 60 60", "fixture.example CNAME *." })
                { text = "$ORIGIN policy.example.\nvalid.example CNAME .\n" + bad; await manager.RefreshEdlAsync(); Check(current.SequenceEqual(manager.ExportEdl()), "Unsupported RPZ fragment partially accepted: " + bad); }
                var selection = manager.Evaluate(IPAddress.Loopback, "fixture.example", [], []).Matches.Single();
                manager.SetPolicy(manager.Policy with { EdlPublications = [new("chosen", "Domain", [new(selection.Source, selection.Id)], true)] }, manager.Policy.Revision);
                Reject(() => manager.PublishRpz("chosen", "policy.example"), "Monitor publication became NXDOMAIN intent");
                manager.SetPolicy(manager.Policy with { EdlPublications = [new("chosen", "Domain", [new(selection.Source, selection.Id)], true, "Block")] }, manager.Policy.Revision);
                string exported = manager.PublishRpz("chosen", "policy.example"); Check(exported == "$ORIGIN policy.example.\nfixture.example CNAME .\n", "RPZ export inferred unselected evidence");
                text = exported; await manager.RefreshEdlAsync(); Check(manager.EdlStatus()[0].Entries == 1, "Supported RPZ export did not roundtrip");
                entered = new(TaskCreationOptions.RunContinuationsAsynchronously); release = new(TaskCreationOptions.RunContinuationsAsynchronously);
                using var cancel = new CancellationTokenSource(); active = manager.RefreshEdlAsync(cancel.Token); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); current = manager.ExportEdl(); cancel.Cancel();
                try { await active; throw new Exception("Cancellation ignored"); } catch (OperationCanceledException) { checks++; }
                Check(current.SequenceEqual(manager.ExportEdl()), "Cancellation changed snapshot"); release.TrySetResult(); entered = release = null;
                foreach (var invalid in new[] { feed with { SourceConfidence = 101 }, feed with { MaximumAgeHours = 0 }, feed with { Format = "RPZ" }, rpz with { Kind = "Network" } }) Reject(() => manager.SetPolicy(manager.Policy with { EdlFeeds = [invalid] }, manager.Policy.Revision), "Invalid feed quality accepted");
                Check(manager.Policy.Mode == "Monitor" && manager.Policy.DeviceDnsResponse == "Monitor" && manager.Policy.DhcpResponse == "Observe", "Monitor/DNS/DHCP defaults changed");
            }
            Console.WriteLine($"PASS: {checks} feed-management checks; actual pinned loopback TLS fixture, restart/durable backoff, whole-snapshot failure/persistence retention, policy ABA, revision rollback/replay, strict RPZ subset and concurrent consumers. No DNS packets or external targets.");
        }
        finally { await server.StopAsync(); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
