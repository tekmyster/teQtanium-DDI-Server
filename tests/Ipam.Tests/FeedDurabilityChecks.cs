// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

static class FeedDurabilityChecks
{
    sealed class Provider : HttpMessageHandler
    {
        public int Calls; public string Text = "prior.fixture.test";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken t)
        { Calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Text, Encoding.UTF8, "text/plain") }); }
    }
    public static async Task Crash(string folder, string phase)
    {
        await using var manager = new DdiSecurityManager(folder, new PublicSuffixes(["test"]), new HttpClient(new Provider { Text = "new.fixture.test" }), feedCheckpoint: p => { if (p == phase) Environment.Exit(73); });
        manager.Start(); await Task.Delay(TimeSpan.FromSeconds(10)); Environment.Exit(74);
    }
    public static async Task Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "feed-durability-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        int checks = 0; void Check(bool okay, string why) { if (!okay) throw new Exception(why); checks++; }
        var feed = new EdlFeed("fixture", "Domain", "https://fixture.test/feed", true, RefreshSeconds: 60) { MaximumAgeHours = 1, SourceConfidence = 60, MinimumConfidence = 60 };
        try
        {
            foreach (string phase in new[] { "Fetched", "Validated", "BeforePersist", "Flushed", "Persisted", "Activated" })
            {
                string folder = Path.Combine(root, phase); var transport = new Provider(); byte[] old;
                await using (var seed = new DdiSecurityManager(folder, new PublicSuffixes(["test"]), new HttpClient(transport)))
                { seed.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [feed] }, 0); await seed.RefreshEdlAsync(); old = seed.ExportEdl(); }
                // Delete only this fixture's reservation so the child native worker has an actually due automatic refresh.
                File.Delete(Path.Combine(folder, "security-feed-schedule.json"));
                var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
                start.ArgumentList.Add(typeof(FeedDurabilityChecks).Assembly.Location); start.ArgumentList.Add("--feed-crash"); start.ArgumentList.Add(folder); start.ArgumentList.Add(phase);
                using var process = Process.Start(start); string stdout = await process.StandardOutput.ReadToEndAsync(), stderr = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
                Check(process.ExitCode == 73, "Owned crash checkpoint not reached: " + phase + stdout + stderr);
                await using var cold = new DdiSecurityManager(folder, new PublicSuffixes(["test"]), new HttpClient(new Provider()));
                bool committed = phase is "Persisted" or "Activated";
                var status = cold.EdlStatus().Single(); var snapshot = JsonSerializer.Deserialize<EdlSnapshot[]>(cold.ExportEdl(), DdiSecurityManager.JsonOptions).Single();
                Check((!cold.ExportEdl().SequenceEqual(old)) == committed && snapshot.Values.Single() == (committed ? "new.fixture.test" : "prior.fixture.test"), "Crash cold snapshot mismatch at " + phase);
                Check(status.AttemptOutcome == (committed ? "Succeeded" : "Interrupted") && status.AttemptId?.Length == 32 && status.NextAttempt > DateTime.UtcNow, "Crash receipt did not reconcile with durable commit at " + phase);
                string id = status.AttemptId; await cold.RefreshEdlAsync(scheduled: true); Check(cold.EdlStatus()[0].AttemptId == id, "Crash restart retried before durable due time");
                Check(cold.Evaluate(IPAddress.Loopback, snapshot.Values.Single(), [], []).Matches.Length == 1, "Crash reload did not activate complete generation");
                Console.WriteLine($"Checkpoint {phase}: child PID={process.Id}, exit={process.ExitCode}, outcome={status.AttemptOutcome}, generation={snapshot.CommitId}, digest={snapshot.ContentSha256}");
            }
            var now = DateTime.UtcNow; var provider = new Provider(); string clockFolder = Path.Combine(root, "clock");
            await using (var manager = new DdiSecurityManager(clockFolder, new PublicSuffixes(["test"]), new HttpClient(provider), feedClock: () => now))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [feed, feed with { Id = "second", Enabled = false }] }, 0);
                await manager.RefreshEdlAsync(scheduled: true); int before = provider.Calls;
                Check(manager.EdlStatus()[0].Entries == 1 && manager.EdlStatus()[1].AttemptOutcome == "None", "Inclusive confidence or disabled first-run failed");
                var seeded = JsonSerializer.Deserialize<EdlSnapshot[]>(manager.ExportEdl(), DdiSecurityManager.JsonOptions)[0];
                now = manager.EdlStatus()[0].NextAttempt.Value.AddTicks(-1); await manager.RefreshEdlAsync(scheduled: true); Check(provider.Calls == before, "Refreshed before exact due boundary");
                provider.Text = "unsupported incomplete fixture"; now = now.AddTicks(1); await manager.RefreshEdlAsync(scheduled: true); Check(provider.Calls == before + 1, "Did not refresh at due boundary");
                for (int i = 0; i < 17; i++) { now = manager.EdlStatus()[0].NextAttempt.Value; await manager.RefreshEdlAsync(scheduled: true); }
                Check(manager.EdlStatus()[0].ConsecutiveFailures == 16 && manager.EdlStatus()[0].NextAttempt.Value - now == TimeSpan.FromDays(1), "Backoff count/time cap failed");
                now = seeded.FetchedAt.AddHours(1).AddTicks(-1); Check(manager.EdlStatus()[0].Entries == 1, "Age ended before exact boundary");
                now = now.AddTicks(1); Check(manager.EdlStatus()[0].Entries == 0, "Evidence active at expiry boundary");
                now = now.AddTicks(1); Check(manager.EdlStatus()[0].Entries == 0, "Expired evidence revived");
                now = seeded.FetchedAt; manager.SetPolicy(manager.Policy with { EdlFeeds = [feed with { MinimumConfidence = 61 }] }, manager.Policy.Revision); Check(manager.EdlStatus()[0].Entries == 0, "Below confidence threshold eligible");
                manager.SetPolicy(manager.Policy with { EdlFeeds = [feed with { MinimumConfidence = 59 }] }, manager.Policy.Revision); Check(manager.EdlStatus()[0].Entries == 1, "Above confidence threshold ineligible");
                manager.SetPolicy(manager.Policy with { Enabled = false }, manager.Policy.Revision); Check(manager.EdlStatus()[0].Entries == 0, "Disabled policy reports active evidence");
            }
            Console.WriteLine($"PASS: {checks} deterministic due/age/confidence/backoff and owned process interruption checks. Six actual child-process exits at declared local store boundaries; injected transport layer, no DNS packets or external targets.");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
