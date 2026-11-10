// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Net;
using System.Text;
using System.Text.Json;

static class FeedReconciliationChecks
{
    sealed class Provider : HttpMessageHandler
    {
        public int Calls;
        public string Text = "one.fixture.test";
        public HttpStatusCode Status = HttpStatusCode.OK;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        { Calls++; return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Text, Encoding.UTF8, "text/plain") }); }
    }
    public static async Task Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "feed-reconciliation-" + Guid.NewGuid().ToString("N"));
        int checks = 0;
        void Check(bool okay, string why) { if (!okay) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
        var feed = new EdlFeed("one", "Domain", "https://fixture.test/one", true, RefreshSeconds: 60);
        var suffixes = new PublicSuffixes(["test"]);
        try
        {
            // Establish the exact visibility contract before changing the native assertion:
            // Activated is after snapshot/index activation and before separate terminal status persistence.
            string orderingFolder = Path.Combine(root, "ordering");
            using var release = new ManualResetEventSlim();
            var activated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using (var manager = new DdiSecurityManager(orderingFolder, suffixes, new HttpClient(new Provider()), feedCheckpoint: phase =>
            {
                if (phase == "Activated") { activated.TrySetResult(); if (!release.Wait(TimeSpan.FromSeconds(10))) throw new Exception("Ordering fixture release timed out"); }
            }))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [feed] }, 0);
                Task refresh = Task.Run(() => manager.RefreshEdlAsync());
                try
                {
                    await activated.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    var visible = manager.EdlStatus().Single();
                    using var disk = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(orderingFolder, "security-feed-schedule.json")));
                    Check(visible.AttemptOutcome == "Succeeded" && visible.AttemptCompletedAt is null && visible.ConsecutiveFailures == 0, "committed receipt is visible before terminal completion timestamp");
                    Check(disk.RootElement.GetProperty("one").GetProperty("outcome").GetString() == "Running", "separate durable reservation remains Running at Activated checkpoint");
                    Check(manager.Evaluate(IPAddress.Loopback, "one.fixture.test", [], []).Matches.Length == 1, "activated snapshot is consumable while terminal status is pending");
                }
                finally { release.Set(); await refresh; }
                var terminal = manager.EdlStatus().Single();
                using var completed = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(orderingFolder, "security-feed-schedule.json")));
                Check(terminal.AttemptCompletedAt.HasValue && completed.RootElement.GetProperty("one").GetProperty("outcome").GetString() == "Succeeded", "normal terminal save subsequently persists completion timestamp and outcome");
            }
            string folder = Path.Combine(root, "recovery"), schedule = Path.Combine(folder, "security-feed-schedule.json");
            var provider = new Provider(); DateTime now = DateTime.UtcNow; bool failTerminal = false; byte[] reservation = null; string committedId = null; DateTime? reservedDue = null;
            await using (var manager = new DdiSecurityManager(folder, suffixes, new HttpClient(provider), () => now, phase =>
            {
                if (phase == "Activated" && failTerminal)
                {
                    reservation = File.ReadAllBytes(schedule); File.Delete(schedule); Directory.CreateDirectory(schedule);
                }
            }))
            {
                manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [feed] }, 0);
                await manager.RefreshEdlAsync(); byte[] first = manager.ExportEdl();
                provider.Status = HttpStatusCode.ServiceUnavailable;
                for (int i = 0; i < 3; i++) await manager.RefreshEdlAsync();
                Check(manager.EdlStatus()[0].ConsecutiveFailures == 3 && first.SequenceEqual(manager.ExportEdl()), "three HTTP failures retain prior snapshot and failure history");
                provider.Status = HttpStatusCode.OK; provider.Text = "two.fixture.test"; failTerminal = true;
                await manager.RefreshEdlAsync();
                var status = manager.EdlStatus()[0]; committedId = status.AttemptId; reservedDue = status.NextAttempt;
                Check(status.AttemptOutcome == "Succeeded" && status.ConsecutiveFailures == 0 && status.AttemptCompletedAt is null, "status-write fault preserves truthful committed success without invented completion time");
                Check(manager.Evaluate(IPAddress.Loopback, "two.fixture.test", [], []).Matches.Length == 1, "committed generation activates despite terminal status-write fault");
                using var held = JsonDocument.Parse(reservation);
                Check(held.RootElement.GetProperty("one").GetProperty("failures").GetInt32() == 4 && held.RootElement.GetProperty("one").GetProperty("outcome").GetString() == "Running", "retained exact reservation contains pre-terminal raw count four");
                Directory.Delete(schedule); File.WriteAllBytes(schedule, reservation); failTerminal = false;
            }
            await using (var cold = new DdiSecurityManager(folder, suffixes, new HttpClient(provider), () => now))
            {
                var recovered = cold.EdlStatus()[0];
                Check(recovered.AttemptOutcome == "Succeeded" && recovered.ConsecutiveFailures == 0 && recovered.AttemptId == committedId && recovered.NextAttempt == reservedDue, "cold receipt reconciles success while retaining exact conservative due reservation");
                Check(cold.Evaluate(IPAddress.Loopback, "two.fixture.test", [], []).Matches.Length == 1, "cold index consumes the committed complete generation");
                provider.Status = HttpStatusCode.ServiceUnavailable; int before = provider.Calls;
                now = reservedDue.Value.AddTicks(-1); await cold.RefreshEdlAsync(scheduled: true);
                Check(provider.Calls == before && cold.EdlStatus()[0].AttemptId == committedId, "cold scheduler does not shorten retained conservative due time");
                now = reservedDue.Value; await cold.RefreshEdlAsync(scheduled: true); var failed = cold.EdlStatus()[0];
                Console.WriteLine($"RECONCILIATION next failure count={failed.ConsecutiveFailures}; actual due delay={(failed.NextAttempt - now)?.TotalSeconds}; outcome={failed.AttemptOutcome}");
                Check(provider.Calls == before + 1 && failed.AttemptOutcome == "Failed" && failed.ConsecutiveFailures == 1 && failed.NextAttempt - now == TimeSpan.FromSeconds(60), "first post-recovery failure starts count one and 60-second backoff");
                DateTime next = failed.NextAttempt.Value; string failedId = failed.AttemptId;
                now = next.AddTicks(-1); await cold.RefreshEdlAsync(scheduled: true);
                Check(provider.Calls == before + 1 && cold.EdlStatus()[0].AttemptId == failedId, "actual scheduler holds first failure until its 60-second due time");
                now = next; await cold.RefreshEdlAsync(scheduled: true);
                Check(provider.Calls == before + 2 && cold.EdlStatus()[0].ConsecutiveFailures == 2 && cold.EdlStatus()[0].NextAttempt - now == TimeSpan.FromSeconds(120), "next actual due failure advances to count two and 120 seconds");
                now = DateTime.UtcNow; provider.Status = HttpStatusCode.OK; provider.Text = "three.fixture.test"; await cold.RefreshEdlAsync();
                Check(cold.EdlStatus()[0].ConsecutiveFailures == 0 && cold.EdlStatus()[0].AttemptCompletedAt.HasValue, "ordinary subsequent success resets durable failure history");
                var changed = feed with { Url = "https://fixture.test/changed" };
                cold.SetPolicy(cold.Policy with { EdlFeeds = [changed] }, cold.Policy.Revision);
                Check(cold.EdlStatus()[0].AttemptOutcome == "None" && cold.EdlStatus()[0].Entries == 0, "changed source and full configuration do not inherit committed receipt");
                provider.Status = HttpStatusCode.ServiceUnavailable; await cold.RefreshEdlAsync(scheduled: true);
                Check(cold.EdlStatus()[0].ConsecutiveFailures == 1 && cold.EdlStatus()[0].NextAttempt - now == TimeSpan.FromSeconds(60), "new source configuration starts its own failure history");
            }
            Console.WriteLine($"PASS: {checks} receipt reconciliation and precise status visibility assertions; owned injected-transport store fixture. PID={Environment.ProcessId}; config={root}");
        }
        finally
        {
            string resolved = Path.GetFullPath(root); if (!resolved.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(resolved).StartsWith("feed-reconciliation-")) throw new Exception("Unexpected fixture cleanup path");
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
            Console.WriteLine("Owned reconciliation fixture removed=" + !Directory.Exists(resolved));
        }
    }
}
