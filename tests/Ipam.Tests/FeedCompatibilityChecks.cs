// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Net;
using System.Text;
using System.Text.Json;

static class FeedCompatibilityChecks
{
    sealed class Provider : HttpMessageHandler
    {
        public string Text = "one.fixture.test"; public bool FailFirst; public TaskCompletionSource Entered, Release;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken t)
        {
            Entered?.TrySetResult(); if (Release is not null) await Release.Task.WaitAsync(t);
            return new(FailFirst && r.RequestUri.AbsolutePath == "/first" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK) { Content = new StringContent(Text, Encoding.UTF8, "text/plain") };
        }
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "feed-compatibility-" + Guid.NewGuid().ToString("N")); int checks = 0;
        void Check(bool okay, string why) { if (!okay) throw new Exception(why); checks++; }
        void Reject(Action a, string why) { try { a(); } catch (Exception ex) when (ex is ArgumentException or IOException or InvalidOperationException or UnauthorizedAccessException) { checks++; return; } throw new Exception(why); }
        var provider = new Provider(); var first = new EdlFeed("first", "Domain", "https://fixture.test/first", true); var second = first with { Id = "second", Url = "https://fixture.test/second" };
        try
        {
            await using var manager = new DdiSecurityManager(folder, new PublicSuffixes(["test"]), new HttpClient(provider));
            manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [first, second], Indicators = [new("local", "Domain", "manual.fixture.test", "Monitor", "Local")] }, 0);
            await manager.RefreshEdlAsync(); byte[] old = manager.ExportEdl();
            provider.FailFirst = true; provider.Text = "two.fixture.test"; await manager.RefreshEdlAsync();
            var snapshots = JsonSerializer.Deserialize<EdlSnapshot[]>(manager.ExportEdl(), DdiSecurityManager.JsonOptions);
            Check(snapshots.Single(s => s.FeedId == "first").Values.Single() == "one.fixture.test" && snapshots.Single(s => s.FeedId == "second").Values.Single() == "two.fixture.test", "Failure prevented healthy next source refresh or replaced failed source");
            Check(manager.Evaluate(IPAddress.Loopback, "manual.fixture.test", [], []).Matches.Length == 1, "Feed failure removed independent manual evidence");
            string current = manager.EdlRevision; byte[] before = manager.ExportEdl();
            string cachePath = Path.Combine(folder, "security-edl.json"); byte[] disk = File.ReadAllBytes(cachePath); File.Delete(cachePath); Directory.CreateDirectory(cachePath);
            Reject(() => manager.RollbackEdl(old, manager.Policy.Revision, current), "Unavailable rollback destination accepted");
            Check(manager.EdlRevision == current && manager.ExportEdl().SequenceEqual(before), "Failed rollback changed generation/index"); Directory.Delete(cachePath); File.WriteAllBytes(cachePath, disk);
            await using (var cold = new DdiSecurityManager(folder, new PublicSuffixes(["test"]))) Check(cold.ExportEdl().SequenceEqual(before), "Failed rollback cold durable readback differs");
            Reject(() => manager.RollbackEdl(old, manager.Policy.Revision, current, () => false), "Revoked rollback authorization accepted");
            provider.FailFirst = false; provider.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously); provider.Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Task active = manager.RefreshEdlAsync(feedId: "first"); await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); manager.RollbackEdl(old, manager.Policy.Revision, current); string rolled = manager.EdlRevision; provider.Release.TrySetResult(); await active;
            Check(manager.EdlRevision == rolled, "Old in-flight refresh replaced explicit rollback"); provider.Entered = provider.Release = null;
            foreach (var changed in new[] { first with { Enabled = false }, first with { Url = "https://fixture.test/new" }, first with { Kind = "Network" }, first with { ApiKeyEnvironment = "DDI_EDL_NEW_API_KEY" }, first with { Id = "renamed" } })
            { manager.SetPolicy(manager.Policy with { EdlFeeds = [changed] }, manager.Policy.Revision); Check(manager.Evaluate(IPAddress.Loopback, "one.fixture.test", [], []).Matches.Length == 0, "Changed source binding reused old generation"); }
            manager.SetPolicy(manager.Policy with { EdlFeeds = [] }, manager.Policy.Revision); Check(manager.Evaluate(IPAddress.Loopback, "one.fixture.test", [], []).Matches.Length == 0, "Deleted source retained active rules");
            manager.SetPolicy(manager.Policy with { EdlFeeds = [first] }, manager.Policy.Revision);
            string legacy = JsonSerializer.Serialize(new[] { new { FeedId = first.Id, Kind = first.Kind, SourceUrl = first.Url, FetchedAt = DateTime.UtcNow.AddMinutes(-5), Expires = DateTime.UtcNow.AddHours(1), Values = new[] { "legacy.fixture.test" } } }, DdiSecurityManager.JsonOptions);
            manager.RestoreEdl(Encoding.UTF8.GetBytes(legacy));
            Check(manager.EdlStatus()[0].IntegrityState == "LegacyUnchecked" && manager.EdlStatus()[0].Entries == 1 && manager.EdlStatus()[0].ValidatedAt is null, "Legacy migration invented digest/validation or lost evidence");
            await using (var cold = new DdiSecurityManager(folder, new PublicSuffixes(["test"]))) Check(cold.EdlStatus()[0].IntegrityState == "LegacyUnchecked" && cold.Evaluate(IPAddress.Loopback, "legacy.fixture.test", [], []).Matches.Length == 1, "Legacy cold migration failed");
            provider.Text = ""; await manager.RefreshEdlAsync(); Check(manager.EdlStatus()[0].Entries == 0 && manager.EdlStatus()[0].IntegrityState == "VerifiedSha256", "Explicit empty plain snapshot not committed");
            var rpz = first with { Format = "RpzQnameNxdomain", RpzZone = "policy.test" }; manager.SetPolicy(manager.Policy with { EdlFeeds = [rpz] }, manager.Policy.Revision);
            provider.Text = "$ORIGIN policy.test.\n; comment only\n"; await manager.RefreshEdlAsync(); Check(manager.EdlStatus()[0].Entries == 0, "Explicit empty RPZ fragment not committed");
            provider.Text = "$ORIGIN policy.test.\nONE.fixture.test CNAME .\none.fixture.test.policy.test. IN CNAME .\n"; await manager.RefreshEdlAsync(); Check(manager.EdlStatus()[0].Entries == 1 && manager.Evaluate(IPAddress.Loopback, "sub.one.fixture.test", [], []).Matches.Length == 0, "Canonical RPZ duplicate or exact-only semantics failed");
            before = manager.ExportEdl(); provider.Text = "; missing required origin"; await manager.RefreshEdlAsync(); Check(before.SequenceEqual(manager.ExportEdl()), "Missing-origin comment-only input cleared prior snapshot");
            Console.WriteLine($"PASS: {checks} whole-store rollback/persistence/source-binding/legacy/empty/duplicate/fairness checks (injected transport; owned local stores).");
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
