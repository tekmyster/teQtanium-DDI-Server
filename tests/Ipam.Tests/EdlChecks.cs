// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Net;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class EdlChecks
{
    sealed class Feed : HttpMessageHandler
    {
        public string Text = "fixture.example\nFIXTURE.EXAMPLE.\n# comment\n";
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string MediaType = "text/plain";
        public int Calls;
        public Func<CancellationToken, Task> Wait;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            if (request.Method != HttpMethod.Get || request.Headers.GetValues("Authorization").Single() != "Bearer fixture-key") throw new Exception("EDL auth/method invalid");
            if (Wait is not null) await Wait(token);
            return new(Status) { Content = new StringContent(Text, Encoding.UTF8, MediaType) };
        }
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-edl-test-" + Guid.NewGuid().ToString("N"));
        const string reference = "DDI_EDL_TEST_API_KEY";
        Environment.SetEnvironmentVariable(reference, "fixture-key");
        int checks = 0;
        void Check(bool condition, string reason) { if (!condition) throw new Exception(reason); checks++; }
        void Reject(Action action, string reason) { try { action(); } catch (Exception ex) when (ex is ArgumentException || ex is FormatException) { checks++; return; } throw new Exception(reason); }
        var suffixes = new PublicSuffixes(["example"]);
        var client = IPAddress.Parse("192.0.2.2"); var feed = new Feed();
        try
        {
            await using var manager = new DdiSecurityManager(Path.Combine(folder, "origin"), suffixes, new HttpClient(feed));
            var source = new EdlFeed("existing", "Domain", "https://provider.test/lists/review.txt", true, ApiKeyEnvironment: reference);
            manager.SetPolicy(SecurityPolicy.Default with { Enabled = true, Mode = "Block", DeviceThreshold = 1, DeviceDnsResponse = "Block", DhcpResponse = "DenyNewLeases", EdlFeeds = [source] }, 0);
            await manager.RefreshEdlAsync();
            Check(manager.EdlStatus().Single().Entries == 1 && manager.Evaluate(client, "fixture.example", [], []).Action == "Monitor", "Default EDL monitor or dedup failed");
            byte[] complete = manager.ExportEdl();
            Check(!Encoding.UTF8.GetString(complete).Contains("fixture-key"), "EDL credential exported");
            Check(manager.Evaluate(client, "sub.fixture.example", [], []).Action == "Allow", "Exact EDL domain expanded to suffix");
            var device = new SecurityDevice("fixture", "client", "02-00-00-00-00-01", "host", "default", "", null);
            manager.DeviceResolver = _ => device;
            var request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("fixture.example", DnsResourceRecordType.A, DnsClass.IN)]);
            var response = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, request.Question);
            Check(manager.InspectResponse(request, new IPEndPoint(client, 1000), response).RCODE == DnsResponseCode.NoError && manager.Signals().Length > 0, "EDL monitor evidence absent from DNS device context");
            Check(!manager.ObserveDhcp(device.Scope, device.ClientIdentifier, device.HardwareAddress, "host", false), "Monitor EDL evidence denied DHCP at low threshold");
            Check(manager.CheckQuery(request, new IPEndPoint(client, 1000)) is null, "Monitor EDL evidence denied subsequent DNS");
            foreach (string invalid in new[] { "*.fixture.example", "https://fixture.example/path", "192.0.2.1", "bad name.example", "good.example\nbad name.example", "<html>sign in</html>", new string('a', 2 * 1024 * 1024 + 1), string.Join('\n', Enumerable.Range(0, 10001).Select(i => "host" + i + ".example")), string.Join('\n', Enumerable.Repeat("# comment", 20001)) })
            {
                feed.Text = invalid; manager.SetPolicy(manager.Policy, manager.Policy.Revision); await manager.RefreshEdlAsync();
                Check(manager.ExportEdl().SequenceEqual(complete) && manager.EdlStatus()[0].Status.Contains("failed"), "Invalid or partial EDL replaced complete snapshot");
            }
            foreach (HttpStatusCode status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Redirect, HttpStatusCode.PartialContent, HttpStatusCode.ServiceUnavailable })
            {
                feed.Status = status; manager.SetPolicy(manager.Policy, manager.Policy.Revision); await manager.RefreshEdlAsync();
                Check(manager.ExportEdl().SequenceEqual(complete), "Failure/partial/redirect replaced EDL snapshot");
            }
            feed.Status = HttpStatusCode.OK; feed.Text = "fixture.example"; feed.MediaType = "text/html";
            manager.SetPolicy(manager.Policy, manager.Policy.Revision); await manager.RefreshEdlAsync();
            Check(manager.ExportEdl().SequenceEqual(complete), "HTML accepted as EDL"); feed.MediaType = "text/plain";
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            feed.Wait = async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); };
            ThreatIndicator imported = manager.Evaluate(client, "fixture.example", [], []).Matches.Single();
            manager.SetPolicy(manager.Policy with { EdlPublications = [new("concurrent", "Domain", [new(imported.Source, imported.Id)], true)] }, manager.Policy.Revision);
            using (var cancel = new CancellationTokenSource())
            {
                Task refreshing = manager.RefreshEdlAsync(cancel.Token); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                int before = feed.Calls; await manager.RefreshEdlAsync();
                Check(feed.Calls == before, "Overlapping EDL refresh reached transport");
                Check(Enumerable.Range(0, 1000).AsParallel().All(_ => manager.Evaluate(client, "fixture.example", [], []).Action == "Monitor"), "Concurrent resolver reads blocked or lost complete cache");
                Check(Enumerable.Range(0, 100).AsParallel().All(_ => manager.PublishEdl("concurrent").Text == "fixture.example\n"), "Concurrent publication exposed incomplete refresh");
                cancel.Cancel(); try { await refreshing; throw new Exception("EDL cancellation ignored"); } catch (OperationCanceledException) { checks++; }
                Check(manager.ExportEdl().SequenceEqual(complete), "Cancelled EDL refresh replaced cache");
            }
            feed.Wait = null;

            var snapshots = JsonSerializer.Deserialize<EdlSnapshot[]>(complete, DdiSecurityManager.JsonOptions);
            await using var peer = new DdiSecurityManager(Path.Combine(folder, "peer"), suffixes);
            peer.RestorePolicy(manager.ExportPolicy()); peer.RestoreEdl(complete);
            Check(peer.Evaluate(client, "fixture.example", [], []).Action == "Monitor", "Replicated EDL missing");
            await using (var restarted = new DdiSecurityManager(Path.Combine(folder, "peer"), suffixes))
                Check(restarted.Evaluate(client, "fixture.example", [], []).Action == "Monitor" && restarted.EdlStatus()[0].Status.Contains("refresh required"), "Restart lost EDL or overstated health");
            foreach (var invalid in new[] { snapshots[0] with { Expires = DateTime.UtcNow.AddDays(8) }, snapshots[0] with { SourceUrl = "http://provider.test" }, snapshots[0] with { Values = ["bad name.example"] } })
                Reject(() => peer.RestoreEdl(JsonSerializer.SerializeToUtf8Bytes(new[] { invalid }, DdiSecurityManager.JsonOptions)), "Invalid replicated EDL accepted");
            peer.RestoreEdl(JsonSerializer.SerializeToUtf8Bytes(new[] { snapshots[0] with { ContentSha256 = "", FetchedAt = DateTime.UtcNow.AddHours(-2), Expires = DateTime.UtcNow.AddHours(-1) } }, DdiSecurityManager.JsonOptions));
            Check(peer.Evaluate(client, "fixture.example", [], []).Action == "Allow" && peer.EdlStatus()[0].Status.Contains("Expired"), "Expired EDL remains active");
            peer.SetPolicy(peer.Policy with { EdlFeeds = [source with { Url = "https://other.test/feed.txt" }] }, peer.Policy.Revision);
            Check(peer.Evaluate(client, "fixture.example", [], []).Action == "Allow", "Source mismatch reused EDL");
            manager.SetPolicy(manager.Policy with { EdlFeeds = [source with { Action = "Block" }] }, manager.Policy.Revision);
            Check(manager.Evaluate(client, "fixture.example", [], []).Action == "Block", "Explicit EDL enforcement not honored");
            manager.SetPolicy(manager.Policy with { Indicators = [new("exemption", "Domain", "fixture.example", "Allow", "Local")] }, manager.Policy.Revision);
            Check(manager.Evaluate(client, "fixture.example", [], []).Action == "Allow", "Local allow precedence lost");

            // Deliberate exact selections only; no event or inventory enumerator is available to publication.
            var local = new ThreatIndicator("publish", "Domain", "selected.example", "Monitor", "Local");
            var url = new ThreatIndicator("url", "Url", "https://selected.example/only-this-path", "Block", "Local");
            var network = new ThreatIndicator("network", "Network", "203.0.113.0/24", "Block", "Local");
            manager.SetPolicy(manager.Policy with { Indicators = [local, url, network, new("private", "Domain", "private-observed.example", "Monitor", "Local"), new("scoped", "Domain", "scoped.example", "Block", "Local", ClientNetwork: "192.0.2.0/24")], EdlPublications = [new("domains", "Domain", [new("Local", "publish"), new("Local", "scoped")], true), new("urls", "Url", [new("Local", "url")], true), new("ips", "Network", [new("Local", "network")], true)] }, manager.Policy.Revision);
            Check(manager.PublishEdl("domains").Text == "selected.example\n", "Publication leaked unselected/scoped evidence");
            Check(manager.PublishEdl("domains").IntendedAction == "Monitor", "Publication default action not Monitor");
            Check(manager.PublishEdl("urls").Text == "https://selected.example/only-this-path\n", "URL path lost in publication");
            Check(manager.PublishEdl("ips").Text == "203.0.113.0/24\n", "Network publication format incorrect");
            Reject(() => manager.PublishEdl("missing"), "Unconfigured public list accepted");
            manager.SetPolicy(manager.Policy with { Indicators = manager.Policy.Indicators.Append(new("allow", "DomainSuffix", "example", "Allow", "Local")).Append(new("allow-net", "Network", "203.0.113.5", "Allow", "Local")).ToArray() }, manager.Policy.Revision);
            Check(manager.PublishEdl("domains").Text.Length == 0 && manager.PublishEdl("ips").Text.Length == 0, "Published lists overrode local exemptions");
            var misp = new ThreatIndicator("misp:selected", "Domain", "misp-selected.example", "Monitor", "MISP", 50, DateTime.UtcNow.AddHours(1));
            manager.SetPolicy(manager.Policy with { Misp = new(true, "https://misp.test"), Indicators = [], EdlPublications = [new("selected-misp", "Domain", [new("MISP", "misp:selected")], true)] }, manager.Policy.Revision);
            manager.RestoreEnrichment(JsonSerializer.SerializeToUtf8Bytes(new MispCache("https://misp.test", [misp]), DdiSecurityManager.JsonOptions));
            Check(manager.PublishEdl("selected-misp").Text == "misp-selected.example\n" && manager.Evaluate(client, "misp-selected.example", [], []).Action == "Monitor", "MISP selected publication mutated action");
            manager.RestoreEnrichment(JsonSerializer.SerializeToUtf8Bytes(new MispCache("https://misp.test", []), DdiSecurityManager.JsonOptions));
            Check(manager.PublishEdl("selected-misp").Text.Length == 0 && manager.PublishEdl("selected-misp").State.Contains("unavailable"), "MISP retraction still published or hidden");
            foreach (var invalid in new[] { source with { Url = "http://provider.test/feed" }, source with { Url = "https://user:pass@provider.test/feed" }, source with { ApiKeyEnvironment = "UNRELATED_SECRET" }, source with { Kind = "Auto" }, source with { Action = "Allow" } })
                Reject(() => manager.SetPolicy(manager.Policy with { EdlFeeds = [invalid] }, manager.Policy.Revision), "Invalid EDL policy accepted");
            feed.Text = ""; manager.SetPolicy(manager.Policy with { EdlFeeds = [source] }, manager.Policy.Revision); await manager.RefreshEdlAsync();
            Check(manager.EdlStatus()[0].Entries == 0 && manager.EdlStatus()[0].Status == "Available" && manager.Evaluate(client, "fixture.example", [], []).Action == "Allow", "Valid empty EDL mistaken for outage or not retracted");
            Console.WriteLine($"PASS: {checks} EDL import, selection/publication, expiry, restart and cross-service assertions (isolated fixtures).");
        }
        finally { Environment.SetEnvironmentVariable(reference, null); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
