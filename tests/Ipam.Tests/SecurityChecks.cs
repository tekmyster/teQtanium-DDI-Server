using DnsServerCore.Security;
using System.Net;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class SecurityChecks
{
    sealed class MispStub : HttpMessageHandler
    {
        public int Calls;
        public bool Fail;
        public bool Empty;
        public string LastBody;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++; LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
            if (!request.Headers.TryGetValues("Authorization", out var keys) || keys.Single() != "test-key") throw new Exception("Missing MISP authentication header");
            return new HttpResponseMessage(Fail ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK)
            {
                Content = new StringContent(Empty ? "{\"response\":{\"Attribute\":[]}}" : """
                    {"response":{"Attribute":[
                      {"uuid":"00000000-0000-4000-8000-000000000001","type":"domain","value":"misp.example","event_id":"42","to_ids":true,"timestamp":"1720000000","Tag":[{"name":"tlp:green"}]},
                      {"uuid":"00000000-0000-4000-8000-000000000002","type":"ip-dst","value":"203.0.113.4","to_ids":false},
                      {"uuid":"00000000-0000-4000-8000-000000000003","type":"url","value":"https://legit.example/specific-bad-path","to_ids":true},
                      {"uuid":"00000000-0000-4000-8000-000000000004","type":"domain","value":"deleted.example","deleted":"1","to_ids":true}
                    ]}}
                    """, Encoding.UTF8, "application/json")
            };
        }
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-security-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        int checks = 0;
        void Check(bool condition, string reason) { if (!condition) throw new Exception(reason); checks++; }
        void Reject(Action action, string reason)
        { try { action(); } catch (ArgumentException) { checks++; return; } catch (InvalidOperationException) { checks++; return; } throw new Exception(reason); }
        PublicSuffixes suffixes = new(["com", "example", "co.uk", "github.io", "*.ck", "!www.ck"]);
        Check(suffixes.RegistrableDomain("a.b.example.co.uk") == "example.co.uk", "Multi-label public suffix grouping failed");
        Check(suffixes.RegistrableDomain("a.project.github.io") == "project.github.io", "Private hosting suffix grouping failed");
        Check(suffixes.RegistrableDomain("x.a.b.ck") == "a.b.ck", "Wildcard public suffix grouping failed");
        Check(suffixes.RegistrableDomain("x.www.ck") == "www.ck", "Exception public suffix grouping failed");
            Check(PublicSuffixes.Normalize("BÜCHER.EXAMPLE.") == "xn--bcher-kva.example", "IDN normalization failed");
        Check(BehavioralAnalyzer.Entropy("aaaaaaaa") == 0, "Entropy of repeated character failed");
        var behavior = new BehavioralAnalyzer(suffixes);
        DateTime now = DateTime.UtcNow;
        Check(behavior.Observe("client", "abcdefghijklmnopqrstuvwxyz0123456789.bad.example", "TXT", true, now).Score == 0, "One unusual query is treated as exfiltration");
        BehavioralScore benign = null;
        for (int i = 0; i < 120; i++) benign = behavior.Observe("normal", "api.service.example", "A", false, now);
        Check(benign.Score < 70, "Repeated ordinary lookups exceed alert threshold");
        BehavioralScore suspicious = null;
        for (int i = 0; i < 80; i++) suspicious = behavior.Observe("suspicious", $"abcdefghijklmnopqrstuvwxyz0123456789{i:D4}.leak.example", "TXT", true, now);
        Check(suspicious.Score >= 70 && suspicious.Contributions.Length >= 3 && suspicious.Confidence == "Uncalibrated", "Synthetic exfiltration-like traffic lacks explained risk");
        Check(behavior.Observe("suspicious", "ordinary.leak.example", "A", false, now.AddMinutes(61)).Score == 0, "Window does not expire");
        var client = IPAddress.Parse("192.0.2.10");
        try
        {
            await using var manager = new DdiSecurityManager(Path.Combine(folder, "east1"), suffixes);
            manager.NodeName = () => "east1.example";
            SecurityPolicy policy = SecurityPolicy.Default with { Indicators = [new("domain", "Domain", "bad.example", "Block", "Local"), new("suffix", "DomainSuffix", "suffix.example", "Block", "Local"), new("ip", "Network", "203.0.113.0/24", "Block", "Local"), new("v6", "Network", "2001:db8:bad::/48", "Block", "Local"), new("url", "Url", "https://path.example/malicious", "Block", "Local"), new("expired", "Domain", "expired.example", "Block", "Local", Expires: now.AddMinutes(-1))] };
            manager.SetPolicy(policy, 0);
            Check(manager.Evaluate(client, "bad.example", [], []).Action == "Allow", "Disabled module modifies decisions");
            manager.SetPolicy(manager.Policy with { Enabled = true }, 1);
            Check(manager.Evaluate(client, "BAD.EXAMPLE.", [], []).Action == "Monitor", "Monitor mode blocks traffic");
            manager.SetPolicy(manager.Policy with { Mode = "Block", InspectAuthoritative = true }, 2);
            Check(manager.Evaluate(client, "bad.example", [], []).Action == "Block", "Exact domain does not block");
            Check(manager.Evaluate(client, "sub.bad.example", [], []).Action == "Allow", "Exact match incorrectly expands to subdomains");
            Check(manager.Evaluate(client, "a.suffix.example", [], []).Action == "Block", "Explicit suffix match failed");
            Check(manager.Evaluate(client, "notsuffix.example", [], []).Action == "Allow", "Suffix label boundary failed");
            Check(manager.Evaluate(client, "expired.example", [], []).Action == "Allow", "Expired indicator still enforced");
            Check(manager.Evaluate(client, "path.example", [], []).Action == "Allow", "URL path blocks entire hostname");
            Check(manager.Evaluate(client, "safe.example", ["bad.example"], []).Action == "Block", "CNAME threat match failed");
            Check(manager.Evaluate(client, "safe.example", [], [IPAddress.Parse("203.0.113.99")]).Action == "Block", "Resolved IPv4 network match failed");
            Check(manager.Evaluate(client, "safe.example", [], [IPAddress.Parse("::ffff:203.0.113.99")]).Action == "Block", "Mapped IPv6 answer bypasses IPv4 reputation");
            Check(manager.Evaluate(client, "safe.example", [], [IPAddress.Parse("2001:db8:bad::1")]).Action == "Block", "Resolved IPv6 network match failed");
            Reject(() => manager.SetPolicy(manager.Policy, 0), "Stale security revision accepted");
            Reject(() => manager.SetPolicy(manager.Policy with { Indicators = [new("x", "Domain", "bad.example", "Unknown", "test")] }, 3), "Invalid indicator action accepted");
            manager.SetPolicy(manager.Policy with { Indicators = manager.Policy.Indicators.Append(new("allow", "Domain", "safe.example", "Allow", "Local", ClientNetwork: "192.0.2.0/24")).ToArray() }, 3);
            Check(manager.Evaluate(client, "safe.example", ["bad.example"], [IPAddress.Parse("203.0.113.99")]).Action == "Allow", "Query exception does not suppress this module's matches");
            Check(manager.Evaluate(IPAddress.Parse("198.51.100.1"), "safe.example", ["bad.example"], []).Action == "Block", "Client-scoped exception leaked outside its network");
            Check(manager.Evaluate(IPAddress.Parse("::ffff:192.0.2.10"), "safe.example", ["bad.example"], []).Action == "Allow", "IPv4-mapped source scoping failed");
            DnsDatagram request = new(12, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [new DnsQuestionRecord("ordinary.example", DnsResourceRecordType.A, DnsClass.IN)]);
            DnsResourceRecord good = new("ordinary.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.5")));
            DnsResourceRecord unrelated = new("unrelated.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("203.0.113.5")));
            DnsDatagram original = new(12, true, DnsOpcode.StandardQuery, false, false, true, true, true, true, DnsResponseCode.NoError, request.Question, [good], null, [unrelated]);
            Check(ReferenceEquals(manager.InspectResponse(request, new IPEndPoint(client, 1234), original), original), "Additional-section glue caused a false block");
            DnsResourceRecord bad = new("ordinary.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("203.0.113.5")));
            DnsDatagram malicious = original.Clone([bad], null, null);
            var device = new SecurityDevice("East", "client-1", "02-00-00-00-00-01", "host", "view", "East DC", 10);
            manager.DeviceResolver = _ => device;
            var blocked = manager.InspectResponse(request, new IPEndPoint(client, 1234), malicious);
            Check(blocked.RCODE == DnsResponseCode.Refused && !blocked.AuthenticData && blocked.CheckingDisabled && blocked.Answer.Count == 0, "Rewritten block flags or answers incorrect");
            Check(manager.RecentEvents().Any(e => e.Device?.Site == "East DC"), "Security evidence lacks DDI context");
            Check(manager.Signals().Length == 1 && manager.Signals()[0].Score == 100, "DNS IoC was not shared as device risk");
            Check(!manager.ObserveDhcp("East", "client-1", device.HardwareAddress, "host", false), "Default DHCP response disconnects clients");
            manager.SetPolicy(manager.Policy with { DhcpResponse = "DenyNewLeases", DeviceDnsResponse = "Block" }, 4);
            Check(manager.ObserveDhcp("East", "client-1", device.HardwareAddress, "host", false), "Opt-in DHCP response ignores DNS IoC");
            Check(!manager.ObserveDhcp("East", "client-1", device.HardwareAddress, "host", true), "New-lease response denies an existing lease renewal");
            Check(!manager.ObserveDhcp("East", "other-client", device.HardwareAddress, "host", false), "IoC attached to wrong DHCP client identity");
            Check(manager.InspectResponse(request, new IPEndPoint(client, 1234), original).RCODE == DnsResponseCode.Refused, "Shared device response does not protect subsequent DNS queries");
            Check(manager.CheckQuery(request, new IPEndPoint(client, 1234))?.RCODE == DnsResponseCode.Refused, "Known device risk is checked only after recursive resolution");
            await using var east2 = new DdiSecurityManager(Path.Combine(folder, "east2"), suffixes);
            await using var west = new DdiSecurityManager(Path.Combine(folder, "west"), suffixes);
            east2.RestorePolicy(manager.ExportPolicy()); west.RestorePolicy(manager.ExportPolicy());
            Check(east2.MergeSignals(manager.Signals()) == 1 && west.MergeSignals(manager.Signals()) == 1, "Signals did not propagate to three-node store model");
            Check(east2.MergeSignals(manager.Signals()) == 0, "Duplicate signal was replayed");
            Check(west.ObserveDhcp("East", "client-1", device.HardwareAddress, "host", false), "Regional DHCP consumer cannot see DNS IoC");
            var beforeRemoval = manager.Policy;
            manager.SetPolicy(manager.Policy with { Indicators = manager.Policy.Indicators.Where(i => i.Id != "ip").ToArray() }, manager.Policy.Revision);
            Check(!manager.ObserveDhcp("East", "client-1", device.HardwareAddress, "host", false), "Removed indicator continues restricting DHCP through an old signal");
            manager.SetPolicy(beforeRemoval, manager.Policy.Revision);
            Reject(() => west.MergeSignals([manager.Signals()[0] with { Expires = now.AddDays(1) }]), "Unbounded signal lifetime accepted");
            Check(west.MergeSignals([manager.Signals()[0] with { Id = new string('a', 64), Timestamp = now.AddMinutes(-20), Expires = now.AddMinutes(-10) }]) == 0, "Expired signal resurrected");
            for (int i = 0; i < 100; i++) manager.ObserveDhcp("West", "chatty-client", "02-00-00-00-00-02", "chatty", false);
            Check(manager.Signals().Any(s => s.Service == "DHCP"), "DHCP anomaly absent from shared evidence");
            var stub = new MispStub();
            Environment.SetEnvironmentVariable("DDI_MISP_TEST_API_KEY", "test-key");
            await using var misp = new DdiSecurityManager(Path.Combine(folder, "misp"), suffixes, new HttpClient(stub));
            misp.SetPolicy(SecurityPolicy.Default with { Enabled = true, Mode = "Block", Misp = new MispSettings(true, "https://misp.test/", "DDI_MISP_TEST_API_KEY") }, 0);
            await misp.RefreshMispAsync();
            Check(stub.Calls == 1 && misp.MispStatus.Indicators == 3, "MISP pagination or normalization failed");
            Check(stub.LastBody.Contains("restSearch") == false && stub.LastBody.Contains("page"), "MISP request pagination absent");
            Check(misp.Evaluate(client, "misp.example", [], []).Action == "Monitor", "MISP enrichment is automatically enforced");
            misp.DeviceResolver = _ => device;
            DnsDatagram mispRequest = new(14, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("misp.example", DnsResourceRecordType.A, DnsClass.IN)]);
            DnsDatagram mispResponse = new(14, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, mispRequest.Question, [new DnsResourceRecord("misp.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("203.0.113.4")))]);
            Check(misp.InspectResponse(mispRequest, new IPEndPoint(client, 4444), mispResponse).RCODE == DnsResponseCode.NoError && misp.Signals().Any(s => s.Score == 50), "MISP monitor evidence is not shared with the device signal store");
            Check(!misp.ObserveDhcp(device.Scope, device.ClientIdentifier, device.HardwareAddress, "host", false) && misp.RecentEvents().Any(e => e.Service == "DHCP"), "DHCP is unaware of lower-confidence MISP evidence");
            Check(misp.Evaluate(client, "deleted.example", [], []).Action == "Allow", "Deleted MISP attribute imported");
            Check(misp.Evaluate(client, "legit.example", [], []).Action == "Allow", "MISP URL path overblocks host");
            int before = stub.Calls;
            for (int i = 0; i < 20; i++) misp.Evaluate(client, "misp.example", [], []);
            Check(stub.Calls == before, "DNS evaluation performs live MISP calls");
            stub.Fail = true; await misp.RefreshMispAsync();
            Check(misp.Evaluate(client, "misp.example", [], []).Action == "Monitor" && misp.MispStatus.Status.Contains("last complete"), "MISP outage discarded last valid cache");
            west.SetPolicy(west.Policy with { Misp = misp.Policy.Misp }, west.Policy.Revision);
            west.RestoreEnrichment(misp.ExportEnrichment());
            Check(west.Evaluate(client, "misp.example", [], []).Action == "Monitor", "Replicated enrichment not visible on peer");
            west.SetPolicy(west.Policy with { Misp = west.Policy.Misp with { Url = "https://different-misp.test/" } }, west.Policy.Revision);
            Check(west.Evaluate(client, "misp.example", [], []).Action == "Allow", "Old MISP source cache remains active after source change");
            stub.Fail = false; stub.Empty = true; await misp.RefreshMispAsync();
            Check(misp.Evaluate(client, "misp.example", [], []).Action == "Allow", "Successful feed retraction leaves stale match");
            Check(misp.Signals().Length == 0, "Retracted MISP evidence continues to influence device signals");
            Reject(() => misp.SetPolicy(misp.Policy with { Misp = new(true, "http://misp.test", "DDI_MISP_TEST_API_KEY") }, misp.Policy.Revision), "Unencrypted MISP endpoint accepted");
            Reject(() => misp.SetPolicy(misp.Policy with { Misp = new(true, "https://misp.test", "AWS_SECRET_ACCESS_KEY") }, misp.Policy.Revision), "Unrelated environment secret can be used as a MISP credential");
            manager.PublishSignals = (_, _) => Task.FromException(new IOException("Simulated bad link"));
            manager.Start();
            await Task.Delay(500);
            Check(manager.SignalStatus.DeliveryErrors > 0 && manager.Signals().Length > 0, "Bad link discarded device evidence or hid sync failure");
            var delivered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            manager.PublishSignals = (signals, _) => { east2.MergeSignals(signals); west.MergeSignals(signals); delivered.TrySetResult(true); return Task.CompletedTask; };
            await delivered.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Check(west.Signals().Any(s => s.Service == "DHCP") && east2.Signals().Any(s => s.Service == "DNS"), "Signal retry did not recover after a bad link");
            Console.WriteLine($"PASS: {checks} security model, cross-service signal, three-store replication, and mocked MISP checks.");
        }
        finally
        {
            Environment.SetEnvironmentVariable("DDI_MISP_TEST_API_KEY", null);
            if (Path.GetDirectoryName(folder) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) throw new Exception("Unexpected test directory");
            Directory.Delete(folder, true);
        }
    }
}
