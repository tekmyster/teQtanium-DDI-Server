using DnsServerCore;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.Dns;
using DnsServerCore.HttpApi;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static partial class DistributedTransportChecks
{
    static int Port()
    {
        // DNS uses both transports; Windows can reserve a UDP port while TCP remains available.
        for (int attempt = 0; attempt < 100; attempt++)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            try
            {
                listener.Start();
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch (SocketException) { }
            finally { listener.Stop(); }
        }
        throw new IOException("Could not find a loopback port available for both TCP and UDP.");
    }
    sealed class PinnedHandler : HttpClientHandler
    {
        public string LoseLifecycleResponse;
        public bool LoseCapacityResponse;
        public bool Disconnected;
        public string LoseVotingResponse;
        public Action<string> AfterVotingResponse;
        public bool Stall;
        public string LoseMigrationResponse;
        public Action<string> AfterOwnershipResponse;
        public PinnedHandler(X509Certificate2 certificate)
        { string expected = certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256); ServerCertificateCustomValidationCallback = (_, actual, _, _) => actual is not null && actual.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256) == expected; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Stall) await Task.Delay(Timeout.Infinite, cancellationToken);
            if (Disconnected) throw new HttpRequestException("Simulated disconnected replication link");
            var response = await base.SendAsync(request, cancellationToken);
            if (request.RequestUri.AbsolutePath.Contains("/voting/")) AfterVotingResponse?.Invoke(request.RequestUri.AbsolutePath.Split('/').Last());
            if (LoseVotingResponse is not null && request.RequestUri.AbsolutePath.EndsWith("/voting/" + LoseVotingResponse)) { LoseVotingResponse = null; response.Dispose(); throw new HttpRequestException("Voting reply lost after durable native processing"); }
            if (LoseLifecycleResponse is not null && request.RequestUri.AbsolutePath.EndsWith("/grants/"+LoseLifecycleResponse)) { LoseLifecycleResponse=null; response.Dispose(); throw new HttpRequestException("Lifecycle reply lost after durable mutation"); }
            if (LoseCapacityResponse && request.RequestUri.AbsolutePath.EndsWith("/dhcp/grant")) { LoseCapacityResponse=false; response.Dispose(); throw new HttpRequestException("Capacity reply lost after durable grant"); }
            if (request.RequestUri.AbsolutePath.Contains("/changes/")) AfterOwnershipResponse?.Invoke(request.RequestUri.AbsolutePath.Split('/').Last());
            if (LoseMigrationResponse is not null && request.RequestUri.AbsolutePath.EndsWith("/changes/" + LoseMigrationResponse, StringComparison.Ordinal))
            { LoseMigrationResponse = null; response.Dispose(); throw new HttpRequestException("Ownership response lost after remote durable processing"); }
            if (LoseMigrationResponse is not null && request.RequestUri.AbsolutePath.EndsWith("/migration/" + LoseMigrationResponse, StringComparison.Ordinal))
            {
                LoseMigrationResponse = null; response.Dispose(); throw new HttpRequestException("Migration response lost after remote durable processing");
            }
            return response;
        }
    }
    static T Field<T>(object instance, string name) => (T)instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(instance);
    static async Task<JsonElement> Call(HttpClient client, string path, params (string Key, string Value)[] fields)
    {
        using var response = await client.PostAsync(path, new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value))));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
    }
    public static async Task Run(bool serve = false, bool ownershipOnly = false, bool capacityOnly = false, bool votingOnly = false)
    {
        string folder = capacityOnly ? Environment.GetEnvironmentVariable("TEQTANIUM_CAPACITY_ROOT") ?? Path.Combine(Path.GetTempPath(), "ddi-transport-tests-" + Guid.NewGuid().ToString("N")) : Path.Combine(Path.GetTempPath(), "ddi-transport-tests-" + Guid.NewGuid().ToString("N"));
        if (votingOnly && Environment.GetEnvironmentVariable("TEQTANIUM_VOTING_ROOT") is string votingRoot) folder = votingRoot;
        if (Path.GetDirectoryName(folder) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar) || !(Path.GetFileName(folder).StartsWith("ddi-transport-tests-") || Path.GetFileName(folder).StartsWith("ddi-capacity-kill-"))) throw new Exception("Unexpected fixture directory");
        Directory.CreateDirectory(folder);
        var services = new List<DnsWebService>(); var originals = new List<HttpClient>(); var freshAdmins = new List<HttpClient>(); var tlsClients = new List<HttpClient>(); var peerApis = new List<HttpApiClient>();
        int nodeCount = votingOnly ? 6 : 3;
        string[] names = Enumerable.Range(1, nodeCount).Select(n => "127.0.0." + n).ToArray(); int[] tlsPorts = new int[nodeCount]; string[] serviceTokens = new string[nodeCount]; string[] passwords = new string[nodeCount]; var certificates = new X509Certificate2[nodeCount];
        string[] variables = ["DNS_SERVER_ADMIN_PASSWORD", "DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "DNS_SERVER_WEB_SERVICE_HTTP_PORT", "DNS_SERVER_WEB_SERVICE_HTTPS_PORT", "DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS", "DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT", "DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT", "DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH"];
        var originalEnvironment = variables.ToDictionary(n => n, Environment.GetEnvironmentVariable); int checks = 0;
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; }
        try
        {
            string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
            for (int index = 0; index < nodeCount; index++)
            {
                string config = Path.Combine(folder, "node-" + index); Directory.CreateDirectory(config); int httpPort = Port(); tlsPorts[index] = Port(); passwords[index] = capacityOnly ? "Isolated-Capacity-Fixture1!" : Guid.NewGuid().ToString("N") + "Aa!9";
                if (votingOnly) passwords[index] = "Isolated-Voting-Fixture1!";
                string fixturePorts=Path.Combine(config,"capacity-ports.json");
                if((capacityOnly || votingOnly) && File.Exists(fixturePorts)) { var saved=JsonSerializer.Deserialize<int[]>(File.ReadAllText(fixturePorts));httpPort=saved[0];tlsPorts[index]=saved[1]; }
                else if(capacityOnly || votingOnly) File.WriteAllText(fixturePorts,JsonSerializer.Serialize(new[]{httpPort,tlsPorts[index]}));
                Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", passwords[index]); Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
                Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", httpPort.ToString()); Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTPS_PORT", tlsPorts[index].ToString());
                Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS", "true"); Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT", "true"); Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT", "false");
                Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
                await using (var log = new LogManager(true, config)) using (var dns = new DnsServer(config, Path.Combine(repository, "DnsServerCore/dohwww"), log))
                { dns.LoadConfigFile(); dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, Port())]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
                var service = new DnsWebService(true, config); services.Add(service); await service.StartAsync(true);
                var original = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + httpPort) }; originals.Add(original);
                var login = await Call(original, "/api/user/login", ("user", "admin"), ("pass", passwords[index])); Check(login.GetProperty("status").GetString() == "ok", "Original administrative login failed");
                original.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
                certificates[index] = (X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
                var tls = new HttpClient(new PinnedHandler(certificates[index])) { BaseAddress = new Uri("https://127.0.0.1:" + tlsPorts[index]) }; tlsClients.Add(tls);
                // The fixture establishes enrolled membership explicitly; cluster enrollment/DANE remains a separate test.
                object auth = Field<object>(service, "_authManager"); Type sessionType = auth.GetType().Assembly.GetType("DnsServerCore.Auth.UserSessionType");
                var createSession = auth.GetType().GetMethods().Single(m => m.Name == "CreateSession" && m.GetParameters()[2].ParameterType == typeof(string));
                var session = createSession.Invoke(auth, [Enum.Parse(sessionType, "ClusterApiToken"), "isolated-replication-lab", "admin", IPAddress.Loopback, "DDI transport test"]);
                serviceTokens[index] = (string)session.GetType().GetProperty("Token").GetValue(session);
                tls.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", serviceTokens[index]);
            }
            var linkHandlers = new List<PinnedHandler>();
            var links = new Dictionary<(int Source, int Target), PinnedHandler>();
            for (int index = 0; index < nodeCount; index++)
            {
                var manager = Field<ClusterManager>(services[index], "_clusterManager"); var nodes = new Dictionary<int, ClusterNode>();
                for (int peer = 0; peer < nodeCount; peer++)
                {
                    var node = new ClusterNode(manager, peer + 1, new Uri("https://" + names[peer] + ":" + tlsPorts[peer]), [IPAddress.Loopback], peer == 0 ? ClusterNodeType.Primary : ClusterNodeType.Secondary, peer == index ? ClusterNodeState.Self : ClusterNodeState.Connected); nodes.Add(peer + 1, node);
                    if (peer == index) continue;
                    var api = new HttpApiClient(node.Url, ipv6Mode: IPv6Mode.Disabled); peerApis.Add(api);
                    var pinned = new PinnedHandler(certificates[peer]); linkHandlers.Add(pinned);
                    links[(index, peer)] = pinned;
                    var transport = new HttpClient(pinned) { BaseAddress = new Uri("https://127.0.0.1:" + tlsPorts[peer]), Timeout = TimeSpan.FromSeconds(3) };
                    Field<HttpClient>(api, "_httpClient").Dispose(); typeof(HttpApiClient).GetField("_httpClient", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(api, transport); api.UseApiToken(serviceTokens[peer]);
                    typeof(ClusterNode).GetField("_apiClient", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(node, api);
                }
                typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(manager, nodes);
            }
            for (int index = 0; index < nodeCount; index++)
            {
                // Fresh transport sessions authenticate with the new token and exercise its required write privilege.
                Check((await Call(tlsClients[index], "/api/ddi/dhcp/state/get")).GetProperty("status").GetString() == "ok", "Fresh TLS cluster token read failed");
                using (var plaintext = new HttpClient { BaseAddress = originals[index].BaseAddress })
                {
                    plaintext.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", serviceTokens[index]);
                    Check((await Call(plaintext, "/api/ddi/dhcp/state/get")).GetProperty("status").GetString() == "error", "Direct service token can read allocation state over HTTP");
                }
                var empty = new AllocationState(1, [], []);
                Check((await Call(tlsClients[index], "/api/ddi/dhcp/state/ingest", ("state", JsonSerializer.Serialize(empty, DistributedAllocation.JsonOptions)))).GetProperty("status").GetString() == "ok", "Fresh TLS cluster token write failed");
                Check((await Call(tlsClients[index], "/api/ddi/dhcp/state/ingest?actingUser=admin", ("state", JsonSerializer.Serialize(empty, DistributedAllocation.JsonOptions)))).GetProperty("status").GetString() == "error", "Proxied session can ingest evidence");
                var fresh = new HttpClient(new PinnedHandler(certificates[index])) { BaseAddress = tlsClients[index].BaseAddress }; freshAdmins.Add(fresh);
                var login = await Call(fresh, "/api/user/login", ("user", "admin"), ("pass", passwords[index])); Check(login.GetProperty("status").GetString() == "ok", "Fresh administrator TLS authentication failed");
                fresh.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
                Check((await Call(fresh, "/api/ddi/dhcp/state/get")).GetProperty("status").GetString() == "ok", "Fresh administrator lacks DHCP view access");
                Check((await Call(fresh, "/api/dhcp/scopes/set", ("name", "Default"), ("domainName", "lab.example"))).GetProperty("status").GetString() == "ok", "Fresh administrator lacks DHCP modify access");
            }
            if (votingOnly) { await CheckVoting(services, originals, freshAdmins, tlsClients, names, links, folder, Check); Console.WriteLine($"PASS: {checks} native voting and isolated-owner checks"); return; }
            if (capacityOnly) { Environment.SetEnvironmentVariable("TEQTANIUM_CAPACITY_ADMIN_PROOF", passwords[1]); await CheckCapacity(services, originals, freshAdmins, tlsClients, names, links, Check); Console.WriteLine($"PASS: {checks} native capacity checks"); return; }
            if (ownershipOnly)
            {
                await CheckOwnershipChanges(services, originals, freshAdmins, tlsClients, names, passwords, links, Check);
                Console.WriteLine($"PASS: {checks} bounded native ownership checks; no production effects"); return;
            }
            await CheckIngestionBoundaries(services[0], tlsClients[0], originals[0], freshAdmins[0], Check);
            if (Environment.GetEnvironmentVariable("TEQTANIUM_SYNC_BASELINE") == "1") { await CheckCapturedIngestion(services, tlsClients, Check); Console.WriteLine($"PASS: {checks} baseline native HTTPS parser reproduction checks"); return; }
            await CheckLiveMigration(services, originals, freshAdmins, tlsClients, names, disconnected => links[(0, 2)].Disconnected = disconnected, action => links[(0, 2)].LoseMigrationResponse = action, Check);
            var bootstrap = await Call(originals[0], "/api/ddi/dhcp/plan/set", ("scope", "Default"), ("owners", string.Join(',', names)));
            Check(bootstrap.GetProperty("status").GetString() == "ok", "Live TLS bootstrap failed: " + bootstrap);
            var stores = services.Select(s => Field<DistributedAllocation>(s, "_allocation")).ToArray();
            var promotionRejected = await Call(freshAdmins[1], "/api/admin/cluster/secondary/promote", ("forceDeletePrimary", "true"), ("retainFencedPrimary", "true"));
            Check(promotionRejected.GetProperty("status").GetString() == "error" && promotionRejected.GetProperty("errorMessage").GetString().Contains("durable capacity handoff"), "Fenced promotion accepts incomplete owner surrender");
            Check((await Call(tlsClients[1], "/api/ddi/dhcp/recoverFencedOwner", ("owner", names[0]), ("state", "{}"))).GetProperty("status").GetString() == "error", "Cluster service token can impersonate the administrative recovery controller");
            Check((await Call(freshAdmins[1], "/api/ddi/dhcp/recoverFencedOwner", ("owner", names[0]), ("state", JsonSerializer.Serialize(stores[0].Snapshot() with { Replicas = [] }, DistributedAllocation.JsonOptions)))).GetProperty("status").GetString() == "error", "Recovery accepts absent owner grants");
            var fencedNode = new ClusterNode(Field<ClusterManager>(services[1], "_clusterManager"), 900, new Uri("https://fenced.lab.example:53443"), [IPAddress.Loopback], ClusterNodeType.Secondary, ClusterNodeState.Fenced);
            using (var fencedBytes = new MemoryStream())
            {
                using (var writer = new BinaryWriter(fencedBytes, Encoding.UTF8, true)) fencedNode.WriteTo(writer);
                fencedBytes.Position = 0;
                using var reader = new BinaryReader(fencedBytes, Encoding.UTF8, true);
                using var restoredFenced = new ClusterNode(Field<ClusterManager>(services[1], "_clusterManager"), reader);
                restoredFenced.InitializeHeartbeatTimer();
                Check(restoredFenced.IsFenced && restoredFenced.State == ClusterNodeState.Fenced && Field<object>(restoredFenced, "_heartbeatTimer") is null, "Restart reactivates a fenced peer heartbeat");
                try { await restoredFenced.GetAllocationStateAsync(); throw new Exception("Fenced peer service API was called"); }
                catch (InvalidOperationException) { Check(true, "Fenced peer API withheld"); }
            }
            fencedNode.Dispose();
            var primaryManager = Field<ClusterManager>(services[0], "_clusterManager");
            var originalNodes = Field<Dictionary<int, ClusterNode>>(primaryManager, "_clusterNodes");
            var protectedOwner = new ClusterNode(primaryManager, 2, originalNodes[2].Url, originalNodes[2].IPAddresses, ClusterNodeType.Secondary, ClusterNodeState.Fenced);
            var protectedNodes = new Dictionary<int, ClusterNode>(originalNodes) { [2] = protectedOwner };
            typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(primaryManager, protectedNodes);
            try
            {
                var deletion = await Call(freshAdmins[0], "/api/admin/cluster/primary/deleteSecondary", ("secondaryNodeId", "2"));
                Check(deletion.GetProperty("status").GetString() == "error" && deletion.GetProperty("errorMessage").GetString().Contains("anchors DHCP ownership"), "Fenced owner can be removed while its authority epoch still depends on membership");
            }
            finally
            {
                typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(primaryManager, originalNodes);
                protectedOwner.Dispose();
            }
            Check(stores.Select(s => s.Plan("Default").Epoch).Distinct().Count() == 1, "Owners installed different allocation epochs");
            var sequence = new AllocationSequence(stores[0].Plan("Default")); uint address = sequence.Candidates(names[0]).First(); DateTime expiry = DateTime.UtcNow.AddHours(1);
            Check(stores[0].Hold("Default", address, "1-0201", "02-01", "client.lab.example", expiry), "Live owner hold failed"); stores[0].Commit("Default", address, "1-0201", "02-01", "client.lab.example", expiry);
            var synchronize = typeof(DnsWebService).GetMethod("SynchronizeAllocation", BindingFlags.Instance | BindingFlags.NonPublic);
            await (Task)synchronize.Invoke(services[0], [CancellationToken.None]);
            Check(stores[1].ResolveLive(address)?.Lease.Client == "1-0201" && stores[2].ResolveLive(address)?.Lease.Client == "1-0201", "Live HTTPS replication did not reach three servers");
            var primaryScope = Field<DhcpServer>(services[0], "_dhcpServer").GetScope("Default");
            primaryScope.DomainName = "updated.lab.example"; primaryScope.LeaseTimeDays = 0; primaryScope.LeaseTimeHours = 2;
            await (Task)synchronize.Invoke(services[0], [CancellationToken.None]);
            await (Task)synchronize.Invoke(services[1], [CancellationToken.None]); await (Task)synchronize.Invoke(services[2], [CancellationToken.None]);
            Check(services.Skip(1).All(s => Field<DhcpServer>(s, "_dhcpServer").GetScope("Default").DomainName == "updated.lab.example" && Field<DhcpServer>(s, "_dhcpServer").GetScope("Default").LeaseTimeHours == 2), "Shared scope options do not synchronize over actual HTTPS");
            Check(services.All(s => !Field<DhcpServer>(s, "_dhcpServer").GetScope("Default").Enabled), "Configuration synchronization activated a local DHCP listener");
            Check(stores.All(s => s.Snapshot().Configurations?.Single(configuration => configuration.Scope == "Default").Revision >= 1), "Applied configuration revisions are missing");
            Field<DhcpServer>(services[1], "_dhcpServer").GetScope("Default").DomainName = "local-drift.example";
            await (Task)synchronize.Invoke(services[1], [CancellationToken.None]);
            Check(Field<DhcpServer>(services[1], "_dhcpServer").GetScope("Default").DomainName == "updated.lab.example", "Equal-revision desired configuration does not reconcile local option drift");
            // Drive replication explicitly so a background pass cannot relay around
            // the deliberately stalled fixture links during the negative assertion.
            foreach (var store in stores) { Field<CancellationTokenSource>(store, "_stop").Cancel(); await (Field<Task>(store, "_worker") ?? Task.CompletedTask); }
            foreach (var link in links) if (link.Key.Source == 2 || link.Key.Target == 2) link.Value.Stall = true;
            uint partialAddress = sequence.Candidates(names[0]).Skip(2).First();
            stores[0].Commit("Default", partialAddress, "1-0204", "02-04", "partial.lab.example", expiry);
            var timeoutClock = System.Diagnostics.Stopwatch.StartNew(); bool timedOut = false;
            try { await (Task)synchronize.Invoke(services[0], [CancellationToken.None]); } catch (IOException) { timedOut = true; }
            Console.WriteLine($"Partial peer stall observed failure={timedOut} elapsedMs={timeoutClock.ElapsedMilliseconds}; existing three-second deadline retained");
            Check(timedOut && timeoutClock.Elapsed < TimeSpan.FromSeconds(8), "Stalled ingestion did not observe the existing bounded deadline");
            Check(stores[1].ResolveLive(partialAddress) is not null && stores[2].ResolveLive(partialAddress) is null && stores[0].FindLease("Default", "1-0204") is not null, "Partial failure lost authority or pretended all peers converged");
            foreach (var link in links) link.Value.Stall = false;
            await (Task)synchronize.Invoke(services[0], [CancellationToken.None]);
            Check(stores[2].ResolveLive(partialAddress) is not null, "Stalled peer did not converge on retry");
            foreach (var handler in linkHandlers) handler.Disconnected = true;
            uint secondAddress = sequence.Candidates(names[0]).Skip(1).First();
            Check(stores[0].Hold("Default", secondAddress, "1-0202", "02-02", "isolated.lab.example", expiry), "Disconnected owner cannot allocate independently"); stores[0].Commit("Default", secondAddress, "1-0202", "02-02", "isolated.lab.example", expiry);
            try { await (Task)synchronize.Invoke(services[0], [CancellationToken.None]); } catch (IOException) { }
            Check(stores[1].ResolveLive(secondAddress) is null && stores[0].FindLease("Default", "1-0202") is not null, "Failed delivery lost local evidence or pretended convergence");
            foreach (var handler in linkHandlers) handler.Disconnected = false;
            await (Task)synchronize.Invoke(services[0], [CancellationToken.None]);
            Check(stores[1].ResolveLive(secondAddress) is not null && stores[2].ResolveLive(secondAddress) is not null, "Reconnect failed to converge over actual HTTPS endpoints");
            foreach (var link in links) if (link.Key.Source == 0 || link.Key.Target == 0) link.Value.Disconnected = true;
            uint secondaryAddress = sequence.Candidates(names[1]).First();
            stores[1].Hold("Default", secondaryAddress, "1-0303", "03-03", "secondary.lab.example", expiry); stores[1].Commit("Default", secondaryAddress, "1-0303", "03-03", "secondary.lab.example", expiry);
            try { await (Task)synchronize.Invoke(services[1], [CancellationToken.None]); } catch (IOException) { }
            Check(stores[2].ResolveLive(secondaryAddress)?.Lease.Client == "1-0303", "Secondary peers cannot exchange leases when the configuration primary is unreachable");
            foreach (var handler in linkHandlers) handler.Disconnected = false;
            var grant = await Call(tlsClients[1], "/api/ddi/dhcp/grant", ("scope", "Default"), ("borrower", names[0]), ("requestId", Guid.NewGuid().ToString("N")));
            Check(grant.GetProperty("status").GetString() == "ok" && grant.GetProperty("response").GetProperty("state").ValueKind == JsonValueKind.Object, "Live donor grant endpoint failed");
            stores[0].Merge(Encoding.UTF8.GetBytes(grant.GetProperty("response").GetProperty("state").GetRawText()));
            Check(stores[0].GrantedAddresses("Default").Length == 1, "Live donor authority not usable by borrower");
            long donorSequence = stores[0].Snapshot().Replicas.Single(r => r.Scope == "Default" && r.Node == names[0]).Sequence;
            string handoffId = Guid.NewGuid().ToString("N");
            var parameters = new (string, string)[] { ("scope", "Default"), ("receiver", names[2]), ("addresses", AllocationSequence.Address(address).ToString()), ("requestId", handoffId), ("expectedSequence", donorSequence.ToString()) };
            Check((await Call(tlsClients[0], "/api/ddi/dhcp/handoff", parameters)).GetProperty("status").GetString() == "error", "Service token can initiate an administrative handoff");
            links[(0, 2)].Disconnected = true;
            var handoff = await Call(originals[0], "/api/ddi/dhcp/handoff", parameters);
            Check(handoff.GetProperty("status").GetString() == "ok" && !handoff.GetProperty("response").GetProperty("receiverAcknowledged").GetBoolean(), "Lost receiver link does not report durable surrender separately");
            Check(!stores[0].HasAuthority("Default", address) && !stores[2].HasAuthority("Default", address), "Failed delivery restores donor authority or invents receiver authority");
            links[(0, 2)].Disconnected = false;
            handoff = await Call(originals[0], "/api/ddi/dhcp/handoff", parameters);
            Check(handoff.GetProperty("status").GetString() == "ok" && handoff.GetProperty("response").GetProperty("receiverAcknowledged").GetBoolean(), "Same handoff cannot retry delivery over HTTPS");
            Check(stores[2].FindLease("Default", "1-0201")?.Expires == expiry && stores[2].ResolveLive(address)?.Node == names[2], "Receiving native server loses inherited lease or shared identity");
            await (Task)synchronize.Invoke(services[0], [CancellationToken.None]);
            Check(stores[1].ResolveLive(address)?.Node == names[2] && !stores[1].Available("Default", address, "other"), "Third server is unaware of the new lease authority");
            Check((await Call(originals[0], "/api/zones/create", ("zone", "lab.example"), ("type", "Primary"))).GetProperty("status").GetString() == "ok", "Handoff DNS cleanup fixture failed");
            services[0].DnsServer.AuthZoneManager.SetRecords("lab.example", [new DnsResourceRecord("client.lab.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(AllocationSequence.Address(address)))]);
            primaryScope.DomainName = "lab.example"; primaryScope.DnsUpdates = true;
            Field<DhcpServer>(services[0], "_dhcpServer").RemoveDnsEntries(primaryScope, Lease.Recover(stores[2].FindLease("Default", "1-0201"), false));
            var remainingRecords = new List<DnsResourceRecord>(); services[0].DnsServer.AuthZoneManager.ListAllZoneRecords("lab.example", [DnsResourceRecordType.A], remainingRecords);
            Check(remainingRecords.Any(r => r.Name == "client.lab.example"), "Expired donor lease cleanup deletes the recipient's DNS record");
            await CheckUnusedRecoveryTransport(services, originals, freshAdmins, tlsClients, names, Check);
            await CheckCapturedIngestion(services, tlsClients, Check);
            Console.WriteLine($"PASS: {checks} three-server certificate-pinned HTTPS replication, bootstrap, authentication, link failure, grant and unused-owner recovery checks; loopback fresh read/modify sessions verified.");
            if (serve)
            {
                string connectionFile = Path.Combine(AppContext.BaseDirectory, "lab-connection.json");
                File.WriteAllText(connectionFile, JsonSerializer.Serialize(new { url = originals[0].BaseAddress.ToString(), user = "admin", password = passwords[0], configFolder = folder }));
                Console.WriteLine("Isolated three-server UI lab ready; connection details saved under test output directory.");
                string stopFile = connectionFile + ".stop";
                try { while (!File.Exists(stopFile)) await Task.Delay(250); }
                finally { File.Delete(connectionFile); if (File.Exists(stopFile)) File.Delete(stopFile); }
            }
        }
        finally
        {
            // Roll back temporary service credentials before releasing original sessions, including failed tests.
            for (int index = 0; index < serviceTokens.Length && index < services.Count; index++)
                if (serviceTokens[index] is not null) Field<DnsServerCore.Auth.AuthManager>(services[index], "_authManager").DeleteSession(serviceTokens[index]);
            // Original administrative sessions remain open through every fresh-session check.
            foreach (var client in freshAdmins) client.Dispose(); foreach (var client in tlsClients) client.Dispose(); foreach (var original in originals) original.Dispose();
            foreach (var service in services) await service.DisposeAsync(); foreach (var api in peerApis) api.Dispose();
            Environment.SetEnvironmentVariable("TEQTANIUM_CAPACITY_ADMIN_PROOF", null);
            foreach (var pair in originalEnvironment) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            if (Path.GetDirectoryName(folder) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) throw new Exception("Unexpected lab directory");
            if (!votingOnly || Environment.GetEnvironmentVariable("TEQTANIUM_VOTING_ROOT") is null) Directory.Delete(folder, true);
        }
    }
    static async Task CheckIngestionBoundaries(DnsWebService service, HttpClient token, HttpClient plaintext, HttpClient admin, Action<bool, string> check)
    {
        static string EncodedValue(int length)
        {
            const string start = "{\"version\":1,\"plans\":[],\"replicas\":[],\"padding\":\"";
            const string end = "\"}";
            int overhead = Uri.EscapeDataString(start + end).Length;
            int remaining = length - overhead;
            return start + new string('!', remaining / 3) + new string('a', remaining % 3) + end;
        }
        byte[] before = Field<DistributedAllocation>(service, "_allocation").Export();
        bool baseline = Environment.GetEnvironmentVariable("TEQTANIUM_SYNC_BASELINE") == "1";
        foreach (int delta in new[] {-1, 0, 1})
        {
            string state = EncodedValue(4 * 1024 * 1024 + delta);
            using var form = new FormUrlEncodedContent(new Dictionary<string,string>{{"state",state}});
            check((await form.ReadAsByteArrayAsync()).Length - 6 == 4 * 1024 * 1024 + delta, "Encoded boundary fixture is inexact");
            var result = await Call(token, "/api/ddi/dhcp/state/ingest", ("state", state));
            bool ok = result.GetProperty("status").GetString() == "ok";
            Console.WriteLine($"Native authenticated ingestion encodedValue={4 * 1024 * 1024 + delta} decodedBytes={Encoding.UTF8.GetByteCount(state)} status={result.GetProperty("status").GetString()}" + (ok ? "" : " category=" + result.GetProperty("errorMessage").GetString()));
            check(ok == (!baseline || delta <= 0), "Native ingestion boundary outcome is incorrect");
        }
        if (baseline) return;
        string large = EncodedValue(5 * 1024 * 1024);
        check((await Call(admin, "/api/ddi/dhcp/state/ingest", ("state", large))).GetProperty("status").GetString() == "error", "Administrative session bypasses cluster ingestion restriction");
        check((await Call(token, "/api/ddi/dhcp/state/ingest?actingUser=admin", ("state", large))).GetProperty("status").GetString() == "error", "Proxied session bypasses direct service restriction");
        check((await Call(plaintext, "/api/ddi/dhcp/state/ingest", ("state", large))).GetProperty("status").GetString() == "error", "Plaintext session accepts ingestion");
        var certificate = (X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        using (var unauthenticated = new HttpClient(new PinnedHandler(certificate)) { BaseAddress = token.BaseAddress })
        {
            foreach (string credential in new[] { "", new string('0',64) })
            {
                unauthenticated.DefaultRequestHeaders.Authorization = credential == "" ? null : new AuthenticationHeaderValue("Bearer", credential);
                check((await Call(unauthenticated, "/api/ddi/dhcp/state/ingest", ("state", large))).GetProperty("status").GetString() != "ok", "Missing/invalid bearer credential acquired ingestion allowance");
            }
            object auth = Field<object>(service, "_authManager");
            Type kind = auth.GetType().Assembly.GetType("DnsServerCore.Auth.UserSessionType");
            var create = auth.GetType().GetMethods().Single(m => m.Name == "CreateSession" && m.GetParameters()[2].ParameterType == typeof(string));
            var expired = create.Invoke(auth, [Enum.Parse(kind,"Standard"), null, "admin", IPAddress.Loopback, "Expired isolated fixture"]);
            expired.GetType().GetField("_lastSeen", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(expired, DateTime.UtcNow.AddYears(-10));
            check((bool)expired.GetType().GetMethod("HasExpired").Invoke(expired, null), "Expired fixture did not expire");
            unauthenticated.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (string)expired.GetType().GetProperty("Token").GetValue(expired));
            check((await Call(unauthenticated, "/api/ddi/dhcp/state/ingest", ("state", large))).GetProperty("status").GetString() != "ok", "Expired session acquired ingestion allowance");
        }
        var unrelated = await Call(token, "/api/ddi/dhcp/prepare", ("state", large));
        check(unrelated.GetProperty("status").GetString() == "error" && unrelated.GetProperty("errorMessage").GetString().Contains("4194304"), "Unrelated form route limit changed");
        const string prefix = "{\"version\":1,\"plans\":[],\"replicas\":[],\"padding\":\"";
        const string suffix = "\"}";
        foreach (int delta in new[] {-1, 0, 1})
        {
            string state = prefix + new string('!', 8 * 1024 * 1024 + delta - prefix.Length - suffix.Length) + suffix;
            var outcome = await Call(token, "/api/ddi/dhcp/state/ingest", ("state", state));
            bool ok = outcome.GetProperty("status").GetString() == "ok";
            check(ok == (delta <= 0), "Decoded allocation boundary outcome is incorrect");
            if (!ok) check(outcome.GetProperty("errorMessage").GetString().Contains("8 MiB"), "Decoded limit did not reject oversized state");
            Console.WriteLine($"Native authenticated ingestion decodedBytes={8 * 1024 * 1024 + delta} status={outcome.GetProperty("status").GetString()}");
        }
        int unicodeTarget = 8 * 1024 * 1024 + 1;
        int available = unicodeTarget - prefix.Length - suffix.Length;
        string unicode = prefix + new string('\u20ac', available / 3) + new string('a', available % 3) + suffix;
        check(unicode.Length < 8 * 1024 * 1024 && Encoding.UTF8.GetByteCount(unicode) == unicodeTarget, "UTF-8 fixture does not distinguish characters from bytes");
        var unicodeResult = await Call(token, "/api/ddi/dhcp/state/ingest", ("state", unicode));
        check(unicodeResult.GetProperty("status").GetString() == "error" && unicodeResult.GetProperty("errorMessage").GetString().Contains("8 MiB"), "UTF-8 byte limit was replaced by a character limit");
        // Send an oversized declared body without streaming it: ordinary HttpClient
        // can surface a write reset when Kestrel rejects it before body transmission.
        using (var socket = new TcpClient())
        {
            await socket.ConnectAsync(IPAddress.Loopback, token.BaseAddress.Port);
            string expectedPin = certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            using var tls = new System.Net.Security.SslStream(socket.GetStream(), false, (_, actual, _, _) => actual is not null && actual.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256) == expectedPin);
            await tls.AuthenticateAsClientAsync("127.0.0.1");
            string headers = "POST /api/ddi/dhcp/state/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + (3 * 8 * 1024 * 1024 + 7) + "\r\nAuthorization: " + token.DefaultRequestHeaders.Authorization + "\r\nConnection: close\r\n\r\n";
            await tls.WriteAsync(Encoding.ASCII.GetBytes(headers));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var response = new MemoryStream(); byte[] buffer = new byte[4096]; int read;
            while ((read = await tls.ReadAsync(buffer, timeout.Token)) > 0) { await response.WriteAsync(buffer.AsMemory(0,read)); if(response.Length > 65536) throw new Exception("Unexpected oversized rejection response"); }
            string error = Encoding.UTF8.GetString(response.ToArray());
            check(error.Contains("413") || error.Contains("Request body too large"), "Encoded ingestion body cap was not enforced");
            Console.WriteLine("Encoded cap native TLS response=" + error.Split('\n')[0].Trim() + "; category=RequestBodyTooLarge; no body sent");
        }
        check((await Call(token, "/api/ddi/dhcp/state/get")).GetProperty("status").GetString() == "ok", "Normal authenticated request failed after oversized-body rejection");
        check(Field<DistributedAllocation>(service, "_allocation").Export().SequenceEqual(before), "Boundary/auth rejection tests mutated allocation state");
        Console.WriteLine("Native ingestion negative checks PASS: missing/invalid/expired/admin/plaintext/proxied credentials; unrelated form; UTF-8 bytes; encoded body cap; allocation state unchanged");
    }
    static async Task CheckCapturedIngestion(List<DnsWebService> services, List<HttpClient> clients, Action<bool, string> check)
    {
        string folder = Environment.GetEnvironmentVariable("TEQTANIUM_SYNC_CAPTURE_DIRECTORY");
        if (folder is null) return;
        var captures = new List<AllocationState>();
        foreach (string ip in new[] {"10.81.60.226", "10.81.60.227"})
        {
            using var json = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(folder, $"current-{ip}-allocation-private.json")));
            captures.Add(JsonSerializer.Deserialize<AllocationState>(json.RootElement.GetProperty("state").GetRawText(), DistributedAllocation.JsonOptions));
        }
        for (int i = 0; i < 2; i++)
        {
            var store = Field<DistributedAllocation>(services[i], "_allocation");
            var manager = Field<ClusterManager>(services[i], "_clusterManager");
            var nodes = Field<Dictionary<int, ClusterNode>>(manager, "_clusterNodes");
            int id = 100;
            foreach (string name in captures.SelectMany(c => c.Replicas.Select(r => r.Node)).Distinct())
                nodes.Add(++id, new ClusterNode(manager, id, new Uri("https://" + name + ":53443"), [IPAddress.Loopback], ClusterNodeType.Secondary, ClusterNodeState.Fenced));
            // Local fixture identity is distinct; exact production captures remain peer evidence.
            store.Merge(JsonSerializer.SerializeToUtf8Bytes(captures[i], DistributedAllocation.JsonOptions), true);
            string incoming = JsonSerializer.Serialize(captures[1-i], DistributedAllocation.JsonOptions);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var response = await Call(clients[i], "/api/ddi/dhcp/state/ingest", ("state", incoming));
            clock.Stop();
            if (Environment.GetEnvironmentVariable("TEQTANIUM_SYNC_BASELINE") == "1")
            {
                check(response.GetProperty("status").GetString() == "error" && response.GetProperty("errorMessage").GetString().Contains("4194304"), "Baseline capture did not reproduce native encoded-value parser failure");
                Console.WriteLine($"Captured receiver={i} baseline native HTTPS ingestion rejected: {response.GetProperty("errorMessage").GetString()}");
                continue;
            }
            check(response.GetProperty("status").GetString() == "ok", "Exact captured publication failed native authenticated ingestion");
            var applied = store.Snapshot();
            foreach (var expected in captures.SelectMany(c => c.Replicas).GroupBy(r => (r.Scope,r.Node)).Select(g => g.MaxBy(r => r.Sequence)))
                check(JsonSerializer.Serialize(applied.Replicas.Single(r => r.Scope == expected.Scope && r.Node == expected.Node), DistributedAllocation.JsonOptions) == JsonSerializer.Serialize(expected, DistributedAllocation.JsonOptions), "Native ingestion lost captured journal/grant/recovery content");
            Console.WriteLine($"Captured receiver={i} native HTTPS ingestion PASS elapsedMs={clock.ElapsedMilliseconds}; exact latest replica content preserved");
        }
    }
    static async Task CheckUnusedRecoveryTransport(List<DnsWebService> services, List<HttpClient> originals, List<HttpClient> admins, List<HttpClient> tokens, string[] names, Action<bool, string> check)
    {
        const string scopeName = "UnusedRecovery";
        var stores = services.Select(s => Field<DistributedAllocation>(s, "_allocation")).ToArray();
        var scopes = new List<Scope>();
        foreach (var service in services)
        {
            var server = Field<DhcpServer>(service, "_dhcpServer");
            var scope = new Scope(scopeName, false, IPAddress.Parse("198.19.1.1"), IPAddress.Parse("198.19.1.18"), IPAddress.Parse("255.255.255.0"), Field<LogManager>(service, "_log"), server) { IgnoreClientIdentifierOption = true, DnsUpdates = false };
            await server.AddScopeAsync(scope); scopes.Add(scope);
        }
        var plan = scopes[0].BuildAllocationPlan(Guid.NewGuid().ToString("N"), "unused-https", names);
        foreach (var store in stores) store.AddPlan(plan);
        uint held = new AllocationSequence(plan).Candidates(names[2]).First();
        stores[2].Commit(scopeName, held, "1-0203", "02-03", "held.lab.example", DateTime.UtcNow.AddHours(1));
        string id = Guid.NewGuid().ToString("N");
        stores[2].RecoverUnusedCapacity(scopeName, [names[0], names[1]], id, stores[2].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[2]).Sequence);
        string state = JsonSerializer.Serialize(stores[2].Snapshot(), DistributedAllocation.JsonOptions);
        (string Key, string Value)[] fields = [("owner", names[2]), ("scope", scopeName), ("recoveryId", id), ("state", state)];
        check((await Call(tokens[0], "/api/ddi/dhcp/recoverUnusedOwner", fields)).GetProperty("status").GetString() == "error", "Cluster service token can authorize fenced unused recovery");
        check((await Call(originals[0], "/api/ddi/dhcp/recoverUnusedOwner", fields)).GetProperty("status").GetString() == "error", "Plain HTTP can authorize unused recovery");
        check((await Call(admins[2], "/api/ddi/dhcp/recoverUnusedOwner", fields)).GetProperty("status").GetString() == "error", "Failed owner imports its own recovery as a survivor");
        for (int receiver = 0; receiver < 2; receiver++)
        {
            var response = await Call(admins[receiver], "/api/ddi/dhcp/recoverUnusedOwner", fields);
            check(response.GetProperty("status").GetString() == "ok", "Direct TLS administrative unused recovery failed: " + response);
            check((await Call(admins[receiver], "/api/ddi/dhcp/recoverUnusedOwner", fields)).GetProperty("status").GetString() == "ok", "Lost import response cannot retry the same recovery");
            check(!stores[receiver].HasAuthority(scopeName, held), "Unused recovery imports a live donor lease as free capacity");
        }
        uint[] first = stores[0].GrantedAddresses(scopeName), second = stores[1].GrantedAddresses(scopeName);
        check(first.Length == 3 && second.Length == 2 && !first.Intersect(second).Any(), "HTTPS unused recovery does not divide five addresses disjointly across two survivors");
        var snapshot = stores[2].Snapshot(); var donor = snapshot.Replicas.Single(r => r.Scope == scopeName && r.Node == names[2]);
        var invalid = snapshot with { Replicas = snapshot.Replicas.Where(r => r != donor).Append(donor with { UnusedRecoveries = [donor.UnusedRecoveries[0] with { Receivers = [names[1], names[0]] }] }).ToArray() };
        check((await Call(admins[0], "/api/ddi/dhcp/recoverUnusedOwner", ("owner", names[2]), ("scope", scopeName), ("recoveryId", id), ("state", JsonSerializer.Serialize(invalid, DistributedAllocation.JsonOptions)))).GetProperty("status").GetString() == "error", "HTTPS importer accepts a conflicting recovered division");
        check(scopes.All(s => !s.Enabled) && stores.All(s => s.Plan(scopeName).Owners.SequenceEqual(plan.Owners)), "Recovery changes serving roles or stable owner membership");
    }
    static async Task CheckLiveMigration(List<DnsWebService> services, List<HttpClient> originals, List<HttpClient> admins, List<HttpClient> peers, string[] names, Action<bool> disconnectLast, Action<string> loseLastResponse, Action<bool, string> check)
    {
        var servers = services.Select(service => Field<DhcpServer>(service, "_dhcpServer")).ToArray();
        var stores = services.Select(service => Field<DistributedAllocation>(service, "_allocation")).ToArray();
        var scopes = servers.Select((server, index) => new Scope("Live", false, IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.90"), IPAddress.Parse("255.255.255.0"), Field<LogManager>(services[index], "_log"), server)
        { DnsUpdates = false, PingCheckEnabled = false, IgnoreClientIdentifierOption = true, DomainName = "migration.lab.example", LeaseTimeDays = index == 0 ? (ushort)5 : (ushort)1 }).ToArray();
        for (int index = 0; index < servers.Length; index++) await servers[index].AddScopeAsync(scopes[index]);
        DhcpMessage Packet(byte client, byte type = 1, IPAddress address = null)
        {
            byte[] wire = new byte[244]; wire[0] = 1; wire[1] = 1; wire[2] = 6; wire[7] = client; wire[28] = 2; wire[33] = client;
            address?.GetAddressBytes().CopyTo(wire, 12);
            new byte[] { 99, 130, 83, 99, 53, 1, type, 255 }.CopyTo(wire, 236);
            return new DhcpMessage(new MemoryStream(wire));
        }
        Lease lease = await scopes[0].GetOfferAsync(Packet(71)); scopes[0].CommitLease(lease);
        DateTime acknowledgedExpiry = lease.LeaseExpires;
        Lease dormant = await scopes[1].GetOfferAsync(Packet(71)); scopes[1].CommitLease(dormant);
        check(lease.Address.Equals(dormant.Address), "Dormant peer fixture lacks matching residual evidence");
        Lease offer = await scopes[0].GetOfferAsync(Packet(72));
        Lease declined = await scopes[0].GetOfferAsync(Packet(73)); scopes[0].DeclineLease(declined);
        using (var configuration = new MemoryStream())
        {
            scopes[0].WriteTo(configuration, false, false); configuration.Position = 0;
            using var restarted = new Scope(configuration, Field<LogManager>(services[0], "_log"), servers[0]);
            check(restarted.GetExistingLeaseOrOffer(Packet(72))?.Address.Equals(offer.Address) == true, "Native restart loses a durably advertised offer");
            check((await restarted.GetOfferAsync(Packet(71)))?.LeaseExpires == lease.LeaseExpires, "Native restart loses acknowledged client lifetime");
            restarted.BlockLocallyAdministeredMacAddresses = true;
            check(await restarted.GetOfferAsync(Packet(71)) is null && await restarted.GetOfferAsync(Packet(72)) is null, "Durable native recovery bypasses existing hardware policy");
            restarted.BlockLocallyAdministeredMacAddresses = false;
            var afterRestart = await restarted.GetOfferAsync(Packet(74));
            check(afterRestart is not null && !afterRestart.Address.Equals(lease.Address) && !afterRestart.Address.Equals(offer.Address) && !afterRestart.Address.Equals(declined.Address), "Native restart reallocates an unknown active binding or quarantine");
            restarted.ReleaseLease(afterRestart);
        }
        var dns = services[0].DnsServer; var originalForwarders = dns.Forwarders;
        using (var dnsGate = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            dnsGate.Bind(new IPEndPoint(IPAddress.Loopback, 0)); sender.Bind(new IPEndPoint(IPAddress.Loopback, 0)); receiver.Bind(new IPEndPoint(lease.Address, 68));
            dns.Forwarders = [NameServerAddress.Parse("127.0.0.1:" + ((IPEndPoint)dnsGate.LocalEndPoint).Port)];
            scopes[0].NtpServerDomainNames = ["ack-race-" + Guid.NewGuid().ToString("N") + ".example.net"];
            scopes[0].SetEnabled(true);
            typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scopes[0], IPAddress.Loopback);
            byte[] query = new byte[4096];
            var waitingQuery = dnsGate.ReceiveFromAsync(query.AsMemory(), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), deadline.Token);
            var process = typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic);
            var acknowledgement = (Task)process.Invoke(servers[0], [Packet(71, 3, lease.Address), new IPEndPoint(lease.Address, 68), default(IPPacketInformation), sender]);
            try
            {
                var receivedQuery = await waitingQuery;
                check(!acknowledgement.IsCompleted, "ACK fixture is not stalled in a real options lookup");
                scopes[0].SetEnabled(false);
                var capture = scopes[0].CaptureNativeAllocationAsync(names[0], deadline.Token);
                check(!capture.IsCompleted && scopes[0].MigrationCapturing, "Capture crosses an in-flight native ACK");
                check((await Call(admins[0], "/api/dhcp/scopes/set", ("name", "Live"), ("domainName", "raced.example"))).GetProperty("status").GetString() == "error", "Edit crosses in-flight ACK capture");
                query[2] = 0x81; query[3] = 0x83;
                await dnsGate.SendToAsync(query.AsMemory(0, receivedQuery.ReceivedBytes), SocketFlags.None, receivedQuery.RemoteEndPoint, deadline.Token);
                await acknowledgement.WaitAsync(deadline.Token);
                byte[] reply = new byte[4096]; int received = await receiver.ReceiveAsync(reply.AsMemory(), SocketFlags.None, deadline.Token);
                var ack = new DhcpMessage(new MemoryStream(reply, 0, received));
                check(ack.DhcpMessageType.Type == DhcpMessageType.Ack && ack.YourClientIpAddress.Equals(lease.Address), "Native UDP ACK was not delivered before capture completed");
                var captured = await capture;
                acknowledgedExpiry = captured.Entries.Where(entry => entry.State == "Lease" && entry.Address == AllocationSequence.Number(ack.YourClientIpAddress) && entry.Client == lease.ClientIdentifier.ToString()).Max(entry => entry.Expires);
                check(acknowledgedExpiry == scopes[0].GetExistingLeaseOrOffer(Packet(71)).LeaseExpires, "Capture loses the exact last in-flight ACK lifetime");
            }
            finally
            {
                scopes[0].SetEnabled(false); scopes[0].NtpServerDomainNames = null; dns.Forwarders = originalForwarders;
                await acknowledgement.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }
        lease = scopes[0].GetExistingLeaseOrOffer(Packet(71));
        check((await Call(originals[0], "/api/ddi/dhcp/migration/check", ("scope", "Live"))).GetProperty("status").GetString() == "error", "Plain HTTP can initiate live migration");
        check((await Call(peers[0], "/api/ddi/dhcp/migration/preview", ("scope", "Live"), ("id", Guid.NewGuid().ToString("N")))).GetProperty("status").GetString() == "error", "Service token can initiate administrator migration");
        check((await Call(admins[1], "/api/ddi/dhcp/migration/check", ("scope", "Live"))).GetProperty("status").GetString() == "error", "Secondary can coordinate live migration");
        var compatibility = await Call(admins[0], "/api/ddi/dhcp/migration/check", ("scope", "Live"));
        check(compatibility.GetProperty("status").GetString() == "ok", "Pre-pause eligibility check fails for matching peers: " + compatibility);
        scopes[2].ChangeNetwork(IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.91"), IPAddress.Parse("255.255.255.0"));
        check((await Call(admins[0], "/api/ddi/dhcp/migration/check", ("scope", "Live"))).GetProperty("status").GetString() == "error", "Eligibility drift is ignored before pausing");
        scopes[2].ChangeNetwork(IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.90"), IPAddress.Parse("255.255.255.0"));
        using (var blocker = scopes[0].BeginAdministrativeChange())
        {
            using var cancellation = new CancellationTokenSource();
            var capture = scopes[0].CaptureNativeAllocationAsync(names[0], cancellation.Token);
            check(!capture.IsCompleted && scopes[0].MigrationCapturing, "Capture does not wait for an admitted edit");
            check((await Call(admins[0], "/api/dhcp/scopes/set", ("name", "Live"), ("domainName", "raced.example"))).GetProperty("status").GetString() == "error", "Edit crosses capture admission barrier");
            check((await Call(admins[0], "/api/dhcp/scopes/enable", ("name", "Live"))).GetProperty("status").GetString() == "error", "Enable crosses capture admission barrier");
            check((await Call(admins[0], "/api/dhcp/scopes/delete", ("name", "Live"))).GetProperty("status").GetString() == "error", "Delete crosses capture admission barrier");
            check((await Call(admins[0], "/api/dhcp/scopes/set", ("name", "Live"), ("newName", "Replaced"))).GetProperty("status").GetString() == "error", "Rename replaces a captured scope");
            try
            {
                await services[0].RestoreConfigAsync(new MemoryStream(), false, false, false, false, false, false, false, false, false, false, true, false, false, false);
                throw new Exception("Scope restore crossed capture admission barrier");
            }
            catch (InvalidOperationException) { check(scopes[0].MigrationCapturing && ReferenceEquals(servers[0].GetScope("Live"), scopes[0]), "Rejected scope restore mutates captured native authority"); }
            cancellation.Cancel();
            try { await capture; throw new Exception("Cancelled capture completed"); } catch (OperationCanceledException) { }
            check(!scopes[0].MigrationCapturing && stores[0].Plan("Live") is null, "Cancelled capture leaves a phantom prepared migration");
        }
        string migrationId = Guid.NewGuid().ToString("N");
        var preview = await Call(admins[0], "/api/ddi/dhcp/migration/preview", ("scope", "Live"), ("id", migrationId));
        check(preview.GetProperty("status").GetString() == "ok", "Native migration HTTPS preview failed: " + preview);
        var input = preview.GetProperty("response").GetProperty("state").Deserialize<AllocationBootstrapInput>(DistributedAllocation.JsonOptions);
        string Hash(AllocationBootstrapInput migration) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(migration, DistributedAllocation.JsonOptions)));
        Task<JsonElement> Prepare(AllocationBootstrapInput migration) => Call(admins[0], "/api/ddi/dhcp/migration/prepare", ("migration", JsonSerializer.Serialize(migration, DistributedAllocation.JsonOptions)), ("expectedHash", Hash(migration)));
        scopes[0].DomainName = "changed-after-review.example";
        check((await Prepare(input)).GetProperty("status").GetString() == "error" && stores[0].Plan("Live") is null, "Stale options prepare initial authority");
        scopes[0].DomainName = "migration.lab.example";
        scopes[2].SetEnabled(true);
        check((await Prepare(input)).GetProperty("status").GetString() == "error" && stores[2].Plan("Live") is null && stores[0].BootstrapPending("Live"), "Enabled peer is prepared or partial preparation is rolled back unsafely");
        scopes[2].SetEnabled(false);
        disconnectLast(true);
        check((await Prepare(input)).GetProperty("status").GetString() == "error", "Lost prepare delivery pretends success");
        disconnectLast(false);
        loseLastResponse("stage");
        check((await Prepare(input)).GetProperty("status").GetString() == "error" && stores[2].BootstrapPending("Live") && !stores[0].Bootstrap("Live").PreparedNodes.Contains(names[2]), "Lost stage response invents receipt or removes remote preparation");
        string authorityPath = Field<string>(stores[0], "_path");
        await stores[0].DisposeAsync();
        stores[0] = new DistributedAllocation(authorityPath) { NodeName = () => names[0] };
        typeof(DnsWebService).GetField("_allocation", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(services[0], stores[0]); servers[0].Allocation = stores[0];
        check(stores[0].BootstrapPending("Live") && !stores[0].HasAuthority("Live", AllocationSequence.Number(lease.Address)), "Coordinator restart clears the prepared serving barrier");
        check((await Call(admins[0], "/api/ddi/dhcp/migration/status", ("scope", "Live"))).GetProperty("status").GetString() == "ok", "Real HTTPS status cannot resume restarted authoritative store");
        scopes[1].DomainName = "interrupted-option-application.example"; scopes[1].LeaseTimeDays = 2;
        check((await Prepare(input)).GetProperty("status").GetString() == "ok", "Lost-response replay fails to finish durable preparation");
        check(scopes.All(scope => !scope.Enabled) && stores.All(store => store.BootstrapPending("Live")), "Prepare activates a listener or serving authority");
        check(scopes.All(scope => scope.LeaseTimeDays == 5 && scope.DomainName == "migration.lab.example"), "Source options were not preserved and applied to peers");
        string preparedHash = stores[0].Bootstrap("Live").Hash;
        try
        {
            await services[0].RestoreConfigAsync(new MemoryStream(), false, false, false, true, false, false, false, false, false, false, true, false, false, true);
            throw new Exception("Restore with deletion replaces prepared authority");
        }
        catch (InvalidOperationException) { check(stores[0].Bootstrap("Live").Hash == preparedHash && stores[0].BootstrapPending("Live") && !stores[0].HasAuthority("Live", AllocationSequence.Number(lease.Address)), "Failed restore removes the prepared journal or serving barrier"); }
        check((await Call(admins[0], "/api/dhcp/scopes/delete", ("name", "Live"))).GetProperty("status").GetString() == "error", "Delete removes a prepared scope");
        check((await Call(admins[0], "/api/dhcp/scopes/set", ("name", "Live"), ("newName", "Replaced"))).GetProperty("status").GetString() == "error", "Rename removes prepared ownership");
        var oldMesh = stores[0].Snapshot() with { Bootstraps = [], NativeHolds = [], Configurations = [], Replicas = [] };
        check((await Call(peers[0], "/api/ddi/dhcp/state/ingest", ("state", JsonSerializer.Serialize(oldMesh, DistributedAllocation.JsonOptions)))).GetProperty("status").GetString() == "ok" && stores[0].Bootstrap("Live").Hash == preparedHash && stores[0].BootstrapPending("Live"), "Old mesh snapshot removes a prepared journal or native protection");
        check((await Call(admins[0], "/api/dhcp/scopes/set", ("name", "Live"), ("leaseTimeDays", "2"))).GetProperty("status").GetString() == "error", "Prepared migration permits admin edits");
        var status = await Call(admins[0], "/api/ddi/dhcp/migration/status", ("scope", "Live"));
        check(status.GetProperty("response").GetProperty("migration").GetProperty("id").GetString() == migrationId, "Status cannot recover immutable reviewed payload");
        Task<JsonElement> Commit() => Call(admins[0], "/api/ddi/dhcp/migration/commit", ("scope", "Live"), ("id", migrationId), ("expectedHash", Hash(input)));
        var manager = Field<ClusterManager>(services[0], "_clusterManager"); var enrolled = Field<Dictionary<int, ClusterNode>>(manager, "_clusterNodes");
        typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(manager, enrolled.Where(pair => pair.Key != 3).ToDictionary(pair => pair.Key, pair => pair.Value));
        try { check((await Commit()).GetProperty("status").GetString() == "error" && stores[0].BootstrapPending("Live"), "Membership drift permits commit"); }
        finally { typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(manager, enrolled); }
        disconnectLast(true);
        check((await Commit()).GetProperty("status").GetString() == "error" && stores[0].BootstrapPending("Live") && !stores[1].BootstrapPending("Live"), "Partial peer commit loses durable coordinator boundary");
        disconnectLast(false);
        loseLastResponse("commitPeer");
        check((await Commit()).GetProperty("status").GetString() == "error" && stores[0].BootstrapPending("Live") && !stores[2].BootstrapPending("Live"), "Lost remote commit response pretends coordinated success or rolls authority backward");
        check((await Commit()).GetProperty("status").GetString() == "ok", "Commit retry fails after partial peer response loss");
        check(stores[0].FindLease("Live", lease.ClientIdentifier.ToString())?.Expires == acknowledgedExpiry && stores[0].FindLease("Live", lease.ClientIdentifier.ToString())?.Address == AllocationSequence.Number(lease.Address), "Transport migration loses existing client address or exact captured ACK expiry");
        check(stores[0].FindOffer("Live", offer.ClientIdentifier.ToString())?.Address == AllocationSequence.Number(offer.Address) && !stores[0].Available("Live", AllocationSequence.Number(declined.Address)), "Transport migration loses offer or DECLINE protection");
        scopes[0].LeaseTimeDays = 1; scopes[0].CommitLease(Lease.Recover(stores[0].FindLease("Live", lease.ClientIdentifier.ToString()), false));
        var expiry = stores[0].FindLease("Live", lease.ClientIdentifier.ToString()).Expires;
        check(expiry == acknowledgedExpiry, "Native renewal hook shortens migrated lifetime");
        using (var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            sender.Bind(new IPEndPoint(IPAddress.Loopback, 0)); receiver.Bind(new IPEndPoint(lease.Address, 68));
            scopes[0].SetEnabled(true);
            typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scopes[0], IPAddress.Loopback);
            disconnectLast(true);
            try
            {
                var process = typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic);
                await ((Task)process.Invoke(servers[0], [Packet(71, 3, lease.Address), new IPEndPoint(lease.Address, 68), default(IPPacketInformation), sender])).WaitAsync(deadline.Token);
                byte[] wire = new byte[4096]; int length = await receiver.ReceiveAsync(wire.AsMemory(), SocketFlags.None, deadline.Token);
                var acknowledgement = new DhcpMessage(new MemoryStream(wire, 0, length));
                check(acknowledgement.DhcpMessageType.Type == DhcpMessageType.Ack && acknowledgement.YourClientIpAddress.Equals(lease.Address) && stores[0].FindLease("Live", lease.ClientIdentifier.ToString()).Expires == acknowledgedExpiry, "Real migrated renewal ACK loses captured client lifetime during peer isolation");
            }
            finally { disconnectLast(false); scopes[0].SetEnabled(false); }
        }
        check((await Prepare(input)).GetProperty("status").GetString() == "ok" && (await Commit()).GetProperty("status").GetString() == "ok" && stores[0].FindLease("Live", lease.ClientIdentifier.ToString()).Expires == expiry, "Committed replay overwrites live authority");
        var offers = await Task.WhenAll(scopes.SelectMany((scope, index) => Enumerable.Range(80 + index * 10, 5).Select(client => scope.GetOfferAsync(Packet((byte)client)))));
        check(offers.All(value => value is not null) && offers.Select(value => value.Address).Distinct().Count() == offers.Length && offers.All(value => !value.Address.Equals(lease.Address) && !value.Address.Equals(offer.Address) && !value.Address.Equals(declined.Address)), "Actual concurrent offers reuse protected native addresses after migration");
    }
}


