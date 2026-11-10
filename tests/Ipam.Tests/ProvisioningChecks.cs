// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using DnsServerCore;
using DnsServerCore.Dhcp;
using DnsServerCore.Dns;
using DnsServerCore.Ipam;
using DnsServerCore.Dns.ResourceRecords;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class ProvisioningChecks
{
    static int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    public static async Task Run(bool serve)
    {
        string root = Path.Combine(Path.GetTempPath(), "ipam-provisioning-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        int port = FreePort(), dnsPort = FreePort(), checks = 0;
        string password = Guid.NewGuid().ToString("N") + "Aa9!";
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", port.ToString());
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
        await using (var log = new LogManager(true, root))
        using (var dns = new DnsServer(root, Path.Combine(repository, "DnsServerCore/dohwww"), log))
        { dns.LoadConfigFile(); dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
        var service = new DnsWebService(true, root);
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
        async Task<JsonElement> Call(HttpClient client, string path, params (string Key, string Value)[] values)
        {
            using var content = new FormUrlEncodedContent(values.Select(v => new KeyValuePair<string, string>(v.Key, v.Value)));
            using var response = await client.PostAsync("/api/" + path, content);
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        }
        var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + port) };
        async Task Login()
        {
            var login = await Call(client, "user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true"));
            Check(login.GetProperty("status").GetString() == "ok", "isolated native admin login");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
        }
        async Task<JsonElement> Inventory() => (await Call(client, "ipam/list")).GetProperty("response").GetProperty("inventory");
        async Task<string> Revision() => (await Inventory()).GetProperty("revision").GetInt64().ToString();
        string id = "";
        async Task<JsonElement> Preview(string address, string host, string hardware, string operation = null)
            => await Call(client, "ipam/provisioning/preview", ("revision", await Revision()), ("operationId", operation ?? Guid.NewGuid().ToString("N")), ("subnetId", id), ("address", address), ("hostName", host), ("hardwareAddress", hardware));
        JsonElement Operation(JsonElement result)
        { Check(result.GetProperty("status").GetString() == "ok", "native operation response " + (result.TryGetProperty("errorMessage", out var error) ? error.ToString() : "ok")); return result.GetProperty("response").GetProperty("operation"); }
        async Task<JsonElement> Step(JsonElement op, string action, bool recover = false)
            => await Call(client, "ipam/provisioning/" + action, ("operationId", op.GetProperty("id").GetString()), ("digest", op.GetProperty("digest").GetString()), ("recover", recover.ToString().ToLowerInvariant()));
        try
        {
            await service.StartAsync(true);
            using var anonymous = new HttpClient { BaseAddress = client.BaseAddress };
            Check((await Call(anonymous, "ipam/provisioning/preview")).GetProperty("status").GetString() == "invalid-token", "anonymous preview rejected");
            await Login();
            var dhcp = (DhcpServer)typeof(DnsWebService).GetField("_dhcpServer", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            var log = (LogManager)typeof(DnsWebService).GetField("_log", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            var scope = new Scope("provisioning-fixture", false, IPAddress.Parse("198.18.32.10"), IPAddress.Parse("198.18.32.30"), IPAddress.Parse("255.255.255.0"), log, dhcp) { DnsUpdates = false, PingCheckEnabled = false };
            await dhcp.AddScopeAsync(scope);
            Check((await Call(client, "zones/create", ("zone", "provisioning.test"), ("type", "Primary"))).GetProperty("status").GetString() == "ok", "native local DNS destination created");
            var inventory = await Inventory();
            id = inventory.GetProperty("subnets").EnumerateArray().Single(s => s.GetProperty("dhcpScope").GetString() == scope.Name).GetProperty("id").GetString();
            Check((await Call(client, "ipam/subnets/set", ("revision", await Revision()), ("id", id), ("prefix", "198.18.32.0/24"), ("name", "Provisioning fixture"), ("dhcpScope", scope.Name), ("dnsZone", "provisioning.test"))).GetProperty("status").GetString() == "ok", "native service links saved");
            Check((await Preview("198.18.32.0", "network.provisioning.test", "02-00-00-00-00-00")).GetProperty("status").GetString() == "error", "network address rejected before effects");
            scope.DnsUpdates = true;
            Check((await Preview("198.18.32.21", "ddns.provisioning.test", "02-00-00-00-00-21")).GetProperty("status").GetString() == "error", "DHCP automatic DNS side effects rejected before preview");
            scope.DnsUpdates = false;
            service.DnsServer.AuthZoneManager.CreatePrimaryZone("child.provisioning.test");
            Check((await Preview("198.18.32.21", "host.child.provisioning.test", "02-00-00-00-00-21")).GetProperty("status").GetString() == "error", "child-zone authority cannot be provisioned through parent link");
            // Source discovery must not advance unchanged state between preview and approval.
            var p = Operation(await Preview("198.18.32.10", "host10.provisioning.test", "02-00-00-00-00-10"));
            Check(scope.ReservedLeases.Count == 0 && service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", "host10.provisioning.test", DnsResourceRecordType.A).Count == 0, "preview has no native effects");
            using (var journalLock = new FileStream(Path.Combine(root, "ipam.json.write-lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                Check((await Step(p, "approve")).GetProperty("status").GetString() == "error", "journal lock failure prevents approval before native effects");
            Check(scope.TryEnterServingRequest(), "failed approval releases scope admission guard"); scope.ExitServingRequest();
            Check(scope.ReservedLeases.Count == 0, "failed journal persistence creates no DHCP reservation");
            Check(scope.TryEnterServingRequest(), "native in-flight request admitted before approval");
            var approving = Step(p, "approve");
            await Task.Delay(100);
            Check(!approving.IsCompleted, "approval drains existing native request outside inventory lock");
            scope.ExitServingRequest();
            p = Operation(await approving.WaitAsync(TimeSpan.FromSeconds(5)));
            byte[] heldDiscoverWire = new byte[244]; heldDiscoverWire[0] = 1; heldDiscoverWire[1] = 1; heldDiscoverWire[2] = 6; heldDiscoverWire[28] = 2; heldDiscoverWire[33] = 0x99;
            new byte[] { 99, 130, 83, 99, 53, 1, 1, 255 }.CopyTo(heldDiscoverWire, 236);
            var heldOffer = await (Task<Lease>)typeof(Scope).GetMethod("GetOfferAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(scope, [new DhcpMessage(new MemoryStream(heldDiscoverWire))]);
            Check(heldOffer is not null && heldOffer.Address.ToString() != "198.18.32.10", "native allocator excludes durable approved IPAM hold");
            scope.ReleaseLease(heldOffer);

            Check(p.GetProperty("state").GetString() == "Approved", "approval persists address hold");
            Check((await Preview("198.18.32.10", "other.provisioning.test", "02-00-00-00-00-11")).GetProperty("status").GetString() == "error", "second operation cannot claim held address");
            var applied = await Task.WhenAll(Step(p, "apply"), Step(p, "apply"));
            Check(applied.All(r => r.GetProperty("response").GetProperty("operation").GetProperty("state").GetString() == "Completed"), "two real concurrent same-ID applies reconcile once");
            Check(scope.ReservedLeases.Count == 1 && service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", "host10.provisioning.test", DnsResourceRecordType.A).Count == 1, "one native DNS record and reservation after concurrent apply");
            var ipamFile = Path.Combine(root, "ipam.json");
            var restored = new IpamManager(ipamFile);
            Check(restored.ProvisioningResult(p.GetProperty("id").GetString()).State == "Completed" && restored.Snapshot().Assignments.Count(a => a.Address == "198.18.32.10" && string.IsNullOrEmpty(a.Source)) == 1, "completed journal and real intent survive reload");
            Check((await Preview("198.18.32.11", "changed.provisioning.test", "02-00-00-00-00-11", p.GetProperty("id").GetString())).GetProperty("status").GetString() == "error", "same ID with altered request rejected");
            Check((await Preview("198.18.32.31", "outside.provisioning.test", "02-00-00-00-00-31")).GetProperty("status").GetString() == "error", "outside scope rejected before effects");
            var stale = Operation(await Preview("198.18.32.11", "stale.provisioning.test", "02-00-00-00-00-11"));
            await Call(client, "ipam/views/set", ("revision", await Revision()), ("name", "Force stale revision"));
            Check((await Step(stale, "approve")).GetProperty("status").GetString() == "error", "stale inventory approval rejected");
            var partial = Operation(await Preview("198.18.32.12", "partial.provisioning.test", "02-00-00-00-00-12"));
            partial = Operation(await Step(partial, "approve"));
            string blockedTemporary = Path.Combine(root, "scopes", scope.Name + ".tmp");
            Directory.CreateDirectory(blockedTemporary);
            partial = Operation(await Step(partial, "apply"));
            byte[] pendingWire = new byte[244]; pendingWire[0] = 1; pendingWire[1] = 1; pendingWire[2] = 6; pendingWire[28] = 2; pendingWire[33] = 0x12;
            new byte[] { 99, 130, 83, 99, 53, 1, 1, 255 }.CopyTo(pendingWire, 236);
            var pendingOffer = await (Task<Lease>)typeof(Scope).GetMethod("GetOfferAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(scope, [new DhcpMessage(new MemoryStream(pendingWire))]);
            Check(pendingOffer is null, "native reserved client cannot acquire unknown-outcome address while held");
            Check(partial.GetProperty("state").GetString() == "RecoveryRequired" && partial.GetProperty("dnsOutcome").GetString().Contains("persisted"), "real DHCP disk failure after DNS acknowledgement retains claim");
            Check((await Preview("198.18.32.12", "replacement.provisioning.test", "02-00-00-00-00-22")).GetProperty("status").GetString() == "error", "unknown outcome cannot be bypassed with new operation ID");
            Directory.Delete(blockedTemporary);
            partial = Operation(await Step(partial, "apply"));
            Check(partial.GetProperty("state").GetString() == "Completed", "same-ID retry reconciles existing native DNS and reservation");
            // Real DNS persistence failure leaves a durable pre-effect hold; compensation must not remove an external edit.
            var recovery = Operation(await Preview("198.18.32.13", "recover.provisioning.test", "02-00-00-00-00-13"));
            recovery = Operation(await Step(recovery, "approve"));
            Directory.CreateDirectory(blockedTemporary);
            recovery = Operation(await Step(recovery, "apply"));
            Check(recovery.GetProperty("state").GetString() == "RecoveryRequired", "second partial native transaction remains pending");
            Directory.Delete(blockedTemporary);
            var external = new DnsResourceRecord("recover.provisioning.test", DnsResourceRecordType.A, DnsClass.IN, 600, new DnsARecordData(IPAddress.Parse("198.18.32.29")));
            service.DnsServer.AuthZoneManager.SetRecord("provisioning.test", external);
            recovery = Operation(await Step(recovery, "apply", true));
            Check(recovery.GetProperty("state").GetString() == "RecoveryRequired" && service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", external.Name, DnsResourceRecordType.A).Single().RDATA.Equals(external.RDATA), "compensation preserves concurrent external DNS change and retains hold");
            var clean = Operation(await Preview("198.18.32.14", "clean.provisioning.test", "02-00-00-00-00-14"));
            clean = Operation(await Step(clean, "approve"));
            Directory.CreateDirectory(blockedTemporary);
            clean = Operation(await Step(clean, "apply"));
            Directory.Delete(blockedTemporary);
            clean = Operation(await Step(clean, "apply", true));
            Check(clean.GetProperty("state").GetString() == "Compensated" && service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", "clean.provisioning.test", DnsResourceRecordType.A).Count == 0 && !scope.ReservedLeases.Any(l => l.Address.ToString() == "198.18.32.14"), "owned DNS and DHCP effects compensated without snapshot restore");
            using (var udp = new UdpClient(AddressFamily.InterNetwork))
            {
                var request = new DnsDatagram(31, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [new DnsQuestionRecord("host10.provisioning.test", DnsResourceRecordType.A, DnsClass.IN)]);
                using var wire = new MemoryStream(); request.WriteTo(wire);
                await udp.SendAsync(wire.ToArray(), new IPEndPoint(IPAddress.Loopback, dnsPort));
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var received = await udp.ReceiveAsync(timeout.Token);
                var response = DnsDatagram.ReadFrom(new MemoryStream(received.Buffer));
                Check(response.RCODE == DnsResponseCode.NoError && response.Answer.Any(r => r.RDATA is DnsARecordData a && a.Address.ToString() == "198.18.32.10"), "actual loopback DNS UDP query returns provisioned address");
            }
            // Native external DHCP edits must survive per-object compensation.
            var dhcpChanged = Operation(await Preview("198.18.32.16", "dhcp-change.provisioning.test", "02-00-00-00-00-16"));
            dhcpChanged = Operation(await Step(dhcpChanged, "approve"));
            Directory.CreateDirectory(blockedTemporary);
            dhcpChanged = Operation(await Step(dhcpChanged, "apply"));
            Directory.Delete(blockedTemporary);
            var edited = scope.ReservedLeases.Single(l => l.Address.ToString() == "198.18.32.16");
            edited.Comments = "External administrator edit";
            dhcp.SaveScope(scope.Name);
            dhcpChanged = Operation(await Step(dhcpChanged, "apply", true));
            Check(dhcpChanged.GetProperty("state").GetString() == "RecoveryRequired" && scope.ReservedLeases.Any(l => l.Address.ToString() == "198.18.32.16" && l.Comments == "External administrator edit"), "compensation preserves native external DHCP edit");
            // Real concurrent different-operation preview requests cannot both approve stale authority.
            string raceRevision = await Revision();
            async Task<JsonElement> RacePreview(string host) => await Call(client, "ipam/provisioning/preview", ("revision", raceRevision), ("operationId", Guid.NewGuid().ToString("N")), ("subnetId", id), ("address", "198.18.32.17"), ("hostName", host + ".provisioning.test"), ("hardwareAddress", "02-00-00-00-00-17"));
            var previewRace = await Task.WhenAll(RacePreview("race-a"), RacePreview("race-b"));
            Check(previewRace.Count(r => r.GetProperty("status").GetString() == "ok") == 1, "two actual concurrent operation previews enforce inventory revision");
            // Check the actual native reservation allocator and packet ACK path without binding port 67/68.
            byte[] discoverWire = new byte[244]; discoverWire[0] = 1; discoverWire[1] = 1; discoverWire[2] = 6; discoverWire[28] = 2; discoverWire[33] = 0x10;
            new byte[] { 99, 130, 83, 99, 53, 1, 1, 255 }.CopyTo(discoverWire, 236);
            var discover = new DhcpMessage(new MemoryStream(discoverWire));
            var offerMethod = typeof(Scope).GetMethod("GetOfferAsync", BindingFlags.Instance | BindingFlags.NonPublic);
            var offered = await (Task<Lease>)offerMethod.Invoke(scope, [discover]);
            Check(offered?.Address.ToString() == "198.18.32.10" && offered.Type == LeaseType.Reserved, "actual native allocator offers the provisioned reservation to its client");
            scope.SetEnabled(true);
            typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scope, IPAddress.Loopback);
            byte[] requestWire = discoverWire.ToArray(); requestWire[242] = 3;
            IPAddress.Parse("198.18.32.10").GetAddressBytes().CopyTo(requestWire, 12);

            var processPacket = typeof(DhcpServer).GetMethod("ProcessDhcpMessageAsync", BindingFlags.Instance | BindingFlags.NonPublic);
            var ackTask = (Task<DhcpMessage>)processPacket.Invoke(dhcp, [new DhcpMessage(new MemoryStream(requestWire)), new IPEndPoint(IPAddress.Parse("198.18.32.10"), 68), default(IPPacketInformation)]);
            var ack = await ackTask;
            Check(ack?.DhcpMessageType.Type.ToString() == "Ack" && scope.Leases.Values.Any(l => l.Address.ToString() == "198.18.32.10"), "native request packet acknowledges the provisioned client lease");
            scope.SetEnabled(false);
            // Drop a real HTTP response after fully submitting apply, then reconcile the same ID.
            var lost = Operation(await Preview("198.18.32.18", "lost.provisioning.test", "02-00-00-00-00-18"));
            lost = Operation(await Step(lost, "approve"));
            string lostBody = "operationId=" + lost.GetProperty("id").GetString() + "&digest=" + lost.GetProperty("digest").GetString();
            using var socket = new TcpClient();
            {
                await socket.ConnectAsync(IPAddress.Loopback, port);
                byte[] request = System.Text.Encoding.ASCII.GetBytes("POST /api/ipam/provisioning/apply HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + client.DefaultRequestHeaders.Authorization.Parameter + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + lostBody.Length + "\r\nConnection: close\r\n\r\n" + lostBody);
                await socket.GetStream().WriteAsync(request); await socket.GetStream().FlushAsync();
                // Keep transport open but never read the reply; application acknowledgement is lost.
            }
            for (int attempt = 0; attempt < 40; attempt++)
            {
                var result = Operation(await Step(lost, "result"));
                if (result.GetProperty("state").GetString() == "Completed") { lost = result; break; }
                await Task.Delay(50);
            }
            Check(lost.GetProperty("state").GetString() == "Completed", "lost HTTP acknowledgement still records native completion under original ID");
            // Persist a partial write, stop/restart the actual native service, and reconcile it.
            var restart = Operation(await Preview("198.18.32.19", "restart.provisioning.test", "02-00-00-00-00-19"));
            restart = Operation(await Step(restart, "approve"));
            Directory.CreateDirectory(blockedTemporary);
            restart = Operation(await Step(restart, "apply"));
            Check(restart.GetProperty("state").GetString() == "RecoveryRequired", "restart fixture has real persisted DNS with unacknowledged DHCP");
            await service.DisposeAsync();
            Directory.Delete(blockedTemporary);
            service = new DnsWebService(true, root); await service.StartAsync(true); await Login();
            restart = Operation(await Step(restart, "apply"));
            Check(restart.GetProperty("state").GetString() == "Completed", "actual service restart reconciles native partial transaction with same ID");
            lost = Operation(await Step(lost, "apply"));
            Check(lost.GetProperty("state").GetString() == "Completed", "lost acknowledgement replay after restart returns original result");
            dhcp = (DhcpServer)typeof(DnsWebService).GetField("_dhcpServer", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            scope = dhcp.GetScope("provisioning-fixture");
            Check(scope.ReservedLeases.Count(l => l.Address.ToString() == "198.18.32.18") == 1, "restart and lost-response retry created no duplicate native reservation");
            var beforeOffer = Operation(await Preview("198.18.32.21", "offer-conflict.provisioning.test", "02-00-00-00-00-21"));
            byte[] offerConflictWire = new byte[250]; offerConflictWire[0] = 1; offerConflictWire[1] = 1; offerConflictWire[2] = 6; offerConflictWire[28] = 2; offerConflictWire[33] = 0x21;
            new byte[] { 99, 130, 83, 99, 53, 1, 1, 50, 4, 198, 18, 32, 21, 255 }.CopyTo(offerConflictWire, 236);
            var conflictOffer = await (Task<Lease>)offerMethod.Invoke(scope, [new DhcpMessage(new MemoryStream(offerConflictWire))]);
            Check(conflictOffer?.Address.ToString() == "198.18.32.21", "native offer acquired after preview before approval");
            Check((await Step(beforeOffer, "approve")).GetProperty("status").GetString() == "error", "approval cannot acquire hold over a new native offer");
            scope.CommitLease(conflictOffer);
            Check((await Step(beforeOffer, "approve")).GetProperty("status").GetString() == "error", "approval cannot acquire hold over a committed native lease");
            Check(!dhcp.ProvisioningAddressHeld("unrelated-scope", IPAddress.Parse("198.18.32.13")) && dhcp.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.13")), "durable hold callback is bound to exact scope and address");
            // Native CNAME writer races the conditional A mutation, using the actual shared RRset primitives.
            for (int iteration = 0; iteration < 24; iteration++)
            {
                string host = "native-race-" + iteration + ".provisioning.test";
                var aRecord = new DnsResourceRecord(host, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("198.18.32.200")));
                aRecord.GetAuthGenericRecordInfo().Comments = "native-race-" + iteration;
                var cname = new DnsResourceRecord(host, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("elsewhere.provisioning.test"));
                using var barrier = new Barrier(2);
                var aTask = Task.Run(() => { barrier.SignalAndWait(); try { service.DnsServer.AuthZoneManager.ProvisionAddress("provisioning.test", aRecord, "native-race-" + iteration, false); } catch (InvalidOperationException) { } });
                var cTask = Task.Run(() => { barrier.SignalAndWait(); try { service.DnsServer.AuthZoneManager.SetRecord("provisioning.test", cname); } catch (InvalidOperationException) { } });
                await Task.WhenAll(aTask, cTask).WaitAsync(TimeSpan.FromSeconds(10));
                Check(service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", host, DnsResourceRecordType.A).Count * service.DnsServer.AuthZoneManager.GetRecords("provisioning.test", host, DnsResourceRecordType.CNAME).Count == 0, "native CNAME/A concurrent writer invariant " + iteration);
            }
            // Per-service permission failures are tested with isolated native users; original admin stays open.
            var auth = (DnsServerCore.Auth.AuthManager)typeof(DnsWebService).GetField("_authManager", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            string readerPassword = Guid.NewGuid().ToString("N") + "Aa9!";
            var reader = auth.CreateUser("Fixture reader", "fixture-reader", readerPassword);
            auth.SetPermission(DnsServerCore.Auth.PermissionSection.Settings, reader, DnsServerCore.Auth.PermissionFlag.View);
            auth.SaveConfigFile(true);
            using var restricted = new HttpClient { BaseAddress = client.BaseAddress };
            var readerLogin = await Call(restricted, "user/login", ("user", "fixture-reader"), ("pass", readerPassword), ("includeInfo", "true"));
            restricted.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", readerLogin.GetProperty("token").GetString());
            var readerInventory = (await Call(restricted, "ipam/list")).GetProperty("response").GetProperty("inventory");
            Check(readerInventory.GetProperty("provisioning").ValueKind == JsonValueKind.Null && !readerInventory.GetProperty("changes").EnumerateArray().Any(c => c.GetProperty("operation").GetString().StartsWith("provisioning.")), "general inventory history does not disclose private operation journals");
            Check((await Call(restricted, "ipam/provisioning/preview")).GetProperty("status").GetString() == "error", "read-only user cannot preview a write");
            auth.SetPermission(DnsServerCore.Auth.PermissionSection.Settings, reader, DnsServerCore.Auth.PermissionFlag.View | DnsServerCore.Auth.PermissionFlag.Modify);
            Check((await Call(restricted, "ipam/provisioning/preview", ("revision", await Revision()), ("operationId", Guid.NewGuid().ToString("N")), ("subnetId", id), ("address", "198.18.32.20"), ("hostName", "denied.provisioning.test"), ("hardwareAddress", "02-00-00-00-00-20"))).GetProperty("status").GetString() == "error", "Settings modify alone does not authorize native DNS/DHCP writes");
            Check((await Call(restricted, "ipam/provisioning/result", ("operationId", p.GetProperty("id").GetString()))).GetProperty("status").GetString() == "error", "another operator cannot read private provisioning result");
            auth.SetPermission(DnsServerCore.Auth.PermissionSection.Settings, reader, DnsServerCore.Auth.PermissionFlag.View);
            auth.SaveConfigFile(true);
            using var fresh = new HttpClient { BaseAddress = client.BaseAddress };
            var freshLogin = await Call(fresh, "user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true"));
            fresh.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", freshLogin.GetProperty("token").GetString());
            Check((await Call(fresh, "ipam/views/set", ("revision", await Revision()), ("name", "Fresh loopback administration validated"))).GetProperty("status").GetString() == "ok", "fresh loopback admin authenticates and modifies after isolated permission fixture");
            int baselineChecks = checks;
            await ProvisioningAuthorizationChecks.Run(service, client, password, id, scope,
                Path.Combine(repository, "../AUTHORIZATION-RESULT.json"), serve, Call, Revision, Check);
            Console.WriteLine(JsonSerializer.Serialize(new { checks, baselineChecks, authorizationChecks = checks - baselineChecks, root, port, dnsPort, atUtc = DateTime.UtcNow, status = "PASS", clientLeaseAcquisition = "native-offer-and-packet-ACK-tested-no-OS-client-or-real-port67" }));
            if (serve)
            {
                File.WriteAllText(Path.Combine(repository, "../ui-session.json"), JsonSerializer.Serialize(new { url = client.BaseAddress.ToString(), token = client.DefaultRequestHeaders.Authorization.Parameter, password, readerPassword, root, subnetId = id }));
                Console.WriteLine("Serving isolated UI fixture. Press Enter to stop.");
                Console.ReadLine();
            }
        }
        finally { client.Dispose(); await service.DisposeAsync(); }
    }
}
