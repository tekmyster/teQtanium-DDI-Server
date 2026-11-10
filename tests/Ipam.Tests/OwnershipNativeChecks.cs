// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static partial class DistributedTransportChecks
{
    static async Task CheckOwnershipChanges(List<DnsWebService> services, List<HttpClient> originals, List<HttpClient> admins, List<HttpClient> peers,
        string[] names, string[] passwords, Dictionary<(int Source, int Target), PinnedHandler> links, Action<bool, string> check)
    {
        const string scopeName = "Ownership";
        static string Json<T>(T value) => JsonSerializer.Serialize(value, DistributedAllocation.JsonOptions);
        static bool Ok(JsonElement response) => response.GetProperty("status").GetString() == "ok";
        var servers = services.Select(s => Field<DhcpServer>(s, "_dhcpServer")).ToArray();
        var stores = services.Select(s => Field<DistributedAllocation>(s, "_allocation")).ToArray();
        var scopes = new Scope[3];
        string evidence = Environment.GetEnvironmentVariable("TEQTANIUM_OWNERSHIP_EVIDENCE"); int evidenceNumber = 0;
        void SaveEvidence(string label)
        {
            if (evidence is null) return;
            Directory.CreateDirectory(evidence);
            var nodes = stores.Select((store, index) =>
            {
                using var configuration = new MemoryStream(); scopes[index].WriteTo(configuration, false, false);
                string file = Path.Combine(Field<string>(servers[index], "_scopesFolder"), scopeName + ".scope");
                return new { node = names[index], webHttps = admins[index].BaseAddress, webHttp = originals[index].BaseAddress, dns = services[index].DnsServer.LocalEndPoints.Select(p => p.ToString()).ToArray(), nativeEnabled = scopes[index].Enabled, nativeConfiguration = Convert.ToBase64String(configuration.ToArray()), nativeFileSha256 = File.Exists(file) ? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))) : null, state = store.Snapshot() };
            }).ToArray();
            File.WriteAllText(Path.Combine(evidence, $"{++evidenceNumber:D3}-{label}.json"), Json(new { atUtc = DateTime.UtcNow, processId = Environment.ProcessId, scope = scopeName, source = "127.0.0.1", nodes }));
        }
        void Report(string value) => Console.WriteLine("OWNERSHIP " + value);
        async Task Good(Task<JsonElement> call, string label) { var result = await call; check(Ok(result), label + ": " + result); Report(label); }
        async Task Bad(Task<JsonElement> call, string label) { var result = await call; check(!Ok(result), label + ": " + result); Report("REFUSED " + label); }
        await Good(Call(admins[0], "/api/zones/create", ("zone", "ownership-isolation.test"), ("type", "Primary")), "isolated authoritative DNS zone");
        await Good(Call(admins[0], "/api/zones/records/add", ("domain", "check.ownership-isolation.test"), ("type", "A"), ("ipAddress", "192.0.2.200")), "isolated authoritative DNS record");
        async Task CheckDns(string phase)
        {
            var endpoint = services[0].DnsServer.LocalEndPoints[0];
            using var query = new MemoryStream(); query.Write(new byte[] { 0x71, 0x32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (string label in "check.ownership-isolation.test".Split('.')) { query.WriteByte((byte)label.Length); query.Write(Encoding.ASCII.GetBytes(label)); }
            query.Write(new byte[] { 0, 0, 1, 0, 1 }); byte[] request = query.ToArray();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            foreach (bool tcp in new[] { false, true })
            {
                byte[] wire;
                if (tcp)
                {
                    using var socket = new TcpClient(); await socket.ConnectAsync(endpoint.Address, endpoint.Port, deadline.Token); var stream = socket.GetStream();
                    byte[] length = [(byte)(request.Length >> 8), (byte)request.Length]; await stream.WriteAsync(length, deadline.Token); await stream.WriteAsync(request, deadline.Token);
                    await stream.ReadExactlyAsync(length, deadline.Token); wire = new byte[(length[0] << 8) | length[1]]; await stream.ReadExactlyAsync(wire, deadline.Token);
                }
                else
                {
                    using var socket = new UdpClient(AddressFamily.InterNetwork); await socket.SendAsync(request, endpoint, deadline.Token); wire = (await socket.ReceiveAsync(deadline.Token)).Buffer;
                }
                var reply = DnsDatagram.ReadFrom(new MemoryStream(wire));
                check(reply.RCODE == DnsResponseCode.NoError && reply.Answer.Any(r => r.RDATA is DnsARecordData data && data.Address.Equals(IPAddress.Parse("192.0.2.200"))), "actual DNS " + (tcp ? "TCP " : "UDP ") + phase + " remains authoritative");
            }
        }
        await CheckDns("before ownership change");
        for (int i = 0; i < 3; i++)
        {
            scopes[i] = new Scope(scopeName, false, IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.90"), IPAddress.Parse("255.255.255.0"), Field<LogManager>(services[i], "_log"), servers[i]);
            await servers[i].AddScopeAsync(scopes[i]);
            await Good(Call(admins[i], "/api/dhcp/scopes/set", ("name", scopeName), ("dnsUpdates", "false"), ("pingCheckEnabled", "false"), ("ignoreClientIdentifierOption", "true"), ("domainName", "ownership.test")), "native paused scope configuration " + i);
        }
        await Good(Call(admins[0], "/api/ddi/dhcp/plan/set", ("scope", scopeName), ("owners", string.Join(',', names))), "native initial ownership bootstrap");
        var old = stores[0].Plan(scopeName);
        DhcpMessage Packet(byte client, byte type = 1, IPAddress address = null)
        {
            byte[] wire = new byte[244]; wire[0] = 1; wire[1] = 1; wire[2] = 6; wire[7] = client; wire[28] = 2; wire[33] = client;
            address?.GetAddressBytes().CopyTo(wire, 12); new byte[] { 99, 130, 83, 99, 53, 1, type, 255 }.CopyTo(wire, 236);
            return new DhcpMessage(new MemoryStream(wire));
        }
        AllocationPlan Desired(string[] owners, string first = "127.0.0.10", string last = "127.0.0.95", Exclusion[] excluded = null, Lease[] reserved = null)
        {
            using var bytes = new MemoryStream(); scopes[0].WriteTo(bytes, false, false); bytes.Position = 0;
            using var source = new Scope(bytes, Field<LogManager>(services[0], "_log"), servers[0]);
            source.SetEnabled(false); source.ChangeNetwork(IPAddress.Parse(first), IPAddress.Parse(last), IPAddress.Parse("255.255.255.0"));
            source.Exclusions = excluded ?? []; source.ReservedLeases = reserved ?? [];
            string id = Guid.NewGuid().ToString("N");
            using var configuration = new MemoryStream(); source.WriteTo(configuration, false, false);
            return source.BuildAllocationPlan(id, id, owners) with { Configuration = Convert.ToBase64String(configuration.ToArray()) };
        }
        Task<JsonElement> Preview(AllocationPlan plan, string epoch = null, HttpClient actor = null) => Call(actor ?? admins[0], "/api/ddi/dhcp/changes/preview", ("plan", Json(plan)), ("expectedEpoch", epoch ?? stores[0].Plan(scopeName).Epoch));
        Task<JsonElement> Prepare(AllocationChangeInput input, HttpClient actor = null) => Call(actor ?? admins[0], "/api/ddi/dhcp/changes/prepare", ("change", Json(input)), ("expectedHash", DistributedAllocation.ChangeHash(input)));
        Task<JsonElement> Commit(AllocationChangeInput input, HttpClient actor = null) => Call(actor ?? admins[0], "/api/ddi/dhcp/changes/commit", ("scope", scopeName), ("id", input.Id), ("expectedHash", DistributedAllocation.ChangeHash(input)));
        async Task<AllocationChangeInput> Review(AllocationPlan plan)
        {
            var reply = await Preview(plan); check(Ok(reply), "Native ownership preview: " + reply);
            return reply.GetProperty("response").GetProperty("state").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions);
        }
        async Task Apply(AllocationPlan plan)
        {
            var input = await Review(plan); await Good(Prepare(input), "prepare " + input.Id); await Good(Commit(input), "commit " + input.Id);
            check(scopes.All(s => s.MatchesAllocationPlan(input.Plan)) && stores.All(s => s.Plan(scopeName).Epoch == input.Id), "native configuration/readback matches immutable successor");
            SaveEvidence("committed-successor");
        }
        // Actual native allocator entrypoints create original protected client state.
        var binding = await scopes[0].GetOfferAsync(Packet(41)); scopes[0].CommitLease(binding);
        var offered = await scopes[1].GetOfferAsync(Packet(42));
        DateTime expiry = binding.LeaseExpires; // the exact native ACK lifetime, including its post-journal ExtendLease timestamp
        uint leaseAddress = AllocationSequence.Number(binding.Address), offerAddress = AllocationSequence.Number(offered.Address);
        Report("initial protected lease=" + binding.Address + " offer=" + offered.Address + " expiry=" + expiry.ToString("O"));
        SaveEvidence("original-protected-state");
        var desired = Desired(names, "127.0.0.20", "127.0.0.95", [new(IPAddress.Parse("127.0.0.30"), IPAddress.Parse("127.0.0.31"))]);
        byte[] before = stores[0].Export();
        await Bad(Preview(desired, actor: originals[0]), "HTTP coordinator");
        await Bad(Preview(desired, actor: peers[0]), "service token coordinator");
        await Bad(Preview(desired, actor: admins[1]), "secondary coordinator");
        await Bad(Preview(desired, "stale"), "stale epoch preview");
        await Bad(Call(admins[0], "/api/ddi/dhcp/changes/freezePeer", ("id", desired.Epoch), ("currentPlan", Json(old))), "administrator impersonates peer");
        check(before.SequenceEqual(stores[0].Export()), "negative auth and stale checks do not mutate state");
        links[(0, 2)].Disconnected = true;
        await Bad(Preview(desired), "unavailable old owner leaves partial freeze"); links[(0, 2)].Disconnected = false;
        check(stores[0].ChangePending(scopeName) && stores[1].ChangePending(scopeName) && !stores[2].ChangePending(scopeName), "partial freeze explicit on exact participants");
        SaveEvidence("partial-freeze");
        await CheckDns("during partial DHCP freeze");
        check(await scopes[0].GetOfferAsync(Packet(43)) is null, "frozen native allocator offers nothing");
        check(!stores[0].Available(scopeName, leaseAddress, binding.ClientIdentifier.ToString()), "frozen renewal authority withheld");
        await Bad(Preview(desired with { Epoch = Guid.NewGuid().ToString("N") }), "competing change while frozen");
        links[(0, 2)].LoseMigrationResponse = "freezePeer";
        await Bad(Preview(desired), "lost response after durable last-owner freeze");
        check(stores.All(s => s.ChangePending(scopeName)), "lost freeze response never clears barriers");
        var input = await Review(desired);
        foreach (var frozen in input.Frozen) check(frozen.Plan.Epoch == old.Epoch && stores.Single(s => s.NodeName() == frozen.Node).Change(scopeName).Frozen == Json(frozen), "review contains exact original frozen state " + frozen.Node);
        await Bad(Call(admins[0], "/api/ddi/dhcp/changes/prepare", ("change", Json(input)), ("expectedHash", "wrong")), "changed review digest");
        string failedScopePath = Path.Combine(Field<string>(servers[1], "_scopesFolder"), scopeName + ".tmp");
        using (var blockedSave = new FileStream(failedScopePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            await Bad(Prepare(input), "actual peer native scope persistence failure");
        check(stores[1].Change(scopeName).Phase == "Prepared" && stores[1].Change(scopeName).PreparedNodes.Length == 0 && stores[0].Change(scopeName).PreparedNodes.Length == 1, "failed native save produces no local or coordinator receipt");
        SaveEvidence("failed-native-save-no-receipt");
        await Bad(Call(peers[1], "/api/ddi/dhcp/changes/commitPeer", ("scope", scopeName), ("id", input.Id), ("expectedHash", DistributedAllocation.ChangeHash(input)), ("preparedNodes", Json(names))), "peer certificate cannot replace missing local configuration receipt");
        links[(0, 2)].LoseMigrationResponse = "stage";
        await Bad(Prepare(input), "lost response after durable last-owner prepare");
        check(stores.All(s => s.ChangePending(scopeName)) && stores[0].Change(scopeName).PreparedNodes.Length == 2, "lost preparation response invents no receipt");
        SaveEvidence("lost-prepare-response");
        await Bad(Commit(input), "commit without every preparation receipt");
        // Reopen the actual disposable authority manager after a partial native operation.
        string authorityPath = Field<string>(stores[0], "_path"); await stores[0].DisposeAsync();
        stores[0] = new DistributedAllocation(authorityPath) { NodeName = () => names[0] };
        typeof(DnsWebService).GetField("_allocation", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(services[0], stores[0]); servers[0].Allocation = stores[0];
        check(stores[0].ChangePending(scopeName) && !stores[0].HasAuthority(scopeName, leaseAddress), "reopened native manager preserves prepared barrier");
        await Good(Prepare(input), "native exact prepare retry after manager reopen");
        await Bad(Call(admins[0], "/api/dhcp/scopes/enable", ("name", scopeName)), "cannot enable pending scope");
        await Bad(Call(admins[0], "/api/dhcp/scopes/set", ("name", scopeName), ("domainName", "wrong.test")), "cannot edit pending scope");
        await Bad(Call(admins[0], "/api/dhcp/scopes/delete", ("name", scopeName)), "cannot delete pending scope");
        links[(0, 2)].Disconnected = true; await Bad(Commit(input), "partial peer commit"); links[(0, 2)].Disconnected = false;
        check(stores[0].ChangePending(scopeName) && !stores[1].ChangePending(scopeName) && stores[2].ChangePending(scopeName), "partial publication permits only disjoint new authority");
        SaveEvidence("partial-commit");
        links[(0, 2)].LoseMigrationResponse = "commitPeer"; await Bad(Commit(input), "lost response after remote commit");
        check(stores[0].ChangePending(scopeName) && !stores[2].ChangePending(scopeName), "ambiguous remote commit never restores old authority");
        await Good(Commit(input), "native commit retry");
        SaveEvidence("first-commit");
        await Good(Prepare(input), "idempotent prepare after commit");
        int leaseOwner = Array.FindIndex(stores, s => s.FindLease(scopeName, binding.ClientIdentifier.ToString()) is not null);
        int offerOwner = Array.FindIndex(stores, s => s.FindOffer(scopeName, offered.ClientIdentifier.ToString()) is not null);
        check(leaseOwner >= 0 && stores[leaseOwner].FindLease(scopeName, binding.ClientIdentifier.ToString()).Expires == expiry, "range shrink preserves exact acknowledged expiry");
        check(offerOwner >= 0 && stores.Count(s => s.HasLiveOffer(scopeName, offerAddress, offered.ClientIdentifier.ToString())) == 1, "range shrink preserves one current offer owner");
        check(stores.All(s => !s.Available(scopeName, leaseAddress, "1-0299") && !s.Available(scopeName, offerAddress, "1-0299")), "no new client can take retained lease or offer");
        await Bad(Call(peers[0], "/api/ddi/dhcp/state/ingest", ("state", Json(new AllocationState(1, [old], input.Frozen.Select(f => f.Replica).ToArray())))), "ordinary mesh cannot restore old epoch");
        // Real native DHCP request processing writes an ACK to an owned loopback UDP socket.
        async Task Ack(int owner, byte client, IPAddress address)
        {
            using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            sender.Bind(new IPEndPoint(IPAddress.Loopback, 0)); receiver.Bind(new IPEndPoint(address, 68));
            scopes[owner].SetEnabled(true); typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scopes[owner], IPAddress.Loopback);
            try
            {
                await ((Task)typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(servers[owner], [Packet(client, 3, address), new IPEndPoint(address, 68), default(IPPacketInformation), sender])).WaitAsync(deadline.Token);
                byte[] wire = new byte[4096]; int size = await receiver.ReceiveAsync(wire.AsMemory(), SocketFlags.None, deadline.Token);
                var reply = new DhcpMessage(new MemoryStream(wire, 0, size));
                check(reply.DhcpMessageType.Type == DhcpMessageType.Ack && reply.YourClientIpAddress.Equals(address), "native DHCP UDP ACK for retained binding " + address);
            }
            finally { scopes[owner].SetEnabled(false); }
        }
        await Ack(leaseOwner, 41, binding.Address);
        await Ack(offerOwner, 42, offered.Address);
        check(stores[leaseOwner].FindLease(scopeName, binding.ClientIdentifier.ToString()).Expires >= expiry, "renewal does not shorten prior lease lifetime");
        var concurrentOffers = await Task.WhenAll(scopes.SelectMany((s, index) => Enumerable.Range(50 + index * 10, 4).Select(c => s.GetOfferAsync(Packet((byte)c)))));
        check(concurrentOffers.All(l => l is not null) && concurrentOffers.Select(l => l.Address).Distinct().Count() == 12 && concurrentOffers.All(l => !l.Address.Equals(binding.Address) && !l.Address.Equals(offered.Address)), "concurrent native offers remain disjoint and protect retained bindings");
        foreach (var lease in concurrentOffers) check(AllocationSequence.Number(lease.Address) >= AllocationSequence.Number(IPAddress.Parse("127.0.0.20")) && lease.Address.ToString() != "127.0.0.30" && lease.Address.ToString() != "127.0.0.31", "successor eligibility controls new offers");
        // Exclusion removal and expansion use a fresh epoch, retaining client protections.
        await Apply(Desired(names, "127.0.0.10", "127.0.0.99"));
        // Native reservation collision retains the existing client, withholding new reservation owner.
        var reservation = new Lease(LeaseType.Reserved, new ClientIdentifierOption(1, new byte[] { 2, 0, 0, 0, 0, 99 }), null, new byte[] { 2, 0, 0, 0, 0, 99 }, binding.Address, "reservation", 0);
        await Apply(Desired(names, reserved: [reservation]));
        check(scopes.All(s => s.ReservedLeases.Single().Address.Equals(binding.Address)), "native reservation configuration readback exact");
        check(stores.All(s => !s.Available(scopeName, leaseAddress, reservation.ClientIdentifier.ToString())), "reservation cannot steal other client's protected lease");
        leaseOwner = Array.FindIndex(stores, s => s.FindLease(scopeName, binding.ClientIdentifier.ToString()) is not null); await Ack(leaseOwner, 41, binding.Address);
        await Apply(Desired(names)); check(scopes.All(s => s.ReservedLeases.Count == 0), "reservation removal clears all native old reservations");
        await Apply(Desired(names, excluded: [new(binding.Address, binding.Address)]));
        leaseOwner = Array.FindIndex(stores, s => s.FindLease(scopeName, binding.ClientIdentifier.ToString()) is not null); await Ack(leaseOwner, 41, binding.Address);
        check(stores.All(s => !s.Available(scopeName, leaseAddress, "1-0298")), "new exclusion withholds protected binding from other clients");
        await Apply(Desired(names));
        var movedReservation = new Lease(LeaseType.Reserved, binding.ClientIdentifier, null, binding.HardwareAddress, IPAddress.Parse("127.0.0.85"), "moved", 0);
        await Apply(Desired(names, reserved: [movedReservation]));
        leaseOwner = Array.FindIndex(stores, s => s.FindLease(scopeName, binding.ClientIdentifier.ToString()) is not null); await Ack(leaseOwner, 41, binding.Address);
        check(stores[leaseOwner].FindLease(scopeName, binding.ClientIdentifier.ToString()).Address == leaseAddress, "moving a client's reservation retains its current binding");
        await Apply(Desired(names));
        // Removing a cooperative owner transfers its current direct bindings; adding it back is reviewed separately.
        await Apply(Desired(names.Take(2).ToArray()));
        check(stores[2].Plan(scopeName).Owners.Length == 2 && await scopes[2].GetOfferAsync(Packet(91)) is null, "retired owner cannot serve old capacity");
        await Apply(Desired(names));
        // Mid-flight permission and role revocation after a genuine peer HTTP response.
        var auth = Field<AuthManager>(services[0], "_authManager"); string actorPassword = "Fixture-" + Guid.NewGuid().ToString("N"); var actor = auth.CreateUser("Ownership fixture", "ownership-actor", actorPassword);
        var full = PermissionFlag.View | PermissionFlag.Modify | PermissionFlag.Delete;
        auth.SetPermission(PermissionSection.Administration, actor, full); auth.SetPermission(PermissionSection.DhcpServer, actor, full);
        // A native user session is created for the isolated actor; original administrator remains open.
        var certificate = (System.Security.Cryptography.X509Certificates.X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(services[0]);
        using var actorClient = new HttpClient(new PinnedHandler(certificate)) { BaseAddress = admins[0].BaseAddress };
        var actorLogin = await Call(actorClient, "/api/user/login", ("user", actor.Username), ("pass", actorPassword)); check(Ok(actorLogin), "actual actor authentication");
        actorClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", actorLogin.GetProperty("token").GetString());
        var pending = Desired(names);
        auth.SetPermission(PermissionSection.DhcpServer, actor, PermissionFlag.View);
        byte[] viewOnlyBefore = stores[0].Export(); await Bad(Preview(pending, actor: actorClient), "view-only DHCP actor");
        check(viewOnlyBefore.SequenceEqual(stores[0].Export()), "view-only request does not freeze authority");
        auth.SetPermission(PermissionSection.DhcpServer, actor, full);
        links[(0, 1)].AfterOwnershipResponse = action => { if (action == "freezePeer") auth.SetPermission(PermissionSection.Administration, actor, PermissionFlag.View); };
        try { await Bad(Preview(pending, actor: actorClient), "mid-flight administrator privilege revocation"); }
        finally { links[(0, 1)].AfterOwnershipResponse = null; }
        check(stores[0].ChangePending(scopeName) && stores[2].Change(scopeName).Id != pending.Epoch, "revoked actor cannot continue to remaining participant");
        // Fresh actual login and required privilege/source proof before releasing any fixture admin session.
        using var freshProof = new HttpClient(new PinnedHandler(certificate)) { BaseAddress = admins[0].BaseAddress };
        var proofLogin = await Call(freshProof, "/api/user/login", ("user", "admin"), ("pass", passwords[0])); check(Ok(proofLogin), "separate fresh administrator authenticates after fixture ACL change");
        freshProof.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", proofLogin.GetProperty("token").GetString());
        await Good(Call(freshProof, "/api/dhcp/scopes/set", ("name", "Default"), ("domainName", "ownership-proof.test")), "separate fresh administrator required write");
        var sessions = await Call(freshProof, "/api/admin/sessions/list");
        check(sessions.GetProperty("response").GetProperty("sessions").EnumerateArray().Single(s => s.GetProperty("isCurrentSession").GetBoolean()).GetProperty("lastSeenRemoteAddress").GetString() == "127.0.0.1", "target-seen fresh administrator source is loopback");
        var remaining = await Review(pending); await Good(Prepare(remaining), "admin resumes revoked actor change"); await Good(Commit(remaining), "admin commits resumed change");
        using var freshReader = new HttpClient(new PinnedHandler(certificate)) { BaseAddress = admins[0].BaseAddress };
        var readerLogin = await Call(freshReader, "/api/user/login", ("user", actor.Username), ("pass", actorPassword)); check(Ok(readerLogin), "separate fresh revoked actor authenticates");
        freshReader.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", readerLogin.GetProperty("token").GetString());
        await Good(Call(freshReader, "/api/ddi/dhcp/state/get"), "fresh revoked actor retains intended DHCP view"); await Bad(Preview(Desired(names), actor: freshReader), "fresh actor cannot coordinate after revocation");
        check(Ok(await Call(originals[0], "/api/ddi/dhcp/state/get")), "original administrative session remains usable after fresh checks");
        // A real peer response returns after the coordinator loses its primary role.
        var manager = Field<ClusterManager>(services[0], "_clusterManager"); var currentNodes = Field<Dictionary<int, ClusterNode>>(manager, "_clusterNodes");
        var roleField = typeof(ClusterNode).GetField("_type", BindingFlags.Instance | BindingFlags.NonPublic);
        var rolePlan = Desired(names);
        links[(0, 1)].AfterOwnershipResponse = action => { if (action == "freezePeer") { roleField.SetValue(currentNodes[1], ClusterNodeType.Secondary); roleField.SetValue(currentNodes[2], ClusterNodeType.Primary); } };
        try { await Bad(Preview(rolePlan), "mid-flight primary role loss"); }
        finally { links[(0, 1)].AfterOwnershipResponse = null; roleField.SetValue(currentNodes[1], ClusterNodeType.Primary); roleField.SetValue(currentNodes[2], ClusterNodeType.Secondary); }
        check(stores[0].ChangePending(scopeName) && stores[2].Change(scopeName).Id != rolePlan.Epoch, "role loss stops remaining peer operations");
        var roleReview = await Review(rolePlan); await Good(Prepare(roleReview), "restored fixture primary resumes exact frozen change"); await Good(Commit(roleReview), "restored fixture primary commits exact change");
        // Hold a genuine native renewal in a loopback DNS options lookup while preview drains it.
        using (var dnsGate = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12)))
        {
            var concurrencyPlan = Desired(names); var dns = services[0].DnsServer; var forwarders = dns.Forwarders;
            dnsGate.Bind(new IPEndPoint(IPAddress.Loopback, 0)); sender.Bind(new IPEndPoint(IPAddress.Loopback, 0)); receiver.Bind(new IPEndPoint(binding.Address, 68));
            dns.Forwarders = [NameServerAddress.Parse("127.0.0.1:" + ((IPEndPoint)dnsGate.LocalEndPoint).Port)];
            scopes[0].NtpServerDomainNames = ["inflight-" + Guid.NewGuid().ToString("N") + ".example.net"];
            scopes[0].SetEnabled(true); typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scopes[0], IPAddress.Loopback);
            byte[] query = new byte[4096]; var waiting = dnsGate.ReceiveFromAsync(query.AsMemory(), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), deadline.Token);
            var renewal = (Task)typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(servers[0], [Packet(41, 3, binding.Address), new IPEndPoint(binding.Address, 68), default(IPPacketInformation), sender]);
            try
            {
                var received = await waiting; check(!renewal.IsCompleted, "real renewal is held at native options lookup"); scopes[0].SetEnabled(false);
                var concurrentPreview = Preview(concurrencyPlan);
                await Task.Delay(50, deadline.Token);
                check(!concurrentPreview.IsCompleted && scopes[0].MigrationCapturing, "ownership preview waits for admitted renewal before freezing");
                await Bad(Preview(concurrencyPlan with { Epoch = Guid.NewGuid().ToString("N") }), "competing preview during native renewal drain");
                query[2] = 0x81; query[3] = 0x83; await dnsGate.SendToAsync(query.AsMemory(0, received.ReceivedBytes), SocketFlags.None, received.RemoteEndPoint, deadline.Token);
                await renewal.WaitAsync(deadline.Token); byte[] response = new byte[4096]; int count = await receiver.ReceiveAsync(response.AsMemory(), SocketFlags.None, deadline.Token);
                check(new DhcpMessage(new MemoryStream(response, 0, count)).DhcpMessageType.Type == DhcpMessageType.Ack, "in-flight native UDP ACK completes before ownership freeze");
                var captured = await concurrentPreview.WaitAsync(deadline.Token); check(Ok(captured), "preview completes after admitted renewal");
                var concurrentInput = captured.GetProperty("response").GetProperty("state").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions);
                DateTime acknowledged = scopes[0].GetExistingLeaseOrOffer(Packet(41))?.LeaseExpires ?? concurrentInput.Frozen.Single(f => f.Node == names[0]).Replica.Entries.Single(e => e.Address == leaseAddress).Expires;
                check(concurrentInput.Frozen.Single(f => f.Node == names[0]).Replica.Entries.Single(e => e.Address == leaseAddress).Expires >= acknowledged, "frozen original retains exact final in-flight ACK lifetime");
                await Good(Prepare(concurrentInput), "prepare after in-flight renewal"); await Good(Commit(concurrentInput), "commit after in-flight renewal");
            }
            finally { scopes[0].SetEnabled(false); scopes[0].NtpServerDomainNames = null; dns.Forwarders = forwarders; }
        }
        await CheckDns("after ownership changes");
        SaveEvidence("final-after-concurrent-renewal");
        Report("native fixtures complete; production, UI, real relays and production-source access untested");
    }
}
