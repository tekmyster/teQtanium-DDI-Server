// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;

static partial class DistributedTransportChecks
{
    static async Task CheckVoting(List<DnsWebService> services, List<HttpClient> originals, List<HttpClient> admins, List<HttpClient> peers,
        string[] names, Dictionary<(int Source, int Target), PinnedHandler> links, string root, Action<bool, string> check)
    {
        const string scopeName = "Voting";
        string Json<T>(T value) => JsonSerializer.Serialize(value, VotingLog.Json);
        var stores = services.Select(s => Field<DistributedAllocation>(s, "_allocation")).ToArray();
        var voting = services.Select(s => Field<VotingLog>(s, "_voting")).ToArray();
        var servers = services.Select(s => Field<DhcpServer>(s, "_dhcpServer")).ToArray();
        var scopes = new Scope[services.Count]; int evidenceNumber = 0; byte clientNumber = 10;
        string evidence = Environment.GetEnvironmentVariable("TEQTANIUM_VOTING_EVIDENCE") ?? Path.Combine(root, "evidence"); Directory.CreateDirectory(evidence);
        void Evidence(string label)
        {
            File.WriteAllText(Path.Combine(evidence, $"{DateTime.UtcNow:yyyyMMddTHHmmssfff}-{++evidenceNumber:D3}-{label}.json"), Json(new { label, processId = Environment.ProcessId, utc = DateTime.UtcNow, targetSeenSource = "127.0.0.1", regions = new[] { "east", "east", "central", "west", "west", "learner" }, links = links.Select(p => new { source = names[p.Key.Source], target = names[p.Key.Target], disconnected = p.Value.Disconnected }), nodes = voting.Select((v, i) => new { node = names[i], http = originals[i].BaseAddress, https = admins[i].BaseAddress, dns = services[i].DnsServer.LocalEndPoints.Select(p => p.ToString()), voting = v.Status(), allocation = stores[i].Snapshot(), native = scopes[i] is null ? null : Convert.ToBase64String(File.ReadAllBytes(Path.Combine(Field<string>(servers[i], "_scopesFolder"), scopeName + ".scope"))) }) }));
        }
        bool Ok(JsonElement reply) => reply.GetProperty("status").GetString() == "ok";
        async Task<JsonElement> Good(Task<JsonElement> task, string label) { var reply = await task; check(Ok(reply), label + ": " + reply); Console.WriteLine("VOTING PASS " + label); return reply; }
        async Task Bad(Task<JsonElement> task, string label) { var reply = await task; check(!Ok(reply), label + ": " + reply); Console.WriteLine("VOTING REFUSED " + label); }
        Task<JsonElement> Api(int actor, string action, params (string Key, string Value)[] fields)
        {
            if (action is "voters" or "finalize" or "authorizeOwnership")
            {
                var state = voting[actor].Status().State;
                fields = [.. fields, ("expectedTerm", state.Term.ToString()), ("expectedIndex", state.Log.Length.ToString())];
            }
            return Call(admins[actor], "/api/ddi/voting/" + action, fields);
        }
        Task<JsonElement> Campaign(int actor) => Api(actor, "campaign");
        Task<JsonElement> Sync(int actor) => Api(actor, "sync");
        void Partition(params int[][] groups)
        { foreach (var pair in links) pair.Value.Disconnected = !groups.Any(g => g.Contains(pair.Key.Source) && g.Contains(pair.Key.Target)); }
        void Heal() { foreach (var link in links.Values) link.Disconnected = false; }
        async Task Mesh()
        {
            foreach (var state in stores.Select(s => s.Export()).ToArray())
                for (int i = 0; i < stores.Length; i++) await Good(Call(peers[i], "/api/ddi/dhcp/state/ingest", ("state", System.Text.Encoding.UTF8.GetString(state))), "native capacity mesh " + i);
        }
        DhcpMessage Packet(byte client, byte type = 1, IPAddress address = null)
        {
            byte[] wire = new byte[244]; wire[0] = 1; wire[1] = 1; wire[2] = 6; wire[7] = client; wire[28] = 2; wire[33] = client;
            address?.GetAddressBytes().CopyTo(wire, 12); new byte[] { 99, 130, 83, 99, 53, 1, type, 255 }.CopyTo(wire, 236); return new DhcpMessage(new MemoryStream(wire));
        }
        var leases = new List<(int Node, byte Client, Lease Lease)>();
        async Task LocalService(string label)
        {
            var requests = scopes.Select((s, i) => (Scope: s, Node: i, Client: ++clientNumber)).ToArray();
            var offers = await Task.WhenAll(requests.Select(async r => (r.Node, r.Client, Lease: await r.Scope.GetOfferAsync(Packet(r.Client)))));
            foreach (var offer in offers)
            {
                check(offer.Lease is not null, label + " isolated native offer " + offer.Node);
                scopes[offer.Node].CommitLease(offer.Lease); servers[offer.Node].SaveScope(scopeName);
                check(stores[offer.Node].HasAuthority(scopeName, AllocationSequence.Number(offer.Lease.Address)), label + " offer belongs to persisted owner");
                leases.Add(offer);
            }
            check(leases.Select(l => l.Lease.Address).Distinct().Count() == leases.Count, label + " simultaneous partitioned offers remain globally collision-free");
            check(stores.Select(s => s.Plan(scopeName).Epoch).Distinct().Count() == 1, label + " vote partitions do not repartition scope");
        }
        async Task Ack((int Node, byte Client, Lease Lease) binding, string label)
        {
            int node = binding.Node; var ip = binding.Lease.Address; var expected = stores[node].FindLease(scopeName, binding.Lease.ClientIdentifier.ToString()).Expires;
            using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            sender.Bind(new IPEndPoint(IPAddress.Loopback, 0)); receiver.Bind(new IPEndPoint(ip, 68)); scopes[node].SetEnabled(true);
            typeof(Scope).GetField("_interfaceAddress", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(scopes[node], IPAddress.Loopback);
            try
            {
                await ((Task)typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(servers[node], [Packet(binding.Client, 3, ip), new IPEndPoint(ip, 68), default(IPPacketInformation), sender])).WaitAsync(deadline.Token);
                byte[] wire = new byte[4096]; int length = await receiver.ReceiveAsync(wire.AsMemory(), SocketFlags.None, deadline.Token); var reply = new DhcpMessage(new MemoryStream(wire, 0, length));
                check(reply.DhcpMessageType.Type == DhcpMessageType.Ack && reply.YourClientIpAddress.Equals(ip), label + " parsed handler emits actual UDP ACK for correct client address");
                check(stores[node].FindLease(scopeName, binding.Lease.ClientIdentifier.ToString()).Expires >= expected, label + " native renewal retains protected expiry");
            }
            finally { scopes[node].SetEnabled(false); }
        }
        string mode = Environment.GetEnvironmentVariable("TEQTANIUM_VOTING_PHASE") ?? "full";
        async Task KillBoundary(string label, object saved)
        {
            Evidence(label); File.WriteAllText(Path.Combine(root, "resume.json"), Json(saved));
            var nativeFiles = scopes.Select((s, i) => new { node = i, sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(Field<string>(servers[i], "_scopesFolder"), scopeName + ".scope")))) }).ToArray();
            var protections = stores.SelectMany(s => s.Snapshot().Replicas.Where(r => r.Scope == scopeName && r.Node == s.NodeName()).SelectMany(r => r.Entries.Where(e => e.State == "Lease").Select(e => new { node = s.NodeName(), entry = e }))).ToArray();
            File.WriteAllText(Path.Combine(root, "native-before-kill.json"), Json(new { nativeFiles, protections }));
            File.WriteAllText(Path.Combine(root, "kill-ready.json"), Json(new { processId = Environment.ProcessId, label, utc = DateTime.UtcNow }));
            Console.WriteLine("VOTING KILL READY " + label); await Task.Delay(Timeout.InfiniteTimeSpan);
        }
        if (mode.StartsWith("resume-"))
        {
            for (int i = 0; i < scopes.Length; i++) scopes[i] = servers[i].GetScope(scopeName) ?? throw new Exception("Native scope missing after whole-process reopen");
            using var saved = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "resume.json")));
            using var beforeKill = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "native-before-kill.json")));
            check(saved.RootElement.GetProperty("processId").GetInt32() != Environment.ProcessId, "fresh native process identity after kill");
            foreach (var native in beforeKill.RootElement.GetProperty("nativeFiles").EnumerateArray())
            {
                int node = native.GetProperty("node").GetInt32();
                check(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(Field<string>(servers[node], "_scopesFolder"), scopeName + ".scope")))) == native.GetProperty("sha256").GetString(), "fresh native process reopens exact scope bytes " + node);
            }
            Evidence("whole-native-reopened"); await Good(Campaign(0), "fresh native election after kill");
            if (mode == "resume-joint")
            {
                check(voting.All(v => v.Status().Configuration.NextVoters?.Length == 5), "reopened durable joint configuration");
                await Good(Api(0, "finalize", ("id", saved.RootElement.GetProperty("finalId").GetString())), "resume exact joint finalization");
                await LocalService("post-joint-kill"); await Ack(leases[0], "post-joint-kill");
            }
            else
            {
                var resumedInput = saved.RootElement.GetProperty("input").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions);
                var command = new VotingOwnership(scopeName, resumedInput.Frozen[0].Plan.Epoch, resumedInput.Id, DistributedAllocation.ChangeHash(resumedInput));
                foreach (var v in voting) v.RequireOwnership(command);
                check(stores.All(s => s.ChangePending(scopeName)), "whole-native restart retains pending ownership barriers");
                await Good(Call(admins[0], "/api/ddi/dhcp/changes/prepare", ("change", Json(resumedInput)), ("expectedHash", command.Hash)), "resume exact native preparation");
                await Good(Call(admins[0], "/api/ddi/dhcp/changes/commit", ("scope", scopeName), ("id", resumedInput.Id), ("expectedHash", command.Hash)), "resume exact native ownership commit");
                check(stores.All(s => s.Plan(scopeName).Epoch == resumedInput.Id), "fresh-process exact successor readback");
                await LocalService("post-ownership-kill"); await Ack(leases[0], "post-ownership-kill");
            }
            foreach (var protection in beforeKill.RootElement.GetProperty("protections").EnumerateArray())
            {
                var entry = protection.GetProperty("entry").Deserialize<AllocationEntry>(DistributedAllocation.JsonOptions);
                check(stores.Any(s => s.FindLease(scopeName, entry.Client)?.Expires >= entry.Expires), "whole-native resume preserves exact acknowledged expiry and client " + entry.Client);
            }
            Evidence("whole-native-resume-complete"); return;
        }
        for (int i = 0; i < scopes.Length; i++)
        {
            scopes[i] = new Scope(scopeName, false, IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.230"), IPAddress.Parse("255.255.255.0"), Field<LogManager>(services[i], "_log"), servers[i]);
            await servers[i].AddScopeAsync(scopes[i]);
            await Good(Call(admins[i], "/api/dhcp/scopes/set", ("name", scopeName), ("dnsUpdates", "false"), ("pingCheckEnabled", "false"), ("ignoreClientIdentifierOption", "true")), "paused native owner " + i);
        }
        await Good(Call(admins[0], "/api/ddi/dhcp/plan/set", ("scope", scopeName), ("owners", string.Join(',', names))), "initial six legitimate allocation owners");
        await LocalService("before voting");
        const string unaffectedName = "VotingUnaffected";
        var unaffectedScopes = new Scope[scopes.Length];
        for (int i = 0; i < unaffectedScopes.Length; i++)
        {
            unaffectedScopes[i] = new Scope(unaffectedName, false, IPAddress.Parse("127.0.1.10"), IPAddress.Parse("127.0.1.110"), IPAddress.Parse("255.255.255.0"), Field<LogManager>(services[i], "_log"), servers[i]);
            await servers[i].AddScopeAsync(unaffectedScopes[i]);
            await Good(Call(admins[i], "/api/dhcp/scopes/set", ("name", unaffectedName), ("dnsUpdates", "false"), ("pingCheckEnabled", "false")), "unaffected scope " + i);
        }
        await Good(Call(admins[0], "/api/ddi/dhcp/plan/set", ("scope", unaffectedName), ("owners", string.Join(',', names))), "unaffected scope initial ownership");
        var unaffectedLease = await unaffectedScopes[0].GetOfferAsync(Packet(200)); unaffectedScopes[0].CommitLease(unaffectedLease); servers[0].SaveScope(unaffectedName);
        var unaffectedProtection = stores[0].FindLease(unaffectedName, unaffectedLease.ClientIdentifier.ToString()); string unaffectedEpoch = stores[0].Plan(unaffectedName).Epoch;
        var seed = new VotingSeed(Guid.NewGuid().ToString("N"), names.Take(3).ToArray(), names.Skip(3).ToArray());
        await Bad(Call(originals[0], "/api/ddi/voting/initialize", ("payload", Json(seed))), "plaintext voting administrator");
        await Bad(Call(peers[0], "/api/ddi/voting/initialize", ("payload", Json(seed))), "service token impersonates administrator");
        await Good(Api(0, "initialize", ("payload", Json(seed))), "native identical seed initialization");
        await Good(Api(0, "initialize", ("payload", Json(seed))), "exact initialization retry");
        await Bad(Api(0, "initialize", ("payload", Json(seed with { Group = Guid.NewGuid().ToString("N") }))), "foreign voting group reseed");
        await Bad(Campaign(5), "learner cannot campaign"); await Good(Campaign(0), "three-voter election");
        string pendingBorrow = stores[5].CapacityRequest(scopeName, names[0]);
        var grantReply = await Good(Call(peers[0], "/api/ddi/dhcp/grant", ("scope", scopeName), ("borrower", names[5]), ("requestId", pendingBorrow)), "native permanent grant to learner owner");
        await Good(Call(peers[5], "/api/ddi/dhcp/state/ingest", ("state", grantReply.GetProperty("response").GetProperty("state").GetRawText())), "borrower imports exact donor grant");
        var permanent = stores[0].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[0]).Entries.Single(e => e.GrantId == pendingBorrow);
        string returnGrantId = Guid.NewGuid().ToString("N"), returnId = Guid.NewGuid().ToString("N");
        var returnGrantReply = await Good(Call(peers[1], "/api/ddi/dhcp/grant", ("scope", scopeName), ("borrower", names[4]), ("requestId", returnGrantId)), "native grant for pending return");
        await Good(Call(peers[4], "/api/ddi/dhcp/state/ingest", ("state", returnGrantReply.GetProperty("response").GetProperty("state").GetRawText())), "return borrower imports original grant");
        var originalReturnedGrant = stores[1].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[1]).Entries.Single(e => e.GrantId == returnGrantId);
        var originalEpoch = stores[4].Plan(scopeName).Epoch;
        await Good(Call(admins[4], "/api/ddi/dhcp/grants/return", ("scope", scopeName), ("epoch", originalEpoch), ("owner", names[1]), ("address", AllocationSequence.Address(originalReturnedGrant.Address).ToString()), ("grantId", returnGrantId), ("requestId", returnId), ("expectedSequence", stores[4].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[4]).Sequence.ToString()), ("expectedHash", DistributedAllocation.GrantReviewHash(scopeName, originalEpoch, names[1], originalReturnedGrant))), "native durable pending grant surrender");
        var pendingReturn = stores[4].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[4]).GrantReturns.Single(r => r.Id == returnId);
        await Mesh();
        await Bad(Call(admins[0], "/api/admin/cluster/primary/deleteSecondary", ("secondaryNodeId", "6")), "legacy enrollment deletion bypass");
        await Bad(Call(admins[1], "/api/admin/cluster/secondary/promote", ("forceDeletePrimary", "true")), "legacy primary promotion bypass");
        var staleAppend = voting[0].AppendRequest(0);
        Partition([0, 5], [1, 2, 3, 4]); await Good(Sync(0), "already committed status remains readable without a new leadership claim");
        // Sync alone may confirm an already committed entry. Explicit new proposals
        // and elections below test quorum; status is not a lease on leadership.
        await Bad(Campaign(0), "one voter and learners do not form three-voter quorum");
        await Good(Campaign(1), "two-voter regional survivor elects majority leader"); await LocalService("three voters 2+1 with learners");
        await Ack(leases.First(l => l.Node == 0), "isolated valid owner"); Evidence("three-voter-two-plus-one");
        var staleReply = await Good(Call(peers[2], "/api/ddi/voting/append", ("sender", names[0]), ("payload", Json(staleAppend))), "stale leader append replay response");
        check(!staleReply.GetProperty("response").GetProperty("state").GetProperty("success").GetBoolean(), "stale leader append is explicitly refused");
        Heal(); await Good(Sync(1), "healed old leader converges"); await Good(Campaign(0), "primary elected after healing");
        Partition([0, 1, 5], [2, 3, 4]); await Good(Campaign(0), "leader retained on three-voter majority side"); await LocalService("three voters majority leader"); Heal(); await Good(Sync(0), "heal three voters");
        Partition([0], [1], [2], [3], [4], [5]);
        await Bad(Campaign(0), "three voters all isolated"); await LocalService("three voters no majority"); Evidence("three-voter-all-isolated"); Heal(); await Good(Campaign(0), "restore three-voter connectivity");
        string jointId = Guid.NewGuid().ToString("N"), finalId = Guid.NewGuid().ToString("N");
        // A truly lagging learner must be caught up before promotion. Clear only the
        // volatile current-term match observation by a new election with its link down.
        links[(0, 4)].Disconnected = true; await Good(Campaign(0), "elect without lagging learner");
        await Bad(Api(0, "voters", ("id", jointId), ("payload", Json(names.Take(5).ToArray()))), "uncaught learner promotion"); links[(0, 4)].Disconnected = false;
        await Good(Sync(0), "native learner catch-up");
        Partition([0, 1, 5], [2, 3, 4]);
        await Bad(Api(0, "voters", ("id", jointId), ("payload", Json(names.Take(5).ToArray()))), "old majority cannot commit without new joint majority");
        check(voting[0].Status().Configuration.NextVoters?.Length == 5 && voting[0].Status().State.Commit < voting[0].Status().State.Log.Length, "joint transition remains explicitly uncommitted");
        Evidence("joint-old-majority-insufficient"); Heal();
        links[(0, 4)].LoseVotingResponse = "append";
        await Good(Api(0, "voters", ("id", jointId), ("payload", Json(names.Take(5).ToArray()))), "exact joint retry with one lost durable reply");
        check(voting.All(v => v.Status().Configuration.NextVoters?.Length == 5), "native joint configuration replicated");
        if (mode == "kill-joint") await KillBoundary("joint-committed-before-finalize", new { processId = Environment.ProcessId, jointId, finalId });
        await Good(Api(0, "finalize", ("id", finalId)), "finalize five-voter membership");
        await Good(Api(0, "finalize", ("id", finalId)), "same finalization reply retry");
        check(voting.All(v => v.Status().Configuration.Voters.Length == 5 && v.Status().Configuration.Learners.SequenceEqual([names[5]])), "five voters and separate learner native readback");
        Partition([0, 1, 5], [2, 3, 4]); await Bad(Campaign(0), "five-voter minority plus learner cannot elect"); await Good(Campaign(2), "three-of-five regional majority elects");
        await LocalService("five voters 3+2"); await Ack(leases.First(l => l.Node == 1), "five-voter minority legitimate renewal"); Evidence("five-voter-three-plus-two"); Heal(); await Good(Sync(2), "healed five-voter leader convergence"); await Good(Campaign(0), "primary returns through actual election");
        Partition([0, 1, 2, 5], [3, 4]); await Good(Campaign(0), "leader on five-voter majority side"); await LocalService("five-voter majority leader"); Heal(); await Good(Sync(0), "heal surviving majority");
        Partition([0, 1, 5], [2, 3], [4]); await Bad(Campaign(0), "five voters 2+2+1 regional loss"); await LocalService("five voters 2+2+1"); Evidence("five-voter-two-two-one"); Heal(); await Good(Campaign(0), "restore five-voter quorum");
        // Asymmetric and changing links do not supply extra votes; the learner's
        // non-vote is checked through the native peer endpoint itself.
        var voteRequest = new VotingVote(seed.Group, voting[0].Status().State.Term, names[0], voting[0].Status().State.Log.Length, voting[0].Status().State.Log.Last().Term);
        var learnerVote = await Good(Call(peers[5], "/api/ddi/voting/vote", ("sender", names[0]), ("payload", Json(voteRequest))), "native learner voting response");
        check(!learnerVote.GetProperty("response").GetProperty("state").GetProperty("success").GetBoolean(), "native learner explicitly refuses vote");
        links[(0, 1)].Disconnected = true; await Good(Sync(0), "asymmetric outgoing loss tolerates surviving majority"); links[(0, 1)].Disconnected = false;
        // Concurrent driver operations serialize and exact request identities retain
        // a single joint transition. The competing request cannot alter that result.
        string shrinkId = Guid.NewGuid().ToString("N");
        var competing = await Task.WhenAll(Api(0, "voters", ("id", shrinkId), ("payload", Json(names.Take(3).ToArray()))), Api(0, "voters", ("id", Guid.NewGuid().ToString("N")), ("payload", Json(new[] { names[0], names[3], names[4] }))));
        check(competing.Count(Ok) == 1, "only one concurrent joint membership transition commits");
        var shrink = voting[0].Status().Configuration;
        int disconnectedDemoted = Array.IndexOf(names, shrink.Voters.Except(shrink.NextVoters).First());
        Partition([disconnectedDemoted], Enumerable.Range(0, names.Length).Where(i => i != disconnectedDemoted).ToArray());
        await Good(Api(0, "finalize", ("id", Guid.NewGuid().ToString("N"))), "demote voters to enrolled learners");
        check(voting[disconnectedDemoted].Status().Configuration.NextVoters is not null && !voting[0].Status().Configuration.Voters.Contains(names[disconnectedDemoted]), "isolated former voter has not heard final removal");
        await Bad(Campaign(disconnectedDemoted), "isolated stale former voter cannot form either joint majority");
        check(stores.All(s => s.Plan(scopeName).Owners.SequenceEqual(names)), "voter demotion never surrenders allocation capacity");
        await LocalService("demoted legitimate owners");
        await Ack(leases.First(l => l.Node == disconnectedDemoted), "isolated former voter retains legitimate native renewal");
        Evidence("demoted-voter-missed-finalization-still-legitimate-owner");
        Heal(); await Good(Campaign(0), "heal former voter through current election and log catch-up");
        check(stores.All(s => s.Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[0]).Entries.Contains(permanent)), "membership changes preserve exact permanent donor grant");
        check(stores[5].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[5]).BorrowRequests.Single(r => r.Donor == names[0]).Id == pendingBorrow, "membership changes retain original pending donor request");
        check(stores.All(s => s.Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[4]).GrantReturns.Contains(pendingReturn)), "membership changes preserve exact pending surrender receipt");
        // Test actual current authorization revocation at the remote-response boundary.
        var manager = Field<ClusterManager>(services[0], "_clusterManager"); var enrolled = Field<Dictionary<int, ClusterNode>>(manager, "_clusterNodes");
        links[(0, 1)].AfterVotingResponse = action => { if (action == "append") typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(manager, enrolled.Where(p => p.Key != 6).ToDictionary(p => p.Key, p => p.Value)); };
        try { await Bad(Sync(0), "post-await enrolled membership revocation"); }
        finally { links[(0, 1)].AfterVotingResponse = null; typeof(ClusterManager).GetField("_clusterNodes", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(manager, enrolled); }
        await Good(Sync(0), "resume after restoring exact fixture enrollment");
        bool changedTerm = false;
        links[(0, 1)].AfterVotingResponse = action =>
        {
            if (action != "append" || changedTerm) return; changedTerm = true; var state = voting[0].Status().State;
            string currentVoter = voting[0].Status().Configuration.Voters.First(n => n != names[0]);
            voting[0].Vote(new(seed.Group, state.Term + 1, currentVoter, state.Log.Length, state.Log.Last().Term));
        };
        try { await Bad(Sync(0), "post-await higher term revokes leadership"); }
        finally { links[(0, 1)].AfterVotingResponse = null; }
        await Good(Campaign(0), "elect again after observed higher term");
        await Bad(Call(admins[0], "/api/ddi/voting/voters", ("id", Guid.NewGuid().ToString("N")), ("payload", Json(names.Take(5).ToArray())), ("expectedTerm", "0"), ("expectedIndex", "0")), "stale reviewed voting revision");
        var old = stores[0].Plan(scopeName); string changeId = Guid.NewGuid().ToString("N");
        var protectedBefore = leases.Select(l => stores[l.Node].FindLease(scopeName, l.Lease.ClientIdentifier.ToString()) ?? throw new Exception("Missing live protection before freeze")).ToArray();
        using var nativeBytes = new MemoryStream(); scopes[0].WriteTo(nativeBytes, false, false); nativeBytes.Position = 0;
        using var desiredScope = new Scope(nativeBytes, Field<LogManager>(services[0], "_log"), servers[0]); desiredScope.ChangeNetwork(IPAddress.Parse("127.0.0.10"), IPAddress.Parse("127.0.0.235"), IPAddress.Parse("255.255.255.0"));
        using var desiredBytes = new MemoryStream(); desiredScope.WriteTo(desiredBytes, false, false);
        var desired = desiredScope.BuildAllocationPlan(changeId, changeId, names) with { Configuration = Convert.ToBase64String(desiredBytes.ToArray()) };
        var preview = await Good(Call(admins[0], "/api/ddi/dhcp/changes/preview", ("plan", Json(desired)), ("expectedEpoch", old.Epoch)), "native consensus-gated ownership freeze/review");
        var input = preview.GetProperty("response").GetProperty("state").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions); string hash = DistributedAllocation.ChangeHash(input);
        Task<JsonElement> Prepare() => Call(admins[0], "/api/ddi/dhcp/changes/prepare", ("change", Json(input)), ("expectedHash", hash));
        await Bad(Prepare(), "ownership preparation without committed exact voting authorization");
        var ownershipCommand = new VotingOwnership(scopeName, old.Epoch, input.Id, hash); string authorizationId = Guid.NewGuid().ToString("N");
        await Good(Api(0, "authorizeOwnership", ("id", authorizationId), ("payload", Json(ownershipCommand))), "commit exact ownership authorization");
        links[(0, 5)].LoseMigrationResponse = "stage"; await Bad(Prepare(), "lost native preparation reply retains pending protection");
        await Good(Prepare(), "exact preparation retry after lost response");
        if (mode == "kill-ownership") await KillBoundary("ownership-prepared-after-voting-commit", new { processId = Environment.ProcessId, input, authorizationId });
        await Good(Call(admins[0], "/api/ddi/dhcp/changes/commit", ("scope", scopeName), ("id", input.Id), ("expectedHash", hash)), "native consensus-authorized cooperative ownership commit");
        check(stores.All(s => s.Plan(scopeName).Epoch == input.Id), "all native stores read back exact committed successor");
        foreach (var protection in protectedBefore) check(stores.Any(s => s.FindLease(scopeName, protection.Client)?.Expires >= protection.Expires), "successor retains original protected lifetime");
        check(stores.All(s => s.Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[0]).Entries.Contains(permanent)), "authorized successor preserves exact permanent grant");
        check(stores[5].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[5]).BorrowRequests.Single(r => r.Donor == names[0]).Id == pendingBorrow, "authorized successor retains pending original donor request");
        var successorReturn = stores[4].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[4]).GrantReturns.Single(r => r.Id == returnId);
        check(successorReturn == pendingReturn, "authorized successor retains exact pending receipt");
        await Good(Call(admins[1], "/api/ddi/dhcp/grants/reclaim", ("scope", scopeName), ("epoch", input.Id), ("borrower", names[4]), ("requestId", returnId), ("expectedSequence", stores[1].Snapshot().Replicas.Single(r => r.Scope == scopeName && r.Node == names[1]).Sequence.ToString()), ("expectedHash", DistributedAllocation.GrantReturnHash(scopeName, input.Id, successorReturn))), "original donor reclaims exact pending receipt after consensus successor");
        check(stores[1].HasAuthority(scopeName, originalReturnedGrant.Address) && !stores[4].HasAuthority(scopeName, originalReturnedGrant.Address), "terminal receipt leaves one usable authority");
        await Bad(Call(admins[0], "/api/ddi/dhcp/changes/preview", ("plan", Json(desired with { Epoch = Guid.NewGuid().ToString("N") })), ("expectedEpoch", old.Epoch)), "stale ownership epoch replay");
        await LocalService("post-consensus-ownership"); await Ack(leases.First(), "post-ownership native protected renewal");
        check(stores[0].FindLease(unaffectedName, unaffectedLease.ClientIdentifier.ToString()) == unaffectedProtection && stores.All(s => s.Plan(unaffectedName).Epoch == unaffectedEpoch), "unaffected scope retains exact original client protection and ownership epoch");
        Evidence("final-native-state");
        string votingPath = Path.Combine(root, "node-5", "voting-log.json");
        using (var denied = new FileStream(votingPath + ".tmp", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            var append = voting[0].AppendRequest(0) with { Term = voting[0].Status().State.Term + 1 };
            await Bad(Call(peers[5], "/api/ddi/voting/append", ("sender", names[0]), ("payload", Json(append))), "actual native voting durability failure earns no success receipt");
        }
        await Bad(Api(5, "campaign"), "damaged coordination stays withheld");
        var isolatedOffer = await scopes[5].GetOfferAsync(Packet(++clientNumber));
        check(isolatedOffer is not null && stores[5].HasAuthority(scopeName, AllocationSequence.Number(isolatedOffer.Address)), "coordination durability failure preserves legitimate native DHCP service");
        Console.WriteLine("Layer: native TLS APIs, native allocator entrypoints, parsed-handler actual UDP ACK output; full socket ingress/DORA/relay and production regions untested.");
    }
}
