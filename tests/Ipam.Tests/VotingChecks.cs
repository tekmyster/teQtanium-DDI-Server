// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Cluster;
using System.Text.Json;

static class VotingChecks
{
    public static Task Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "ddi-voting-model-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string[] names = ["a", "b", "c", "d", "e", "f"];
        var seed = new VotingSeed(Guid.NewGuid().ToString("N"), names.Take(3).ToArray(), names.Skip(3).ToArray());
        var nodes = names.Select(n => new VotingLog(Path.Combine(root, n + ".json"))).ToArray(); int checks = 0;
        void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        void Refuse(Action call, string reason) { try { call(); throw new Exception("Unexpected success: " + reason); } catch (InvalidOperationException) { checks++; } }
        void Sync(int leader, params int[] peers)
        {
            long term = nodes[leader].Status().State.Term;
            foreach (int peer in peers)
            {
                var reply = nodes[peer].Append(nodes[leader].AppendRequest(0)); nodes[leader].Observe(reply);
                if (reply.Success) nodes[leader].Acknowledge(names[peer], term, reply.Index);
            }
            nodes[leader].AdvanceCommit();
            foreach (int peer in peers) nodes[peer].Append(nodes[leader].AppendRequest(0));
        }
        void Elect(int leader, params int[] peers)
        {
            var request = nodes[leader].Campaign(names[leader]); var votes = new List<string> { names[leader] };
            foreach (int peer in peers) { var reply = nodes[peer].Vote(request); nodes[leader].Observe(reply); if (reply.Success && reply.Term == request.Term) votes.Add(names[peer]); }
            nodes[leader].Elect(request.Term, votes.ToArray()); Sync(leader, peers);
        }
        try
        {
            for (int i = 0; i < nodes.Length; i++) nodes[i].Initialize(names[i], seed);
            Refuse(() => nodes[0].Initialize("a", seed with { Group = Guid.NewGuid().ToString("N") }), "foreign initialization");
            Refuse(() => nodes[3].Campaign("d"), "learner campaign");
            var request = nodes[0].Campaign("a");
            Check(!nodes[3].Vote(request).Success, "learner grants no vote");
            Refuse(() => nodes[0].Elect(request.Term, ["a", "a", "d", "e", "f"]), "duplicates and learners form no quorum");
            Check(nodes[1].Vote(request).Success, "durable voter grants candidate");
            nodes[1].Dispose(); nodes[1] = new VotingLog(Path.Combine(root, "b.json"));
            Check(!nodes[1].Vote(request with { Candidate = "c" }).Success, "restart cannot vote twice in same term");
            nodes[0].Elect(request.Term, ["a", "b"]); Sync(0, 1, 2, 3, 4, 5);
            var staleLeader = nodes[0].AppendRequest(0);
            Elect(1, 2); Check(nodes[1].Status().State.Commit > 0, "majority election commits current-term barrier");
            Check(!nodes[2].Append(staleLeader).Success, "old leader cannot replay old term");
            nodes[0].Observe(new(nodes[1].Status().State.Term, false, 0)); Refuse(() => nodes[0].Add(Guid.NewGuid().ToString("N"), "Noop", ""), "old leader stepped down");
            Sync(1, 0, 2, 3, 4, 5);
            string jointId = Guid.NewGuid().ToString("N"); int joint = nodes[1].ChangeVoters(jointId, names.Take(5).ToArray());
            Sync(1, 0); Refuse(() => nodes[1].RequireCommitted(joint), "old majority alone lacks new joint majority");
            Sync(1, 2, 3, 4); nodes[1].RequireCommitted(joint); checks++;
            Check(nodes[1].ChangeVoters(jointId, names.Take(5).ToArray()) == joint, "membership retry has one log identity");
            Refuse(() => nodes[1].ChangeVoters(jointId, ["a", "b", "c"]), "changed membership retry");
            string finalId = Guid.NewGuid().ToString("N"); int final = nodes[1].FinishVoters(finalId); Sync(1, 0, 2, 3, 4, 5); nodes[1].RequireCommitted(final);
            Check(nodes.All(n => n.Status().Configuration.Voters.Length == 5 && n.Status().Configuration.NextVoters is null), "five committed voters converge");
            Refuse(() => Elect(3, 4, 5), "Five-voter minority plus learner cannot elect");
            Check(nodes[3].Status().Role == "Candidate", "five voters require three distinct voters");
            // Independently reopen one actual persisted voter and reject rollback/foreign input.
            nodes[2].Dispose(); string path = Path.Combine(root, "c.json"); byte[] saved = File.ReadAllBytes(path); nodes[2] = new VotingLog(path);
            var state = nodes[2].Status().State;
            Check(!nodes[2].Vote(new(Guid.NewGuid().ToString("N"), state.Term + 100, "a", state.Log.Length, state.Term)).Success, "foreign group cannot advance term");
            Check(nodes[2].Status().State.Term == state.Term, "foreign vote did not mutate durable term");
            nodes[2].Dispose(); File.WriteAllBytes(path, saved.Take(saved.Length - 3).ToArray());
            nodes[2] = new VotingLog(path); Refuse(() => nodes[2].Campaign("c"), "truncated state cannot campaign");
            nodes[4].Dispose(); string barrier = Path.Combine(root, "e.json.required"); File.Delete(barrier); nodes[4] = new VotingLog(Path.Combine(root, "e.json"));
            Refuse(() => nodes[4].Initialize("e", seed), "missing barrier cannot reseed");
            nodes[5].Dispose(); string learnerPath = Path.Combine(root, "f.json");
            // A real OS file share denial at the durable stage must produce no vote/append success.
            nodes[5] = new VotingLog(learnerPath);
            using (var denied = new FileStream(learnerPath + ".tmp", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                bool failed = false;
                try { nodes[5].Append(new(seed.Group, nodes[5].Status().State.Term + 10, "a", 0, 0, [], 0)); }
                catch (IOException) { failed = true; }
                Check(failed, "actual persistence failure rejects durable append");
                Refuse(() => nodes[5].Initialize("f", seed), "failed persistence poisons mutation path");
            }
            Console.WriteLine($"PASS: {checks} voting store checks (not native TLS/socket qualification)");
            return Task.CompletedTask;
        }
        finally { foreach (var node in nodes) node.Dispose(); Directory.Delete(root, true); }
    }
}
