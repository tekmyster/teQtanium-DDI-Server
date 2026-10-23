// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Dhcp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace DnsServerCore.Cluster
{
    // Operator-driven Raft log. Enrollment and DHCP serving authority are separate.
    // No timer, failure detector, or this log's leader role grants allocation rights.
    public sealed record VotingSeed(string Group, string[] Voters, string[] Learners);
    public sealed record VotingConfiguration(string[] Voters, string[] NextVoters, string[] Learners);
    public sealed record VotingEntry(long Term, string Id, string Kind, string Payload);
    public sealed record VotingState(string Node, VotingSeed Seed, long Term, string VotedFor, VotingEntry[] Log, int Commit);
    public sealed record VotingStatus(VotingState State, string Role, string Leader, VotingConfiguration Configuration, VotingConfiguration CommittedConfiguration);
    public sealed record VotingVote(string Group, long Term, string Candidate, int LastIndex, long LastTerm);
    public sealed record VotingAppend(string Group, long Term, string Leader, int PreviousIndex, long PreviousTerm, VotingEntry[] Entries, int Commit);
    public sealed record VotingReply(long Term, bool Success, int Index);
    public sealed record VotingOwnership(string Scope, string Epoch, string Successor, string Hash);

    public sealed class VotingLog : IDisposable
    {
        public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        readonly object _sync = new();
        readonly string _path;
        readonly FileStream _lock;
        VotingState _state;
        string _role = "Follower", _leader;
        bool _failed, _disposed;
        readonly Dictionary<string, int> _matched = new(StringComparer.Ordinal);
        const int MaxEntries = 4096, MaxBytes = 512 * 1024;

        public VotingLog(string path)
        {
            _path = path; Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
            _lock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                if (File.Exists(path + ".required"))
                {
                    string required = File.ReadAllText(path + ".required");
                    byte[] bytes = File.Exists(path) ? File.ReadAllBytes(path) : null;
                    if (bytes is null || Hash(bytes) != required)
                    {
                        bytes = File.Exists(path + ".tmp") ? File.ReadAllBytes(path + ".tmp") : null;
                        if (bytes is null || Hash(bytes) != required) throw new InvalidDataException("Voting log is missing or older than its durable barrier. Preserve the files for offline recovery.");
                        File.Move(path + ".tmp", path, true); AllocationDurability.SyncDirectory(path);
                    }
                    _state = JsonSerializer.Deserialize<VotingState>(bytes, Json); Validate(_state);
                }
                else if (File.Exists(path) || File.Exists(path + ".tmp")) throw new InvalidDataException("Voting log barrier is missing; initialization cannot replace prior authority.");
            }
            // Coordination damage withholds mutations, not independent DNS/DHCP
            // serving from its separately protected allocation store.
            catch { _failed = true; }
        }
        static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
        static T Copy<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value, Json), Json);
        void Available() { if (_disposed || _failed) throw new InvalidOperationException("Voting log is unavailable; preserve current DHCP authority and recover the original log."); }
        void Ready() { Available(); if (_state is null) throw new InvalidOperationException("Initialize the identical voting group on every enrolled node first."); }
        static void Names(string[] names)
        {
            if (names is null || names.Length > 64 || names.Any(n => string.IsNullOrWhiteSpace(n) || n.Length > 255) || !names.SequenceEqual(names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))) throw new InvalidDataException("Voting identities must be unique, sorted enrolled node names.");
        }
        static VotingConfiguration Configuration(VotingState state, int count = -1)
        {
            var config = new VotingConfiguration(state.Seed.Voters, null, state.Seed.Learners);
            foreach (var entry in state.Log.Take(count < 0 ? state.Log.Length : count))
                if (entry.Kind is "Joint" or "Stable") config = JsonSerializer.Deserialize<VotingConfiguration>(entry.Payload, Json);
            return config;
        }
        static string[] Members(VotingConfiguration config) => config.Voters.Concat(config.NextVoters ?? []).Concat(config.Learners).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        static bool IsVoter(VotingConfiguration config, string node) => config.Voters.Contains(node) || config.NextVoters?.Contains(node) == true;
        static bool Majority(string[] voters, IEnumerable<string> names) => voters.Count(names.Contains) > voters.Length / 2;
        static bool Quorum(VotingConfiguration config, IEnumerable<string> names) => Majority(config.Voters, names) && (config.NextVoters is null || Majority(config.NextVoters, names));
        static void Validate(VotingState state)
        {
            if (state?.Seed is null || !Guid.TryParseExact(state.Seed.Group, "N", out _) || state.Term < 0 || state.Log is null || state.Log.Length > MaxEntries || state.Commit < 0 || state.Commit > state.Log.Length) throw new InvalidDataException("Invalid voting state.");
            Names(state.Seed.Voters); Names(state.Seed.Learners);
            if (state.Seed.Voters.Length is not (3 or 5) || state.Seed.Voters.Intersect(state.Seed.Learners).Any()) throw new InvalidDataException("Initialize three or five voters and separate learners.");
            var config = Configuration(state, 0); var members = Members(config);
            if (!members.Contains(state.Node) || state.VotedFor is not null && !members.Contains(state.VotedFor)) throw new InvalidDataException("Voting log identity differs from its enrolled seed.");
            var ids = new HashSet<string>(StringComparer.Ordinal); long previousTerm = 0;
            foreach (var entry in state.Log)
            {
                if (entry is null || !Guid.TryParseExact(entry.Id, "N", out _) || !ids.Add(entry.Id) || entry.Term < 1 || entry.Term < previousTerm || entry.Term > state.Term || entry.Payload is null) throw new InvalidDataException("Invalid or conflicting voting entry.");
                previousTerm = entry.Term;
                if (entry.Kind is "Joint" or "Stable")
                {
                    var next = JsonSerializer.Deserialize<VotingConfiguration>(entry.Payload, Json); Names(next.Voters); Names(next.Learners); if (next.NextVoters is not null) Names(next.NextVoters);
                    if (!Members(next).SequenceEqual(members) || next.Voters.Length < 3 || next.Voters.Length > 5 || next.NextVoters is { Length: < 3 or > 5 } || next.Learners.Intersect(next.Voters.Concat(next.NextVoters ?? [])).Any()) throw new InvalidDataException("Voting changes must retain the enrolled seed and three to five voters.");
                    if (entry.Kind == "Joint" && (config.NextVoters is not null || next.NextVoters is null || !next.Voters.SequenceEqual(config.Voters))) throw new InvalidDataException("Start a joint transition from the exact stable voter configuration.");
                    if (entry.Kind == "Stable" && (config.NextVoters is null || next.NextVoters is not null || !next.Voters.SequenceEqual(config.NextVoters))) throw new InvalidDataException("Finalize the exact joint voter configuration.");
                    config = next;
                }
                else if (entry.Kind == "Ownership")
                {
                    var command = JsonSerializer.Deserialize<VotingOwnership>(entry.Payload, Json);
                    if (command is null || string.IsNullOrWhiteSpace(command.Scope) || command.Scope.Length > 255 || string.IsNullOrWhiteSpace(command.Epoch) || !Guid.TryParseExact(command.Successor, "N", out _) || command.Hash?.Length != 64 || command.Hash.Any(c => !Uri.IsHexDigit(c))) throw new InvalidDataException("Invalid exact ownership authorization.");
                }
                else if (entry.Kind != "Noop" || entry.Payload != "") throw new InvalidDataException("Unsupported voting command.");
            }
        }
        void Persist(VotingState next)
        {
            Available(); Validate(next); byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(next, Json);
            if (bytes.Length > MaxBytes) throw new InvalidOperationException("Voting log reached its bounded capacity; retain authority pending qualified compaction.");
            try
            {
                using (var file = new FileStream(_path + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None)) { file.Write(bytes); file.Flush(true); }
                AllocationDurability.SyncDirectory(_path);
                using (var file = new FileStream(_path + ".required", FileMode.Create, FileAccess.Write, FileShare.None)) { file.Write(System.Text.Encoding.ASCII.GetBytes(Hash(bytes))); file.Flush(true); }
                AllocationDurability.SyncDirectory(_path);
                File.Move(_path + ".tmp", _path, true); AllocationDurability.SyncDirectory(_path); _state = next;
            }
            catch { _failed = true; _role = "Follower"; _leader = null; throw; }
        }
        public bool Initialized { get { lock (_sync) { Available(); return _state is not null; } } }
        public VotingStatus Status() { lock (_sync) { Available(); return _state is null ? new(null, _role, null, null, null) : Copy(new VotingStatus(_state, _role, _leader, Configuration(_state), Configuration(_state, _state.Commit))); } }
        public void Initialize(string node, VotingSeed seed)
        {
            lock (_sync)
            {
                Available(); var next = new VotingState(node, Copy(seed), 0, null, [], 0); Validate(next);
                if (_state is not null) { if (_state.Node != node || JsonSerializer.Serialize(_state.Seed, Json) != JsonSerializer.Serialize(seed, Json)) throw new InvalidOperationException("Voting group already initialized differently; resume the original group."); return; }
                Persist(next);
            }
        }
        long TermAt(int index) => index == 0 ? 0 : _state.Log[index - 1].Term;
        void StepDown(long term)
        {
            if (term > _state.Term) Persist(_state with { Term = term, VotedFor = null });
            _role = "Follower"; _leader = null; _matched.Clear();
        }
        public VotingVote Campaign(string node)
        {
            lock (_sync)
            {
                Ready(); if (node != _state.Node || !IsVoter(Configuration(_state), node)) throw new InvalidOperationException("Only a current voter can campaign; catch up learners before promotion.");
                Persist(_state with { Term = checked(_state.Term + 1), VotedFor = node }); _role = "Candidate"; _leader = null; _matched.Clear();
                return new(_state.Seed.Group, _state.Term, node, _state.Log.Length, TermAt(_state.Log.Length));
            }
        }
        public VotingReply Vote(VotingVote vote)
        {
            lock (_sync)
            {
                Ready(); var config = Configuration(_state);
                if (vote.Group != _state.Seed.Group || !IsVoter(config, vote.Candidate) || !IsVoter(config, _state.Node) || vote.Term < _state.Term || vote.LastIndex < 0 || vote.LastTerm < 0 || vote.LastTerm > vote.Term) return new(_state.Term, false, _state.Log.Length);
                if (vote.Term > _state.Term) StepDown(vote.Term);
                bool upToDate = vote.LastTerm > TermAt(_state.Log.Length) || vote.LastTerm == TermAt(_state.Log.Length) && vote.LastIndex >= _state.Log.Length;
                bool grant = upToDate && (_state.VotedFor is null || _state.VotedFor == vote.Candidate);
                if (grant) Persist(_state with { VotedFor = vote.Candidate });
                return new(_state.Term, grant, _state.Log.Length);
            }
        }
        public void Observe(VotingReply reply) { lock (_sync) { Ready(); if (reply.Term > _state.Term) StepDown(reply.Term); } }
        public void Elect(long term, string[] votes)
        {
            lock (_sync)
            {
                Ready(); if (_role != "Candidate" || term != _state.Term || !Quorum(Configuration(_state), votes.Distinct())) throw new InvalidOperationException("No current voting majority; retain current ownership and retry a campaign from a connected voter.");
                _role = "Leader"; _leader = _state.Node; _matched.Clear(); _matched[_state.Node] = _state.Log.Length;
                Add(Guid.NewGuid().ToString("N"), "Noop", ""); // Only current-term entries can advance commit.
            }
        }
        public void RequireLeader(long? term = null)
        { lock (_sync) { Ready(); if (_role != "Leader" || _leader != _state.Node || term is not null && term != _state.Term || !IsVoter(Configuration(_state), _state.Node)) throw new InvalidOperationException("Use the elected current-term voting leader; retain existing DHCP ownership."); } }
        public int Add(string id, string kind, string payload)
        {
            lock (_sync)
            {
                RequireLeader(); var existing = Array.FindIndex(_state.Log, e => e.Id == id);
                if (existing >= 0) { var entry = _state.Log[existing]; if (entry.Kind != kind || entry.Payload != payload) throw new InvalidOperationException("Voting operation identity was reused with a different command."); return existing + 1; }
                if (kind != "Noop" && _state.Commit != _state.Log.Length) throw new InvalidOperationException("Replicate and commit the pending log before proposing another operation.");
                Persist(_state with { Log = [.. _state.Log, new(_state.Term, id, kind, payload)] }); _matched[_state.Node] = _state.Log.Length; return _state.Log.Length;
            }
        }
        public int ChangeVoters(string id, string[] voters)
        {
            lock (_sync)
            {
                RequireLeader(); Names(voters); var config = Configuration(_state);
                // A retry of an exact request returns its original log entry.
                var existing = _state.Log.SingleOrDefault(e => e.Id == id);
                if (existing is not null)
                {
                    if (existing.Kind != "Joint" || !JsonSerializer.Deserialize<VotingConfiguration>(existing.Payload, Json).NextVoters.SequenceEqual(voters)) throw new InvalidOperationException("Membership request identity changed.");
                    return Array.IndexOf(_state.Log, existing) + 1;
                }
                if (config.NextVoters is not null || !voters.Contains(_state.Node) || voters.SequenceEqual(config.Voters)) throw new InvalidOperationException("Finish the pending joint transition and retain the leader as a voter.");
                if (voters.Except(Members(config)).Any()) throw new InvalidOperationException("Only initialized enrolled learners can be promoted in this stage.");
                if (voters.Except(config.Voters).Any(n => !_matched.TryGetValue(n, out int index) || index < _state.Log.Length)) throw new InvalidOperationException("Replicate the complete current log to every promoted learner first.");
                var joint = new VotingConfiguration(config.Voters, voters, Members(config).Except(config.Voters.Concat(voters)).Order(StringComparer.Ordinal).ToArray());
                return Add(id, "Joint", JsonSerializer.Serialize(joint, Json));
            }
        }
        public int FinishVoters(string id)
        {
            lock (_sync)
            {
                RequireLeader(); var config = Configuration(_state);
                var existing = _state.Log.SingleOrDefault(e => e.Id == id);
                if (existing is not null) { if (existing.Kind != "Stable") throw new InvalidOperationException("Membership operation identity changed."); return Array.IndexOf(_state.Log, existing) + 1; }
                if (config.NextVoters is null || _state.Commit != _state.Log.Length || !config.NextVoters.Contains(_state.Node)) throw new InvalidOperationException("Commit the exact joint configuration under both majorities and elect a retained voter before finalizing.");
                return Add(id, "Stable", JsonSerializer.Serialize(new VotingConfiguration(config.NextVoters, null, Members(config).Except(config.NextVoters).Order(StringComparer.Ordinal).ToArray()), Json));
            }
        }
        public VotingAppend AppendRequest(int previous)
        {
            lock (_sync) { RequireLeader(); previous = Math.Clamp(previous, 0, _state.Log.Length); return Copy(new VotingAppend(_state.Seed.Group, _state.Term, _state.Node, previous, TermAt(previous), _state.Log.Skip(previous).ToArray(), _state.Commit)); }
        }
        public VotingReply Append(VotingAppend request)
        {
            lock (_sync)
            {
                Ready();
                // Retained enrollment authenticates transport. A former leader can deliver a
                // higher-term suffix containing the joint/final entries this node missed.
                if (request.Group != _state.Seed.Group || !Members(Configuration(_state, 0)).Contains(request.Leader) || request.Term < _state.Term) return new(_state.Term, false, _state.Log.Length);
                if (request.Term > _state.Term || _role != "Follower") StepDown(request.Term);
                if (request.PreviousIndex < 0 || request.PreviousIndex > _state.Log.Length || request.PreviousTerm != TermAt(request.PreviousIndex)) return new(_state.Term, false, _state.Log.Length);
                if (request.Entries is null || request.Entries.Any(e => e is null || e.Term > request.Term) || request.Commit < 0) throw new InvalidDataException("Invalid append request.");
                var log = _state.Log.ToList(); int index = request.PreviousIndex;
                foreach (var entry in request.Entries)
                {
                    if (index < log.Count && log[index] != entry)
                    {
                        if (index < _state.Commit || log[index].Term == entry.Term) throw new InvalidDataException("Conflicting committed or same-term log; preserve original voting authority.");
                        log.RemoveRange(index, log.Count - index);
                    }
                    if (index == log.Count) log.Add(entry);
                    index++;
                }
                // A stale shorter AppendEntries must never truncate an unrelated suffix.
                var next = _state with { Log = log.ToArray(), Commit = Math.Max(_state.Commit, Math.Min(request.Commit, index)) };
                Validate(next);
                var leaderConfig = Configuration(next);
                if (!IsVoter(leaderConfig, request.Leader)) return new(_state.Term, false, _state.Log.Length);
                Persist(next); _leader = request.Leader; return new(_state.Term, true, index);
            }
        }
        public void Acknowledge(string node, long term, int index)
        {
            lock (_sync)
            {
                RequireLeader(term); if (!Members(Configuration(_state)).Contains(node) || index < 0 || index > _state.Log.Length) throw new InvalidDataException("Invalid log acknowledgement.");
                _matched[node] = Math.Max(_matched.GetValueOrDefault(node), index);
            }
        }
        public void AdvanceCommit()
        {
            lock (_sync)
            {
                RequireLeader(); var config = Configuration(_state);
                for (int index = _state.Log.Length; index > _state.Commit; index--)
                    if (TermAt(index) == _state.Term && Quorum(config, _matched.Where(p => p.Value >= index).Select(p => p.Key))) { Persist(_state with { Commit = index }); return; }
            }
        }
        public void RequireCommitted(int index)
        { lock (_sync) { RequireLeader(); if (index < 1 || index > _state.Commit) throw new InvalidOperationException("The operation lacks a committed voting majority; retry the exact saved operation after restoring connectivity."); } }
        public void RequireOwnership(VotingOwnership command)
        {
            lock (_sync)
            {
                Ready(); if (!_state.Log.Take(_state.Commit).Any(e => e.Kind == "Ownership" && e.Payload == JsonSerializer.Serialize(command, Json))) throw new InvalidOperationException("Commit the exact scope, current epoch, successor and ownership review hash in the voting log before preparing or committing ownership.");
            }
        }
        public void RequirePeerLeader(string leader, long term)
        {
            lock (_sync) { Ready(); if (_state.Term != term || _leader != leader || !IsVoter(Configuration(_state), leader)) throw new InvalidOperationException("Ownership coordinator is not the observed current-term voting leader; synchronize the committed log first."); }
        }
        public void GuardMutation(Action validate, Action mutation)
        {
            // Term/role/init changes share this lock with the final local store
            // mutation. Never hold it across an await or a peer network request.
            lock (_sync) { Available(); validate(); mutation(); }
        }
        public void Dispose() { lock (_sync) { if (_disposed) return; _disposed = true; _lock.Dispose(); } }
    }
}
