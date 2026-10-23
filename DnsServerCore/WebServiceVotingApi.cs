// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        readonly VotingLog _voting;
        readonly SemaphoreSlim _votingOperation = new(1, 1);
        internal void RequireMutableVotingEnrollment()
        {
            if (_voting.Initialized) throw new InvalidOperationException("Voting enrollment is fixed in this stage; voter changes retain every enrolled node as a voter or learner. Legacy enrollment, identity and primary changes require a separately qualified migration.");
        }
        internal void ValidateVotingEnrollmentUpdate(DnsServerCore.HttpApi.Models.ClusterInfo incoming)
        {
            if (!_voting.Initialized) return;
            var existing = _clusterManager.ClusterNodes;
            if (incoming.ClusterNodes.Count != existing.Count || incoming.ClusterNodes.Any(n => !existing.TryGetValue(n.Id, out var node) || n.Url != node.Url || n.Type != node.Type.ToString() || (n.State == "Fenced") != node.IsFenced || !n.IPAddresses.Order().SequenceEqual(node.IPAddresses.Select(a => a.ToString()).Order())))
                throw new InvalidOperationException("Legacy cluster refresh changed initialized voting enrollment; retain the original identities.");
        }
        void VotingEnrollment()
        {
            if (!_clusterManager.ClusterInitialized || _clusterManager.GetSelfNode().IsFenced) throw new InvalidOperationException("An enrolled, unfenced node is required; retain existing allocation authority.");
            var state = _voting.Status().State;
            if (state is not null && (state.Node != _allocation.NodeName() || !state.Seed.Voters.Concat(state.Seed.Learners).Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())))
                throw new InvalidOperationException("Enrolled identities changed after voting initialization; preserve original membership and recover the original enrollment.");
        }
        void RequireVotingAdmin(HttpContext context)
        {
            if (!HasDirectTlsTransport(context) || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken || context.Request.QueryOrForm("actingUser") is not null || context.Request.QueryOrForm("node") is not null)
                throw new DnsWebServiceException("Use a direct HTTPS administrator session on the intended voting node.");
            RequireDhcpPermission(context, PermissionFlag.Modify);
            if (!_authManager.IsPermitted(PermissionSection.Administration, GetSessionUser(context), PermissionFlag.Delete)) throw new DnsWebServiceException("Access was denied.");
            VotingEnrollment();
        }
        void RequireVotingPeer(HttpContext context, string sender)
        {
            RequireAllocationService(context);
            if (!HasDirectTlsTransport(context) || context.Request.QueryOrForm("node") is not null) throw new DnsWebServiceException("Use a direct HTTPS cluster connection.");
            VotingEnrollment();
            var address = context.Connection.RemoteIpAddress; if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
            if (!_clusterManager.TryGetClusterNode(sender, out var node) || node.IsFenced || !node.IPAddresses.Contains(address)) throw new DnsWebServiceException("Voting sender must match an enrolled unfenced node and its target-observed source address.");
        }
        T ReadVoting<T>(HttpContext context)
        {
            string payload = context.Request.GetQueryOrForm("payload");
            if (Encoding.UTF8.GetByteCount(payload) > 512 * 1024) throw new ArgumentException("Voting RPC exceeds the bounded journal size.");
            return JsonSerializer.Deserialize<T>(payload, VotingLog.Json) ?? throw new ArgumentException("Missing voting payload.");
        }
        static void WriteVoting<T>(HttpContext context, T value)
        { context.GetCurrentJsonWriter().WritePropertyName("state"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), value, VotingLog.Json); }
        async Task<T> VotingCall<T>(string node, string action, object payload, CancellationToken cancellationToken)
        {
            if (!_clusterManager.TryGetClusterNode(node, out var peer) || peer.IsFenced) throw new InvalidOperationException("Voting peer is no longer enrolled or is fenced.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _allocationStop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(3));
            var bytes = await peer.VotingRequestAsync(action, new Dictionary<string, string> { ["payload"] = JsonSerializer.Serialize(payload, VotingLog.Json), ["sender"] = _allocation.NodeName() }, deadline.Token);
            return JsonSerializer.Deserialize<T>(bytes, VotingLog.Json);
        }
        void GetVotingStatus(HttpContext context)
        {
            if (context.GetCurrentSession().Type == UserSessionType.ClusterApiToken) RequireVotingPeer(context, context.Request.GetQueryOrForm("sender"));
            else { RequireDhcpPermission(context, PermissionFlag.View); if (!HasDirectTlsTransport(context) || context.Request.QueryOrForm("actingUser") is not null) throw new DnsWebServiceException("Use direct HTTPS to read voting status."); }
            WriteVoting(context, _voting.Status());
        }
        void InitializeVotingPeer(HttpContext context)
        {
            string sender = context.Request.GetQueryOrForm("sender"); RequireVotingPeer(context, sender);
            if (sender != _clusterManager.GetPrimaryNode().Name) throw new DnsWebServiceException("Only the enrolled primary may initialize voting.");
            var seed = ReadVoting<VotingSeed>(context); CheckVotingSeed(seed); _voting.Initialize(_allocation.NodeName(), seed); WriteVoting(context, _voting.Status());
        }
        void CheckVotingSeed(VotingSeed seed)
        {
            if (!seed.Voters.Concat(seed.Learners).Order(StringComparer.Ordinal).SequenceEqual(BootstrapOwners())) throw new InvalidOperationException("Initialize every enrolled node with the same exact voter and learner identities.");
        }
        async Task InitializeVoting(HttpContext context)
        {
            RequireVotingAdmin(context); if (_clusterManager.GetSelfNode().Type != ClusterNodeType.Primary) throw new InvalidOperationException("Initialize voting from the enrolled primary.");
            var seed = ReadVoting<VotingSeed>(context); CheckVotingSeed(seed);
            await _votingOperation.WaitAsync(context.RequestAborted);
            try
            {
                RequireVotingAdmin(context); _voting.Initialize(_allocation.NodeName(), seed);
                foreach (string node in seed.Voters.Concat(seed.Learners).Where(n => n != _allocation.NodeName()))
                {
                    var result = await VotingCall<VotingStatus>(node, "initializePeer", seed, context.RequestAborted);
                    RequireVotingAdmin(context); CheckVotingSeed(seed);
                    if (result.State?.Node != node || JsonSerializer.Serialize(result.State.Seed, VotingLog.Json) != JsonSerializer.Serialize(seed, VotingLog.Json)) throw new InvalidOperationException("Peer initialized a different voting group.");
                }
                WriteVoting(context, _voting.Status());
            }
            finally { _votingOperation.Release(); }
        }
        void VoteVoting(HttpContext context)
        {
            var vote = ReadVoting<VotingVote>(context); RequireVotingPeer(context, vote.Candidate);
            if (context.Request.GetQueryOrForm("sender") != vote.Candidate) throw new DnsWebServiceException("Candidate and authenticated transport sender differ.");
            WriteVoting(context, _voting.Vote(vote));
        }
        void AppendVoting(HttpContext context)
        {
            var request = ReadVoting<VotingAppend>(context); RequireVotingPeer(context, request.Leader);
            if (context.Request.GetQueryOrForm("sender") != request.Leader) throw new DnsWebServiceException("Leader and authenticated transport sender differ.");
            WriteVoting(context, _voting.Append(request));
        }
        // Serialized local driver; incoming peer RPCs remain independent so terms can
        // revoke leadership while network requests are outstanding.
        async Task ReplicateVoting(HttpContext context, long term)
        {
            RequireVotingAdmin(context); _voting.RequireLeader(term);
            var status = _voting.Status(); int last = status.State.Log.Length;
            foreach (string node in status.State.Seed.Voters.Concat(status.State.Seed.Learners).Where(n => n != _allocation.NodeName()))
            {
                for (int previous = last; previous >= 0; previous--)
                {
                    RequireVotingAdmin(context); _voting.RequireLeader(term);
                    VotingReply reply;
                    try { reply = await VotingCall<VotingReply>(node, "append", _voting.AppendRequest(previous), context.RequestAborted); }
                    catch (Exception ex) when (ex is HttpRequestException || ex is OperationCanceledException && !context.RequestAborted.IsCancellationRequested || ex is DnsServerCore.HttpApi.HttpApiClientException) { break; }
                    _voting.Observe(reply); RequireVotingAdmin(context); _voting.RequireLeader(term);
                    if (reply.Success) { _voting.Acknowledge(node, term, reply.Index); break; }
                }
            }
            RequireVotingAdmin(context); _voting.RequireLeader(term); _voting.AdvanceCommit();
            // Propagate committed position. A missing reply remains ambiguous and
            // cannot count as application on that peer; explicit sync retries it.
            foreach (string node in status.State.Seed.Voters.Concat(status.State.Seed.Learners).Where(n => n != _allocation.NodeName()))
            {
                try
                {
                    var reply = await VotingCall<VotingReply>(node, "append", _voting.AppendRequest(0), context.RequestAborted);
                    _voting.Observe(reply); RequireVotingAdmin(context); _voting.RequireLeader(term);
                    if (reply.Success) _voting.Acknowledge(node, term, reply.Index);
                }
                catch (Exception ex) when (ex is HttpRequestException || ex is OperationCanceledException && !context.RequestAborted.IsCancellationRequested || ex is DnsServerCore.HttpApi.HttpApiClientException) { }
            }
            RequireVotingAdmin(context); _voting.RequireLeader(term);
        }
        async Task CampaignVoting(HttpContext context)
        {
            RequireVotingAdmin(context); await _votingOperation.WaitAsync(context.RequestAborted);
            try
            {
                RequireVotingAdmin(context); var request = _voting.Campaign(_allocation.NodeName()); var votes = new List<string> { _allocation.NodeName() };
                foreach (string node in _voting.Status().State.Seed.Voters.Concat(_voting.Status().State.Seed.Learners).Where(n => n != _allocation.NodeName()))
                {
                    try
                    {
                        var reply = await VotingCall<VotingReply>(node, "vote", request, context.RequestAborted);
                        _voting.Observe(reply); RequireVotingAdmin(context);
                        if (reply.Success && reply.Term == request.Term) votes.Add(node);
                    }
                    catch (Exception ex) when (ex is HttpRequestException || ex is OperationCanceledException && !context.RequestAborted.IsCancellationRequested || ex is DnsServerCore.HttpApi.HttpApiClientException) { }
                }
                RequireVotingAdmin(context); _voting.Elect(request.Term, votes.ToArray()); await ReplicateVoting(context, request.Term);
                _voting.RequireCommitted(_voting.Status().State.Log.Length); WriteVoting(context, _voting.Status());
            }
            finally { _votingOperation.Release(); }
        }
        async Task MutateVoting(HttpContext context)
        {
            RequireVotingAdmin(context); await _votingOperation.WaitAsync(context.RequestAborted);
            try
            {
                RequireVotingAdmin(context); _voting.RequireLeader(); long term = _voting.Status().State.Term;
                string action = context.Request.Path.Value.Split('/').Last(); int index;
                if (action != "sync")
                {
                    long expectedTerm = long.Parse(context.Request.GetQueryOrForm("expectedTerm"), System.Globalization.CultureInfo.InvariantCulture);
                    int expectedIndex = int.Parse(context.Request.GetQueryOrForm("expectedIndex"), System.Globalization.CultureInfo.InvariantCulture);
                    var current = _voting.Status().State; string id = context.Request.GetQueryOrForm("id");
                    if (expectedTerm != current.Term || expectedIndex != current.Log.Length && !current.Log.Any(e => e.Id == id)) throw new InvalidOperationException("Voting term or reviewed log position changed; read current status and retain the exact original operation identity.");
                }
                if (action == "voters") index = _voting.ChangeVoters(context.Request.GetQueryOrForm("id"), ReadVoting<string[]>(context));
                else if (action == "finalize") index = _voting.FinishVoters(context.Request.GetQueryOrForm("id"));
                else if (action == "authorizeOwnership")
                {
                    var command = ReadVoting<VotingOwnership>(context); var change = _allocation.Change(command.Scope);
                    if (_clusterManager.GetSelfNode().Type != ClusterNodeType.Primary || change?.Id != command.Successor || _allocation.Plan(command.Scope)?.Epoch != command.Epoch || change.Phase != "Frozen") throw new InvalidOperationException("Authorize the original primary's exact frozen ownership review while its original epoch remains current.");
                    index = _voting.Add(context.Request.GetQueryOrForm("id"), "Ownership", JsonSerializer.Serialize(command, VotingLog.Json));
                }
                else index = _voting.Status().State.Log.Length;
                await ReplicateVoting(context, term); _voting.RequireCommitted(index); WriteVoting(context, _voting.Status());
            }
            finally { _votingOperation.Release(); }
        }
    }
}
