using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceSecurityApi
        {
            readonly DnsWebService _service;
            public WebServiceSecurityApi(DnsWebService service) { _service = service; }
            User Authorize(HttpContext context, PermissionFlag flag)
            {
                User user = _service.GetSessionUser(context);
                if (!_service._authManager.IsPermitted(PermissionSection.Settings, user, flag)) throw new DnsWebServiceException("Access was denied.");
                if (flag != PermissionFlag.View && _service._clusterManager.ClusterInitialized && _service._clusterManager.GetSelfNode().Type != ClusterNodeType.Primary) throw new DnsWebServiceException("Security policy changes must be made on the cluster primary.");
                return user;
            }
            static void Write(HttpContext context, string name, object value)
            { var writer = context.GetCurrentJsonWriter(); writer.WritePropertyName(name); JsonSerializer.Serialize(writer, value, value.GetType(), DdiSecurityManager.JsonOptions); }
            public void GetPolicy(HttpContext context)
            {
                User user = AuthorizePredictive(context, PermissionFlag.View);
                bool primary = !_service._clusterManager.ClusterInitialized || _service._clusterManager.GetSelfNode().Type == ClusterNodeType.Primary;
                Write(context, "canModify", primary && _service._authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.Modify));
                Write(context, "configurationAccess", primary ? "Settings modify permission is required to edit this configuration." : "Open the cluster primary to change security configuration.");
                Write(context, "policyLoadWarning", _service._security.PolicyLoadWarning ?? ""); Write(context, "policy", _service._security.Policy);
                Write(context, "mispHealth", _service._security.MispStatus); Write(context, "droppedEvents", _service._security.DroppedEvents);
                Write(context, "signalHealth", _service._security.SignalStatus);
                Write(context, "edlHealth", _service._security.EdlStatus());
                Write(context, "snapshotRevision", _service._security.EdlRevision);
                Write(context, "signals", _service._security.Signals());
            }
            public void SetPolicy(HttpContext context)
            {
                User user = AuthorizePredictive(context, PermissionFlag.Modify);
                string json = context.Request.GetQueryOrForm("policy");
                if (Encoding.UTF8.GetByteCount(json) > 2 * 1024 * 1024) throw new ArgumentException("Security policy exceeds 2 MiB.");
                var policy = JsonSerializer.Deserialize<SecurityPolicy>(json, DdiSecurityManager.JsonOptions) ?? throw new ArgumentException("Missing security policy.");
                user = AuthorizePredictive(context, PermissionFlag.Modify);
                if (ConnectionsChanged(policy, _service._security.Policy) && !_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to configure enrichment, EDL publication, or model connections.");
                _service._security.SetPolicy(policy, long.Parse(context.Request.GetQueryOrForm("revision")), () =>
                {
                    User current = AuthorizePredictive(context, PermissionFlag.Modify);
                    if (ConnectionsChanged(policy, _service._security.Policy) && !_service._authManager.IsPermitted(PermissionSection.Administration, current, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to change connections.");
                });
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] DDI security policy updated to revision " + _service._security.Policy.Revision);
                if (_service._clusterManager.ClusterInitialized) _service._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                Write(context, "policy", _service._security.Policy);
            }
            public void Events(HttpContext context)
            {
                Authorize(context, PermissionFlag.View); Write(context, "events", _service._security.RecentEvents()); Write(context, "signals", _service._security.Signals());
            }
            // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
            UserSession LivePredictiveSession(HttpContext context)
            {
                context.RequestAborted.ThrowIfCancellationRequested();
                UserSession admitted = context.GetCurrentSession();
                UserSession live = admitted is null ? null : _service._authManager.GetSession(admitted.Token);
                // The request's cached object is admission evidence, not continued authority.
                // Do not refresh LastSeen here: a paused body must not revive an expired session.
                if (live is null || !ReferenceEquals(live, admitted) || live.HasExpired() || live.User.Disabled || !ReferenceEquals(_service._authManager.GetUser(live.User.Username), live.User)) throw new InvalidTokenWebServiceException("Session is no longer current; authenticate again.");
                return live;
            }
            User AuthorizePredictive(HttpContext context, PermissionFlag flag)
            {
                LivePredictiveSession(context);
                User user = _service.GetSessionUser(context); // preserves existing cluster acting-user mapping
                LivePredictiveSession(context); // mapping can read a form; never trust pre-read authority
                if (user is null || user.Disabled || !ReferenceEquals(_service._authManager.GetUser(user.Username), user) || !_service._authManager.IsPermitted(PermissionSection.Settings, user, flag)) throw new DnsWebServiceException("Access was denied.");
                if (flag != PermissionFlag.View && _service._clusterManager.ClusterInitialized && _service._clusterManager.GetSelfNode().Type != ClusterNodeType.Primary) throw new DnsWebServiceException("Security policy changes must be made on the cluster primary.");
                return user;
            }
            static async Task ReadPredictiveForm(HttpContext context)
            { if (context.Request.HasFormContentType) await context.Request.ReadFormAsync(context.RequestAborted); }
            public async Task PredictiveRegistry(HttpContext context)
            {
                AuthorizePredictive(context, PermissionFlag.View);
                await ReadPredictiveForm(context);
                AuthorizePredictive(context, PermissionFlag.View);
                var result = _service._security.PredictiveModels.Snapshot();
                AuthorizePredictive(context, PermissionFlag.View); Write(context, "registry", result);
            }
            public async Task PredictiveContext(HttpContext context)
            {
                AuthorizePredictive(context, PermissionFlag.View);
                await ReadPredictiveForm(context);
                AuthorizePredictive(context, PermissionFlag.View);
                var result = _service._security.PredictiveContext(context.Request.GetQueryOrForm("eventId"), DateTime.UtcNow);
                AuthorizePredictive(context, PermissionFlag.View); Write(context, "evidence", result);
            }
            User AuthorizePredictiveWrite(HttpContext context)
            {
                User user = AuthorizePredictive(context, PermissionFlag.Modify);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to manage local advisory models.");
                return user;
            }
            public async Task TrainPredictive(HttpContext context)
            {
                User user = AuthorizePredictiveWrite(context);
                await ReadPredictiveForm(context);
                AuthorizePredictiveWrite(context);
                var result = _service._security.PredictiveModels.Train(context.Request.GetQueryOrForm("dataset"), long.Parse(context.Request.GetQueryOrForm("revision")), user.Username, DateTime.UtcNow, () => AuthorizePredictiveWrite(context));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Registered local advisory model at revision " + result.Revision);
                AuthorizePredictive(context, PermissionFlag.View); Write(context, "registry", result);
            }
            public async Task SelectPredictive(HttpContext context)
            {
                User user = AuthorizePredictiveWrite(context);
                await ReadPredictiveForm(context);
                AuthorizePredictiveWrite(context);
                var result = _service._security.PredictiveModels.Select(context.Request.GetQueryOrForm("modelId", ""), long.Parse(context.Request.GetQueryOrForm("revision")), user.Username, DateTime.UtcNow, () => AuthorizePredictiveWrite(context));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Selected local advisory model at revision " + result.Revision);
                AuthorizePredictive(context, PermissionFlag.View); Write(context, "registry", result);
            }
            public async Task RetirePredictive(HttpContext context)
            {
                User user = AuthorizePredictiveWrite(context);
                await ReadPredictiveForm(context);
                AuthorizePredictiveWrite(context);
                var result = _service._security.PredictiveModels.Retire(context.Request.GetQueryOrForm("modelId"), long.Parse(context.Request.GetQueryOrForm("revision")), user.Username, DateTime.UtcNow, () => AuthorizePredictiveWrite(context));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Retired local advisory model at revision " + result.Revision);
                AuthorizePredictive(context, PermissionFlag.View); Write(context, "registry", result);
            }
            // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
            public async Task TestModelConnection(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.View);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to test a model connection.");
                string json = context.Request.GetQueryOrForm("settings");
                if (Encoding.UTF8.GetByteCount(json) > 8192) throw new ArgumentException("Model connection settings exceed 8 KiB.");
                var settings = JsonSerializer.Deserialize<LlmSettings>(json, DdiSecurityManager.JsonOptions) ?? throw new ArgumentException("Enter model connection settings.");
                Write(context, "analysis", await _service._security.TestModelConnectionAsync(settings, context.RequestAborted));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Tested model connection with synthetic data.");
            }
            public async Task AnalyzeEvent(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.View);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to send event evidence to a model.");
                var analysis = await _service._security.AnalyzeEventAsync(context.Request.GetQueryOrForm("eventId"), context.RequestAborted);
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Requested advisory model analysis for security event " + analysis.EventId);
                Write(context, "analysis", analysis);
            }
            public void History(HttpContext context)
            { Authorize(context, PermissionFlag.View); Write(context, "policies", _service._security.PolicyHistory().Select(p => new { p.Revision, p.Enabled, p.Mode, indicators = p.Indicators.Length }).ToArray()); }
            public void Rollback(HttpContext context)
            {
                User user = AuthorizePredictive(context, PermissionFlag.Modify);
                long revision = long.Parse(context.Request.GetQueryOrForm("revision")); long target = long.Parse(context.Request.GetQueryOrForm("targetRevision"));
                _service._security.RollbackPolicy(target, revision, policy => {
                    User current = AuthorizePredictive(context, PermissionFlag.Modify);
                    if (ConnectionsChanged(policy, _service._security.Policy) && !_service._authManager.IsPermitted(PermissionSection.Administration, current, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to change enrichment, EDL publication, or model connections.");
                });
                if (_service._clusterManager.ClusterInitialized) _service._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Rolled back security policy content from revision " + target + " as new revision " + _service._security.Policy.Revision);
                Write(context, "policy", _service._security.Policy);
            }
            public async Task Search(HttpContext context)
            {
                Authorize(context, PermissionFlag.View);
                var from = DateTimeOffset.Parse(context.Request.GetQueryOrForm("from"), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime;
                var to = DateTimeOffset.Parse(context.Request.GetQueryOrForm("to"), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime;
                Write(context, "search", await _service._security.SearchEventsAsync(from, to, context.Request.GetQueryOrForm("client", ""), context.Request.GetQueryOrForm("query", ""), int.Parse(context.Request.GetQueryOrForm("limit", "200")), context.RequestAborted));
            }
            public void Dispositions(HttpContext context)
            { Authorize(context, PermissionFlag.View); Write(context, "dispositions", _service._security.Dispositions()); }
            public void SetDisposition(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                Write(context, "disposition", _service._security.SetDisposition(context.Request.GetQueryOrForm("eventId"), context.Request.GetQueryOrForm("status"), context.Request.GetQueryOrForm("notes", ""), user.Username));
            }
            public void Simulate(HttpContext context)
            {
                Authorize(context, PermissionFlag.View); var request = context.Request;
                string[] cnames = request.GetQueryOrForm("cnames", "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                string[] addresses = request.GetQueryOrForm("addresses", "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                Write(context, "decision", _service._security.Evaluate(IPAddress.Parse(request.GetQueryOrForm("client", "127.0.0.1")), request.GetQueryOrForm("query"), cnames, addresses.Select(IPAddress.Parse)));
            }
            public void IngestSignals(HttpContext context)
            {
                if (!_service._clusterManager.ClusterInitialized || context.GetCurrentSession().Type != UserSessionType.ClusterApiToken || _service._clusterManager.GetSelfNode().Type != ClusterNodeType.Primary || !context.Request.IsHttps || context.Request.QueryOrForm("actingUser") is not null) throw new DnsWebServiceException("A direct HTTPS cluster API session on the primary is required; proxied user sessions cannot ingest signals.");
                string payload = context.Request.GetQueryOrForm("signals");
                if (Encoding.UTF8.GetByteCount(payload) > 2 * 1024 * 1024) throw new ArgumentException("Signal batch exceeds 2 MiB.");
                SecuritySignal[] signals = JsonSerializer.Deserialize<SecuritySignal[]>(payload, DdiSecurityManager.JsonOptions) ?? throw new ArgumentException("Missing signals.");
                foreach (var signal in signals)
                    if (signal is null || !_service._clusterManager.TryGetClusterNode(signal.Node, out _)) throw new ArgumentException("Signal source is not a registered cluster node.");
                Write(context, "accepted", _service._security.MergeSignals(signals));
            }
            static bool ConnectionsChanged(SecurityPolicy proposed, SecurityPolicy current) => proposed.Misp != current.Misp || (proposed.Llm ?? new LlmSettings()) != (current.Llm ?? new LlmSettings()) || JsonSerializer.Serialize(proposed.EdlFeeds, DdiSecurityManager.JsonOptions) != JsonSerializer.Serialize(current.EdlFeeds, DdiSecurityManager.JsonOptions) || JsonSerializer.Serialize(proposed.EdlPublications, DdiSecurityManager.JsonOptions) != JsonSerializer.Serialize(current.EdlPublications, DdiSecurityManager.JsonOptions);
            bool CanCommitFeed(HttpContext context, long revision)
            {
                if (context.RequestAborted.IsCancellationRequested || !_service.TryValidateSession(context, out _) || _service._security.Policy.Revision != revision) return false;
                try
                {
                    User user = Authorize(context, PermissionFlag.Modify);
                    return _service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify);
                }
                catch (DnsWebServiceException) { return false; }
            }
            public async Task RefreshFeed(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to refresh feed sources.");
                long revision = long.Parse(context.Request.GetQueryOrForm("revision"));
                string id = context.Request.GetQueryOrForm("feedId");
                if (!CanCommitFeed(context, revision) || _service._security.EdlRevision != context.Request.GetQueryOrForm("snapshotRevision")) throw new InvalidOperationException("Feed state changed; reload before refresh.");
                if (!_service._security.Policy.EdlFeeds.Any(f => f.Id == id && f.Enabled)) throw new ArgumentException("Choose an enabled feed source.");
                await _service._security.RefreshEdlAsync(context.RequestAborted, scheduled: true, commitAuthorized: () => CanCommitFeed(context, revision), feedId: id);
                if (!_service.TryValidateSession(context, out _)) throw new InvalidTokenWebServiceException("Refresh completed; authenticate again to read its outcome.");
                User current = Authorize(context, PermissionFlag.View);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, current, PermissionFlag.View)) throw new DnsWebServiceException("Authenticate with Administration view permission to read the refresh outcome.");
                Write(context, "attempt", _service._security.EdlStatus().Single(f => f.FeedId == id));
                Write(context, "snapshotRevision", _service._security.EdlRevision);
            }
            public void FeedAttempt(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.View);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.View)) throw new DnsWebServiceException("Administration view permission is required to read refresh attempts.");
                string id = context.Request.GetQueryOrForm("attemptId");
                Write(context, "attempt", _service._security.EdlStatus().SingleOrDefault(f => f.AttemptId == id) ?? throw new ArgumentException("Refresh attempt is not retained on this node."));
            }
            public void CancelFeed(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to cancel refresh attempts.");
                _service._security.CancelFeedAttempt(context.Request.GetQueryOrForm("attemptId"));
                Write(context, "state", "Cancellation requested; read the attempt outcome.");
            }
            public async Task RollbackFeed(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to restore feed snapshots.");
                byte[] snapshot;
                if (context.Request.ContentType?.Split(';')[0] == "application/json")
                {
                    using var bytes = new MemoryStream(); byte[] buffer = new byte[8192]; int read;
                    while ((read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted)) > 0)
                    { if (bytes.Length + read > 16 * 1024 * 1024) throw new ArgumentException("Feed snapshot exceeds 16 MiB."); bytes.Write(buffer, 0, read); }
                    snapshot = bytes.ToArray();
                }
                else
                {
                    string json = context.Request.GetQueryOrForm("snapshot");
                    if (Encoding.UTF8.GetByteCount(json) > 16 * 1024 * 1024) throw new ArgumentException("Feed snapshot exceeds 16 MiB.");
                    snapshot = Encoding.UTF8.GetBytes(json);
                }
                long revision = long.Parse(context.Request.GetQueryOrForm("revision"));
                _service._security.RollbackEdl(snapshot, revision, context.Request.GetQueryOrForm("snapshotRevision"), () => CanCommitFeed(context, revision));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] Restored validated feed snapshot.");
                if (_service._clusterManager.ClusterInitialized) _service._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                Write(context, "snapshotRevision", _service._security.EdlRevision);
            }
            public async Task ExportEdl(HttpContext context)
            {
                // Transport and header-only authentication are checked before the ordinary JSON API middleware.
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                if (!HasDirectTlsTransport(context)) { context.Response.StatusCode = 403; return; }
                if (!context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || context.Request.Query.ContainsKey("token") || context.Request.Query.ContainsKey("node") || context.GetCurrentSession().Type == UserSessionType.ClusterApiToken)
                { context.Response.StatusCode = 401; return; }
                User user = _service.GetSessionUser(context);
                if (!_service._authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.View) || !_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.View))
                { context.Response.StatusCode = 403; return; }
                EdlOutput output;
                try { output = _service._security.PublishEdl(context.Request.Query["list"].ToString()); }
                catch (ArgumentException) { context.Response.StatusCode = 404; return; }
                context.Response.ContentType = "text/plain; charset=utf-8";
                context.Response.Headers["X-teQtanium-EDL-Kind"] = output.Kind;
                context.Response.Headers["X-teQtanium-EDL-Action"] = output.IntendedAction;
                context.Response.Headers["X-teQtanium-EDL-State"] = output.State;
                context.Response.Headers["X-teQtanium-EDL-Generated"] = output.GeneratedAt.ToString("O");
                if (output.Expires.HasValue) context.Response.Headers["X-teQtanium-EDL-Expires"] = output.Expires.Value.ToString("O");
                string format = context.Request.Query["format"].ToString();
                if (format.Length > 0 && format != "rpz") { context.Response.StatusCode = 400; return; }
                string text;
                try { text = format == "rpz" ? DdiSecurityManager.FormatRpz(output, context.Request.Query["zone"].ToString()) : output.Text; }
                catch (ArgumentException) { context.Response.StatusCode = 400; return; }
                await context.Response.WriteAsync(text, context.RequestAborted);
            }
        }
    }
}
