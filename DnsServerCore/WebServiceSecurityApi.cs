using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
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
                Authorize(context, PermissionFlag.View); Write(context, "policy", _service._security.Policy);
                Write(context, "mispHealth", _service._security.MispStatus); Write(context, "droppedEvents", _service._security.DroppedEvents);
                Write(context, "signalHealth", _service._security.SignalStatus);
                Write(context, "signals", _service._security.Signals());
            }
            public void SetPolicy(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                string json = context.Request.GetQueryOrForm("policy");
                if (Encoding.UTF8.GetByteCount(json) > 2 * 1024 * 1024) throw new ArgumentException("Security policy exceeds 2 MiB.");
                var policy = JsonSerializer.Deserialize<SecurityPolicy>(json, DdiSecurityManager.JsonOptions) ?? throw new ArgumentException("Missing security policy.");
                if ((policy.Misp != _service._security.Policy.Misp || (policy.Llm ?? new LlmSettings()) != (_service._security.Policy.Llm ?? new LlmSettings())) && !_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to configure enrichment or model connections.");
                _service._security.SetPolicy(policy, long.Parse(context.Request.GetQueryOrForm("revision")));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] DDI security policy updated to revision " + _service._security.Policy.Revision);
                if (_service._clusterManager.ClusterInitialized) _service._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                Write(context, "policy", _service._security.Policy);
            }
            public void Events(HttpContext context)
            {
                Authorize(context, PermissionFlag.View); Write(context, "events", _service._security.RecentEvents()); Write(context, "signals", _service._security.Signals());
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
                User user = Authorize(context, PermissionFlag.Modify);
                long revision = long.Parse(context.Request.GetQueryOrForm("revision")); long target = long.Parse(context.Request.GetQueryOrForm("targetRevision"));
                var policy = _service._security.PolicyHistory().SingleOrDefault(p => p.Revision == target) ?? throw new ArgumentException("Policy revision is not retained.");
                if ((policy.Misp != _service._security.Policy.Misp || (policy.Llm ?? new LlmSettings()) != (_service._security.Policy.Llm ?? new LlmSettings())) && !_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify)) throw new DnsWebServiceException("Administration modify permission is required to change enrichment or model connections.");
                _service._security.SetPolicy(policy, revision);
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
        }
    }
}
