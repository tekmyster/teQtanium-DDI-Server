using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Ipam;
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Threading;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        readonly NetBoxConnector _netbox;
        Timer _netboxTimer;
        bool NetBoxAuthorized(string actor, bool deletion = false)
        {
            var user = _authManager.GetUser(actor);
            return user is not null && !user.Disabled && _authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify) && _authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.Modify) &&
                (!deletion || _authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Delete) && _authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.Delete)) &&
                (!_clusterManager.ClusterInitialized || _clusterManager.GetSelfNode().Type == ClusterNodeType.Primary);
        }
        void RequireNetBoxAdmin(HttpContext context, bool deletion = false)
        { if (!NetBoxAuthorized(GetSessionUser(context).Username, deletion)) throw new DnsWebServiceException("Current Administration and Settings permissions and cluster-primary ownership are required."); }
        void TickNetBox()
        { try { _netbox.TryStartReconciliation(() => _ipam.Snapshot(), actor => NetBoxAuthorized(actor), DateTime.UtcNow); } catch (Exception ex) { _log.Write("NetBox reconciliation could not start.", ex); } }
        static void WriteNetBox(HttpContext context, string name, object value)
        { var writer = context.GetCurrentJsonWriter(); writer.WritePropertyName(name); JsonSerializer.Serialize(writer, value, value.GetType(), NetBoxConnector.JsonOptions); }
        void GetNetBoxSettings(HttpContext context)
        { RequireNetBoxAdmin(context); _netbox.RetryPendingOutcome(); WriteNetBox(context, "settings", _netbox.Settings); WriteNetBox(context, "schedule", _netbox.Schedule); WriteNetBox(context, "run", (object)_netbox.Run ?? new { status = "NotStarted", detail = "No scheduled review has run." }); WriteNetBox(context, "publication", (object)_netbox.PublicationResult ?? new { status = "NotStarted", applied = 0 }); WriteNetBox(context, "canDelete", NetBoxAuthorized(GetSessionUser(context).Username, true)); }
        async Task SetNetBoxSettings(HttpContext context)
        {
            RequireNetBoxAdmin(context); string json = context.Request.GetQueryOrForm("settings");
            if (json.Length > 64 * 1024) throw new ArgumentException("Integration settings exceed 64 KiB.");
            var settings = JsonSerializer.Deserialize<NetBoxSettings>(json, NetBoxConnector.JsonOptions) ?? throw new ArgumentException("Missing settings.");
            if (settings.Mappings is null || Array.Exists(settings.Mappings, m => !Array.Exists(_ipam.Snapshot().Views, v => v.Id == m.ViewId))) throw new ArgumentException("Mapping references an unknown network view.");
            await _netbox.ConfigureAsync(settings, context.RequestAborted); WriteNetBox(context, "settings", _netbox.Settings);
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Updated NetBox integration settings.");
        }
        async Task PreviewNetBox(HttpContext context)
        {
            RequireNetBoxAdmin(context); string actor = GetSessionUser(context).Username;
            WriteNetBox(context, "preview", await _netbox.PreviewAsync(_ipam.Snapshot(), context.RequestAborted, () => NetBoxAuthorized(actor)));
        }
        async Task ReadNetBoxPreview(HttpContext context)
        { RequireNetBoxAdmin(context); var preview = await _netbox.ReadPreviewAsync(_ipam.Snapshot().Revision, context.RequestAborted); WriteNetBox(context, "preview", (object)preview ?? new { changes = Array.Empty<object>() }); }
        static string[] NetBoxSelection(HttpContext context) => (context.Request.GetQueryOrForm("keys") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries);
        async Task PreviewNetBoxDeletions(HttpContext context)
        {
            RequireNetBoxAdmin(context, true); string actor = GetSessionUser(context).Username; var keys = NetBoxSelection(context);
            if (keys.Length == 0) throw new ArgumentException("Select the managed objects to delete.");
            WriteNetBox(context, "preview", await _netbox.PreviewAsync(_ipam.Snapshot(), context.RequestAborted, () => NetBoxAuthorized(actor, true), keys));
        }
        async Task ApplyNetBox(HttpContext context)
        {
            RequireNetBoxAdmin(context); string actor = GetSessionUser(context).Username;
            // Deletion capability is checked for every apply containing an explicitly reviewed delete.
            WriteNetBox(context, "result", await _netbox.ApplyAsync(context.Request.GetQueryOrForm("previewId"), _ipam.Snapshot().Revision, context.RequestAborted, () => _ipam.Snapshot().Revision, () => NetBoxAuthorized(actor), () => NetBoxAuthorized(actor, true)));
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Applied a reviewed NetBox publication.");
        }
        async Task SetNetBoxSchedule(HttpContext context)
        {
            RequireNetBoxAdmin(context); string json = context.Request.GetQueryOrForm("schedule");
            if (json.Length > 4096) throw new ArgumentException("Schedule exceeds 4 KiB.");
            var schedule = JsonSerializer.Deserialize<NetBoxSchedule>(json, NetBoxConnector.JsonOptions) ?? throw new ArgumentException("Missing schedule.");
            await _netbox.ConfigureScheduleAsync(schedule with { Actor = GetSessionUser(context).Username }, context.RequestAborted);
            WriteNetBox(context, "schedule", _netbox.Schedule);
        }
        void RunNetBoxSchedule(HttpContext context)
        { RequireNetBoxAdmin(context); WriteNetBox(context, "started", _netbox.TryStartReconciliation(() => _ipam.Snapshot(), actor => NetBoxAuthorized(actor), DateTime.UtcNow, true)); }
        void CancelNetBoxSchedule(HttpContext context)
        { RequireNetBoxAdmin(context); WriteNetBox(context, "cancelled", _netbox.CancelReconciliation()); }
        async Task PreviewNetBoxImport(HttpContext context)
        {
            RequireNetBoxAdmin(context); string actor = GetSessionUser(context).Username;
            WriteNetBox(context, "preview", await _netbox.PreviewImportAsync(_ipam.Snapshot(), context.RequestAborted, () => NetBoxAuthorized(actor)));
        }
        async Task ApplyNetBoxImport(HttpContext context)
        {
            RequireNetBoxAdmin(context); string actor = GetSessionUser(context).Username;
            WriteNetBox(context, "imported", await _netbox.ApplyImportAsync(context.Request.GetQueryOrForm("previewId"), NetBoxSelection(context), _ipam, actor, context.RequestAborted, () => NetBoxAuthorized(actor)));
            _log.Write(GetRemoteEndPoint(context), "[" + actor + "] Added individually reviewed NetBox proposals to local IPAM intent.");
        }
    }
}
