// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Auth;
using DnsServerCore.Logging;
using Microsoft.AspNetCore.Http;
using System;
using System.Globalization;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;

namespace DnsServerCore;

public partial class DnsWebService
{
    void RequireSyslogPermission(HttpContext context, bool modify)
    {
        RequireSyslogSession(context.GetCurrentSession(), modify);
    }
    void RequireSyslogSession(UserSession session, bool modify)
    {
        var user = _authManager.GetUser(session.User.Username);
        if (_authManager.GetSession(session.Token) != session || session.HasExpired() || user is null || user.Disabled)
            throw new DnsWebServiceException("The syslog session is no longer authorized. Sign in again.");
        if (!_authManager.IsPermitted(PermissionSection.Settings, user, modify ? PermissionFlag.Modify : PermissionFlag.View))
            throw new DnsWebServiceException("Access was denied.");
        if (session.Type is not (UserSessionType.Standard or UserSessionType.ApiToken))
            throw new DnsWebServiceException("Use a direct administrator session on this server for syslog settings.");
        if (modify && !_authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Modify))
            throw new DnsWebServiceException("Administration modify permission is required to forward logs.");
    }
    void WriteSyslogSettings(HttpContext context)
    {
        var writer = context.GetCurrentJsonWriter();
        writer.WritePropertyName("settings"); JsonSerializer.Serialize(writer, _syslog.ExportSettings(), SyslogForwarder.JsonOptions);
        writer.WriteString("tlsTrustMode", _syslog.Settings.TlsCaCertificate.Length == 0 ? "System" : "CollectorCa");
        writer.WriteString("tlsCaSha256", _syslog.TlsCaSha256);
        writer.WritePropertyName("health"); JsonSerializer.Serialize(writer, _syslog.Health, SyslogForwarder.JsonOptions);
    }
    void GetSyslogSettings(HttpContext context) { RequireSyslogPermission(context, false); WriteSyslogSettings(context); }
    async Task SetSyslogSettingsAsync(HttpContext context)
    {
        RequireSyslogPermission(context, true);
        string json = context.Request.GetQueryOrForm("settings");
        if (json.Length > 4096) throw new ArgumentException("Syslog settings are too large.");
        var settings = JsonSerializer.Deserialize<SyslogSettings>(json, SyslogForwarder.JsonOptions) ?? throw new ArgumentException("Enter syslog settings.");
        long revision = long.Parse(context.Request.GetQueryOrForm("revision"), CultureInfo.InvariantCulture);
        await _syslog.ConfigureAsync(settings, revision, context.RequestAborted, () => RequireSyslogPermission(context, true));
        RequireSyslogPermission(context, true);
        _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] Updated syslog forwarding settings.");
        WriteSyslogSettings(context);
    }
    void SendSyslogTest(HttpContext context)
    {
        RequireSyslogPermission(context, true);
        if (!_syslog.Settings.Enabled) throw new ArgumentException("Enable and save syslog forwarding before sending a test.");
        if (!_syslog.SendTest()) throw new InvalidOperationException("The syslog queue is full. Try again after the collector is reachable.");
        context.GetCurrentJsonWriter().WriteBoolean("queued", true); WriteSyslogSettings(context);
    }
}
