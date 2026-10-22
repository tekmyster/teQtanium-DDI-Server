// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC â€” remains GPL-3.0.
using DnsServerCore.Auth;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Text.Json;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        // Aggregate snapshots only. No synchronization, network probe, inventory rows or event reads.
        void GetOperationsMetrics(HttpContext context)
        {
            var user = GetSessionUser(context);
            bool View(PermissionSection section) => _authManager.IsPermitted(section, user, PermissionFlag.View);
            if (!View(PermissionSection.Dashboard)) throw new DnsWebServiceException("Access was denied.");
            context.Response.Headers.CacheControl = "no-store";
            string window = context.Request.Query["minutes"];
            int minutes = window is null or "" ? 60 : int.TryParse(window, out int value) && value is 15 or 60 ? value : throw new ArgumentException("Choose a 15 or 60 minute window.");
            object llm = null, ipam = null, protection = null, dhcp = null;
            var now = DateTime.UtcNow;
            if (View(PermissionSection.Settings))
            {
                var policy = _security.Policy; var model = policy.Llm ?? new LlmSettings();
                llm = new { enabled = model.Enabled, configured = !string.IsNullOrWhiteSpace(model.Endpoint) && !string.IsNullOrWhiteSpace(model.Model), configuredModel = model.Model, metrics = _security.ModelMetrics(minutes) };
                var inventory = _ipam.Snapshot();
                // Only known source labels cross this boundary; unknown labels may contain inventory metadata.
                string Source(string source) => source switch { "DhcpScope" or "DnsReverseZone" or "DhcpGateway" or "DhcpReservation" or "DnsRecord" => source, null or "" => "Manual", _ => "Other" };
                ipam = new { networks = inventory.Subnets.Length, assignments = inventory.Assignments.Length, revision = inventory.Revision, lastChange = inventory.Changes.Length == 0 ? (DateTime?)null : inventory.Changes.Max(c => c.Timestamp), sources = inventory.Assignments.GroupBy(a => Source(a.Source)).Select(g => new { source = g.Key, count = g.Count() }).ToArray(), netBoxEnabled = _netbox.Settings.Enabled };
                var misp = _security.MispStatus;
                // Cache usability and local traversal outcomes are independent dimensions.
                string integrationState = misp.CacheState == "Usable" ? (misp.ActiveUnsupportedAttributes > 0 ? "PartialCoverage" : "Available") : misp.CacheState;
                protection = new { enabled = policy.Enabled, mode = policy.Mode == "Block" ? "Block" : "Monitor", misp = new { state = integrationState, lastSuccess = misp.LastSuccess, lastAttempt = misp.LastAttempt, indicators = misp.Indicators, snapshotEntries = misp.SnapshotEntries, unsupportedAttributes = misp.UnsupportedAttributes, dnsMatchingIndicators = misp.DnsMatchingIndicators, urlEvidenceOnly = misp.UrlEvidenceOnly, completeSnapshot = misp.CompleteSnapshot,
                    cacheState = misp.CacheState, cacheSourceUrl = misp.CacheSourceUrl, cacheOrigin = misp.CacheOrigin, cacheReceivedAt = misp.CacheReceivedAt, cacheFetchedAt = misp.CacheFetchedAt, cacheExpiresAt = misp.CacheExpiresAt, cacheLastExpiresAt = misp.CacheLastExpiresAt, activeUnsupportedAttributes = misp.ActiveUnsupportedAttributes,
                    localSuccessSourceMatches = misp.LocalSuccessSourceMatches, localRefreshState = misp.LocalRefreshState, localRefreshStale = misp.LocalRefreshStale, lastFailure = misp.LastFailure } };
            }
            if (View(PermissionSection.DhcpServer))
            {
                var scopes = _dhcpServer.Scopes.Values.ToArray();
                dhcp = new { scopes = scopes.Length, enabledScopes = scopes.Count(s => s.Enabled), activeLeases = scopes.Sum(s => s.Leases.Values.Count(l => l.LeaseExpires > now)), observedAt = now };
            }
            var writer = context.GetCurrentJsonWriter(); writer.WritePropertyName("operations");
            JsonSerializer.Serialize(writer, new { scope = "ThisNode", observedAt = now, processStartedAt = _uptimestamp, llm, ipam, dhcp, protection }, DdiSecurityManager.JsonOptions);
        }
    }
}
