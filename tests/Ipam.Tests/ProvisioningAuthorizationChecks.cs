// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dhcp;
using DnsServerCore.Ipam;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;

static class ProvisioningAuthorizationChecks
{
    public static async Task Run(DnsWebService service, HttpClient original, string adminPassword,
        string subnetId, Scope scope, string resultPath, bool serve,
        Func<HttpClient, string, (string Key, string Value)[], Task<JsonElement>> call,
        Func<Task<string>> revision, Action<bool, string> check)
    {
        var auth = (AuthManager)typeof(DnsWebService).GetField("_authManager", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        var ipam = (IpamManager)typeof(DnsWebService).GetField("_ipam", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        var retained = new List<HttpClient>();
        var receipts = new List<object>();
        const string zone = "provisioning.test";
        var everyone = auth.GetGroup(Group.EVERYONE);
        var full = PermissionFlag.View | PermissionFlag.Modify | PermissionFlag.Delete;
        var originalLeases = scope.Leases.Values.Select(l => l.Address + "|" + l.GetClientInfo()).OrderBy(x => x).ToArray();
        string actorPassword = Guid.NewGuid().ToString("N") + "Aa9!";
        var actor = auth.CreateUser("Provisioning authorization fixture", "provisioning-auth-actor", actorPassword);
        string previewId = Guid.NewGuid().ToString("N"), approvedId = Guid.NewGuid().ToString("N");
        string Status(JsonElement response) => response.GetProperty("status").GetString();
        JsonElement Operation(JsonElement response) => response.GetProperty("response").GetProperty("operation");
        async Task<HttpClient> Fresh(string username, string password, string label)
        {
            var client = new HttpClient { BaseAddress = original.BaseAddress };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("IPAM-Authorization-Revision002-" + label);
            retained.Add(client);
            var login = await call(client, "user/login", [("user", username), ("pass", password), ("includeInfo", "true")]);
            check(Status(login) == "ok", label + " separate fresh authentication");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
            return client;
        }
        async Task FreshAdminProof(string label)
        {
            var fresh = await Fresh("admin", adminPassword, label + "-admin");
            var read = await call(fresh, "ipam/list", []);
            check(Status(read) == "ok", label + " fresh admin reads inventory");
            var write = await call(fresh, "ipam/views/set", [("revision", read.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64().ToString()), ("name", "Authorization proof " + label)]);
            check(Status(write) == "ok", label + " fresh admin modifies while originals remain open");
            var sessions = await call(fresh, "admin/sessions/list", []);
            var targetSeen = sessions.GetProperty("response").GetProperty("sessions").EnumerateArray().Single(s => s.GetProperty("isCurrentSession").GetBoolean());
            check(targetSeen.GetProperty("lastSeenRemoteAddress").GetString() == "127.0.0.1", label + " target sees authorized loopback source");
            check(Status(await call(original, "ipam/list", [])) == "ok", label + " original admin remains usable");
        }
        void DirectRights(PermissionFlag dns, PermissionFlag dhcp, PermissionFlag settings = PermissionFlag.View | PermissionFlag.Modify)
        {
            auth.SetPermission(PermissionSection.Settings, actor, settings);
            auth.SetPermission(PermissionSection.Zones, zone, actor, dns);
            auth.SetPermission(PermissionSection.DhcpServer, actor, dhcp);
            auth.SaveConfigFile(true);
        }
        (string, string)[] Request(string id, string address, string host, string hardware, string inventoryRevision)
            => [("revision", inventoryRevision), ("operationId", id), ("subnetId", subnetId), ("address", address), ("hostName", host), ("hardwareAddress", hardware)];
        void Persist() => File.WriteAllText(resultPath, JsonSerializer.Serialize(new { atUtc = DateTime.UtcNow, source = "127.0.0.1", originalSessionsRetained = true, productionPaths = "untested", receipts }, new JsonSerializerOptions { WriteIndented = true }));
        try
        {
            // Remove inherited native grants only inside this disposable fixture, then grant
            // precise actor permissions. No product ACL default is changed by the repair.
            auth.SetPermission(PermissionSection.DhcpServer, everyone, (PermissionFlag)0);
            auth.SetPermission(PermissionSection.Zones, everyone, (PermissionFlag)0);
            auth.SetPermission(PermissionSection.Zones, zone, everyone, (PermissionFlag)0);
            DirectRights(full, full);
            var owner = await Fresh(actor.Username, actorPassword, "initial-owner");
            await FreshAdminProof("initial-grants");
            var previewRequest = Request(previewId, "198.18.32.24", "auth-preview.provisioning.test", "02-00-00-00-00-24", await revision());
            var preview = await call(owner, "ipam/provisioning/preview", previewRequest);
            check(Status(preview) == "ok", "authorized owner creates preview");
            var approvedRequest = Request(approvedId, "198.18.32.25", "auth-approved.provisioning.test", "02-00-00-00-00-25", await revision());
            var prepared = await call(owner, "ipam/provisioning/preview", approvedRequest);
            check(Status(prepared) == "ok", "authorized owner creates second preview");
            var approvedDigest = Operation(prepared).GetProperty("digest").GetString();
            var approvedParameters = new (string, string)[] { ("operationId", approvedId), ("digest", approvedDigest) };
            check(Status(await call(owner, "ipam/provisioning/approve", approvedParameters)) == "ok", "authorized owner acquires approved hold");
            var scenarios = new[]
            {
                (Name: "dns-view-revoked", Dns: PermissionFlag.Modify | PermissionFlag.Delete, Dhcp: full, Settings: full),
                (Name: "dns-modify-revoked", Dns: PermissionFlag.View | PermissionFlag.Delete, Dhcp: full, Settings: full),
                (Name: "dhcp-view-revoked", Dns: full, Dhcp: PermissionFlag.Modify | PermissionFlag.Delete, Settings: full),
                (Name: "dhcp-modify-revoked", Dns: full, Dhcp: PermissionFlag.View | PermissionFlag.Delete, Settings: full),
                (Name: "settings-only", Dns: (PermissionFlag)0, Dhcp: (PermissionFlag)0, Settings: full),
                (Name: "settings-modify-revoked", Dns: full, Dhcp: full, Settings: PermissionFlag.View),
                (Name: "different-zone-only", Dns: (PermissionFlag)0, Dhcp: full, Settings: full)
            };
            foreach (var scenario in scenarios)
            {
                DirectRights(scenario.Dns, scenario.Dhcp, scenario.Settings);
                if (scenario.Name == "different-zone-only") auth.SetPermission(PermissionSection.Zones, "child.provisioning.test", actor, full);
                var affected = await Fresh(actor.Username, actorPassword, scenario.Name);
                bool dnsView = auth.IsPermitted(PermissionSection.Zones, zone, actor, PermissionFlag.View);
                bool dnsModify = auth.IsPermitted(PermissionSection.Zones, zone, actor, PermissionFlag.Modify);
                bool dhcpView = auth.IsPermitted(PermissionSection.DhcpServer, actor, PermissionFlag.View);
                bool dhcpModify = auth.IsPermitted(PermissionSection.DhcpServer, actor, PermissionFlag.Modify);
                check(dnsView == scenario.Dns.HasFlag(PermissionFlag.View) && dnsModify == scenario.Dns.HasFlag(PermissionFlag.Modify) && dhcpView == scenario.Dhcp.HasFlag(PermissionFlag.View) && dhcpModify == scenario.Dhcp.HasFlag(PermissionFlag.Modify), scenario.Name + " exact effective native flags");
                // The same original operation IDs and the new affected actor session exercise
                // cached Preview and Approved branches, not a new unrelated request.
                var newPreview = await call(affected, "ipam/provisioning/preview", Request(Guid.NewGuid().ToString("N"), "198.18.32.27", "auth-denied-new.provisioning.test", "02-00-00-00-00-27", await revision()));
                var repeatedPreview = await call(affected, "ipam/provisioning/preview", previewRequest);
                var repeatedApprovedPreview = await call(affected, "ipam/provisioning/preview", approvedRequest);
                var reapprove = await call(affected, "ipam/provisioning/approve", approvedParameters);
                var result = await call(affected, "ipam/provisioning/result", [("operationId", approvedId)]);
                var list = await call(affected, "ipam/provisioning/list", []);
                var apply = await call(affected, "ipam/provisioning/apply", approvedParameters);
                var recover = await call(affected, "ipam/provisioning/apply", [..approvedParameters, ("recover", "true")]);
                var cancelPreview = await call(affected, "ipam/provisioning/cancel", [("operationId", previewId)]);
                var cancelApproved = await call(affected, "ipam/provisioning/cancel", [("operationId", approvedId)]);
                var state = ipam.ProvisioningResult(approvedId);
                int visible = list.TryGetProperty("response", out var visibleResponse) ? visibleResponse.GetProperty("operations").GetArrayLength() : -1;
                receipts.Add(new { scenario = scenario.Name, freshAffectedActor = true, dnsView, dnsModify, dhcpView, dhcpModify, newPreview = Status(newPreview), cachedPreview = Status(repeatedPreview), cachedApprovedPreview = Status(repeatedApprovedPreview), reapprove = Status(reapprove), result = Status(result), list = Status(list), visibleOperations = visible, apply = Status(apply), recover = Status(recover), cancelPreview = Status(cancelPreview), cancelApproved = Status(cancelApproved), stateAfterUnauthorizedCancel = state.State, held = ipam.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.25")), noNativeWrites = !scope.ReservedLeases.Any(l => l.Address.ToString() is "198.18.32.24" or "198.18.32.25") });
                await FreshAdminProof(scenario.Name);
                Persist(); // Preserve complete route outcomes even when the baseline fails.
                check(Status(newPreview) == "error" && !newPreview.TryGetProperty("response", out _), scenario.Name + " new preview also denies without data");
                check(Status(repeatedPreview) == "error" && !repeatedPreview.TryGetProperty("response", out _), scenario.Name + " cached Preview denies without operation data");
                check(Status(repeatedApprovedPreview) == "error" && !repeatedApprovedPreview.TryGetProperty("response", out _), scenario.Name + " cached Approved preview denies without operation data");
                check(Status(reapprove) == "error" && !reapprove.TryGetProperty("response", out _), scenario.Name + " reapproval denies before cached reply");
                check(Status(apply) == "error" && Status(recover) == "error", scenario.Name + " apply and recovery deny before journal/native effects");
                check(Status(cancelPreview) == "error" && Status(cancelApproved) == "error", scenario.Name + " both cancellation states deny");
                check(state.State == "Approved" && ipam.ProvisioningResult(previewId).State == "Preview" && ipam.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.25")), scenario.Name + " unauthorized cancellation retains exact hold");
                bool canView = dnsView && dhcpView;
                check(Status(result) == (canView ? "ok" : "error") && visible == (canView ? 2 : 0), scenario.Name + " result/list preserve native view semantics");
                check(!scope.ReservedLeases.Any(l => l.Address.ToString() is "198.18.32.24" or "198.18.32.25") && service.DnsServer.AuthZoneManager.GetRecords(zone, "auth-approved.provisioning.test", TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecordType.A).Count == 0 && service.DnsServer.AuthZoneManager.GetRecords(zone, "auth-preview.provisioning.test", TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecordType.A).Count == 0, scenario.Name + " no unauthorized DNS or DHCP writes");
                check(originalLeases.SequenceEqual(scope.Leases.Values.Select(l => l.Address + "|" + l.GetClientInfo()).OrderBy(x => x)), scenario.Name + " unrelated native clients remain unchanged");
            }
            // Preserve effective grants split between a group (View) and user (Modify).
            auth.SetPermission(PermissionSection.DhcpServer, everyone, PermissionFlag.View);
            auth.SetPermission(PermissionSection.Zones, zone, everyone, PermissionFlag.View);
            DirectRights(PermissionFlag.Modify | PermissionFlag.Delete, PermissionFlag.Modify | PermissionFlag.Delete);
            foreach (string missingDelete in new[] { "dns-delete-revoked", "dhcp-delete-revoked" })
            {
                DirectRights(missingDelete.StartsWith("dns") ? PermissionFlag.Modify : PermissionFlag.Modify | PermissionFlag.Delete,
                    missingDelete.StartsWith("dhcp") ? PermissionFlag.Modify : PermissionFlag.Modify | PermissionFlag.Delete);
                var affected = await Fresh(actor.Username, actorPassword, missingDelete);
                var recovery = await call(affected, "ipam/provisioning/apply", [..approvedParameters, ("recover", "true")]);
                await FreshAdminProof(missingDelete);
                receipts.Add(new { scenario = missingDelete, freshAffectedActor = true, recover = Status(recovery), stateAfter = ipam.ProvisioningResult(approvedId).State });
                Persist();
                check(Status(recovery) == "error" && ipam.ProvisioningResult(approvedId).State == "Approved", missingDelete + " recovery requires delete before changing the journal");
            }
            DirectRights(PermissionFlag.Modify | PermissionFlag.Delete, PermissionFlag.Modify | PermissionFlag.Delete);
            var restored = await Fresh(actor.Username, actorPassword, "restored-split-grants");
            await FreshAdminProof("restored-split-grants");
            check(Status(await call(restored, "ipam/provisioning/preview", previewRequest)) == "ok", "restored owner cached preview honors split effective grants");
            check(Status(await call(restored, "ipam/provisioning/approve", approvedParameters)) == "ok", "restored owner approved retry remains idempotent");
            foreach (string route in new[] { "result", "approve", "apply", "cancel" })
                check(Status(await call(original, "ipam/provisioning/" + route, approvedParameters)) == "error", "fully privileged other actor cannot " + route + " original owner's request");
            check(Status(await call(original, "ipam/provisioning/preview", approvedRequest)) == "error", "fully privileged other actor cannot reuse cached preview");
            check(ipam.ProvisioningResult(approvedId).State == "Approved", "actor binding preserves original hold");
            var applied = await call(restored, "ipam/provisioning/apply", approvedParameters);
            check(Status(applied) == "ok" && Operation(applied).GetProperty("state").GetString() == "Completed", "restored owner configures native services");
            var replayed = await call(restored, "ipam/provisioning/apply", approvedParameters);
            check(Status(replayed) == "ok" && Operation(replayed).GetProperty("state").GetString() == "Completed" && scope.ReservedLeases.Count(l => l.Address.ToString() == "198.18.32.25") == 1, "restored owner same-ID completion creates no duplicate native reservation");
            check(Status(await call(restored, "ipam/provisioning/cancel", [("operationId", previewId)])) == "ok" && ipam.ProvisioningResult(previewId).State == "Cancelled", "restored owner can cancel original unsubmitted preview");
            string cancelApprovedId = Guid.NewGuid().ToString("N");
            var cancelRequest = Request(cancelApprovedId, "198.18.32.26", "auth-cancel-restored.provisioning.test", "02-00-00-00-00-26", await revision());
            var restoredCancelPreview = await call(restored, "ipam/provisioning/preview", cancelRequest);
            check(Status(restoredCancelPreview) == "ok", "restored owner creates a cancellable preview");
            var cancelParameters = new (string, string)[] { ("operationId", cancelApprovedId), ("digest", Operation(restoredCancelPreview).GetProperty("digest").GetString()) };
            check(Status(await call(restored, "ipam/provisioning/approve", cancelParameters)) == "ok", "restored owner approves cancellable hold");
            check(Status(await call(restored, "ipam/provisioning/cancel", cancelParameters)) == "ok" && ipam.ProvisioningResult(cancelApprovedId).State == "Cancelled" && !ipam.ProvisioningAddressHeld(scope.Name, IPAddress.Parse("198.18.32.26")), "restored owner can release only its unsubmitted approved hold");
            receipts.Add(new { scenario = "restored-rights", cachedPreview = "ok", reapprove = "ok", apply = "Completed", sameIdReplay = "Completed", nativeReservations = 1, cancelPreview = "Cancelled", actorBindingPreserved = true });
            if (serve)
            {
                string uiId = Guid.NewGuid().ToString("N");
                var uiRequest = Request(uiId, "198.18.32.28", "auth-ui.provisioning.test", "02-00-00-00-00-28", await revision());
                var uiPreview = await call(restored, "ipam/provisioning/preview", uiRequest);
                check(Status(uiPreview) == "ok", "isolated UI actor preview prepared");
                string uiDigest = Operation(uiPreview).GetProperty("digest").GetString();
                check(Status(await call(restored, "ipam/provisioning/approve", [("operationId", uiId), ("digest", uiDigest)])) == "ok", "isolated UI actor hold approved");
                File.WriteAllText(Path.ChangeExtension(resultPath, "session.json"), JsonSerializer.Serialize(new { username = actor.Username, password = actorPassword, operationId = uiId, digest = uiDigest, address = "198.18.32.28", hostName = "auth-ui.provisioning.test" }));
            }
            await FreshAdminProof("final-cleanup");
            Persist();
        }
        finally
        {
            // All original and affected sessions remain open through the final successful
            // fresh administrative proof and separate native outcome assertions above.
            foreach (var client in retained) client.Dispose();
        }
    }
}
