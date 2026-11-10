// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Ipam;
using System.Text.Json;
using System.Text.Json.Nodes;

static class NetBoxDeletionScopeChecks
{
    public static async Task Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "teqtanium-netbox-deletion-scope-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("DDI_NETBOX_FIXTURE_API_KEY", "fixture-key");
        await using var remote = await NetBoxReconciliationChecks.NativeNetBox.Start(); int checks = 0;
        void Check(bool condition, string why) { if (!condition) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
        async Task Reject(Func<Task> action, string why) { try { await action(); } catch (InvalidOperationException) { Check(true, why); return; } throw new Exception(why); }
        try
        {
            foreach (bool ipv6 in new[] { false, true })
            {
                string name = ipv6 ? "IPv6" : "IPv4", folder = Path.Combine(root, name); Directory.CreateDirectory(folder);
                string prefix = ipv6 ? "2001:db8::/64" : "192.0.2.0/24", changedPrefix = ipv6 ? "2001:db8::/80" : "192.0.2.0/25";
                string address = ipv6 ? "2001:db8::9" : "192.0.2.9", cidr = address + (ipv6 ? "/64" : "/24"), differentMask = address + (ipv6 ? "/96" : "/25");
                int vrf = ipv6 ? 6101 : 6100;
                var manager = new IpamManager(Path.Combine(folder, "ipam.json")); var parent = manager.PutSubnet(0, "fixture", "", "default", prefix, name, "", null, "", "");
                var assignment = manager.PutAssignment(1, "fixture", "", parent.Id, address, "fixture.example", "owner", "Assigned", "");
                using var connector = new NetBoxConnector(Path.Combine(folder, "connector"), remote.Client());
                var settings = new NetBoxSettings(true, remote.Url, "DDI_NETBOX_FIXTURE_API_KEY", "Bearer", [new("default", vrf)]);
                await connector.ConfigureAsync(settings); var created = await connector.PreviewAsync(manager.Snapshot()); await connector.ApplyAsync(created.Id, manager.Snapshot().Revision);
                var external = remote.Objects["ip-addresses"].Single(a => (int)a["vrf"]["id"] == vrf); string marker = (string)external["comments"];
                manager.Delete(manager.Snapshot().Revision, "fixture", "assignment", assignment.Id);
                using (var before = JsonDocument.Parse(manager.Snapshot().Changes.Last().Before)) Check(before.RootElement.GetProperty("parentSubnet").GetProperty("prefix").GetString() == prefix && before.RootElement.GetProperty("parentSubnet").GetProperty("viewId").GetString() == "default", name + " assignment tombstone binds the full historical parent CIDR and view");
                int deletesBefore = remote.Deletes; external["address"] = differentMask;
                var review = await connector.PreviewAsync(manager.Snapshot());
                Check(review.Changes.Single(c => c.Kind == "ip-addresses" && c.RemoteId == (int)external["id"]).Operation == "Conflict", name + " changed remote mask is a conflict rather than a deletion candidate");
                string key = "ip-addresses:" + (int)external["id"];
                await Reject(() => connector.PreviewAsync(manager.Snapshot(), deletionKeys: [key]), name + " changed-mask selection cannot become approved deletion");
                Check(remote.Deletes == deletesBefore && remote.Objects["ip-addresses"].Contains(external), name + " mismatched remote CIDR survives with no DELETE");
                external["address"] = cidr;
                review = await connector.PreviewAsync(manager.Snapshot(), deletionKeys: [key]);
                external["address"] = differentMask; // Deliberately retain last_updated: scope must be checked independently.
                await Reject(() => connector.ApplyAsync(review.Id, manager.Snapshot().Revision, deletionAuthorized: () => true), name + " final execution rejects mask drift even when the remote timestamp is unchanged");
                Check(remote.Deletes == deletesBefore && remote.Objects["ip-addresses"].Contains(external), name + " final full-representation guard sends no DELETE");
                external["address"] = cidr;
                review = await connector.PreviewAsync(manager.Snapshot(), deletionKeys: [key]);
                Check((await connector.ApplyAsync(review.Id, manager.Snapshot().Revision, deletionAuthorized: () => true)).Applied == 1 && remote.Deletes == deletesBefore + 1, name + " correct-mask individually selected control sends one conditional DELETE");
                external = remote.Add("ip-addresses", cidr, vrf, marker); key = "ip-addresses:" + (int)external["id"];
                byte[] intact = manager.Export(); deletesBefore = remote.Deletes;
                async Task Preserved(string reason)
                {
                    var current = await connector.PreviewAsync(manager.Snapshot());
                    Check(current.Changes.Any(c => c.Kind == "ip-addresses" && c.RemoteId == (int)external["id"] && c.Operation == "Conflict"), name + " " + reason + " is visibly nondeletable");
                    await Reject(() => connector.PreviewAsync(manager.Snapshot(), deletionKeys: [key]), name + " " + reason + " selection is refused");
                    Check(remote.Deletes == deletesBefore && remote.Objects["ip-addresses"].Contains(external), name + " " + reason + " preserves remote intent");
                }
                var legacy = JsonNode.Parse(intact).AsObject(); var deletion = legacy["changes"].AsArray().Last(c => (string)c["operation"] == "assignment.delete");
                var legacyBefore = JsonNode.Parse((string)deletion["before"]).AsObject(); legacyBefore.Remove("parentSubnet"); deletion["before"] = legacyBefore.ToJsonString(); manager.Restore(JsonSerializer.SerializeToUtf8Bytes(legacy));
                await Preserved("legacy tombstone without recorded parent scope"); manager.Restore(intact);
                manager.PutSubnet(manager.Snapshot().Revision, "fixture", parent.Id, "default", changedPrefix, name, "", null, "", "");
                await Preserved("parent prefix changed after assignment deletion"); manager.Restore(intact);
                var view = manager.PutView(manager.Snapshot().Revision, "fixture", "", "Other routing domain", "");
                manager.PutSubnet(manager.Snapshot().Revision, "fixture", parent.Id, view.Id, prefix, name, "", null, "", "");
                await connector.ConfigureAsync(settings with { Mappings = [new(view.Id, vrf)] });
                await Preserved("parent view changed even when the new mapping has the same remote VRF"); await connector.ConfigureAsync(settings); manager.Restore(intact);
                var missing = JsonNode.Parse(intact).AsObject(); missing["subnets"] = new JsonArray(); manager.Restore(JsonSerializer.SerializeToUtf8Bytes(missing));
                await Preserved("missing parent without an explicit matching parent deletion"); manager.Restore(intact);
                manager.PutSubnet(manager.Snapshot().Revision, "fixture", parent.Id, "default", changedPrefix, name, "", null, "", ""); manager.Delete(manager.Snapshot().Revision, "fixture", "subnet", parent.Id);
                await Preserved("deleted parent whose last prefix differs from the assignment tombstone"); manager.Restore(intact);
                manager.Delete(manager.Snapshot().Revision, "fixture", "subnet", parent.Id);
                review = await connector.PreviewAsync(manager.Snapshot(), deletionKeys: [key]);
                Check(review.Changes.Single(c => c.Kind == "ip-addresses").Operation == "Delete", name + " matching explicit parent-deletion history preserves historical full-CIDR proof");
                Check((await connector.ApplyAsync(review.Id, manager.Snapshot().Revision, deletionAuthorized: () => true)).Applied == 1 && remote.Deletes == deletesBefore + 1, name + " correct historical CIDR survives parent removal and deletes only the selected address");
                Check(remote.Objects["prefixes"].Any(p => (int)p["vrf"]["id"] == vrf), name + " unselected parent prefix is preserved");
                connector.Dispose();
            }
            Console.WriteLine($"PASS {checks} full historical NetBox deletion CIDR/view/parent checks; native TLS, positive conditional controls and negative preservation.");
        }
        finally { Environment.SetEnvironmentVariable("DDI_NETBOX_FIXTURE_API_KEY", null); if (Path.GetDirectoryName(root) == Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) Directory.Delete(root, true); }
    }
}
