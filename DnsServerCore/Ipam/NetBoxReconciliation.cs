// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Ipam
{
    public sealed record NetBoxSubnetMapping(string SubnetId, int? SiteId, int? VlanId, int? TenantId);
    public sealed record NetBoxInterfaceMapping(string AssignmentId, int DeviceId, int InterfaceId, int? TenantId);
    public sealed record NetBoxPolicy(string[] Types, string[] SubnetIds, NetBoxSubnetMapping[] Subnets, NetBoxInterfaceMapping[] Interfaces);
    public sealed record NetBoxSchedule(bool Enabled, int IntervalMinutes, string Mode, string Actor = "", int TimeoutSeconds = 60);
    public sealed record NetBoxRun(string Id, string Status, DateTime Started, DateTime? Finished, DateTime NextDue, string PreviewId, string Detail, int Failures = 0, string SettingsHash = "", long InventoryRevision = -1);
    public sealed record NetBoxImportChange(string Key, string Kind, int RemoteId, string ViewId, string SubnetId, string Natural, string Name, string Status, string Description, string RemoteUpdated, string Fingerprint, string Operation, string Reason);
    public sealed record NetBoxImportPreview(string Id, long InventoryRevision, DateTime Created, string SettingsHash, NetBoxImportChange[] Changes);
    public sealed record IpamNetBoxReceipt(string PreviewId, string SettingsHash, string Actor, DateTime Applied, long Revision, NetBoxImportChange[] Objects);

    public sealed partial class NetBoxConnector
    {
        static readonly ConcurrentDictionary<string, SemaphoreSlim> Targets = new(StringComparer.OrdinalIgnoreCase);
        readonly AsyncLocal<Func<bool>> _authorization = new();
        readonly object _runSync = new();
        CancellationTokenSource _runCancellation;
        Task _runTask;
        NetBoxSchedule _schedule = new(false, 30, "Review");
        NetBoxRun _run;
        NetBoxRun _pendingRun;
        public NetBoxSchedule Schedule { get { lock (_runSync) return _schedule; } }
        public NetBoxRun Run { get { lock (_runSync) return _pendingRun is null ? _run : _pendingRun with { Status = "SavingOutcome", Detail = "Collection ended. Its outcome is waiting for storage; reload status after storage recovers. Collection will not be replayed." }; } }
        public bool PendingOutcome { get { lock (_runSync) return _pendingRun is not null; } }
        public NetBoxResult PublicationResult
        {
            get
            {
                string file = Path.Combine(_folder, "netbox-result.json"); if (!File.Exists(file)) return null;
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return JsonSerializer.Deserialize<NetBoxResult>(stream, JsonOptions);
            }
        }
        static NetBoxSettings CloneSettings(NetBoxSettings settings) => JsonSerializer.Deserialize<NetBoxSettings>(JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions), JsonOptions);
        static void ValidatePolicy(NetBoxPolicy p)
        {
            if (p is null) return; // Backward-compatible mapped prefix/address publication.
            if (p.Types is null || p.SubnetIds is null || p.Subnets is null || p.Interfaces is null || p.Types.Length > 2 || p.Types.Distinct().Count() != p.Types.Length || p.Types.Any(t => t is not "prefixes" and not "ip-addresses") || p.SubnetIds.Length > 1000 || p.SubnetIds.Any(string.IsNullOrWhiteSpace) || p.SubnetIds.Distinct().Count() != p.SubnetIds.Length || p.Subnets.Length > 1000 || p.Interfaces.Length > 1000 || p.Subnets.Any(m => m is null || string.IsNullOrWhiteSpace(m.SubnetId) || m.SiteId <= 0 || m.VlanId <= 0 || m.TenantId <= 0) || p.Interfaces.Any(m => m is null || string.IsNullOrWhiteSpace(m.AssignmentId) || m.DeviceId <= 0 || m.InterfaceId <= 0 || m.TenantId <= 0) || p.Subnets.Select(m => m.SubnetId).Distinct().Count() != p.Subnets.Length || p.Interfaces.Select(m => m.AssignmentId).Distinct().Count() != p.Interfaces.Length) throw new ArgumentException("Choose unique object types, subnet scope and positive NetBox reference IDs.");
        }
        async Task Enter(CancellationToken token)
        {
            if (PendingOutcome) throw new InvalidOperationException("The previous outcome is waiting for storage. Reload status after storage recovers.");
            if (!await _gate.WaitAsync(0, token)) throw new InvalidOperationException("NetBox work is already running. Reload its outcome before retrying.");
        }
        sealed class Admission(SemaphoreSlim gate, FileStream lease) : IDisposable { public void Dispose() { lease.Dispose(); gate.Release(); } }
        async Task<IDisposable> Admit(CancellationToken token)
        {
            var uri = Endpoint("api/");
            // Origin-wide admission deliberately also covers different API base paths/credentials.
            // DNS aliases/distributed services still require one operator-selected canonical origin.
            var gate = Targets.GetOrAdd(uri.GetLeftPart(UriPartial.Authority), _ => new(1, 1));
            if (!await gate.WaitAsync(0, token)) throw new InvalidOperationException("Another reconciliation is using this NetBox target. Retry after it finishes.");
            try
            {
                string originHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant())));
                string locks = Path.Combine(Path.GetTempPath(), "teqtanium-netbox-target-admission"); Directory.CreateDirectory(locks);
                var lease = new FileStream(Path.Combine(locks, originHash + ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                return new Admission(gate, lease);
            }
            catch (IOException) { gate.Release(); throw new InvalidOperationException("Another local process is using this NetBox target. Reload its outcome before retrying."); }
            catch { gate.Release(); throw; }
        }
        bool InScope(IpamSubnet subnet, string kind) => _settings.Mappings.Any(m => m.ViewId == subnet.ViewId) && (_settings.Policy is null || _settings.Policy.Types.Contains(kind) && (_settings.Policy.SubnetIds.Length == 0 || _settings.Policy.SubnetIds.Contains(subnet.Id)));
        static int? Reference(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : value.ValueKind == JsonValueKind.Object ? value.GetProperty("id").GetInt32() : value.GetInt32();
        async Task<JsonElement> ReadReference(string resource, int id, CancellationToken token)
        {
            var value = (await Request(HttpMethod.Get, Endpoint("api/" + resource + "/" + id + "/"), null, null, token)).Json;
            if (!value.TryGetProperty("id", out var found) || found.GetInt32() != id) throw new InvalidOperationException("NetBox returned a different reference identity. Review the mapping.");
            return value;
        }
        async Task<string> ValidateReferences(IpamSnapshot inventory, CancellationToken token)
        {
            var p = _settings.Policy;
            List<string> references = [];
            async Task<JsonElement> Read(string resource, int id)
            { var value = await ReadReference(resource, id, token); references.Add(resource + "/" + id + ":" + Fingerprint(value)); return value; }
            T Deleted<T>(string id, string operation) where T : class
            {
                var change = inventory?.Changes.LastOrDefault(c => c.ObjectId == id && c.Operation == operation && c.After is null);
                return change?.Before is null ? null : JsonSerializer.Deserialize<T>(change.Before, JsonOptions);
            }
            IpamSubnet Subnet(string id) => inventory?.Subnets.SingleOrDefault(s => s.Id == id) ?? Deleted<IpamSubnet>(id, "subnet.delete");
            string Hash() => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", references))));
            if (p is null) return Hash();
            if (inventory is not null && p.SubnetIds.Any(id => Subnet(id) is null)) throw new InvalidOperationException("A scoped subnet has no current inventory or deletion history. Review the integration scope.");
            foreach (var m in p.Subnets)
            {
                if (inventory is not null && (Subnet(m.SubnetId) is not { } mappedSubnet || !InScope(mappedSubnet, "prefixes"))) throw new InvalidOperationException("A prefix mapping is outside the selected scope.");
                if (m.SiteId is int site) await Read("dcim/sites", site);
                if (m.VlanId is int vlan)
                {
                    var remote = await Read("ipam/vlans", vlan);
                    if (m.SiteId is int selectedSite && remote.TryGetProperty("site", out var siteValue) && Reference(siteValue) is int actualSite && selectedSite != actualSite) throw new InvalidOperationException("The selected VLAN belongs to another site.");
                    if (m.SiteId is int groupSite && remote.TryGetProperty("group", out var groupValue) && Reference(groupValue) is int groupId)
                    {
                        var group = await Read("ipam/vlan-groups", groupId); string scopeType = Text(group, "scope_type");
                        if (scopeType.Length > 0 && (scopeType != "dcim.site" || !group.TryGetProperty("scope_id", out var scope) || Reference(scope) != groupSite)) throw new InvalidOperationException("The VLAN group scope does not match the selected site. Review its supported site mapping.");
                    }
                    if (m.TenantId is int selectedTenant && remote.TryGetProperty("tenant", out var tenantValue) && Reference(tenantValue) is int actualTenant && selectedTenant != actualTenant) throw new InvalidOperationException("The selected VLAN belongs to another tenant.");
                }
                if (m.TenantId is int tenant) await Read("tenancy/tenants", tenant);
            }
            foreach (var m in p.Interfaces)
            {
                var a = inventory?.Assignments.SingleOrDefault(a => a.Id == m.AssignmentId) ?? Deleted<IpamAssignment>(m.AssignmentId, "assignment.delete");
                if (inventory is not null && (a is null || Subnet(a.SubnetId) is not { } parent || !InScope(parent, "ip-addresses"))) throw new InvalidOperationException("An interface mapping is outside the selected address scope.");
                var device = await Read("dcim/devices", m.DeviceId);
                if (m.TenantId is int selectedTenant && device.TryGetProperty("tenant", out var tenantValue) && Reference(tenantValue) is int actualTenant && selectedTenant != actualTenant) throw new InvalidOperationException("The selected device belongs to another tenant.");
                var iface = await Read("dcim/interfaces", m.InterfaceId);
                if (Reference(iface.GetProperty("device")) != m.DeviceId) throw new InvalidOperationException("The selected interface belongs to another device. Review the DCIM mapping.");
                if (m.TenantId is int tenant) await Read("tenancy/tenants", tenant);
            }
            return Hash();
        }
        string MappedFields(string kind, string id, string fields)
        {
            var result = JsonNode.Parse(fields).AsObject();
            if (kind == "prefixes" && _settings.Policy?.Subnets.SingleOrDefault(m => m.SubnetId == id) is { } subnet)
            {
                // NetBox 4.2+ generic prefix scope. No guessed site/VLAN from local display text.
                if (subnet.SiteId is int site) { result["scope_type"] = "dcim.site"; result["scope_id"] = site; }
                if (subnet.VlanId is int vlan) result["vlan"] = vlan;
                if (subnet.TenantId is int tenant) result["tenant"] = tenant;
            }
            if (kind == "ip-addresses" && _settings.Policy?.Interfaces.SingleOrDefault(m => m.AssignmentId == id) is { } iface)
            { result["assigned_object_type"] = "dcim.interface"; result["assigned_object_id"] = iface.InterfaceId; if (iface.TenantId is int tenant) result["tenant"] = tenant; }
            return result.ToJsonString(JsonOptions);
        }
        void AppendDeletions(IpamSnapshot inventory, JsonElement[] prefixes, JsonElement[] addresses, List<NetBoxChange> changes, string[] selected)
        {
            if (selected.Length > 100 || selected.Distinct().Count() != selected.Length) throw new ArgumentException("Select at most 100 unique managed deletions.");
            HashSet<string> found = [];
            foreach (var kind in new[] { "ip-addresses", "prefixes" })
            foreach (var remote in kind == "prefixes" ? prefixes : addresses)
            {
                var lines = Text(remote, "comments").Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("DDI:", StringComparison.Ordinal)).ToArray();
                string prefix = "DDI:" + _installation + ":" + kind + ":";
                if (lines.Length != 1 || !lines[0].StartsWith(prefix, StringComparison.Ordinal)) continue;
                string id = lines[0][prefix.Length..];
                if (kind == "prefixes" ? inventory.Subnets.Any(s => s.Id == id) : inventory.Assignments.Any(a => a.Id == id)) continue;
                var tombstone = inventory.Changes.LastOrDefault(c => c.ObjectId == id && c.Operation == (kind == "prefixes" ? "subnet.delete" : "assignment.delete") && c.After is null);
                if (tombstone?.Before is null) continue; // Absence alone is not deletion intent.
                IpamSubnet subnet; string natural; string contextConflict = null; string expectedCidr = null;
                if (kind == "prefixes") { subnet = JsonSerializer.Deserialize<IpamSubnet>(tombstone.Before, JsonOptions); natural = subnet.Prefix; }
                else
                {
                    var assignment = JsonSerializer.Deserialize<IpamAssignment>(tombstone.Before, JsonOptions); natural = assignment.Address;
                    using var deletionRecord = JsonDocument.Parse(tombstone.Before);
                    IpamSubnet originalParent = deletionRecord.RootElement.TryGetProperty("parentSubnet", out var savedParent) ? savedParent.Deserialize<IpamSubnet>(JsonOptions) : null;
                    // Legacy records do not carry this scope proof. A current parent or
                    // earlier independent edit cannot retroactively establish deletion intent.
                    subnet = inventory.Subnets.SingleOrDefault(s => s.Id == assignment.SubnetId);
                    if (subnet is null)
                    {
                        var parent = inventory.Changes.LastOrDefault(c => c.ObjectId == assignment.SubnetId && c.Operation == "subnet.delete");
                        if (parent?.Before is not null) subnet = JsonSerializer.Deserialize<IpamSubnet>(parent.Before, JsonOptions);
                        else { subnet = originalParent; contextConflict = "Parent subnet is missing without an explicit parent deletion record; remote address preserved"; }
                    }
                    if (subnet is null) continue;
                    if (originalParent is null || originalParent.Id != assignment.SubnetId) contextConflict = "Deletion-time parent mask is not proven; remote address preserved";
                    else
                    {
                        expectedCidr = IPAddress.Parse(assignment.Address) + "/" + new IpamNetwork(originalParent.Prefix).PrefixLength;
                        if (subnet.Prefix != originalParent.Prefix || subnet.ViewId != originalParent.ViewId) contextConflict = "Parent prefix or network view changed after local deletion; remote address preserved";
                    }
                }
                var mapping = _settings.Mappings.SingleOrDefault(m => m.ViewId == subnet.ViewId);
                if (!InScope(subnet, kind) || mapping is null || Vrf(remote) != mapping.VrfId || (kind == "prefixes" ? Text(remote, "prefix") != natural : Text(remote, "address").Split('/')[0] != natural)) continue;
                if (kind == "ip-addresses")
                {
                    string actualCidr = IPAddress.Parse(Text(remote, "address").Split('/')[0]) + "/" + new IpamNetwork(Text(remote, "address")).PrefixLength;
                    if (expectedCidr is not null && actualCidr != expectedCidr) contextConflict = "Remote address mask differs from the deletion-time parent mask; remote address preserved";
                    if (contextConflict is not null)
                    {
                        changes.Add(new(kind, id, "Conflict", remote.GetProperty("id").GetInt32(), Text(remote, "last_updated"), remote.GetRawText(), contextConflict, remote.GetRawText()));
                        continue;
                    }
                }
                string key = kind + ":" + remote.GetProperty("id").GetInt32(); found.Add(key);
                bool approve = selected.Contains(key);
                changes.Add(new(kind, id, approve ? "Delete" : "ReviewDeletion", remote.GetProperty("id").GetInt32(), Text(remote, "last_updated"), remote.GetRawText(), approve ? "Explicitly selected local deletion; managed ownership will be checked again" : "Local deletion recorded; select this object for a separate deletion review", remote.GetRawText()));
            }
            if (selected.Any(k => !found.Contains(k))) throw new InvalidOperationException("A selected deletion is no longer eligible. Reload the review; foreign, stale and out-of-scope objects are preserved.");
        }
        void RecoverReconciliation()
        {
            string schedule = Path.Combine(_folder, "netbox-schedule.json"), journal = Path.Combine(_folder, "netbox-run.json");
            if (File.Exists(schedule)) _schedule = JsonSerializer.Deserialize<NetBoxSchedule>(File.ReadAllBytes(schedule), JsonOptions);
            if (File.Exists(journal)) _run = JsonSerializer.Deserialize<NetBoxRun>(File.ReadAllBytes(journal), JsonOptions);
            if (_run?.Status is "Running" or "Publishing")
            { _run = _run with { Status = "Interrupted", Finished = DateTime.UtcNow, Detail = "Service restarted. Review current outcomes before resuming; no operation was replayed." }; Save("netbox-run.json", _run); }
        }
        public async Task ConfigureScheduleAsync(NetBoxSchedule schedule, CancellationToken token = default)
        {
            if (schedule is null || schedule.IntervalMinutes is < 1 or > 10080 || schedule.TimeoutSeconds is < 1 or > 60 || schedule.Mode != "Review" || schedule.Enabled && string.IsNullOrWhiteSpace(schedule.Actor)) throw new ArgumentException("Choose a review interval between 1 minute and 7 days, a 1–60 second time limit and an authorized owner. Scheduled publication is not enabled.");
            await Enter(token);
            try { lock (_runSync) { if (_runTask is { IsCompleted: false }) throw new InvalidOperationException("Cancel running reconciliation before changing its schedule."); Save("netbox-schedule.json", schedule); _schedule = schedule; _run = null; Save("netbox-run.json", _run); } }
            finally { _gate.Release(); }
        }
        void Journal(NetBoxRun run) { lock (_runSync) { Save("netbox-run.json", run); _run = run; } }
        void Terminal(NetBoxRun run)
        {
            lock (_runSync)
            {
                try { Save("netbox-run.json", run); _run = run; _pendingRun = null; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _pendingRun = run; }
            }
        }
        public bool RetryPendingOutcome()
        { lock (_runSync) { if (_pendingRun is null) return false; Terminal(_pendingRun); return _pendingRun is null; } }
        public bool CancelReconciliation() { lock (_runSync) { if (_runCancellation is null || _runTask?.IsCompleted != false) return false; _runCancellation.Cancel(); return true; } }
        public Task WaitForReconciliationAsync() { lock (_runSync) return _runTask ?? Task.CompletedTask; }
        public bool TryStartReconciliation(Func<IpamSnapshot> inventory, Func<string, bool> authorized, DateTime now, bool manual = false)
        {
            lock (_runSync)
            {
                var schedule = _schedule;
                if (!_settings.Enabled || !schedule.Enabled || _pendingRun is not null || _runTask is { IsCompleted: false } || _run?.Status is "Interrupted" or "ReviewRequired" || !manual && _run is not null && _run.NextDue > now) return false;
                if (!authorized(schedule.Actor)) { Journal(new(Guid.NewGuid().ToString("N"), "Blocked", now, now, now.AddMinutes(schedule.IntervalMinutes), "", "Schedule owner no longer has permission or this server is not primary.")); return false; }
                var initial = new NetBoxRun(Guid.NewGuid().ToString("N"), "Running", now, null, now.AddMinutes(schedule.IntervalMinutes), "", "Collecting current scoped inventory.", _run?.Failures ?? 0, SettingsHash(), inventory().Revision);
                Journal(initial); _runCancellation?.Dispose(); _runCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(schedule.TimeoutSeconds)); var token = _runCancellation.Token;
                _runTask = Task.Run(async () =>
                {
                    try
                    {
                        var snapshot = inventory(); string hash = initial.SettingsHash;
                        if (snapshot.Revision != initial.InventoryRevision) throw new InvalidOperationException("Local inventory changed before scheduled collection. Prepare a new review.");
                        bool Current() => authorized(schedule.Actor) && _settings.Enabled && _schedule == schedule && hash == SettingsHash();
                        var preview = await PreviewAsync(snapshot, token, Current);
                        if (!Current() || inventory().Revision != snapshot.Revision) throw new InvalidOperationException("Authority, inventory or settings changed during reconciliation.");
                        Terminal(initial with { Status = preview.Changes.Any(c => c.Operation == "Conflict") ? "ReviewRequired" : "Ready", Finished = DateTime.UtcNow, PreviewId = preview.Id, Detail = "Current review is ready. Review publication separately; scheduling makes no inventory changes.", Failures = 0 });
                    }
                    catch (Exception ex)
                    {
                        int failures = initial.Failures + 1;
                        Terminal(initial with { Status = failures >= 3 ? "ReviewRequired" : token.IsCancellationRequested ? "Cancelled" : "Failed", Finished = DateTime.UtcNow, Failures = failures, Detail = token.IsCancellationRequested ? "Cancelled or exceeded the one-minute limit. Reload current outcomes." : ex is InvalidOperationException ? ex.Message : "Collection failed. Check connectivity and credential reference, then retry." });
                    }
                });
                return true;
            }
        }
        static string Fingerprint(JsonElement value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value.GetRawText())));
        public async Task<NetBoxPreview> ReadPreviewAsync(long revision, CancellationToken token = default)
        {
            await Enter(token);
            try
            {
                string file = Path.Combine(_folder, "netbox-preview.json"); if (!File.Exists(file)) return null;
                var preview = JsonSerializer.Deserialize<NetBoxPreview>(File.ReadAllBytes(file), JsonOptions);
                if (preview.InventoryRevision != revision || preview.SettingsHash != SettingsHash() || preview.Created < DateTime.UtcNow.AddMinutes(-15)) throw new InvalidOperationException("The saved review expired or inventory/settings changed. Prepare a new review.");
                return preview;
            }
            finally { _gate.Release(); }
        }
        public async Task<NetBoxImportPreview> PreviewImportAsync(IpamSnapshot inventory, CancellationToken token = default, Func<bool> authorized = null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(60)); token = deadline.Token;
            await Enter(token);
            try
            {
                using var admission = await Admit(token); _authorization.Value = authorized;
                List<NetBoxImportChange> changes = [];
                foreach (string kind in new[] { "prefixes", "ip-addresses" })
                foreach (var remote in await List(kind, token))
                {
                    if (_settings.Policy is not null && !_settings.Policy.Types.Contains(kind)) continue;
                    var mapping = _settings.Mappings.SingleOrDefault(m => m.VrfId == Vrf(remote)); if (mapping is null) continue;
                    string natural = Text(remote, kind == "prefixes" ? "prefix" : "address"), status = remote.GetProperty("status").ValueKind == JsonValueKind.Object ? Text(remote.GetProperty("status"), "value") : Text(remote, "status");
                    string operation = "Propose", reason = "Missing manual inventory; select individually to add local intent. Services are unchanged.", subnetId = "";
                    if (kind == "prefixes")
                    {
                        var network = new IpamNetwork(natural); natural = network.Prefix;
                        if (inventory.Subnets.Any(s => s.ViewId == mapping.ViewId && new IpamNetwork(s.Prefix).Overlaps(network))) { operation = "Preserve"; reason = "Existing local prefix or overlap remains authoritative."; }
                        if (_settings.Policy?.SubnetIds.Length > 0) continue; // Missing subnets cannot be members of a preselected existing-subnet scope.
                    }
                    else
                    {
                        var ip = IPAddress.Parse(natural.Split('/')[0]);
                        var subnet = inventory.Subnets.Where(s => s.ViewId == mapping.ViewId && !s.Container && new IpamNetwork(s.Prefix).Contains(ip) && InScope(s, kind)).OrderByDescending(s => new IpamNetwork(s.Prefix).PrefixLength).FirstOrDefault();
                        if (subnet is null) continue;
                        subnetId = subnet.Id;
                        bool dynamic = !string.IsNullOrEmpty(subnet.DhcpScope) || status is "dhcp" or "slaac";
                        if (dynamic || inventory.Assignments.Any(a => a.SubnetId == subnet.Id && a.Address == ip.ToString()) || (inventory.DiscoveryRuns ?? []).SelectMany(r => r.Evidence).Any(e => e.Address == ip.ToString()))
                        { operation = "Preserve"; reason = dynamic ? "Dynamic scope or remote observation cannot establish static intent." : "Existing local intent or observation is preserved."; }
                        if (new IpamNetwork(natural).PrefixLength != new IpamNetwork(subnet.Prefix).PrefixLength) { operation = "Preserve"; reason = "Remote address mask differs from the local subnet. Review its semantics before creating local intent."; }
                        natural = ip.ToString();
                    }
                    if (status is not "active" and not "reserved" and not "deprecated" and not "container") { operation = "Preserve"; reason = "Remote status is not eligible static intent."; }
                    int id = remote.GetProperty("id").GetInt32();
                    changes.Add(new(kind + ":" + id, kind, id, mapping.ViewId, subnetId, natural, kind == "prefixes" ? Text(remote, "description") : Text(remote, "dns_name"), status, Text(remote, "description"), Text(remote, "last_updated"), Fingerprint(remote), operation, reason));
                }
                token.ThrowIfCancellationRequested();
                if (authorized is not null && !authorized()) throw new InvalidOperationException("Import review permission changed during collection.");
                var duplicateKeys = changes.GroupBy(c => c.Kind + "|" + c.ViewId + "|" + c.Natural).Where(g => g.Count() > 1).SelectMany(g => g.Select(c => c.Key)).ToHashSet();
                changes = changes.Select(c => duplicateKeys.Contains(c.Key) ? c with { Operation = "Preserve", Reason = "Duplicate remote natural identity requires resolution in NetBox." } : c).ToList();
                var preview = new NetBoxImportPreview(Guid.NewGuid().ToString("N"), inventory.Revision, DateTime.UtcNow, SettingsHash(), changes.ToArray()); Save("netbox-import-preview.json", preview); return preview;
            }
            finally { _authorization.Value = null; _gate.Release(); }
        }
        public async Task<int> ApplyImportAsync(string previewId, string[] keys, IpamManager inventory, string actor, CancellationToken token = default, Func<bool> authorized = null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(60)); token = deadline.Token;
            if (keys is null || keys.Length is < 1 or > 100 || keys.Distinct().Count() != keys.Length) throw new ArgumentException("Select 1 to 100 unique proposals.");
            await Enter(token);
            try
            {
                using var admission = await Admit(token); _authorization.Value = authorized;
                var preview = JsonSerializer.Deserialize<NetBoxImportPreview>(File.ReadAllBytes(Path.Combine(_folder, "netbox-import-preview.json")), JsonOptions);
                if (preview.Id != previewId || preview.InventoryRevision != inventory.Snapshot().Revision || preview.SettingsHash != SettingsHash() || preview.Created < DateTime.UtcNow.AddMinutes(-15)) throw new InvalidOperationException("Import review expired or inventory/settings changed. Generate a fresh review.");
                var selected = keys.Select(k => preview.Changes.SingleOrDefault(c => c.Key == k && c.Operation == "Propose") ?? throw new InvalidOperationException("Select eligible proposals only.")).ToArray();
                foreach (var c in selected)
                {
                    var current = (await Request(HttpMethod.Get, Endpoint("api/ipam/" + c.Kind + "/" + c.RemoteId + "/"), null, null, token)).Json;
                    if (Fingerprint(current) != c.Fingerprint) throw new InvalidOperationException("NetBox changed after review. Generate a fresh proposal.");
                }
                if (authorized is not null && !authorized()) throw new InvalidOperationException("Current import permission is required.");
                token.ThrowIfCancellationRequested();
                return inventory.ImportNetBox(preview.InventoryRevision, actor, selected, preview.Id, preview.SettingsHash, authorized);
            }
            finally { _authorization.Value = null; _gate.Release(); }
        }
    }
    public sealed partial class IpamManager
    {
        static void ValidateNetBoxImports(IpamSnapshot state)
        {
            var receipts = state.NetBoxImports ?? [];
            if (receipts.Length > 1000 || receipts.Any(r => r is null || r.Objects is null || r.Objects.Length is < 1 or > 100 || r.Revision < 1 || r.Revision > state.Revision || string.IsNullOrWhiteSpace(r.Actor) || r.Objects.Any(c => c is null || c.Operation != "Propose" || c.Kind is not "prefixes" and not "ip-addresses"))) throw new ArgumentException("Invalid NetBox import receipts.");
        }
        // A single inventory mutation validates the whole selected set before any durable change.
        public int ImportNetBox(long revision, string actor, NetBoxImportChange[] proposals, string previewId = "", string settingsHash = "", Func<bool> authorized = null) => Mutate(revision, actor, "netbox.import:" + previewId, state =>
        {
            if (authorized is not null && !authorized()) throw new InvalidOperationException("Current import permission is required.");
            if ((state.NetBoxImports ?? []).Length >= 1000) throw new InvalidOperationException("The import receipt limit was reached. Preserve and archive inventory history before further imports.");
            if (!string.IsNullOrEmpty(previewId) && (state.NetBoxImports ?? []).Any(r => r.PreviewId == previewId)) throw new InvalidOperationException("This import review was already consumed.");
            List<IpamSubnet> subnets = state.Subnets.ToList(); List<IpamAssignment> assignments = state.Assignments.ToList();
            foreach (var c in proposals)
            {
                if (c.Operation != "Propose" || !state.Views.Any(v => v.Id == c.ViewId)) throw new InvalidOperationException("Import proposal is outside current inventory.");
                if (c.Kind == "prefixes")
                {
                    var network = new IpamNetwork(c.Natural);
                    if (subnets.Any(s => s.ViewId == c.ViewId && new IpamNetwork(s.Prefix).Overlaps(network))) throw new InvalidOperationException("A local prefix or overlap now exists; it remains authoritative.");
                    subnets.Add(new(Guid.NewGuid().ToString("N"), c.ViewId, network.Prefix, string.IsNullOrWhiteSpace(c.Name) ? network.Prefix : c.Name, "", null, "", "", c.Status == "container"));
                }
                else if (c.Kind == "ip-addresses")
                {
                    var subnet = subnets.SingleOrDefault(s => s.Id == c.SubnetId && s.ViewId == c.ViewId && !s.Container && string.IsNullOrEmpty(s.DhcpScope)) ?? throw new InvalidOperationException("Static import requires an existing unlinked local subnet.");
                    if (c.Status is not "active" and not "reserved" and not "deprecated" || assignments.Any(a => a.SubnetId == subnet.Id && a.Address == c.Natural) || DiscoveryEvidence(subnet.Id, false).Any(e => e.Address == c.Natural) || (state.Provisioning ?? []).Any(p => HoldsAddress(p) && p.Subnet.ViewId == subnet.ViewId && p.Intent.Address == c.Natural)) throw new InvalidOperationException("Local intent, observations and dynamic addresses are preserved.");
                    assignments.Add(new(Guid.NewGuid().ToString("N"), subnet.Id, c.Natural, c.Name, "", c.Status == "reserved" ? "Reserved" : c.Status == "deprecated" ? "Deprecated" : "Assigned", c.Description));
                }
                else throw new ArgumentException("Unsupported import object type.");
            }
            if (authorized is not null && !authorized()) throw new InvalidOperationException("Current import permission is required.");
            return (state with { Subnets = subnets.ToArray(), Assignments = assignments.ToArray(), NetBoxImports = (state.NetBoxImports ?? []).Append(new IpamNetBoxReceipt(previewId, settingsHash, actor, DateTime.UtcNow, state.Revision + 1, proposals.ToArray())).ToArray() }, proposals.Length, "");
        });
    }
}
