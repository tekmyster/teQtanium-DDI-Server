// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Ipam
{
    public sealed record NetBoxMapping(string ViewId, int? VrfId);
    public sealed record NetBoxSettings(bool Enabled, string Url, string ApiKeyEnvironment, string TokenScheme, NetBoxMapping[] Mappings, NetBoxPolicy Policy = null);
    public sealed record NetBoxChange(string Kind, string LocalId, string Operation, int? RemoteId, string RemoteUpdated, string Fields, string Reason, string Before = null);
    public sealed record NetBoxPreview(string Id, long InventoryRevision, DateTime Created, string SettingsHash, NetBoxChange[] Changes, string ReferenceHash = "");
    public sealed record NetBoxResult(string PreviewId, int Applied, string Status);

    // DDI owns mapped prefix/address fields. Existing unowned NetBox objects are conflicts,
    // never silently adopted or deleted. External writes use reviewed, revision-bound previews.
    public sealed partial class NetBoxConnector : IDisposable
    {
        public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        readonly string _folder;
        readonly FileStream _instanceLease;
        string _installation;
        readonly HttpClient _http;
        readonly SemaphoreSlim _gate = new(1, 1);
        NetBoxSettings _settings;
        public NetBoxConnector(string folder, HttpClient client = null)
        {
            _folder = folder; Directory.CreateDirectory(folder);
            _instanceLease = new FileStream(Path.Combine(folder, "netbox-runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            string installationFile = Path.Combine(folder, "netbox-installation.txt");
            if (!File.Exists(installationFile)) File.WriteAllText(installationFile, Guid.NewGuid().ToString("N"));
            _installation = File.ReadAllText(installationFile).Trim();
            if (!Guid.TryParseExact(_installation, "N", out _)) throw new InvalidDataException("Invalid NetBox installation identity.");
            _settings = File.Exists(Path.Combine(folder, "netbox.json")) ? JsonSerializer.Deserialize<NetBoxSettings>(File.ReadAllBytes(Path.Combine(folder, "netbox.json")), JsonOptions) : new(false, "", "DDI_NETBOX_API_KEY", "Bearer", []);
            Validate(_settings);
            RecoverReconciliation();
            _http = client ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
        }
        public NetBoxSettings Settings { get { var settings = _settings; return CloneSettings(settings); } }
        public byte[] ExportConfiguration() => JsonSerializer.SerializeToUtf8Bytes(new NetBoxConfiguration(_installation, Settings), JsonOptions);
        public sealed record NetBoxConfiguration(string Installation, NetBoxSettings Settings);
        public void RestoreConfiguration(byte[] bytes)
        {
            var bundle = JsonSerializer.Deserialize<NetBoxConfiguration>(bytes, JsonOptions) ?? throw new ArgumentException("Invalid NetBox backup.");
            if (!Guid.TryParseExact(bundle.Installation, "N", out _)) throw new ArgumentException("Invalid NetBox identity."); Validate(bundle.Settings);
            _gate.Wait();
            try
            {
                Save("netbox.json", bundle.Settings);
                string identity = Path.Combine(_folder, "netbox-installation.txt");
                using (var stream = new FileStream(identity + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None)) { byte[] data = Encoding.UTF8.GetBytes(bundle.Installation); stream.Write(data); stream.Flush(true); } File.Move(identity + ".tmp", identity, true);
                _installation = bundle.Installation; _settings = CloneSettings(bundle.Settings);
            }
            finally { _gate.Release(); }
        }
        static void Validate(NetBoxSettings settings)
        {
            ValidatePolicy(settings?.Policy);
            if (settings is null || settings.Mappings is null || settings.Mappings.Length > 1000 || settings.Mappings.Any(m => string.IsNullOrWhiteSpace(m.ViewId) || m.ViewId.Length > 255 || m.VrfId <= 0) || settings.Mappings.Select(m => m.ViewId).Distinct().Count() != settings.Mappings.Length || settings.Mappings.Select(m => m.VrfId).Distinct().Count() != settings.Mappings.Length || settings.TokenScheme != "Bearer" && settings.TokenScheme != "Token" || settings.ApiKeyEnvironment is null || !settings.ApiKeyEnvironment.StartsWith("DDI_NETBOX_", StringComparison.Ordinal) || !settings.ApiKeyEnvironment.EndsWith("_API_KEY", StringComparison.Ordinal) || settings.ApiKeyEnvironment.Length > 128 || settings.ApiKeyEnvironment.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')) throw new ArgumentException("Invalid NetBox mappings, authentication scheme, or credential reference.");
            if (settings.Enabled && (!Uri.TryCreate(settings.Url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)) throw new ArgumentException("NetBox requires an HTTPS base URL.");
        }
        void Save(string name, object value)
        {
            string path = Path.Combine(_folder, name); using (var stream = new FileStream(path + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None)) { JsonSerializer.Serialize(stream, value, value?.GetType() ?? typeof(object), JsonOptions); stream.Flush(true); } File.Move(path + ".tmp", path, true);
        }
        public async Task ConfigureAsync(NetBoxSettings settings, CancellationToken cancellationToken = default)
        {
            Validate(settings); await Enter(cancellationToken);
            try { settings = CloneSettings(settings); Save("netbox.json", settings); _settings = settings; }
            finally { _gate.Release(); }
        }
        string SettingsHash() => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(_settings, JsonOptions)));
        Uri Endpoint(string path) => new(new Uri(_settings.Url.TrimEnd('/') + "/"), path);
        string Marker(string kind, string id) => "DDI:" + _installation + ":" + kind + ":" + id;
        static bool Owned(string comments, string marker)
        {
            var owners = comments.Split('\n').Select(line => line.Trim()).Where(line => line.StartsWith("DDI:", StringComparison.Ordinal)).ToArray();
            return owners.Length == 1 && owners[0] == marker;
        }
        async Task<(JsonElement Json, string ETag)> Request(HttpMethod method, Uri uri, string fields, string etag, CancellationToken cancellationToken)
        {
            if (_authorization.Value is not null && !_authorization.Value()) throw new InvalidOperationException("NetBox authority or permission changed; review access and retry.");
            if (!_settings.Enabled) throw new InvalidOperationException("NetBox integration is disabled.");
            Uri root = Endpoint("api/");
            if (uri.Scheme != root.Scheme || uri.Authority != root.Authority || !uri.AbsolutePath.StartsWith(root.AbsolutePath, StringComparison.Ordinal)) throw new ArgumentException("NetBox pagination left the configured API origin.");
            string key = Environment.GetEnvironmentVariable(_settings.ApiKeyEnvironment);
            if (string.IsNullOrEmpty(key)) throw new InvalidOperationException("NetBox API key environment variable is missing.");
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue(_settings.TokenScheme, key);
            if (fields is not null) request.Content = new StringContent(fields, Encoding.UTF8, "application/json");
            if (etag is not null) request.Headers.TryAddWithoutValidation("If-Match", etag);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (_authorization.Value is not null && !_authorization.Value()) throw new InvalidOperationException("NetBox authority or permission changed during collection.");
            if ((int)response.StatusCode is >= 300 and < 400) throw new HttpRequestException("NetBox redirect refused.");
            if (!response.IsSuccessStatusCode) throw new HttpRequestException("NetBox returned HTTP " + (int)response.StatusCode); // no token or potentially sensitive response body
            using var source = await response.Content.ReadAsStreamAsync(cancellationToken); using MemoryStream bytes = new(); byte[] buffer = new byte[8192]; int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0) { if (bytes.Length + read > 8 * 1024 * 1024) throw new InvalidDataException("NetBox response exceeds 8 MiB."); bytes.Write(buffer, 0, read); }
            using var json = JsonDocument.Parse(bytes.Length == 0 && method == HttpMethod.Delete ? "{}"u8.ToArray() : bytes.ToArray()); return (json.RootElement.Clone(), response.Headers.ETag?.ToString());
        }
        async Task<JsonElement[]> List(string kind, CancellationToken cancellationToken)
        {
            List<JsonElement> results = []; Uri next = Endpoint("api/ipam/" + kind + "/?limit=200"); HashSet<string> visited = [];
            while (next is not null)
            {
                if (!visited.Add(next.AbsoluteUri) || visited.Count > 100) throw new InvalidDataException("NetBox pagination exceeded its bounds.");
                var page = (await Request(HttpMethod.Get, next, null, null, cancellationToken)).Json;
                if (!page.TryGetProperty("results", out var rows) || rows.ValueKind != JsonValueKind.Array || !page.TryGetProperty("next", out var value) || value.ValueKind is not JsonValueKind.Null and not JsonValueKind.String) throw new InvalidDataException("NetBox returned an incomplete page. No deletion or import was inferred.");
                results.AddRange(rows.EnumerateArray()); if (results.Count > 10000) throw new InvalidDataException("NetBox snapshot exceeds 10000 objects.");
                next = value.ValueKind == JsonValueKind.Null ? null : new Uri(next, value.GetString());
            }
            return results.ToArray();
        }
        static int? Vrf(JsonElement obj) => obj.GetProperty("vrf").ValueKind == JsonValueKind.Null ? null : obj.GetProperty("vrf").GetProperty("id").GetInt32();
        static string Text(JsonElement obj, string field) => obj.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : "";
        static bool MatchesFields(JsonElement remote, JsonElement fields)
        {
            foreach (var property in fields.EnumerateObject())
            {
                if (!remote.TryGetProperty(property.Name, out var current)) return false;
                if (property.Name is "vrf" or "vlan" or "tenant" or "scope_id" or "assigned_object_id") { if (Reference(current) != Reference(property.Value)) return false; }
                else if (property.Name == "status" && current.ValueKind == JsonValueKind.Object) { if (current.GetProperty("value").GetString() != property.Value.GetString()) return false; }
                else if (current.ToString() != property.Value.ToString()) return false;
            }
            return true;
        }
        public async Task<NetBoxPreview> PreviewAsync(IpamSnapshot inventory, CancellationToken cancellationToken = default, Func<bool> authorized = null, string[] deletionKeys = null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(60)); cancellationToken = deadline.Token;
            await Enter(cancellationToken);
            try
            {
                using var admission = await Admit(cancellationToken);
                _authorization.Value = authorized;
                string referenceHash = await ValidateReferences(inventory, cancellationToken);
                var prefixes = await List("prefixes", cancellationToken); var addresses = await List("ip-addresses", cancellationToken); List<NetBoxChange> changes = [];
                void Compare(string kind, string id, string natural, int? vrf, object data, JsonElement[] objects, string naturalField)
                {
                    string fields = MappedFields(kind, id, JsonSerializer.Serialize(data, JsonOptions)); var matches = objects.Where(o => (kind == "ip-addresses" ? IPAddress.Parse(Text(o, naturalField).Split('/')[0]).Equals(IPAddress.Parse(natural.Split('/')[0])) : Text(o, naturalField) == natural) && Vrf(o) == vrf).ToArray();
                    if (matches.Length > 1) { changes.Add(new(kind, id, "Conflict", null, "", fields, "Multiple NetBox objects have the same address/prefix and VRF")); return; }
                    if (matches.Length == 0) { changes.Add(new(kind, id, "Create", null, "", fields, "No matching object")); return; }
                    var remote = matches[0]; string marker = Marker(kind, id);
                    if (!Owned(Text(remote, "comments"), marker)) { changes.Add(new(kind, id, "Conflict", remote.GetProperty("id").GetInt32(), Text(remote, "last_updated"), fields, "Existing object is not owned by this DDI installation")); return; }
                    // Preserve operator notes when ownership was explicitly established during migration.
                    var desired = JsonNode.Parse(fields).AsObject();
                    desired["comments"] = Text(remote, "comments");
                    fields = desired.ToJsonString(JsonOptions);
                    using var parsed = JsonDocument.Parse(fields);
                    var before = parsed.RootElement.EnumerateObject().Where(p => remote.TryGetProperty(p.Name, out _)).ToDictionary(p => p.Name, p => remote.GetProperty(p.Name).Clone());
                    changes.Add(new(kind, id, MatchesFields(remote, parsed.RootElement) ? "Unchanged" : "Update", remote.GetProperty("id").GetInt32(), Text(remote, "last_updated"), fields, "DDI owns these mapped fields", JsonSerializer.Serialize(before, JsonOptions)));
                }
                foreach (var subnet in inventory.Subnets.Where(s => InScope(s, "prefixes")))
                {
                    var mapping = _settings.Mappings.SingleOrDefault(m => m.ViewId == subnet.ViewId); if (mapping is null) continue;
                    Compare("prefixes", subnet.Id, subnet.Prefix, mapping.VrfId, new { prefix = subnet.Prefix, vrf = mapping.VrfId, status = subnet.Container ? "container" : "active", description = subnet.Name, comments = Marker("prefixes", subnet.Id) }, prefixes, "prefix");
                }
                foreach (var assignment in inventory.Assignments)
                {
                    var subnet = inventory.Subnets.Single(s => s.Id == assignment.SubnetId); if (!InScope(subnet, "ip-addresses")) continue; var mapping = _settings.Mappings.SingleOrDefault(m => m.ViewId == subnet.ViewId); if (mapping is null) continue;
                    string address = assignment.Address + "/" + new IpamNetwork(subnet.Prefix).PrefixLength;
                    Compare("ip-addresses", assignment.Id, address, mapping.VrfId, new { address, vrf = mapping.VrfId, status = assignment.Status switch { "Reserved" => "reserved", "Deprecated" => "deprecated", _ => "active" }, dns_name = assignment.HostName ?? "", description = assignment.Description ?? "", comments = Marker("ip-addresses", assignment.Id) }, addresses, "address");
                }
                AppendDeletions(inventory, prefixes, addresses, changes, deletionKeys ?? []);
                cancellationToken.ThrowIfCancellationRequested();
                if (authorized is not null && !authorized()) throw new InvalidOperationException("NetBox review permission changed during collection.");
                var preview = new NetBoxPreview(Guid.NewGuid().ToString("N"), inventory.Revision, DateTime.UtcNow, SettingsHash(), changes.ToArray(), referenceHash); Save("netbox-preview.json", preview); return preview;
            }
            finally { _authorization.Value = null; _gate.Release(); }
        }
        public async Task<NetBoxResult> ApplyAsync(string previewId, long inventoryRevision, CancellationToken cancellationToken = default, Func<long> readRevision = null, Func<bool> authorized = null, Func<bool> deletionAuthorized = null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(60)); cancellationToken = deadline.Token;
            await Enter(cancellationToken); int applied = 0;
            try
            {
                using var admission = await Admit(cancellationToken);
                _authorization.Value = authorized;
                string resultPath = Path.Combine(_folder, "netbox-result.json");
                if (File.Exists(resultPath) && JsonSerializer.Deserialize<NetBoxResult>(File.ReadAllBytes(resultPath), JsonOptions)?.PreviewId == previewId) throw new InvalidOperationException("This preview was already submitted; generate a fresh preview to reconcile outcomes.");
                var preview = JsonSerializer.Deserialize<NetBoxPreview>(File.ReadAllBytes(Path.Combine(_folder, "netbox-preview.json")), JsonOptions);
                if (preview.Id != previewId || preview.InventoryRevision != inventoryRevision || preview.Created < DateTime.UtcNow.AddMinutes(-15) || preview.SettingsHash != SettingsHash() || preview.Changes.Any(c => c.Operation == "Conflict")) throw new InvalidOperationException("Preview is stale, conflicts, or does not match current intent/settings.");
                if (preview.Changes.Any(c => c.Operation == "Delete") && (deletionAuthorized is null || !deletionAuthorized())) throw new InvalidOperationException("Current deletion permission is required for this review.");
                if (await ValidateReferences(null, cancellationToken) != preview.ReferenceHash) throw new InvalidOperationException("A mapped NetBox reference changed after review. Prepare a new review.");
                Save("netbox-result.json", new NetBoxResult(previewId, 0, "Applying; interrupted outcomes require a new preview"));
                foreach (var change in preview.Changes.Where(c => c.Operation is "Create" or "Update" or "Delete"))
                {
                    if (readRevision is not null && readRevision() != inventoryRevision) throw new InvalidOperationException("DDI intent changed while applying; reconcile remaining objects with a new preview.");
                    string etag = null; var endpoint = Endpoint("api/ipam/" + change.Kind + "/");
                    if (change.Operation is "Update" or "Delete")
                    {
                        endpoint = new Uri(endpoint, change.RemoteId + "/"); var current = await Request(HttpMethod.Get, endpoint, null, null, cancellationToken);
                        if (Text(current.Json, "last_updated") != change.RemoteUpdated || !Owned(Text(current.Json, "comments"), Marker(change.Kind, change.LocalId))) throw new InvalidOperationException("NetBox object changed since preview.");
                        if (change.Operation == "Delete")
                        {
                            if (change.Before is null) throw new InvalidOperationException("Deletion review has no historical representation. Prepare a new review.");
                            using var reviewed = JsonDocument.Parse(change.Before);
                            if (Fingerprint(current.Json) != Fingerprint(reviewed.RootElement)) throw new InvalidOperationException("NetBox deletion scope or representation changed since review. Prepare a new review.");
                        }
                        etag = current.ETag ?? throw new InvalidOperationException("NetBox must support ETag conditional writes before updates are allowed.");
                    }
                    else
                    {
                        // Recheck natural identity immediately before create; uncertain HTTP outcomes are never blindly retried.
                        using var fields = JsonDocument.Parse(change.Fields); string naturalField = change.Kind == "prefixes" ? "prefix" : "address";
                        var current = await List(change.Kind, cancellationToken); var vrfValue = fields.RootElement.GetProperty("vrf"); int? vrf = vrfValue.ValueKind == JsonValueKind.Null ? null : vrfValue.GetInt32();
                        string natural = fields.RootElement.GetProperty(naturalField).GetString();
                        if (current.Any(o => (change.Kind == "ip-addresses" ? IPAddress.Parse(Text(o, naturalField).Split('/')[0]).Equals(IPAddress.Parse(natural.Split('/')[0])) : Text(o, naturalField) == natural) && Vrf(o) == vrf)) throw new InvalidOperationException("NetBox identity appeared since preview.");
                    }
                    if (await ValidateReferences(null, cancellationToken) != preview.ReferenceHash) throw new InvalidOperationException("A mapped NetBox reference changed before publication. Prepare a new review.");
                    if (authorized is not null && !authorized()) throw new InvalidOperationException("NetBox authority or permission changed.");
                    if (readRevision is not null && readRevision() != inventoryRevision) throw new InvalidOperationException("Local intent changed before the external write. Prepare a new review.");
                    if (change.Operation == "Delete" && !deletionAuthorized()) throw new InvalidOperationException("Deletion permission changed during publication.");
                    await Request(change.Operation == "Delete" ? HttpMethod.Delete : change.Operation == "Create" ? HttpMethod.Post : HttpMethod.Patch, endpoint, change.Operation == "Delete" ? null : change.Fields, etag, cancellationToken); applied++;
                    Save("netbox-result.json", new NetBoxResult(previewId, applied, "Applying"));
                }
                var result = new NetBoxResult(previewId, applied, "Completed"); Save("netbox-result.json", result); return result;
            }
            catch
            { if (applied > 0) Save("netbox-result.json", new NetBoxResult(previewId, applied, "Partial; reconcile with a new preview before continuing")); throw; }
            finally { _authorization.Value = null; _gate.Release(); }
        }
        public void Dispose() { CancelReconciliation(); WaitForReconciliationAsync().GetAwaiter().GetResult(); _http.Dispose(); _instanceLease.Dispose(); }
    }
}
