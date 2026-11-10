// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Ipam;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

static class NetBoxReconciliationChecks
{
    static readonly JsonSerializerOptions Json = NetBoxConnector.JsonOptions;
    static readonly BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    public sealed class NativeNetBox : IAsyncDisposable
    {
        public readonly Dictionary<string, List<JsonObject>> Objects = new() { ["prefixes"] = [], ["ip-addresses"] = [] };
        readonly WebApplication server;
        readonly X509Certificate2 certificate;
        public string Url => server.Urls.Single() + "/";
        public bool Slow, Fail, NoEtag, LostCreate, ForeignPagination, IncompletePage, LoopPages, Oversize;
        public string ControlFile;
        public int DelayMs;
        public int Gets, Writes, Deletes, WrongHeaders, InterfaceDevice = 10;
        public int ReferenceVersion = 1, VlanSite = 1, VlanTenant = 3;
        public string MissingReference = "";
        int version = 100;
        public TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        NativeNetBox(WebApplication server, X509Certificate2 certificate) { this.server = server; this.certificate = certificate; }
        public static async Task<NativeNetBox> Start()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(2));
            var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
            var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
            var server = builder.Build(); var fixture = new NativeNetBox(server, certificate);
            server.Run(fixture.Handle); await server.StartAsync(); return fixture;
        }
        public HttpClient Client()
            => PinnedClient(certificate);
        public byte[] Certificate() => certificate.Export(X509ContentType.Cert);
        public static HttpClient PinnedClient(X509Certificate2 certificate)
        {
            var handler = new HttpClientHandler { AllowAutoRedirect = false };
            handler.ServerCertificateCustomValidationCallback = (_, remote, _, errors) =>
            {
                if (remote is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(certificate); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(remote);
            };
            return new(handler) { Timeout = TimeSpan.FromSeconds(10) };
        }
        public JsonObject Add(string kind, string natural, int? vrf = null, string comments = "", string status = "active")
        {
            var obj = new JsonObject { ["id"] = ++version, [kind == "prefixes" ? "prefix" : "address"] = natural, ["vrf"] = vrf is null ? null : new JsonObject { ["id"] = vrf }, ["comments"] = comments, ["status"] = new JsonObject { ["value"] = status }, ["last_updated"] = "v" + version, ["description"] = "Remote fixture", ["dns_name"] = "fixture.example" };
            Objects[kind].Add(obj); return obj;
        }
        async Task Handle(HttpContext context)
        {
            if (ControlFile is not null && File.Exists(ControlFile))
            {
                string mode = File.ReadAllText(ControlFile).Trim();
                Slow = mode == "slow"; Fail = mode == "error"; InterfaceDevice = mode == "wrong-interface" ? 99 : 10;
            }
            if (context.Request.Headers.Authorization != "Bearer fixture-key") { WrongHeaders++; context.Response.StatusCode = 401; return; }
            Entered.TrySetResult();
            if (DelayMs > 0) await Task.Delay(DelayMs, context.RequestAborted);
            if (Slow) { try { await Task.Delay(TimeSpan.FromSeconds(30), context.RequestAborted); } catch (OperationCanceledException) { return; } }
            if (Fail) { context.Response.StatusCode = 503; return; }
            if (IncompletePage) { await context.Response.WriteAsync("{\"next\":null}"); return; }
            if (Oversize) { await context.Response.WriteAsync(new string(' ', 8 * 1024 * 1024 + 1)); return; }
            string[] path = context.Request.Path.Value.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string kind = path.Length > 2 ? path[2] : "";
            if (context.Request.Method == "GET")
            {
                Gets++;
                if (!Objects.TryGetValue(kind, out var objects))
                {
                    int id = int.Parse(path[3]);
                    if (kind == MissingReference) { context.Response.StatusCode = 404; return; }
                    var reference = new JsonObject { ["id"] = id, ["name"] = "Fixture reference", ["last_updated"] = "r" + ReferenceVersion };
                    if (kind == "interfaces") reference["device"] = new JsonObject { ["id"] = InterfaceDevice };
                    if (kind == "vlans") { reference["vid"] = 20; reference["site"] = new JsonObject { ["id"] = VlanSite }; reference["tenant"] = new JsonObject { ["id"] = VlanTenant }; }
                    if (kind == "devices") reference["tenant"] = new JsonObject { ["id"] = 3 };
                    await context.Response.WriteAsync(reference.ToJsonString()); return;
                }
                if (path.Length == 3) { await context.Response.WriteAsJsonAsync(new { count = objects.Count, next = ForeignPagination ? "https://foreign.invalid/api/ipam/prefixes/" : LoopPages ? context.Request.Path + context.Request.QueryString : null, results = objects }); return; }
                var current = objects.SingleOrDefault(o => (int)o["id"] == int.Parse(path[3]));
                if (current is null) { context.Response.StatusCode = 404; return; }
                if (!NoEtag) context.Response.Headers.ETag = "\"" + (string)current["last_updated"] + "\"";
                await context.Response.WriteAsync(current.ToJsonString()); return;
            }
            var list = Objects[kind]; JsonObject old = path.Length > 3 ? list.SingleOrDefault(o => (int)o["id"] == int.Parse(path[3])) : null;
            if (context.Request.Method is "PATCH" or "DELETE")
            {
                if (old is null) { context.Response.StatusCode = 404; return; }
                if (context.Request.Headers.IfMatch != "\"" + (string)old["last_updated"] + "\"") { context.Response.StatusCode = 412; return; }
            }
            if (context.Request.Method == "DELETE") { Writes++; Deletes++; list.Remove(old); context.Response.StatusCode = 204; return; }
            var fields = JsonNode.Parse(await new StreamReader(context.Request.Body).ReadToEndAsync()).AsObject();
            var result = old is null ? new JsonObject() : old.DeepClone().AsObject();
            foreach (var property in fields) result[property.Key] = property.Value?.DeepClone();
            foreach (string name in new[] { "vrf", "vlan", "tenant" }) if (result[name] is JsonValue) result[name] = new JsonObject { ["id"] = (int)result[name] };
            result["status"] = new JsonObject { ["value"] = (string)fields["status"] };
            result["id"] = old is null ? ++version : (int)old["id"]; result["last_updated"] = "v" + ++version;
            if (old is not null) list.Remove(old); list.Add(result); Writes++;
            if (LostCreate && context.Request.Method == "POST") { context.Abort(); return; }
            await context.Response.WriteAsync(result.ToJsonString());
        }
        public async ValueTask DisposeAsync() { await server.StopAsync(); await server.DisposeAsync(); certificate.Dispose(); }
    }
    public static async Task Run(bool serve = false)
    {
        string root = Path.Combine(Path.GetTempPath(), "teqtanium-netbox-local-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        int checks = 0;
        void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
        async Task Reject(Func<Task> action, string message)
        { try { await action(); } catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or HttpRequestException or OperationCanceledException or IOException or InvalidDataException) { Check(true, message); return; } throw new Exception(message); }
        Environment.SetEnvironmentVariable("DDI_NETBOX_FIXTURE_API_KEY", "fixture-key");
        await using var fixture = await NativeNetBox.Start();
        string folder = Path.Combine(root, "connector");
        using var connector = new NetBoxConnector(folder, fixture.Client());
        var inventory = new IpamManager(Path.Combine(root, "inventory.json"));
        var subnet = inventory.PutSubnet(0, "fixture", "", "default", "192.0.2.0/24", "Local lab", "East", 20, "", "");
        var address = inventory.PutAssignment(1, "fixture", "", subnet.Id, "192.0.2.9", "local.example", "Local owner", "Assigned", "Local intent");
        var settings = new NetBoxSettings(true, fixture.Url, "DDI_NETBOX_FIXTURE_API_KEY", "Bearer", [new("default", null)], new(["prefixes", "ip-addresses"], [], [new(subnet.Id, 1, 2, 3)], [new(address.Id, 10, 11, 3)]));
        try
        {
            await connector.ConfigureAsync(settings);
            var preview = await connector.PreviewAsync(inventory.Snapshot());
            Check(fixture.Writes == 0 && preview.Changes.Length == 2, "native TLS preview is read-only and scoped");
            var prefixFields = JsonNode.Parse(preview.Changes.Single(c => c.Kind == "prefixes").Fields);
            var addressFields = JsonNode.Parse(preview.Changes.Single(c => c.Kind == "ip-addresses").Fields);
            Check((string)prefixFields["scope_type"] == "dcim.site" && (int)prefixFields["scope_id"] == 1 && (int)prefixFields["vlan"] == 2 && (int)prefixFields["tenant"] == 3, "explicit site VLAN tenant mapping uses native prefix semantics");
            Check((string)addressFields["assigned_object_type"] == "dcim.interface" && (int)addressFields["assigned_object_id"] == 11, "explicit DCIM device-interface link maps address assignment");
            fixture.InterfaceDevice = 99;
            await Reject(() => connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision), "interface moved to another device is refused at effect");
            Check(fixture.Writes == 0, "reference drift refusal has no mutation"); fixture.InterfaceDevice = 10;
            fixture.ReferenceVersion++;
            await Reject(() => connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision), "mapped reference revision drift invalidates publication review");
            fixture.MissingReference = "sites";
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "removed or inaccessible site reference blocks review"); fixture.MissingReference = "";
            fixture.VlanSite = 2;
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "cross-site VLAN relationship is refused"); fixture.VlanSite = 1;
            fixture.VlanTenant = 4;
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "cross-tenant VLAN relationship is refused"); fixture.VlanTenant = 3;
            preview = await connector.PreviewAsync(inventory.Snapshot());
            Check((await connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision)).Applied == 2, "native TLS publication creates reviewed mapped objects");
            Check((await connector.PreviewAsync(inventory.Snapshot())).Changes.All(c => c.Operation == "Unchanged"), "native nested references reconcile without perpetual updates");
            await connector.ConfigureAsync(settings with { Policy = settings.Policy with { Subnets = [new(subnet.Id, 1, null, null)] } });
            var partialMapping = await connector.PreviewAsync(inventory.Snapshot());
            using (var partialFields = JsonDocument.Parse(partialMapping.Changes.Single(c => c.Kind == "prefixes").Fields)) Check(!partialFields.RootElement.TryGetProperty("vlan", out _) && !partialFields.RootElement.TryGetProperty("tenant", out _), "blank reference mappings preserve existing unselected NetBox relationships");
            await connector.ConfigureAsync(settings);
            var defensive = connector.Settings; defensive.Policy.Types[0] = "bad";
            Check(connector.Settings.Policy.Types[0] == "prefixes", "settings policy arrays are defensive copies");
            await Reject(() => connector.ConfigureAsync(settings with { Policy = settings.Policy with { Types = ["devices"] } }), "unsupported automatic DCIM creation type refused");
            await connector.ConfigureAsync(settings with { Policy = new(["prefixes"], [subnet.Id], [], []) });
            Check((await connector.PreviewAsync(inventory.Snapshot())).Changes.All(c => c.Kind == "prefixes"), "explicit object type limits publication");
            await connector.ConfigureAsync(settings with { Policy = new([], [], [], []) });
            Check((await connector.PreviewAsync(inventory.Snapshot())).Changes.Length == 0, "empty type selection produces empty review");
            await connector.ConfigureAsync(settings with { Policy = null });
            inventory.Delete(inventory.Snapshot().Revision, "fixture", "assignment", address.Id);
            preview = await connector.PreviewAsync(inventory.Snapshot());
            var deletion = preview.Changes.Single(c => c.Operation == "ReviewDeletion"); string key = deletion.Kind + ":" + deletion.RemoteId;
            Check(fixture.Deletes == 0 && deletion.LocalId == address.Id, "local tombstone proposes review without implicit deletion");
            await connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision);
            Check(fixture.Deletes == 0 && fixture.Objects["ip-addresses"].Count == 1, "ordinary apply preserves unapproved managed deletion");
            var remoteAddress = fixture.Objects["ip-addresses"].Single(); string marker = (string)remoteAddress["comments"];
            remoteAddress["comments"] = "foreign";
            await Reject(() => connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]), "foreign object cannot be selected for deletion"); remoteAddress["comments"] = marker;
            await connector.ConfigureAsync(settings with { Policy = new(["prefixes"], [], [], []) });
            await Reject(() => connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]), "deletion type scope is enforced");
            await connector.ConfigureAsync(settings with { Policy = null, Mappings = [new("default", 55)] });
            await Reject(() => connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]), "deletion current VRF mapping is enforced");
            await connector.ConfigureAsync(settings with { Policy = null });
            preview = await connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]);
            await Reject(() => connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision), "selected deletion requires current delete permission");
            remoteAddress["last_updated"] = "external-drift";
            await Reject(() => connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision, deletionAuthorized: () => true), "remote deletion drift preserves changed object");
            preview = await connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]); fixture.NoEtag = true;
            await Reject(() => connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision, deletionAuthorized: () => true), "deletion fails closed without conditional write support"); fixture.NoEtag = false;
            preview = await connector.PreviewAsync(inventory.Snapshot(), deletionKeys: [key]);
            Check((await connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision, deletionAuthorized: () => true)).Applied == 1 && fixture.Deletes == 1, "explicit proven deletion uses native conditional DELETE and accepts HTTP204");
            var orphan = fixture.Add("ip-addresses", "192.0.2.44/24", comments: marker.Replace(address.Id, "absent-without-tombstone"));
            Check(!(await connector.PreviewAsync(inventory.Snapshot())).Changes.Any(c => c.RemoteId == (int)orphan["id"]), "owned absence without explicit local tombstone is preserved");
            fixture.Objects["ip-addresses"].Remove(orphan);
            var external = fixture.Add("ip-addresses", "192.0.2.22/24");
            var dynamic = fixture.Add("ip-addresses", "192.0.2.23/24", status: "dhcp");
            var import = await connector.PreviewImportAsync(inventory.Snapshot());
            Check(import.Changes.Single(c => c.RemoteId == (int)dynamic["id"]).Operation == "Preserve", "remote DHCP observation is not static import intent");
            Check(import.Changes.Single(c => c.Kind == "prefixes").Operation == "Preserve", "existing local prefix remains authoritative on reverse review");
            string importKey = import.Changes.Single(c => c.RemoteId == (int)external["id"]).Key; int before = fixture.Writes;
            await Reject(() => connector.ApplyImportAsync(import.Id, [importKey], inventory, "fixture", authorized: () => false), "revoked import permission blocks local changes");
            Check(inventory.Snapshot().Assignments.Length == 0, "revoked reverse import leaves inventory untouched");
            external["description"] = "changed";
            await Reject(() => connector.ApplyImportAsync(import.Id, [importKey], inventory, "fixture"), "remote reverse proposal drift is refused");
            import = await connector.PreviewImportAsync(inventory.Snapshot());
            inventory.PutAssignment(inventory.Snapshot().Revision, "fixture", "", subnet.Id, "192.0.2.99", "existing.example", "owner", "Assigned", "");
            await Reject(() => connector.ApplyImportAsync(import.Id, [importKey], inventory, "fixture"), "local revision drift invalidates reverse approval");
            import = await connector.PreviewImportAsync(inventory.Snapshot());
            Check(await connector.ApplyImportAsync(import.Id, [importKey], inventory, "fixture", authorized: () => true) == 1, "individually selected missing static intent imported atomically");
            Check(inventory.Snapshot().Assignments.Length == 2 && fixture.Writes == before && inventory.Snapshot().Subnets.Single().DhcpScope == "", "reverse import has no remote writes or service provisioning");
            await Reject(() => connector.ApplyImportAsync(import.Id, [importKey], inventory, "fixture"), "reverse approval cannot replay after successful inventory change");
            Check((await connector.PreviewImportAsync(inventory.Snapshot())).Changes.Single(c => c.Key == importKey).Operation == "Preserve", "imported local intent is authoritative on later reviews");
            Check(inventory.Snapshot().NetBoxImports.Single().Objects.Single().RemoteId == (int)external["id"] && inventory.Snapshot().NetBoxImports.Single().Revision == inventory.Snapshot().Revision, "selected remote identity and consumption receipt commit atomically with local intent");
            var duplicate = fixture.Add("ip-addresses", "192.0.2.22/24");
            var duplicateReview = await connector.PreviewImportAsync(inventory.Snapshot());
            Check(duplicateReview.Changes.Where(c => c.Natural == "192.0.2.22").All(c => c.Operation == "Preserve"), "duplicate remote natural identities remain unselectable"); fixture.Objects["ip-addresses"].Remove(duplicate);
            var mask = fixture.Add("ip-addresses", "192.0.2.33/32");
            Check((await connector.PreviewImportAsync(inventory.Snapshot())).Changes.Single(c => c.RemoteId == (int)mask["id"]).Operation == "Preserve", "remote address masks are not silently flattened into local subnet semantics"); fixture.Objects["ip-addresses"].Remove(mask);
            var ipv6 = inventory.PutSubnet(inventory.Snapshot().Revision, "fixture", "", "default", "2001:db8::/64", "IPv6", "", null, "", "");
            var remote6 = fixture.Add("ip-addresses", "2001:db8::9/64");
            var review6 = await connector.PreviewImportAsync(inventory.Snapshot());
            Check(await connector.ApplyImportAsync(review6.Id, ["ip-addresses:" + (int)remote6["id"]], inventory, "fixture") == 1 && inventory.Snapshot().Assignments.Any(a => a.Address == "2001:db8::9"), "selected IPv6 manual intent preserves canonical address and mask scope");
            int assignmentCount = inventory.Snapshot().Assignments.Length;
            var valid = new NetBoxImportChange("ip-addresses:5000", "ip-addresses", 5000, "default", subnet.Id, "192.0.2.66", "valid.example", "active", "", "v1", "f", "Propose", "test");
            await Reject(() => { inventory.ImportNetBox(inventory.Snapshot().Revision, "fixture", [valid, valid with { Key = "invalid", Natural = "192.0.2.0" }]); return Task.CompletedTask; }, "mixed invalid reverse batch fails atomically");
            Check(inventory.Snapshot().Assignments.Length == assignmentCount && !inventory.Snapshot().Assignments.Any(a => a.Address == "192.0.2.66"), "failed mixed batch adds no unselected or partial local intent");
            var newPrefix = fixture.Add("prefixes", "198.51.100.0/24");
            import = await connector.PreviewImportAsync(inventory.Snapshot());
            Check(await connector.ApplyImportAsync(import.Id, ["prefixes:" + (int)newPrefix["id"]], inventory, "fixture") == 1, "selected missing prefix imports into explicitly mapped view");
            Check(new IpamManager(Path.Combine(root, "inventory.json")).Snapshot().Subnets.Length == 3, "selected reverse intent persists across inventory restart");
            await connector.ConfigureScheduleAsync(new(true, 30, "Review", "fixture"));
            await Reject(() => connector.ConfigureScheduleAsync(new(true, 30, "Publish", "fixture")), "unreviewed scheduled publication is not selectable");
            fixture.Slow = true; fixture.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Check(connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow), "authorized schedule starts a bounded native TLS collection");
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Check(!connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow, true), "overlapping schedule is not queued");
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "manual preview cannot overlap active scheduled operation");
            using (var other = new NetBoxConnector(Path.Combine(root, "second-target-owner"), fixture.Client()))
            {
                await other.ConfigureAsync(settings with { Url = fixture.Url + "alternate-base/", Policy = null });
                await Reject(() => other.PreviewAsync(inventory.Snapshot()), "second connector cannot overlap same target");
            }
            await Reject(() => connector.ConfigureAsync(settings), "settings cannot change while scheduled I/O is admitted");
            Check(connector.CancelReconciliation(), "active schedule cancellation acknowledged"); await connector.WaitForReconciliationAsync(); fixture.Slow = false;
            Check(connector.Run.Status == "Cancelled", "cancelled schedule has durable terminal outcome");
            await Reject(() => { using var duplicate = new NetBoxConnector(folder, fixture.Client()); return Task.CompletedTask; }, "second active service for the same configuration is refused");
            string CopyRestart(string name)
            {
                string copy = Path.Combine(root, name); Directory.CreateDirectory(copy);
                foreach (string path in Directory.GetFiles(folder).Where(p => !p.EndsWith(".lock"))) File.Copy(path, Path.Combine(copy, Path.GetFileName(path)));
                return copy;
            }
            using (var reopened = new NetBoxConnector(CopyRestart("terminal-restart"), fixture.Client())) Check(reopened.Run.Status == "Cancelled", "terminal schedule snapshot survives reopen without replay");
            await connector.ConfigureScheduleAsync(new(true, 30, "Review", "fixture"));
            Check(!connector.TryStartReconciliation(inventory.Snapshot, _ => false, DateTime.UtcNow) && connector.Run.Status == "Blocked", "revoked schedule actor never performs collection");
            await connector.ConfigureScheduleAsync(new(true, 30, "Review", "fixture")); int writesBeforeSchedule = fixture.Writes;
            Check(connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow), "fresh authorized review can resume schedule"); await connector.WaitForReconciliationAsync();
            Check(connector.Run.Status == "ReviewRequired" && fixture.Writes == writesBeforeSchedule, "scheduled conflicts require review and never publish");
            Check(!connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddHours(1)), "review-required schedule remains stopped until explicit resave");
            string interruptedFolder = CopyRestart("interrupted-restart");
            File.WriteAllBytes(Path.Combine(interruptedFolder, "netbox-run.json"), JsonSerializer.SerializeToUtf8Bytes(connector.Run with { Status = "Running" }, Json));
            using (var restarted = new NetBoxConnector(interruptedFolder, fixture.Client()))
            {
                Check(restarted.Run.Status == "Interrupted", "restart retires persisted running marker");
                Check(!restarted.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddDays(1)), "restart never replays interrupted work");
            }
            await connector.ConfigureScheduleAsync(new(true, 1, "Review", "fixture")); fixture.Fail = true;
            for (int n = 0; n < 3; n++) { Check(connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddMinutes(n + 1)), "bounded retry " + (n + 1) + " starts"); await connector.WaitForReconciliationAsync(); }
            Check(connector.Run.Failures == 3 && connector.Run.Status == "ReviewRequired" && !connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddHours(1)), "three failed reads suspend automatic retry"); fixture.Fail = false;
            await connector.ConfigureScheduleAsync(new(false, 30, "Review", "fixture"));
            Check(!connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddDays(1)), "disabled schedule stays inactive");
            await connector.ConfigureScheduleAsync(new(true, 30, "Review", "fixture"));
            fixture.Slow = true; fixture.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Check(connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow), "storage-failure scenario admits real review");
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); int readsBeforeRecovery = fixture.Gets;
            using (var writeLock = new FileStream(Path.Combine(folder, "netbox-run.json"), FileMode.Open, FileAccess.Read, FileShare.None))
            {
                connector.CancelReconciliation(); await connector.WaitForReconciliationAsync();
                Check(connector.PendingOutcome && connector.Run.Status == "SavingOutcome", "failed terminal journal save remains visibly pending after collection ends");
                Check(!connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddDays(1)), "pending terminal outcome prevents new scheduled reads");
                Check(!connector.RetryPendingOutcome() && connector.PendingOutcome, "storage-only retry retains unsaved outcome while lock persists");
                await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "manual work cannot overwrite pending journal outcome");
            }
            Check(connector.RetryPendingOutcome() && connector.Run.Status == "Cancelled" && fixture.Gets == readsBeforeRecovery, "storage recovery persists same cancelled outcome without replaying network reads"); fixture.Slow = false;
            bool permit = true; fixture.DelayMs = 200; fixture.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            var delayed = connector.PreviewImportAsync(inventory.Snapshot(), authorized: () => permit);
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); permit = false;
            await Reject(async () => await delayed, "revocation during TLS response suppresses reverse review disclosure"); fixture.DelayMs = 0;
            using (var ready = new NetBoxConnector(Path.Combine(root, "ready-schedule"), fixture.Client()))
            {
                await ready.ConfigureAsync(settings with { Mappings = [new("default", 909)], Policy = new(["prefixes"], [], [], []) });
                await ready.ConfigureScheduleAsync(new(true, 30, "Review", "fixture")); int beforeReady = fixture.Writes;
                Check(ready.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow), "conflict-free scheduled read starts"); await ready.WaitForReconciliationAsync();
                Check(ready.Run.Status == "Ready" && ready.Run.InventoryRevision == inventory.Snapshot().Revision && ready.Run.SettingsHash.Length == 64 && fixture.Writes == beforeReady, "ready journal binds exact local revision and settings without any publication");
                Check(!ready.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow.AddMinutes(1)), "schedule respects next due instant without catch-up flooding");
                await ready.ConfigureScheduleAsync(new(true, 30, "Review", "fixture", 1)); fixture.Slow = true;
                Check(ready.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow), "explicit one-second deadline starts real bounded review"); await ready.WaitForReconciliationAsync(); fixture.Slow = false;
                Check(ready.Run.Status == "Cancelled" && fixture.Writes == beforeReady, "deadline terminates native read and persists cancellation without publication");
                var stale = await ready.PreviewAsync(inventory.Snapshot()); await ready.ConfigureAsync(settings with { Policy = null });
                await Reject(() => ready.ApplyAsync(stale.Id, inventory.Snapshot().Revision), "changed target scope invalidates cached publication review");
            }
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel(); int beforeCancel = fixture.Gets;
                await Reject(() => connector.PreviewAsync(inventory.Snapshot(), cancelled.Token), "cancellation before dispatch performs no I/O");
                Check(fixture.Gets == beforeCancel, "pre-dispatch cancellation preserves remote read count");
            }
            fixture.IncompletePage = true;
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "incomplete remote page cannot manufacture deletions"); fixture.IncompletePage = false;
            fixture.LoopPages = true;
            await Reject(() => connector.PreviewImportAsync(inventory.Snapshot()), "cyclic pagination is bounded without import"); fixture.LoopPages = false;
            fixture.Oversize = true;
            await Reject(() => connector.PreviewAsync(inventory.Snapshot()), "oversized native response is stopped at eight MiB"); fixture.Oversize = false;
            using (var uncertain = new NetBoxConnector(Path.Combine(root, "uncertain-write"), fixture.Client()))
            {
                await uncertain.ConfigureAsync(settings with { Mappings = [new("default", 777)], Policy = new(["prefixes"], [], [], []) });
                var uncertainPreview = await uncertain.PreviewAsync(inventory.Snapshot()); fixture.LostCreate = true;
                await Reject(() => uncertain.ApplyAsync(uncertainPreview.Id, inventory.Snapshot().Revision), "native lost response surfaces an uncertain submitted create"); fixture.LostCreate = false;
                int writesAfterLoss = fixture.Writes;
                await Reject(() => uncertain.ApplyAsync(uncertainPreview.Id, inventory.Snapshot().Revision), "uncertain native create cannot replay cached review");
                var reconciled = await uncertain.PreviewAsync(inventory.Snapshot());
                Check(reconciled.Changes.Any(c => c.Operation == "Unchanged") && fixture.Writes == writesAfterLoss, "fresh native review reconciles acknowledged remote state without duplicate write");
            }
            fixture.ForeignPagination = true;
            await Reject(() => connector.PreviewImportAsync(inventory.Snapshot()), "reverse pagination cannot leave configured API origin"); fixture.ForeignPagination = false;
            Check(fixture.WrongHeaders == 0 && fixture.Gets > 20, "native requests use intended fixture authentication over pinned TLS");
            await Api(root, fixture, Check, serve);
            if (!serve) await ProcessRestart(root, fixture, inventory, Check, Reject);
            Console.WriteLine($"PASS: {checks} NetBox reconciliation native TLS/model/API checks. Local fixture only; not independent acceptance.");
        }
        finally
        {
            connector.Dispose();
            Environment.SetEnvironmentVariable("DDI_NETBOX_FIXTURE_API_KEY", null);
            if (!serve && Path.GetDirectoryName(root) == Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) Directory.Delete(root, true);
        }
    }
    public static async Task CrashFixture(string folder, string url, string phase)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(folder, "fixture.cer"));
        using var connector = new NetBoxConnector(folder, NativeNetBox.PinnedClient(certificate));
        var inventory = new IpamManager(Path.Combine(folder, "inventory.json"));
        if (inventory.Snapshot().Subnets.Length == 0) inventory.PutSubnet(0, "child-fixture", "", "default", "198.18.0.0/24", "Child fixture", "", null, "", "");
        await connector.ConfigureAsync(new(true, url, "DDI_NETBOX_FIXTURE_API_KEY", "Bearer", [new("default", 5001)], new(["prefixes"], [], [], [])));
        if (phase == "review")
        { await connector.ConfigureScheduleAsync(new(true, 30, "Review", "child-fixture")); connector.TryStartReconciliation(inventory.Snapshot, _ => true, DateTime.UtcNow); }
        else
        {
            var preview = await connector.PreviewAsync(inventory.Snapshot());
            try { await connector.ApplyAsync(preview.Id, inventory.Snapshot().Revision); } catch (HttpRequestException) { }
            File.WriteAllText(Path.Combine(folder, "effect-ended.txt"), "Remote response lost; outcome requires reconciliation.");
        }
        await Task.Delay(Timeout.InfiniteTimeSpan);
    }
    static async Task ProcessRestart(string root, NativeNetBox fixture, IpamManager ignored, Action<bool,string> check, Func<Func<Task>,string,Task> reject)
    {
        async Task<System.Diagnostics.Process> Start(string folder, string phase)
        {
            Directory.CreateDirectory(folder); await File.WriteAllBytesAsync(Path.Combine(folder, "fixture.cer"), fixture.Certificate());
            var start = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            // The runner is invoked with dotnet; arguments use ArgumentList, never shell interpolation.
            start.ArgumentList.Add(typeof(NetBoxReconciliationChecks).Assembly.Location); start.ArgumentList.Add("--netbox-crash"); start.ArgumentList.Add(folder); start.ArgumentList.Add(fixture.Url); start.ArgumentList.Add(phase);
            return System.Diagnostics.Process.Start(start);
        }
        string readingFolder = Path.Combine(root, "actual-read-crash"); fixture.Slow = true; fixture.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var child = await Start(readingFolder, "review"))
        {
            try
            {
                await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10)); check(!child.HasExited, "separate native process is alive during real scheduled TLS I/O");
                using var sameTarget = new NetBoxConnector(Path.Combine(root, "cross-process-target"), fixture.Client());
                await sameTarget.ConfigureAsync(new(true, fixture.Url + "another-base/", "DDI_NETBOX_FIXTURE_API_KEY", "Bearer", [new("default", null)]));
                await reject(() => sameTarget.PreviewAsync(ignored.Snapshot()), "different configuration and process cannot overlap the same canonical target origin");
            }
            finally { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); fixture.Slow = false; }
        }
        int reads = fixture.Gets;
        using (var restarted = new NetBoxConnector(readingFolder, fixture.Client()))
        {
            check(restarted.Run.Status == "Interrupted" && !restarted.TryStartReconciliation(() => new IpamManager(Path.Combine(readingFolder, "inventory.json")).Snapshot(), _ => true, DateTime.UtcNow.AddDays(1)), "actual killed-process restart retires running review without replay");
            check(fixture.Gets == reads, "actual restart performs no remote read until explicit resumption");
        }
        string effectFolder = Path.Combine(root, "actual-effect-crash"); fixture.LostCreate = true; int writes = fixture.Writes;
        using (var child = await Start(effectFolder, "apply"))
        {
            try
            {
                for (int n = 0; n < 1000 && !File.Exists(Path.Combine(effectFolder, "effect-ended.txt")) && !child.HasExited; n++) await Task.Delay(10);
                check(File.Exists(Path.Combine(effectFolder, "effect-ended.txt")) && fixture.Writes == writes + 1, "separate process persists submission marker before native lost create response");
            }
            finally { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); fixture.LostCreate = false; }
        }
        using (var restarted = new NetBoxConnector(effectFolder, fixture.Client()))
        {
            var inventory = new IpamManager(Path.Combine(effectFolder, "inventory.json")); var result = restarted.PublicationResult;
            check(result.Status.StartsWith("Applying") && result.Applied == 0, "actual effect-crash restart retains unknown submitted outcome rather than reporting success");
            await reject(() => restarted.ApplyAsync(result.PreviewId, inventory.Snapshot().Revision), "actual effect-crash cached publication cannot replay");
            var review = await restarted.PreviewAsync(inventory.Snapshot());
            check(review.Changes.Single().Operation == "Unchanged" && fixture.Writes == writes + 1, "fresh restart review recognizes the one remote effect without duplicate creation");
        }
    }
    static async Task Api(string root, NativeNetBox fixture, Action<bool, string> check, bool serve)
    {
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        string folder = Path.Combine(root, "service"); Directory.CreateDirectory(folder);
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        string password = Guid.NewGuid().ToString("N") + "Aa9!";
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", port.ToString());
        string www = serve ? Environment.GetEnvironmentVariable("DDI_IPAM_UI_FIXTURE_WWW") : null;
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", www ?? Path.Combine(repository, "DnsServerCore/www"));
        using var dnsPortReservation = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0); dnsPortReservation.Start(); int dnsPort = ((IPEndPoint)dnsPortReservation.LocalEndpoint).Port; dnsPortReservation.Stop();
        await using (var log = new LogManager(true, folder))
        using (var dns = new DnsServer(folder, Path.Combine(repository, "DnsServerCore/dohwww"), log))
        { dns.LoadConfigFile(); dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
        var service = new DnsWebService(true, folder);
        var old = (NetBoxConnector)typeof(DnsWebService).GetField("_netbox", Private).GetValue(service);
        using var connector = new NetBoxConnector(Path.Combine(root, "api-connector"), fixture.Client());
        typeof(DnsWebService).GetField("_netbox", Private).SetValue(service, connector);
        using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + port), Timeout = TimeSpan.FromSeconds(20) };
        async Task<JsonElement> Call(HttpClient c, string path, params (string Key, string Value)[] values)
        {
            using var body = new FormUrlEncodedContent(values.Select(v => new KeyValuePair<string,string>(v.Key, v.Value)));
            using var result = await c.PostAsync("/api/" + path, body); using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync()); return json.RootElement.Clone();
        }
        bool Ok(JsonElement value) => value.GetProperty("status").GetString() == "ok";
        try
        {
            // Native service uses disposable loopback HTTP and DNS ports with default DHCP disabled.
            await service.StartAsync(true);
            var login = await Call(client, "user/login", ("user", "admin"), ("pass", password)); check(Ok(login), "original disposable administrator authenticates");
            client.DefaultRequestHeaders.Authorization = new("Bearer", login.GetProperty("token").GetString());
            check(Ok(await Call(client, "ipam/netbox/settings/get")), "administrator reads current NetBox controls");
            var manager = (IpamManager)typeof(DnsWebService).GetField("_ipam", Private).GetValue(service);
            var subnet = manager.PutSubnet(manager.Snapshot().Revision, "fixture", "", "default", "203.0.113.0/24", "API lab", "", null, "", "");
            var settings = new NetBoxSettings(true, fixture.Url, "DDI_NETBOX_FIXTURE_API_KEY", "Bearer", [new("default", 90)], new(["prefixes", "ip-addresses"], [subnet.Id], [], []));
            check(Ok(await Call(client, "ipam/netbox/settings/set", ("settings", JsonSerializer.Serialize(settings, Json)))), "API saves explicit bounded local-authority scope");
            var auth = (AuthManager)typeof(DnsWebService).GetField("_authManager", Private).GetValue(service);
            var actor = auth.CreateUser("NetBox fixture operator", "netbox-operator", password);
            var full = PermissionFlag.View | PermissionFlag.Modify;
            auth.SetPermission(PermissionSection.Settings, actor, full); auth.SetPermission(PermissionSection.Administration, actor, full); auth.SaveConfigFile(true);
            using var operatorClient = new HttpClient { BaseAddress = client.BaseAddress, Timeout = TimeSpan.FromSeconds(20) };
            var operatorLogin = await Call(operatorClient, "user/login", ("user", actor.Username), ("pass", password)); check(Ok(operatorLogin), "fresh operator session authenticates after fixture grants");
            operatorClient.DefaultRequestHeaders.Authorization = new("Bearer", operatorLogin.GetProperty("token").GetString());
            check(Ok(await Call(operatorClient, "ipam/netbox/preview")), "fresh operator proves required modify privilege on native review");
            check(!Ok(await Call(operatorClient, "ipam/netbox/deletions/preview", ("keys", "prefixes:1"))), "modify-only actor cannot access deletion review");
            check(Ok(await Call(operatorClient, "ipam/netbox/schedule/set", ("schedule", JsonSerializer.Serialize(new NetBoxSchedule(true, 30, "Review", "admin"), Json)))), "operator configures preview-only schedule");
            check(connector.Schedule.Actor == actor.Username, "schedule owner is server-bound actor, not client-supplied administrator");
            var apiRemote = fixture.Add("ip-addresses", "203.0.113.33/24", 90);
            var apiReview = await Call(operatorClient, "ipam/netbox/import/preview");
            check(Ok(apiReview), "authorized operator prepares actual native API reverse review");
            string apiPreviewId = apiReview.GetProperty("response").GetProperty("preview").GetProperty("id").GetString();
            check(Ok(await Call(operatorClient, "ipam/netbox/import/apply", ("previewId", apiPreviewId), ("keys", "ip-addresses:" + (int)apiRemote["id"]))), "authorized operator applies individually selected native API proposal");
            check(manager.Snapshot().NetBoxImports.Length == 1, "native API import has durable local consumption receipt");
            auth.SetPermission(PermissionSection.Settings, actor, PermissionFlag.View); auth.SaveConfigFile(true);
            foreach (string path in new[] { "settings/get", "preview", "preview/get", "deletions/preview", "import/preview", "import/apply", "schedule/set", "schedule/run", "schedule/cancel", "apply" })
                check(!Ok(await Call(operatorClient, "ipam/netbox/" + path)), "current revoked permission denied at " + path);
            var publicInventory = (await Call(operatorClient, "ipam/list")).GetProperty("response").GetProperty("inventory");
            check(publicInventory.GetProperty("netBoxImports").ValueKind == JsonValueKind.Null && !publicInventory.GetProperty("changes").EnumerateArray().Any(c => c.GetProperty("operation").GetString().StartsWith("netbox.import:")), "ordinary IPAM readers cannot retrieve private NetBox review receipts or hidden import IDs");
            check(!connector.TryStartReconciliation(manager.Snapshot, a => auth.IsPermitted(PermissionSection.Settings, auth.GetUser(a), PermissionFlag.Modify), DateTime.UtcNow), "scheduler rechecks persisted actor rights after revocation");
            using var fresh = new HttpClient { BaseAddress = client.BaseAddress };
            var freshLogin = await Call(fresh, "user/login", ("user", "admin"), ("pass", password)); check(Ok(freshLogin), "separate fresh administrator login succeeds while original remains open");
            fresh.DefaultRequestHeaders.Authorization = new("Bearer", freshLogin.GetProperty("token").GetString());
            check(Ok(await Call(fresh, "ipam/netbox/settings/set", ("settings", JsonSerializer.Serialize(settings, Json)))), "fresh administrator demonstrates real configuration privilege");
            check(Ok(await Call(client, "ipam/netbox/settings/get")), "original administrator remains usable after fixture-only grant changes");
            check(auth.GetSession(freshLogin.GetProperty("token").GetString()).LastSeenRemoteAddress.Equals(IPAddress.Loopback), "target session records the fresh authorized source as 127.0.0.1");
            var cluster = typeof(DnsWebService).GetField("_clusterManager", Private).GetValue(service);
            var nodesField = cluster.GetType().GetField("_clusterNodes", Private); var originalNodes = nodesField.GetValue(cluster);
            var nodeType = cluster.GetType().Assembly.GetType("DnsServerCore.Cluster.ClusterNode");
            var nodeConstructor = nodeType.GetConstructors().Single(c => c.GetParameters().Length == 6); var nodeArgs = nodeConstructor.GetParameters();
            object MakeNodes(string role)
            {
                var node = nodeConstructor.Invoke([cluster, 1, new Uri("https://127.0.0.1:65530/"), new IPAddress[] { IPAddress.Loopback }, Enum.Parse(nodeArgs[4].ParameterType, role), Enum.Parse(nodeArgs[5].ParameterType, "Self")]);
                var dictionary = Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(typeof(int), nodeType)); dictionary.GetType().GetMethod("Add").Invoke(dictionary, [1, node]); return dictionary;
            }
            try
            {
                fixture.DelayMs = 250; fixture.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
                var pendingRoleChange = Call(client, "ipam/netbox/preview"); await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); nodesField.SetValue(cluster, MakeNodes("Secondary"));
                var refused = await pendingRoleChange;
                check(!Ok(refused) && !refused.TryGetProperty("response", out _), "primary-to-secondary transition during native I/O suppresses review response");
                check(!Ok(await Call(client, "ipam/netbox/settings/get")), "secondary cannot load cached NetBox controls");
            }
            finally { fixture.DelayMs = 0; nodesField.SetValue(cluster, originalNodes); }
            check(Ok(await Call(client, "ipam/netbox/settings/get")), "original administrator regains standalone scope after fixture role restoration");
            if (serve)
            {
                await connector.ConfigureScheduleAsync(new(false, 30, "Review", "admin"));
                fixture.Add("ip-addresses", "203.0.113.22/24", 90);
                fixture.ControlFile = Path.Combine(root, "ui-mode.txt"); File.WriteAllText(fixture.ControlFile, "normal");
                string publicCertificate = Path.Combine(root, "ui-fixture.cer"); await File.WriteAllBytesAsync(publicCertificate, fixture.Certificate());
                string sessionFile = Path.Combine(Path.GetDirectoryName(repository.TrimEnd(Path.DirectorySeparatorChar)), "ui-session-private.json");
                await File.WriteAllTextAsync(sessionFile, JsonSerializer.Serialize(new { url = client.BaseAddress.ToString(), token = login.GetProperty("token").GetString(), username = "admin", password, folder, fixture = fixture.Url, publicCertificate, controlFile = fixture.ControlFile, pid = Environment.ProcessId }, Json));
                Console.WriteLine("LOCAL_UI_READY " + sessionFile);
                while (!File.Exists(Path.Combine(root, "stop-ui"))) await Task.Delay(500);
            }
        }
        finally { connector.CancelReconciliation(); await connector.WaitForReconciliationAsync(); await service.StopAsync(); service.Dispose(); old.Dispose(); }
    }
}
