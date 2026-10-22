using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.Security;
using System.Reflection;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.IO.Compression;
using System.Text.Json;

static class MigrationChecks
{
    static int Port() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    public static async Task Run(bool serve = false)
    {
        string root = Path.Combine(Path.GetTempPath(), "ddi-migration-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        string password = Guid.NewGuid().ToString("N") + "Aa9!"; int passed = 0;
        void Check(bool value, string message) { if (!value) throw new Exception(message); passed++; }
        var previous = new Dictionary<string, string>();
        void Env(string name, string value) { if (!previous.ContainsKey(name)) previous[name] = Environment.GetEnvironmentVariable(name); Environment.SetEnvironmentVariable(name, value); }
        async Task<(DnsWebService Service, HttpClient Client, int DnsPort)> Start(string name)
        {
            string folder = Path.Combine(root, name); Directory.CreateDirectory(folder); int webPort = Port(), dnsPort = Port();
            Env("DNS_SERVER_ADMIN_PASSWORD", password); Env("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1"); Env("DNS_SERVER_WEB_SERVICE_HTTP_PORT", webPort.ToString()); Env("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
            await using (var log = new LogManager(true, folder)) using (var dns = new DnsServer(folder, Path.Combine(repository, "DnsServerCore/dohwww"), log))
            { dns.LoadConfigFile(); dns.ServerDomain = name + ".migration.test"; dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
            if (name == "source")
            {
                Directory.CreateDirectory(Path.Combine(folder, "scopes"));
                using var scope = new Scope("Transfer", false, IPAddress.Parse("192.0.2.100"), IPAddress.Parse("192.0.2.149"), IPAddress.Parse("255.255.255.0"), null, null);
                byte[] mac = [2, 0, 0, 0, 0, 42]; var identifier = new ClientIdentifierOption(1, mac);
                var constructor = typeof(Lease).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single(c => c.GetParameters().Length == 7);
                var lease = (Lease)constructor.Invoke([LeaseType.Dynamic, identifier, "host.portable.example", mac, IPAddress.Parse("192.0.2.142"), "", (uint)3600]);
                ((IDictionary<ClientIdentifierOption, Lease>)scope.Leases).Add(identifier, lease);
                using var output = File.Create(Path.Combine(folder, "scopes/Transfer.scope")); scope.WriteTo(output);
            }
            var service = new DnsWebService(true, folder); await service.StartAsync(true);
            var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + webPort) };
            var login = await Call(client, "/api/user/login", ("user", "admin"), ("pass", password));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
            return (service, client, dnsPort);
        }
        static async Task<JsonElement> Call(HttpClient c, string path, params (string Key, string Value)[] fields)
        { using var body = new FormUrlEncodedContent(fields.Select(x => new KeyValuePair<string, string>(x.Key, x.Value))); using var result = await c.PostAsync(path, body); using var doc = JsonDocument.Parse(await result.Content.ReadAsStringAsync()); return doc.RootElement.Clone(); }
        static async Task<JsonElement> Preview(HttpClient c, byte[] package)
        { using var body = new MultipartFormDataContent(); body.Add(new ByteArrayContent(package), "file", "deployment.zip"); using var result = await c.PostAsync("/api/settings/migration/preview", body); using var doc = JsonDocument.Parse(await result.Content.ReadAsStringAsync()); return doc.RootElement.Clone(); }
        var source = await Start("source"); var target = await Start("destination");
        try
        {
            Check((await Call(source.Client, "/api/zones/create", ("zone", "cluster-catalog.source.migration.test"), ("type", "Catalog"))).GetProperty("status").GetString() == "ok", "Source catalog create failed");
            Check((await Call(source.Client, "/api/zones/create", ("zone", "portable.example"), ("type", "Primary"), ("catalog", "cluster-catalog.source.migration.test"))).GetProperty("status").GetString() == "ok", "Source zone create failed");
            Check((await Call(source.Client, "/api/zones/records/add", ("domain", "host.portable.example"), ("zone", "portable.example"), ("type", "A"), ("ipAddress", "192.0.2.42"), ("ttl", "600"))).GetProperty("status").GetString() == "ok", "Source record create failed");
            await Call(source.Client, "/api/settings/set", ("defaultRecordTtl", "600"));
            var sourceInventory = (await Call(source.Client, "/api/ipam/list")).GetProperty("response").GetProperty("inventory");
            string discoveredSubnetId = sourceInventory.GetProperty("subnets").EnumerateArray().Single(s => s.GetProperty("prefix").GetString() == "192.0.2.0/24").GetProperty("id").GetString();
            Check((await Call(source.Client, "/api/ipam/subnets/set", ("revision", sourceInventory.GetProperty("revision").GetInt64().ToString()), ("id", discoveredSubnetId), ("prefix", "192.0.2.0/24"), ("name", "Transferred network"))).GetProperty("status").GetString() == "ok", "Source IPAM intent setup failed");
            var originalLease = (await Call(source.Client, "/api/dhcp/leases/list")).GetProperty("response").GetProperty("leases")[0];
            var sourcePolicy = JsonSerializer.Deserialize<SecurityPolicy>((await Call(source.Client, "/api/security/policy/get")).GetProperty("response").GetProperty("policy").GetRawText(), DdiSecurityManager.JsonOptions);
            sourcePolicy = sourcePolicy with { Indicators = [new ThreatIndicator("migration-ioc", "Domain", "bad.portable.example", "Block", "Migration test")], Misp = new MispSettings(false, "https://misp.migration.test/"), EdlFeeds = [new("private", "Network", "https://private.migration.test/list.txt", ApiKeyEnvironment: "DDI_EDL_PRIVATE_API_KEY")], EdlPublications = [new("private", "Domain", [new("Migration test", "migration-ioc")], true)] };
            Check((await Call(source.Client, "/api/security/policy/set", ("revision", "0"), ("policy", JsonSerializer.Serialize(sourcePolicy, DdiSecurityManager.JsonOptions)))).GetProperty("status").GetString() == "ok", "Source policy setup failed");
            using var export = await source.Client.GetAsync("/api/settings/migration/export"); byte[] package = await export.Content.ReadAsByteArrayAsync();
            Check(export.Content.Headers.ContentType.MediaType == "application/zip", "Migration export did not return ZIP: " + (export.Content.Headers.ContentType.MediaType == "application/zip" ? "" : System.Text.Encoding.UTF8.GetString(package)));
            using (var zip = new ZipArchive(new MemoryStream(package)))
            {
                Check(zip.GetEntry("migration-manifest.json") != null && zip.GetEntry("portable-dns.json") != null, "Migration manifest/settings missing");
                Check(zip.GetEntry("auth.config") == null && zip.GetEntry("cluster.config") == null && zip.GetEntry("dhcp-allocation.json") == null && zip.GetEntry("dns.config") == null, "Deployment identity leaked into package");
            }
            using (var unauthenticated = new HttpClient { BaseAddress = target.Client.BaseAddress })
                Check((await Preview(unauthenticated, package)).GetProperty("status").GetString() == "invalid-token", "Anonymous migration preview allowed");
            byte[] malformed;
            using (var output = new MemoryStream()) { using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) { using var file = zip.CreateEntry("zones/../escape.zone").Open(); file.WriteByte(1); } malformed = output.ToArray(); }
            Check((await Preview(target.Client, malformed)).GetProperty("status").GetString() != "ok", "Traversal archive accepted");
            static byte[] Change(byte[] original, string name, byte[] replacement, bool keepManifest)
            {
                using var output = new MemoryStream(); using var sourceZip = new ZipArchive(new MemoryStream(original));
                using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
                    foreach (var entry in sourceZip.Entries)
                    {
                        if (!keepManifest && entry.FullName == "migration-manifest.json") continue;
                        using var destination = zip.CreateEntry(entry.FullName).Open();
                        if (entry.FullName == name) destination.Write(replacement); else { using var input = entry.Open(); input.CopyTo(destination); }
                    }
                return output.ToArray();
            }
            byte[] bad = Change(package, "portable-dns.json", System.Text.Encoding.UTF8.GetBytes("{}"), true);
            Check((await Preview(target.Client, bad)).GetProperty("status").GetString() != "ok", "Modified manifest package accepted");
            // A selective native backup remains compatible; cluster catalog identity is deliberately not portable.
            using var nativeBackup = await source.Client.GetAsync("/api/settings/backup?zones=true&scopes=true");
            using var nativeZip = new ZipArchive(new MemoryStream(await nativeBackup.Content.ReadAsByteArrayAsync()));
            using var legacyMemory = new MemoryStream();
            using (var filtered = new ZipArchive(legacyMemory, ZipArchiveMode.Create, true))
                foreach (var entry in nativeZip.Entries.Where(x => !x.FullName.StartsWith("zones/cluster-catalog."))) { using var destination = filtered.CreateEntry(entry.FullName).Open(); using var input = entry.Open(); input.CopyTo(destination); }
            using var legacyResponse = new HttpResponseMessage { Content = new ByteArrayContent(legacyMemory.ToArray()) };
            byte[] legacy = await legacyResponse.Content.ReadAsByteArrayAsync(); var legacyReview = await Preview(target.Client, legacy);
            Check(legacyReview.GetProperty("status").GetString() == "ok" && !legacyReview.GetProperty("response").GetProperty("verifiedManifest").GetBoolean(), "Native backup compatibility failed");
            await Call(target.Client, "/api/settings/set", ("defaultRecordTtl", "900"));
            byte[] invalidSettings = Change(package, "portable-dns.json", System.Text.Encoding.UTF8.GetBytes("{\"defaultRecordTtl\":\"not-a-duration\"}"), false);
            var rollbackReview = await Preview(target.Client, invalidSettings);
            var failed = await Call(target.Client, "/api/settings/migration/import", ("review", rollbackReview.GetProperty("response").GetProperty("review").GetString()));
            Check(failed.GetProperty("status").GetString() != "ok", "Invalid settings applied");
            Check((await Call(target.Client, "/api/zones/list")).GetProperty("response").GetProperty("zones").GetArrayLength() == 0, "Partial-import zone was not removed on rollback");
            Check((await Call(target.Client, "/api/settings/get")).GetProperty("response").GetProperty("defaultRecordTtl").GetInt32() == 900, "Runtime pre-import settings were not restored");
            using (var output = new MemoryStream()) { using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) { using var file = zip.CreateEntry("zones/drive:stream.zone").Open(); file.WriteByte(1); } malformed = output.ToArray(); }
            Check((await Preview(target.Client, malformed)).GetProperty("status").GetString() != "ok", "Alternate stream path accepted");
            var review = await Preview(target.Client, package);
            Check(review.GetProperty("status").GetString() == "ok", "Migration preview failed: " + review);
            Check(review.GetProperty("response").GetProperty("canImport").GetBoolean(), "Empty destination rejected: " + review);
            Check(review.GetProperty("response").GetProperty("verifiedManifest").GetBoolean(), "Checksums not verified");
            string id = review.GetProperty("response").GetProperty("review").GetString();
            await Call(target.Client, "/api/settings/set", ("defaultRecordTtl", "901"));
            Check((await Call(target.Client, "/api/settings/migration/import", ("review", id))).GetProperty("status").GetString() != "ok", "Changed target accepted stale review");
            review = await Preview(target.Client, package); id = review.GetProperty("response").GetProperty("review").GetString();
            var applied = await Call(target.Client, "/api/settings/migration/import", ("review", id));
            Check(applied.GetProperty("status").GetString() == "ok", "Migration import failed: " + applied);
            Check(File.Exists(Path.Combine(root, "destination", applied.GetProperty("response").GetProperty("recoveryBackup").GetString())), "Pre-import backup missing");
            var settings = (await Call(target.Client, "/api/settings/get")).GetProperty("response");
            Check(settings.GetProperty("dnsServerDomain").GetString() == "destination.migration.test", "Destination identity replaced");
            Check(settings.GetProperty("dnsServerLocalEndPoints")[0].GetString().EndsWith(":" + target.DnsPort), "DNS listener replaced");
            Check(settings.GetProperty("defaultRecordTtl").GetInt32() == 600, "Resolver settings not transferred");
            var scopes = (await Call(target.Client, "/api/dhcp/scopes/list")).GetProperty("response").GetProperty("scopes");
            Check(scopes.EnumerateArray().Any(x => x.GetProperty("name").GetString() == "Transfer" && !x.GetProperty("enabled").GetBoolean()), "Imported scope not disabled");
            var importedLease = (await Call(target.Client, "/api/dhcp/leases/list")).GetProperty("response").GetProperty("leases")[0];
            Check(importedLease.GetRawText() == originalLease.GetRawText(), "Lease snapshot identity or expiration changed");
            var importedPolicy = (await Call(target.Client, "/api/security/policy/get")).GetProperty("response").GetProperty("policy");
            Check(!importedPolicy.GetProperty("misp").GetProperty("enabled").GetBoolean() && importedPolicy.GetProperty("misp").GetProperty("url").GetString() == "", "External enrichment activated or its source endpoint copied");
            Check(importedPolicy.GetProperty("edlFeeds").GetArrayLength() == 0 && importedPolicy.GetProperty("edlPublications").GetArrayLength() == 0, "Private EDL connection or publication copied to new deployment");
            Check(importedPolicy.GetProperty("indicators").EnumerateArray().Any(x => x.GetProperty("id").GetString() == "migration-ioc"), "Security policy not transferred");
            var recordReply = await Call(target.Client, "/api/zones/records/get", ("domain", "host.portable.example"), ("zone", "portable.example"));
            Check(recordReply.GetProperty("status").GetString() == "ok", "Imported record read failed: " + recordReply);
            var records = recordReply.GetProperty("response").GetProperty("records");
            Check(records.EnumerateArray().Any(x => x.GetProperty("type").GetString() == "A"), "DNS record not transferred");
            Check(recordReply.GetProperty("response").GetProperty("zone").GetProperty("catalog").ValueKind == JsonValueKind.Null, "Old cluster catalog membership retained");
            using var fresh = new HttpClient { BaseAddress = target.Client.BaseAddress };
            var login = await Call(fresh, "/api/user/login", ("user", "admin"), ("pass", password));
            Check(login.GetProperty("status").GetString() == "ok", "Destination credential stopped working"); fresh.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
            Check((await Call(fresh, "/api/settings/set", ("defaultRecordTtl", "600"))).GetProperty("status").GetString() == "ok", "Fresh administrative modification denied");
            Check(!(await Preview(fresh, package)).GetProperty("response").GetProperty("canImport").GetBoolean(), "Active deployment accepted migration");
            Check((await Call(fresh, "/api/settings/migration/import", ("review", id))).GetProperty("response").GetProperty("state").GetString() == "Committed", "Completed operation receipt was not rediscovered");
            var inventory = (await Call(fresh, "/api/ipam/list")).GetProperty("response").GetProperty("inventory");
            Check(inventory.GetProperty("subnets").EnumerateArray().Any(s => s.GetProperty("name").GetString() == "Transferred network" && s.GetProperty("prefix").GetString() == "192.0.2.0/24"), "IPAM intent not transferred");
            Console.WriteLine("Passed " + passed + " migration checks.");
            if (serve)
            {
                var browser = await Start("browser-destination");
                string connection = Path.Combine(repository, "artifacts/migration-ui-connection.json");
                string packagePath = Path.Combine(repository, "artifacts/migration-ui-package.zip"); File.WriteAllBytes(packagePath, package);
                File.WriteAllText(connection, JsonSerializer.Serialize(new { url = browser.Client.BaseAddress.ToString(), user = "admin", password, packagePath }));
                Console.WriteLine("Isolated migration UI server ready; details saved under artifacts.");
                try { while (!File.Exists(connection + ".stop")) await Task.Delay(250); }
                finally { browser.Client.Dispose(); await browser.Service.DisposeAsync(); File.Delete(connection); if (File.Exists(connection + ".stop")) File.Delete(connection + ".stop"); }
            }
        }
        finally
        {
            source.Client.Dispose(); target.Client.Dispose(); await source.Service.DisposeAsync(); await target.Service.DisposeAsync();
            foreach (var item in previous) Environment.SetEnvironmentVariable(item.Key, item.Value);
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
