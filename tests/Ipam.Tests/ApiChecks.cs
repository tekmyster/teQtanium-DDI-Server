using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using DnsServerCore;
using DnsServerCore.Dns;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using DnsServerCore.Security;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class ApiChecks
{
    static int FreePort() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    public static async Task Run(bool serve)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-ipam-api-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        int port = FreePort();
        int dnsPort = FreePort();
        string password = Guid.NewGuid().ToString("N") + "Aa!9";
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", port.ToString());
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
        await using (var log = new LogManager(true, folder))
        using (var dns = new DnsServer(folder, Path.Combine(repository, "DnsServerCore/dohwww"), log))
        {
            dns.LoadConfigFile();
            if (serve) dns.ServerDomain = "demo.teqtanium.test";
            dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)];
            dns.EnableCheckForUpdate = false;
            dns.SaveConfigFile(true);
        }
        await using var service = new DnsWebService(true, folder);
        try
        {
            await service.StartAsync(true);
            using var original = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + port) };
            int checks = 0;
            void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; }
            async Task<JsonElement> Call(HttpClient client, string path, params (string Key, string Value)[] parameters)
            {
                using var content = new FormUrlEncodedContent(parameters.Select(p => new KeyValuePair<string, string>(p.Key, p.Value)));
                using var response = await client.PostAsync(path, content);
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                return json.RootElement.Clone();
            }
            var denied = await Call(original, "/api/ipam/list");
            Check(denied.GetProperty("status").GetString() == "invalid-token", "Unauthenticated access was allowed");
            Check((await Call(original, "/api/logging/syslog/get")).GetProperty("status").GetString() == "invalid-token", "Anonymous syslog settings exposed");
            var login = await Call(original, "/api/user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true"));
            Check(login.GetProperty("status").GetString() == "ok", "Admin authentication failed");
            Check(login.GetProperty("info").GetProperty("productVersion").GetString() == "0.1.0-alpha.4" && login.GetProperty("info").GetProperty("version").GetString() == "15.6.1", "Product alpha version changed engine compatibility identity");
            // Login responses have a top-level token; keep this session open throughout validation.
            string token = login.GetProperty("token").GetString();
            original.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            async Task<string> Revision() => (await Call(original, "/api/ipam/list")).GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64().ToString();
            var inventory = await Call(original, "/api/ipam/list");
            Check(inventory.GetProperty("response").GetProperty("inventory").GetProperty("subnets").EnumerateArray().Any(s => s.GetProperty("dhcpScope").GetString() == "Default" && s.GetProperty("source").GetString() == "DhcpScope"), "Fresh installation did not populate DHCP subnet automatically");
            var subnet = await Call(original, "/api/ipam/subnets/set", ("revision", await Revision()), ("prefix", "192.0.2.0/24"), ("name", "API lab"));
            Check(subnet.GetProperty("status").GetString() == "ok", "Subnet API failed: " + subnet);
            string subnetId = subnet.GetProperty("response").GetProperty("subnet").GetProperty("id").GetString();
            string staleRevision = await Revision();
            var assignment = await Call(original, "/api/ipam/assignments/set", ("revision", await Revision()), ("subnetId", subnetId), ("address", "192.0.2.10"), ("hostName", "host.example"));
            Check(assignment.GetProperty("status").GetString() == "ok", "Assignment API failed");
            var stale = await Call(original, "/api/ipam/assignments/set", ("revision", staleRevision), ("subnetId", subnetId), ("address", "192.0.2.11"));
            Check(stale.GetProperty("status").GetString() == "error", "Stale API write allowed");
            var next = await Call(original, "/api/ipam/addresses/nextAvailable", ("subnetId", subnetId));
            Check(next.GetProperty("response").GetProperty("address").GetString() == "192.0.2.1", "Available address API failed");
            var createdZone = await Call(original, "/api/zones/create", ("zone", "example"), ("type", "Primary"));
            Check(createdZone.GetProperty("status").GetString() == "ok", "Zone creation failed: " + createdZone);
            service.DnsServer.AuthZoneManager.SetRecords("example", [new TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecord("host.example", TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecordType.A, TechnitiumLibrary.Net.Dns.ResourceRecords.DnsClass.IN, 60, new TechnitiumLibrary.Net.Dns.ResourceRecords.DnsARecordData(IPAddress.Parse("192.0.2.10")))]);
            var linked = await Call(original, "/api/ipam/subnets/set", ("revision", await Revision()), ("id", subnetId), ("prefix", "192.0.2.0/24"), ("name", "API lab"), ("dnsZone", "example"));
            Check(linked.GetProperty("status").GetString() == "ok", "Zone linkage failed: " + linked);
            var inspect = await Call(original, "/api/ipam/subnets/inspect", ("subnetId", subnetId));
            Check(inspect.GetProperty("response").GetProperty("observations").GetArrayLength() == 1 && inspect.GetProperty("response").GetProperty("findings").GetArrayLength() == 0, "DNS reconciliation failed");
            var html = await original.GetStringAsync("/");
            Check(html.Contains("mainPanelTabPaneIpam") && (await original.GetStringAsync("/js/ipam.js")).Contains("refreshIpam"), "IPAM UI assets unavailable");
            // Independently authenticate and verify administrative access before releasing the original session.
            using var fresh = new HttpClient { BaseAddress = original.BaseAddress };
            var freshLogin = await Call(fresh, "/api/user/login", ("user", "admin"), ("pass", password), ("includeInfo", "true"));
            Check(freshLogin.GetProperty("status").GetString() == "ok", "Fresh session login failed");
            fresh.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", freshLogin.GetProperty("token").GetString());
            var freshInventory = await Call(fresh, "/api/ipam/list");
            Check(freshInventory.GetProperty("response").GetProperty("inventory").GetProperty("assignments").EnumerateArray().Any(a => a.GetProperty("hostName").GetString() == "host.example"), "Fresh session cannot read intended state");
            var freshWrite = await Call(fresh, "/api/ipam/views/set", ("revision", await Revision()), ("name", "Fresh session validated"));
            Check(freshWrite.GetProperty("status").GetString() == "ok", "Fresh session lacks administrative modify privilege");
            service.DnsServer.AuthZoneManager.CreatePrimaryZone("restart-permission.example");
            var permissionManager = (DnsServerCore.Auth.AuthManager)typeof(DnsWebService).GetField("_authManager", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            Check(permissionManager.GetPermission(DnsServerCore.Auth.PermissionSection.Zones, "restart-permission.example") is null, "Missing-permission restart fixture was not established");
            typeof(DnsWebService).GetMethod("InspectAndFixZonePermissions", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(service, []);
            using (var postRepair = new HttpClient { BaseAddress = original.BaseAddress })
            {
                var postRepairLogin = await Call(postRepair, "/api/user/login", ("user", "admin"), ("pass", password));
                Check(postRepairLogin.GetProperty("status").GetString() == "ok", "Fresh login failed after restoring missing zone permission");
                postRepair.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", postRepairLogin.GetProperty("token").GetString());
                Check((await Call(postRepair, "/api/zones/records/add", ("domain", "probe.restart-permission.example"), ("type", "A"), ("ipAddress", "192.0.2.43"))).GetProperty("status").GetString() == "ok", "Fresh administrative session cannot modify the recovered zone");
            }
            Check((await Call(fresh, "/api/ddi/dhcp/state/get")).GetProperty("response").GetProperty("state").GetProperty("plans").GetArrayLength() == 0, "Unexpected distributed DHCP bootstrap state");
            Check((await Call(fresh, "/api/ddi/dhcp/prepare", ("state", "{}"))).GetProperty("status").GetString() == "error", "Ordinary admin session can prepare cluster ownership");
            Check((await Call(fresh, "/api/ipam/netbox/settings/get")).GetProperty("response").GetProperty("settings").GetProperty("enabled").GetBoolean() == false, "NetBox integration does not default disabled");
            string defaultSubnetId = inventory.GetProperty("response").GetProperty("inventory").GetProperty("subnets").EnumerateArray().Single(s => s.GetProperty("dhcpScope").GetString() == "Default").GetProperty("id").GetString();
            var dhcpSubnet = await Call(original, "/api/ipam/subnets/set", ("id", defaultSubnetId), ("revision", await Revision()), ("prefix", "192.168.1.0/24"), ("name", "DHCP lab"), ("dhcpScope", "Default"));
            Check(dhcpSubnet.GetProperty("status").GetString() == "ok", "DHCP scope linkage failed: " + dhcpSubnet);
            string dhcpSubnetId = dhcpSubnet.GetProperty("response").GetProperty("subnet").GetProperty("id").GetString();
            var reserved = await Call(original, "/api/dhcp/scopes/addReservedLease", ("name", "Default"), ("hardwareAddress", "02-00-00-00-00-01"), ("ipAddress", "192.168.1.50"), ("hostName", "reserved.home"));
            Check(reserved.GetProperty("status").GetString() == "ok", "DHCP reservation setup failed");
            var dhcpInspect = await Call(original, "/api/ipam/subnets/inspect", ("subnetId", dhcpSubnetId));
            Check(dhcpInspect.GetProperty("response").GetProperty("observations").EnumerateArray().Any(o => o.GetProperty("source").GetString() == "DhcpReservation"), "DHCP reservation not reconciled");
            var discovered = await Call(original, "/api/ipam/list");
            Check(discovered.GetProperty("response").GetProperty("inventory").GetProperty("assignments").EnumerateArray().Any(a => a.GetProperty("address").GetString() == "192.168.1.50" && a.GetProperty("source").GetString() == "DhcpReservation"), "Reservation did not populate IPAM without import");
            long backupRevision = discovered.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64();
            using var backupResponse = await original.GetAsync("/api/settings/backup?dnsSettings=true");
            byte[] backupBytes = await backupResponse.Content.ReadAsByteArrayAsync();
            using (var archive = new System.IO.Compression.ZipArchive(new MemoryStream(backupBytes)))
                Check(archive.GetEntry("ipam.json") is not null, "Backup omits IPAM inventory");
            var changedAfterBackup = await Call(original, "/api/ipam/views/set", ("revision", await Revision()), ("name", "Discard during restore"));
            Check(changedAfterBackup.GetProperty("status").GetString() == "ok", "Pre-restore mutation failed");
            using var upload = new MultipartFormDataContent();
            upload.Add(new StringContent("true"), "dnsSettings");
            upload.Add(new ByteArrayContent(backupBytes), "file", "ipam-lab.zip");
            using var restoredResponse = await original.PostAsync("/api/settings/restore", upload);
            using var restoredJson = JsonDocument.Parse(await restoredResponse.Content.ReadAsStringAsync());
            Check(restoredJson.RootElement.GetProperty("status").GetString() == "ok", "Settings restore failed: " + restoredJson.RootElement);
            var restoredInventory = await Call(fresh, "/api/ipam/list");
            Check(restoredInventory.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64() == backupRevision, "Restored IPAM state not active");
            string readerPassword = Guid.NewGuid().ToString("N") + "Bb!8";
            var readerCreated = await Call(original, "/api/admin/users/create", ("user", "ipam-reader-test"), ("pass", readerPassword));
            Check(readerCreated.GetProperty("status").GetString() == "ok", "Permission test user setup failed");
            using var reader = new HttpClient { BaseAddress = original.BaseAddress };
            var readerLogin = await Call(reader, "/api/user/login", ("user", "ipam-reader-test"), ("pass", readerPassword), ("includeInfo", "true"));
            Check(readerLogin.GetProperty("status").GetString() == "ok", "Fresh test user authentication failed");
            reader.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", readerLogin.GetProperty("token").GetString());
            Check((await Call(reader, "/api/ipam/list")).GetProperty("status").GetString() == "error", "IPAM inventory leaked to user without Settings access");
            Check((await Call(reader, "/api/ipam/views/set", ("revision", "5"), ("name", "Forbidden"))).GetProperty("status").GetString() == "error", "Unauthorized IPAM modification allowed");
            Check((await Call(reader, "/api/ddi/dhcp/handoff", ("scope", "Default"))).GetProperty("status").GetString() == "error", "Unprivileged user can surrender DHCP ownership");
            Check((await Call(fresh, "/api/ipam/list")).GetProperty("status").GetString() == "ok", "Fresh admin access lost after lab changes");
            var securityGet = await Call(original, "/api/security/policy/get");
            Check(securityGet.GetProperty("status").GetString() == "ok" && !securityGet.GetProperty("response").GetProperty("policy").GetProperty("enabled").GetBoolean(), "Security default changes existing DNS behavior");
            Check((await Call(reader, "/api/security/policy/get")).GetProperty("status").GetString() == "error", "Security evidence leaked to unauthorized user");
            var securityPolicy = SecurityPolicy.Default with { Enabled = true, InspectAuthoritative = true, Indicators = [new("ip-rule", "Network", "203.0.113.0/24", "Block", "Local lab"), new("domain-rule", "Domain", "badname.example", "Block", "Local lab")] };
            string SerializePolicy(SecurityPolicy p) => JsonSerializer.Serialize(p, DdiSecurityManager.JsonOptions);
            var securitySet = await Call(original, "/api/security/policy/set", ("revision", "0"), ("policy", SerializePolicy(securityPolicy)));
            Check(securitySet.GetProperty("status").GetString() == "ok", "Security policy API failed: " + securitySet);
            var simulation = await Call(original, "/api/security/simulate", ("query", "ordinary.example"), ("addresses", "203.0.113.9"));
            Check(simulation.GetProperty("response").GetProperty("decision").GetProperty("action").GetString() == "Monitor", "Simulation ignores monitor mode");
            service.DnsServer.AuthZoneManager.SetRecords("example", [new DnsResourceRecord("badip.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("203.0.113.9")))]);
            service.DnsServer.AuthZoneManager.SetRecords("example", [new DnsResourceRecord("badname.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.11")))]);
            async Task<DnsDatagram> UdpQuery(string name)
            {
                using var udp = new UdpClient(AddressFamily.InterNetwork);
                DnsDatagram request = new(31, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);
                using MemoryStream wire = new(); request.WriteTo(wire);
                await udp.SendAsync(wire.ToArray(), new IPEndPoint(IPAddress.Loopback, dnsPort));
                using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
                var result = await udp.ReceiveAsync(timeout.Token);
                return DnsDatagram.ReadFrom(new MemoryStream(result.Buffer));
            }
            Check((await UdpQuery("badip.example")).RCODE == DnsResponseCode.NoError, "Monitor mode rewrites live DNS response");
            securityPolicy = securityPolicy with { Mode = "Block", DhcpResponse = "DenyNewLeases", DeviceDnsResponse = "Block" };
            Check((await Call(original, "/api/security/policy/set", ("revision", "1"), ("policy", SerializePolicy(securityPolicy)))).GetProperty("status").GetString() == "ok", "Block policy activation failed");
            Check((await Call(original, "/api/security/policy/set", ("revision", "1"), ("policy", SerializePolicy(securityPolicy)))).GetProperty("status").GetString() == "error", "Stale security policy API write accepted");
            byte[] hardware = [2, 0, 0, 0, 0, 9];
            string clientIdentifier = new DnsServerCore.Dhcp.Options.ClientIdentifierOption(1, hardware).ToString();
            service.DnsServer.SecurityManager.DeviceResolver = ip => ip.Equals(IPAddress.Loopback) ? new SecurityDevice("Default", clientIdentifier, BitConverter.ToString(hardware), "lab-client", "default", "Lab", 99) : null;
            var badResponse = await UdpQuery("badip.example");
            Check(badResponse.RCODE == DnsResponseCode.Refused && !badResponse.AuthenticData && badResponse.CheckingDisabled, "Live DNS IP block flags failed");
            Check((await UdpQuery("badname.example")).RCODE == DnsResponseCode.Refused, "Live DNS domain blocking failed");
            Check(!(await Call(original, "/api/logging/syslog/get")).GetProperty("response").GetProperty("settings").GetProperty("enabled").GetBoolean(), "Syslog must default disabled");
            using (var collector = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            {
                int collectorPort = ((IPEndPoint)collector.Client.LocalEndPoint).Port;
                var forwarding = new DnsServerCore.Logging.SyslogSettings(Enabled:true,Server:"127.0.0.1",Port:collectorPort,SystemEvents:false,SecurityEvents:true,DnsQueries:true);
                string forwardingJson = JsonSerializer.Serialize(forwarding, DnsServerCore.Logging.SyslogForwarder.JsonOptions);
                Check((await Call(original,"/api/logging/syslog/set",("revision","0"),("settings",forwardingJson))).GetProperty("status").GetString()=="ok", "Admin cannot configure syslog");
                Check((await Call(original,"/api/logging/syslog/set",("revision","0"),("settings",forwardingJson))).GetProperty("status").GetString()=="error", "Stale syslog update accepted");
                Check((await UdpQuery("badname.example")).RCODE==DnsResponseCode.Refused,"Forwarding changed the security response");
                string firstMessage=System.Text.Encoding.UTF8.GetString((await collector.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer);
                string secondMessage=System.Text.Encoding.UTF8.GetString((await collector.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer);
                Check(new[]{firstMessage,secondMessage}.Any(m=>m.Contains(" security - ") && m.Contains("badname.example") && m.Contains("Block")), "Security event did not reach the collector");
                Check(new[]{firstMessage,secondMessage}.Any(m=>m.Contains(" dns - ") && m.Contains("badname.example") && m.Contains("Refused")), "DNS query hook did not reach the collector");
                Check((await Call(original,"/api/logging/syslog/test")).GetProperty("response").GetProperty("queued").GetBoolean(), "Syslog test API falsely reported success");
                Check(System.Text.Encoding.UTF8.GetString((await collector.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer).Contains("syslog forwarding test"), "API test record not received");
                using var syslogBackupResponse=await original.GetAsync("/api/settings/backup?logSettings=true");
                byte[] syslogBackup=await syslogBackupResponse.Content.ReadAsByteArrayAsync();
                using(var syslogArchive=new System.IO.Compression.ZipArchive(new MemoryStream(syslogBackup))) Check(syslogArchive.GetEntry("syslog.json") is not null,"Logging backup omits syslog settings");
                Check((await Call(original,"/api/logging/syslog/set",("revision","1"),("settings",JsonSerializer.Serialize(forwarding with{Enabled=false},DnsServerCore.Logging.SyslogForwarder.JsonOptions)))).GetProperty("status").GetString()=="ok","Could not disable forwarding");
                using var syslogRestore=new MultipartFormDataContent();syslogRestore.Add(new StringContent("true"),"logSettings");syslogRestore.Add(new ByteArrayContent(syslogBackup),"file","syslog-backup.zip");
                using var syslogRestoreResponse=await original.PostAsync("/api/settings/restore",syslogRestore);using var syslogRestoreJson=JsonDocument.Parse(await syslogRestoreResponse.Content.ReadAsStringAsync());
                Check(syslogRestoreJson.RootElement.GetProperty("status").GetString()=="ok","Syslog native restore failed");
                Check((await Call(original,"/api/logging/syslog/get")).GetProperty("response").GetProperty("settings").GetProperty("enabled").GetBoolean(),"Syslog restore did not apply settings");
                Check((await Call(original,"/api/logging/syslog/set",("revision","3"),("settings",JsonSerializer.Serialize(forwarding with{Enabled=false},DnsServerCore.Logging.SyslogForwarder.JsonOptions)))).GetProperty("status").GetString()=="ok","Could not retire collector test");
            }
            Check((await UdpQuery("host.example")).RCODE == DnsResponseCode.Refused, "Shared device signal not applied to other DNS requests");
            Check((await UdpQuery("no-upstream.invalid")).RCODE == DnsResponseCode.Refused, "Device policy did not block before recursive lookup");
            var dhcpServer = (DnsServerCore.Dhcp.DhcpServer)typeof(DnsWebService).GetField("_dhcpServer", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(service);
            DnsServerCore.Dhcp.Scope localScope = dhcpServer.GetScope("Default");
            byte[] discoverWire = new byte[244];
            discoverWire[0] = 1; discoverWire[1] = 1; discoverWire[2] = 6; hardware.CopyTo(discoverWire, 28);
            new byte[] { 99, 130, 83, 99, 53, 1, 1, 255 }.CopyTo(discoverWire, 236);
            Type messageType = typeof(DnsServerCore.Dhcp.Scope).Assembly.GetType("DnsServerCore.Dhcp.DhcpMessage");
            var discover = Activator.CreateInstance(messageType, [new MemoryStream(discoverWire)]);
            var getOffer = typeof(DnsServerCore.Dhcp.Scope).GetMethod("GetOfferAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            var offer = await (Task<DnsServerCore.Dhcp.Lease>)getOffer.Invoke(localScope, [discover]);
            Check(offer is null, "DHCP allocation hook ignores DNS device signal");
            var securityEvents = await Call(fresh, "/api/security/events/list");
            Check(securityEvents.GetProperty("response").GetProperty("events").GetArrayLength() >= 3 && securityEvents.GetProperty("response").GetProperty("signals").GetArrayLength() >= 1, "Security investigation API lacks cross-service evidence");
            Check((await Call(original, "/api/security/signals/ingest", ("signals", "[]"))).GetProperty("status").GetString() == "error", "Non-cluster session allowed cluster signal injection");
            using (var peerClient = new DnsServerCore.HttpApi.HttpApiClient(original.BaseAddress, ipv6Mode: IPv6Mode.Disabled))
            {
                peerClient.UseApiToken(token);
                bool insecureTransportRejected = false;
                try { await peerClient.PushSecuritySignalsAsync("[]"); }
                catch (DnsServerCore.HttpApi.HttpApiClientException ex) { insecureTransportRejected = ex.Message.Contains("requires HTTPS"); }
                Check(insecureTransportRejected, "Peer publication can transmit signals over plaintext HTTP");
            }
            Check((await Call(reader, "/api/security/policy/set", ("revision", "2"), ("policy", SerializePolicy(securityPolicy)))).GetProperty("status").GetString() == "error", "Unauthorized security policy write accepted");
            Check((await original.GetStringAsync("/js/security.js")).Contains("refreshSecurity"), "Security console asset not served");
            using var securityBackup = await original.GetAsync("/api/settings/backup?dnsSettings=true");
            using (var archive = new System.IO.Compression.ZipArchive(new MemoryStream(await securityBackup.Content.ReadAsByteArrayAsync())))
                Check(archive.GetEntry("security.json") is not null && archive.GetEntry("security-signals.json") is not null && archive.GetEntry("security-misp.json") is not null && archive.GetEntry("security-edl.json") is not null, "Shared security state omitted from configuration transfer format");
            Check((await Call(fresh, "/api/security/policy/get")).GetProperty("status").GetString() == "ok", "Fresh administrative security access failed");
            var protectedPolicy = securityPolicy with { Misp = new MispSettings(false, "https://configured.example/"), Indicators = securityPolicy.Indicators.Append(new ThreatIndicator("inventory-ioc", "Network", "192.0.2.10", "Monitor", "Inventory lab")).ToArray() };
            Check((await Call(original, "/api/security/policy/set", ("revision", "2"), ("policy", SerializePolicy(protectedPolicy)))).GetProperty("status").GetString() == "ok", "Inventory security policy setup failed");
            var inventoryThreats = await Call(original, "/api/ipam/subnets/inspect", ("subnetId", subnetId));
            Check(inventoryThreats.GetProperty("response").GetProperty("securityFindings").GetArrayLength() > 0, "IPAM is unaware of shared threat intelligence");
            Check((await Call(original, "/api/admin/users/set", ("user", "ipam-reader-test"), ("memberOfGroups", "DNS Administrators"))).GetProperty("status").GetString() == "ok", "DNS administrator role fixture failed");
            using var dnsAdmin = new HttpClient { BaseAddress = original.BaseAddress };
            var dnsLogin = await Call(dnsAdmin, "/api/user/login", ("user", "ipam-reader-test"), ("pass", readerPassword), ("includeInfo", "true"));
            Check(dnsLogin.GetProperty("status").GetString() == "ok", "Fresh session after role change failed");
            dnsAdmin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", dnsLogin.GetProperty("token").GetString());
            Check((await Call(dnsAdmin, "/api/security/policy/get")).GetProperty("status").GetString() == "ok", "Fresh DNS admin session lacks intended view privilege");
            Check((await Call(dnsAdmin, "/api/ipam/netbox/settings/get")).GetProperty("status").GetString() == "error", "DNS-only administrator can access NetBox integration controls");
            Check((await Call(dnsAdmin, "/api/security/policy/set", ("revision", "3"), ("policy", SerializePolicy(protectedPolicy)))).GetProperty("status").GetString() == "ok", "Fresh DNS admin session lacks intended policy modify privilege");
            var unauthorizedSource = protectedPolicy with { Misp = new MispSettings(false, "https://unapproved.example/") };
            Check((await Call(dnsAdmin, "/api/security/policy/set", ("revision", "4"), ("policy", SerializePolicy(unauthorizedSource)))).GetProperty("status").GetString() == "error", "DNS-only admin can redirect MISP credential use");
            var unauthorizedEdl = protectedPolicy with { EdlFeeds = [new("unapproved", "Network", "https://unapproved.example/feed.txt")] };
            Check((await Call(dnsAdmin, "/api/security/policy/set", ("revision", "4"), ("policy", SerializePolicy(unauthorizedEdl)))).GetProperty("status").GetString() == "error", "DNS-only admin can configure EDL credential destination");
            unauthorizedEdl = protectedPolicy with { EdlPublications = [new("unapproved", "Network", [new("Inventory lab", "inventory-ioc")], true)] };
            Check((await Call(dnsAdmin, "/api/security/policy/set", ("revision", "4"), ("policy", SerializePolicy(unauthorizedEdl)))).GetProperty("status").GetString() == "error", "DNS-only admin can publish private intelligence");
            using (var insecureEdl = await original.GetAsync("/api/security/edl/export?list=private"))
                Check(insecureEdl.StatusCode == HttpStatusCode.Forbidden && (await insecureEdl.Content.ReadAsStringAsync()).Length == 0, "EDL publication allowed plaintext or returned a false successful list");
            using (var alternateEdl = await original.GetAsync("/api/security/edl/export/?list=private"))
                Check(alternateEdl.StatusCode == HttpStatusCode.Forbidden && (await alternateEdl.Content.ReadAsStringAsync()).Length == 0, "Trailing-slash EDL route bypassed transport boundary");
            checks += await EdlHttpChecks.Run(service, (DdiSecurityManager)typeof(DnsWebService).GetField("_security", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(service), original, dnsAdmin, reader);
            using (var restrictedSecurityBackup = new MemoryStream())
            {
                using (var zip = new System.IO.Compression.ZipArchive(restrictedSecurityBackup, System.IO.Compression.ZipArchiveMode.Create, true))
                using (var writer = new StreamWriter(zip.CreateEntry("security-edl.json").Open())) writer.Write("[]");
                using var attempt = new MultipartFormDataContent(); attempt.Add(new StringContent("true"), "dnsSettings"); attempt.Add(new ByteArrayContent(restrictedSecurityBackup.ToArray()), "file", "restricted-security.zip");
                using var result = await dnsAdmin.PostAsync("/api/settings/restore", attempt); using var parsed = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
                Check(parsed.RootElement.GetProperty("status").GetString() == "error", "Native restore bypassed security intelligence administration permission");
            }
            Check((await Call(dnsAdmin,"/api/logging/syslog/set",("revision","4"),("settings","{}"))).GetProperty("status").GetString()=="error", "DNS-only admin can redirect syslog exports");
            using(var restrictedBackup=new MemoryStream())
            {
                using(var zip=new System.IO.Compression.ZipArchive(restrictedBackup,System.IO.Compression.ZipArchiveMode.Create,true))
                using(var writer=new StreamWriter(zip.CreateEntry("syslog.json").Open())) writer.Write("{\"enabled\":true,\"server\":\"127.0.0.1\",\"port\":514}");
                using var attempt=new MultipartFormDataContent();attempt.Add(new StringContent("true"),"logSettings");attempt.Add(new ByteArrayContent(restrictedBackup.ToArray()),"file","restricted-syslog.zip");
                using var result=await dnsAdmin.PostAsync("/api/settings/restore",attempt);using var parsed=JsonDocument.Parse(await result.Content.ReadAsStringAsync());
                Check(parsed.RootElement.GetProperty("status").GetString()=="error","Native restore bypassed syslog administration permission");
                Check(!(await Call(original,"/api/logging/syslog/get")).GetProperty("response").GetProperty("settings").GetProperty("enabled").GetBoolean(),"Rejected restore changed forwarding");
            }
            Check((await Call(fresh, "/api/security/policy/get")).GetProperty("response").GetProperty("policy").GetProperty("revision").GetInt64() == 4, "Denied source change mutated policy or fresh administrative access was lost");
            Check((await Call(fresh, "/api/security/policy/history")).GetProperty("response").GetProperty("policies").GetArrayLength() > 1, "Policy history API lacks prior revisions");
            Check((await Call(dnsAdmin, "/api/security/policy/rollback", ("revision", "4"), ("targetRevision", "1"))).GetProperty("status").GetString() == "error", "Rollback bypasses MISP configuration permission");
            Check((await Call(fresh, "/api/security/policy/rollback", ("revision", "4"), ("targetRevision", "4"))).GetProperty("response").GetProperty("policy").GetProperty("revision").GetInt64() == 5, "Rollback does not publish a new policy revision");
            var modelPolicy = JsonSerializer.Deserialize<SecurityPolicy>((await Call(fresh, "/api/security/policy/get")).GetProperty("response").GetProperty("policy").GetRawText(), DdiSecurityManager.JsonOptions) with { Llm = new LlmSettings(false, "http://127.0.0.1:11434/v1/chat/completions", "local-model") };
            Check((await Call(dnsAdmin, "/api/security/policy/set", ("revision", "5"), ("policy", SerializePolicy(modelPolicy)))).GetProperty("status").GetString() == "error", "DNS-only administrator can redirect model evidence");
            Check((await Call(original, "/api/security/policy/set", ("revision", "5"), ("policy", SerializePolicy(modelPolicy)))).GetProperty("status").GetString() == "ok", "Administrator cannot configure optional model connection");
            Check((await Call(fresh, "/api/security/policy/get")).GetProperty("response").GetProperty("policy").GetProperty("revision").GetInt64() == 6, "Fresh administrator cannot verify the model configuration change");
            Check((await Call(dnsAdmin, "/api/security/policy/rollback", ("revision", "6"), ("targetRevision", "5"))).GetProperty("status").GetString() == "error", "Rollback bypasses model configuration permission");
            Check((await Call(dnsAdmin, "/api/security/events/analyze", ("eventId", "missing"))).GetProperty("status").GetString() == "error", "DNS-only administrator can send model evidence");
            var modelEventId = securityEvents.GetProperty("response").GetProperty("events")[0].GetProperty("id").GetString();
            Check((await Call(fresh, "/api/security/events/analyze", ("eventId", modelEventId))).GetProperty("status").GetString() == "error", "Disabled model connection reports successful analysis");
            var securityManager = (DdiSecurityManager)typeof(DnsWebService).GetField("_security", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            for (int i = 0; i < 40; i++)
            {
                var analyticRequest = new DnsDatagram(42, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                    [new DnsQuestionRecord($"abcdefghijklmnopqrstuvwxyz0123456789{i:D4}.leak.example", DnsResourceRecordType.TXT, DnsClass.IN)]);
                var analyticResponse = new DnsDatagram(42, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NxDomain, analyticRequest.Question);
                securityManager.InspectResponse(analyticRequest, new IPEndPoint(IPAddress.Parse("192.0.2.200"), 12345), analyticResponse);
            }
            var analyticEvent = securityManager.RecentEvents().Last();
            Check(analyticEvent.Behavior?.Findings?.Any(f => f.Kind == "DnsTunneling" && f.Score >= 70) == true && analyticEvent.Action == "Monitor", "Corroborated analytics did not reach the event API without automatic blocking");
            var modelBuilder = WebApplication.CreateBuilder();
            modelBuilder.Logging.ClearProviders(); modelBuilder.WebHost.UseUrls("http://127.0.0.1:" + FreePort());
            await using var modelFixture = modelBuilder.Build();
            modelFixture.MapPost("/v1/chat/completions", () => new { choices = new[] { new { message = new { content = "Fixture explanation: investigate the observed pattern. <b>This text must not become markup.</b>" } } } });
            await modelFixture.StartAsync();
            modelPolicy = modelPolicy with { Llm = modelPolicy.Llm with { Enabled = true, Endpoint = modelFixture.Urls.Single() + "/v1/chat/completions" } };
            Check((await Call(original, "/api/security/policy/set", ("revision", "6"), ("policy", SerializePolicy(modelPolicy)))).GetProperty("status").GetString() == "ok", "Optional local model fixture cannot be enabled");
            var analyzed = await Call(fresh, "/api/security/events/analyze", ("eventId", analyticEvent.Id));
            Check(analyzed.GetProperty("status").GetString() == "ok" && analyzed.GetProperty("response").GetProperty("analysis").GetProperty("status").GetString() == "Advisory", "Fresh administrator cannot complete a loopback model analysis");
            Check(securityManager.Policy.Revision == 7 && securityManager.RecentEvents().Last().Id == analyticEvent.Id, "Model explanation mutated protection or event evidence");
            var investigation = await Call(fresh, "/api/security/events/search", ("from", DateTime.UtcNow.AddMinutes(-10).ToString("O")), ("to", DateTime.UtcNow.AddMinutes(1).ToString("O")));
            var investigatedEvents = investigation.GetProperty("response").GetProperty("search").GetProperty("events");
            Check(investigatedEvents.GetArrayLength() > 0, "Investigation search API lacks events");
            Check((await Call(fresh, "/api/security/dispositions/set", ("eventId", investigatedEvents[0].GetProperty("id").GetString()), ("status", "Investigating"), ("notes", "Isolated test"))).GetProperty("status").GetString() == "ok", "Analyst disposition API failed");
            using var discoveredScope = new DnsServerCore.Dhcp.Scope("Automatic lab", false, IPAddress.Parse("192.168.44.100"), IPAddress.Parse("192.168.44.149"), IPAddress.Parse("255.255.255.0"), null, null);
            discoveredScope.DomainName = "example";
            byte[] discoveryMac = [2, 0, 0, 0, 44, 121];
            var discoveryClient = new DnsServerCore.Dhcp.Options.ClientIdentifierOption(1, discoveryMac);
            var leaseConstructor = typeof(DnsServerCore.Dhcp.Lease).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single(c => c.GetParameters().Length == 7);
            var discoveryLease = (DnsServerCore.Dhcp.Lease)leaseConstructor.Invoke([DnsServerCore.Dhcp.LeaseType.Dynamic, discoveryClient, "dynamic.example", discoveryMac, IPAddress.Parse("192.168.44.121"), "", (uint)3600]);
            ((IDictionary<DnsServerCore.Dhcp.Options.ClientIdentifierOption, DnsServerCore.Dhcp.Lease>)discoveredScope.Leases).Add(discoveryClient, discoveryLease);
            await dhcpServer.AddScopeAsync(discoveredScope);
            var staticRecord = new DnsResourceRecord("static-auto.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.168.44.20")));
            var dynamicRecord = new DnsResourceRecord("dynamic.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.168.44.121")));
            service.DnsServer.AuthZoneManager.SetRecords("example", [staticRecord]);
            service.DnsServer.AuthZoneManager.SetRecords("example", [dynamicRecord]);
            var discoveredManager = (DnsServerCore.Ipam.IpamManager)typeof(DnsWebService).GetField("_ipam", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            DateTime discoveryDeadline = DateTime.UtcNow.AddSeconds(35);
            // Read the store directly: no inventory request or import may trigger this population.
            while (!discoveredManager.Snapshot().Subnets.Any(s => s.DhcpScope == "Automatic lab") && DateTime.UtcNow < discoveryDeadline) await Task.Delay(200);
            var autoDiscoveredSubnet = discoveredManager.Snapshot().Subnets.SingleOrDefault(s => s.DhcpScope == "Automatic lab");
            Check(autoDiscoveredSubnet is not null && autoDiscoveredSubnet.Source == "DhcpScope", "Background discovery required a manual import or inventory request");
            Check(discoveredManager.Snapshot().Assignments.Any(a => a.Address == "192.168.44.20" && a.Source == "DnsRecord"), "Authoritative DNS did not populate a known subnet");
            Check(!discoveredManager.Snapshot().Assignments.Any(a => a.Address == "192.168.44.121"), "Dynamic lease became permanent allocation intent");
            var autoInspection = await Call(original, "/api/ipam/subnets/inspect", ("subnetId", autoDiscoveredSubnet.Id));
            Check(autoInspection.GetProperty("response").GetProperty("observations").EnumerateArray().Any(o => o.GetProperty("address").GetString() == "192.168.44.121" && o.GetProperty("source").GetString() == "DhcpLease"), "Active lease absent from automatically populated network");
            var safeCandidate = await Call(original, "/api/ipam/addresses/nextAvailable", ("subnetId", autoDiscoveredSubnet.Id));
            Check(safeCandidate.GetProperty("response").GetProperty("address").GetString() == "192.168.44.1", "Dynamic pool altered usable static range");
            typeof(DnsServerCore.Dhcp.Lease).GetField("_leaseExpires", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(discoveryLease, DateTime.UtcNow.AddMinutes(-1));
            var expiredInspection = await Call(original, "/api/ipam/subnets/inspect", ("subnetId", autoDiscoveredSubnet.Id));
            Check(!expiredInspection.GetProperty("response").GetProperty("observations").EnumerateArray().Any(o => o.GetProperty("address").GetString() == "192.168.44.121" && o.GetProperty("source").GetString() == "DhcpLease"), "Expired lease remained live IPAM usage");
            Check(!discoveredManager.Snapshot().Assignments.Any(a => a.Address == "192.168.44.121"), "Lingering dynamic DNS became static intent after lease expiry");
            Console.WriteLine($"PASS: {checks} authenticated IPAM/security API and live DNS/DHCP-hook checks; loopback fresh administrative read and modify verified.");
            if (serve)
            {
                string connectionFile = Path.Combine(AppContext.BaseDirectory, "lab-connection.json");
                File.WriteAllText(connectionFile, JsonSerializer.Serialize(new { url = original.BaseAddress.ToString(), user = "admin", password, configFolder = folder }));
                Console.WriteLine("Isolated UI lab ready; connection details saved under test output directory.");
                string stopFile = connectionFile + ".stop";
                try { while (!File.Exists(stopFile)) await Task.Delay(250); }
                finally { File.Delete(connectionFile); if (File.Exists(stopFile)) File.Delete(stopFile); }
            }
        }
        finally
        {
            await service.DisposeAsync();
            if (Path.GetDirectoryName(folder) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) throw new Exception("Unexpected lab directory");
            Directory.Delete(folder, true);
        }
    }
}
