// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Security;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

static class DirectTransportChecks
{
    static int Port() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
    static async Task<JsonElement> Call(HttpClient client, string path, params (string, string)[] fields)
    {
        using var response = await client.PostAsync(path, new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Item1, f.Item2))));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-actual-transport-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
        int checks = 0;
        void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; }
        int http = Port(), https = Port(), dnsPort = Port(); string password = Guid.NewGuid().ToString("N") + "Aa!9";
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        string pfx = Path.Combine(folder, "fixture.pfx"); File.WriteAllBytes(pfx, certificate.Export(X509ContentType.Pfx));
        var environment = new Dictionary<string, string>
        {
            ["DNS_SERVER_ADMIN_PASSWORD"] = password, ["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] = "127.0.0.1",
            ["DNS_SERVER_WEB_SERVICE_HTTP_PORT"] = http.ToString(), ["DNS_SERVER_WEB_SERVICE_HTTPS_PORT"] = https.ToString(),
            ["DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS"] = "true", ["DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT"] = "false",
            ["DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH"] = pfx, ["DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH"] = Path.Combine(repository, "DnsServerCore/www")
        };
        var prior = environment.ToDictionary(e => e.Key, e => Environment.GetEnvironmentVariable(e.Key));
        foreach (var entry in environment) Environment.SetEnvironmentVariable(entry.Key, entry.Value);
        try
        {
            await using (var log = new LogManager(true, folder))
            using (var dns = new DnsServer(folder, Path.Combine(repository, "DnsServerCore/dohwww"), log))
            { dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
            await using var service = new DnsWebService(true, folder);
            var auth = (AuthManager)typeof(DnsWebService).GetField("_authManager", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(service);
            // Exercise the actual optional middleware, without contacting an identity provider.
            auth.SsoEnabled = true; auth.SsoAuthority = new("https://127.0.0.1:1/fixture"); auth.SsoClientId = "fixture"; auth.SsoClientSecret = "fixture";
            await service.StartAsync(true);
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            handler.ServerCertificateCustomValidationCallback = (_, remote, _, errors) =>
            {
                if (remote is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(certificate); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; return chain.Build(remote);
            };
            using var original = new HttpClient(handler, false) { BaseAddress = new($"https://127.0.0.1:{https}") };
            var login = await Call(original, "/api/user/login", ("user", "admin"), ("pass", password)); original.DefaultRequestHeaders.Authorization = new("Bearer", login.GetProperty("token").GetString());
            using var fresh = new HttpClient(handler, false) { BaseAddress = original.BaseAddress };
            var freshLogin = await Call(fresh, "/api/user/login", ("user", "admin"), ("pass", password)); fresh.DefaultRequestHeaders.Authorization = new("Bearer", freshLogin.GetProperty("token").GetString());
            var inventory = await Call(fresh, "/api/ipam/list");
            var modified = await Call(fresh, "/api/ipam/views/set", ("revision", inventory.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64().ToString()), ("name", "Fresh fixture"));
            Check(modified.GetProperty("status").GetString() == "ok" && auth.GetSession(freshLogin.GetProperty("token").GetString()).LastSeenRemoteAddress.Equals(IPAddress.Loopback), "Fresh administrative privileges/source failed while original remained open");
            string readerPassword = Guid.NewGuid().ToString("N") + "Bb!9";
            Check((await Call(original, "/api/admin/users/create", ("user", "edl-reader"), ("pass", readerPassword))).GetProperty("status").GetString() == "ok", "Reader fixture creation failed");
            var readerUser = auth.GetUser("edl-reader"); auth.SetPermission(PermissionSection.Settings, readerUser, PermissionFlag.View); auth.SetPermission(PermissionSection.Administration, readerUser, PermissionFlag.View);
            using var reader = new HttpClient(handler, false) { BaseAddress = original.BaseAddress };
            var readerLogin = await Call(reader, "/api/user/login", ("user", "edl-reader"), ("pass", readerPassword)); reader.DefaultRequestHeaders.Authorization = new("Bearer", readerLogin.GetProperty("token").GetString());
            var security = (DdiSecurityManager)typeof(DnsWebService).GetField("_security", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(service);
            security.SetPolicy(SecurityPolicy.Default with { Indicators = [new("selected", "Url", "https://selected.example/path", "Monitor", "Local")], EdlPublications = [new("selected", "Url", [new("Local", "selected")], true)] }, 0);
            Check((await Call(reader, "/api/security/policy/get")).GetProperty("status").GetString() == "ok" && auth.GetSession(readerLogin.GetProperty("token").GetString()).LastSeenRemoteAddress.Equals(IPAddress.Loopback), "Fresh reader authentication/source failed");
            Check((await Call(reader, "/api/security/policy/set", ("revision", "1"), ("policy", JsonSerializer.Serialize(security.Policy, DdiSecurityManager.JsonOptions)))).GetProperty("status").GetString() == "error", "Read-only fixture can modify policy");
            foreach (string forwarded in new[] { "https", "http" })
            {
                reader.DefaultRequestHeaders.Remove("X-Forwarded-Proto"); reader.DefaultRequestHeaders.Add("X-Forwarded-Proto", forwarded);
                using var output = await reader.GetAsync("/api/security/edl/export?list=selected");
                Check(output.StatusCode == HttpStatusCode.OK && await output.Content.ReadAsStringAsync() == "https://selected.example/path\n", "Actual TLS incorrectly depends on forwarded origin scheme");
            }
            using var plain = new HttpClient { BaseAddress = new($"http://127.0.0.1:{http}") }; plain.DefaultRequestHeaders.Authorization = reader.DefaultRequestHeaders.Authorization;
            foreach (string path in new[] { "/api/security/edl/export", "/API/SECURITY/EDL/EXPORT", "/api/security/edl/%65xport", "/api/security/edl/export/", "/api/security/edl/export//" })
            foreach (string forwarded in new[] { "", "https" })
            {
                plain.DefaultRequestHeaders.Remove("X-Forwarded-Proto"); if (forwarded.Length > 0) plain.DefaultRequestHeaders.Add("X-Forwarded-Proto", forwarded);
                using var output = await plain.GetAsync(path + "?list=selected");
                Check(output.StatusCode == HttpStatusCode.Forbidden && (await output.Content.ReadAsStringAsync()).Length == 0, "Plain listener accepted forwarded TLS representation: " + path);
            }
            using var anonymous = new HttpClient(handler, false) { BaseAddress = original.BaseAddress };
            using (var output = await anonymous.GetAsync("/api/security/edl/export?list=selected")) Check(output.StatusCode == HttpStatusCode.Unauthorized, "TLS removed authentication boundary");
            using (var output = await anonymous.GetAsync("/api/security/edl//export?list=selected")) Check(!(await output.Content.ReadAsStringAsync()).Contains("selected.example"), "Non-route leaked selected intelligence");
            Console.WriteLine($"PASS: {checks} actual-listener SSO/direct-TLS checks; fresh admin read/modify and read-only reader source 127.0.0.1 verified with original open; no OIDC-provider login claim.");
        }
        finally { foreach (var entry in prior) Environment.SetEnvironmentVariable(entry.Key, entry.Value); Directory.Delete(folder, true); }
    }
}
