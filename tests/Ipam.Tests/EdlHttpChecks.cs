// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

static class EdlHttpChecks
{
    // Exercise actual service authentication, middleware and export handler through loopback TLS.
    // No production listener, credential, ACL or platform trust is modified.
    public static async Task<int> Run(DnsWebService service, DdiSecurityManager security, HttpClient administrator, HttpClient dnsOnly, HttpClient reader)
    {
        int checks = 0;
        void Check(bool condition, string reason) { if (!condition) throw new Exception(reason); checks++; }
        using var rsa = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certificateRequest.CertificateExtensions.Add(san.Build());
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var generated = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(certificate)));
        await using var server = builder.Build();
        object api = typeof(DnsWebService).GetField("_securityApi", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(service);
        var middleware = typeof(DnsWebService).GetMethod("WebServiceApiMiddleware", BindingFlags.NonPublic | BindingFlags.Instance);
        var transport = typeof(DnsWebService).GetMethod("WebServiceDirectTransportMiddleware", BindingFlags.NonPublic | BindingFlags.Instance);
        var export = api.GetType().GetMethod("ExportEdl");
        server.MapGet("/api/security/edl/export", async context =>
        {
            RequestDelegate next = ctx => (Task)export.Invoke(api, [ctx]);
            RequestDelegate apiMiddleware = ctx => (Task)middleware.Invoke(service, [ctx, next]);
            await (Task)transport.Invoke(service, [context, apiMiddleware]);
        });
        await server.StartAsync();
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        handler.ServerCertificateCustomValidationCallback = (_, remote, _, errors) =>
        {
            if (remote is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
            using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(certificate); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(remote);
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(server.Urls.Single()) };
        var before = security.Policy;
        string historyPath = Path.Combine((string)typeof(DdiSecurityManager).GetField("_folder", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(security), "security-policy-history.json");
        byte[] history = File.ReadAllBytes(historyPath);
        try
        {
            // Fixture-local publication policy; restore exact revision/content before returning to API suite.
            security.RestorePolicy(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(before with { Indicators = before.Indicators.Append(new("http-selected", "Url", "https://fixture.example/path", "Monitor", "Local")).ToArray(), EdlPublications = [new("fixture", "Url", [new("Local", "http-selected")], true)] }, DdiSecurityManager.JsonOptions));
            using (var anonymous = await client.GetAsync("/api/security/edl/export?list=fixture"))
                Check(anonymous.StatusCode == HttpStatusCode.Unauthorized && (await anonymous.Content.ReadAsStringAsync()).Length == 0, "Anonymous EDL access accepted or leaked JSON");
            using (var alternatePath = await client.GetAsync("/api/security/edl/export/?list=fixture"))
                Check(alternatePath.StatusCode == HttpStatusCode.Unauthorized && (await alternatePath.Content.ReadAsStringAsync()).Length == 0, "Trailing-slash EDL route bypassed raw authentication boundary");
            foreach (var restricted in new[] { dnsOnly, reader })
            {
                client.DefaultRequestHeaders.Authorization = restricted.DefaultRequestHeaders.Authorization;
                using var denied = await client.GetAsync("/api/security/edl/export?list=fixture");
                Check(denied.StatusCode == HttpStatusCode.Forbidden && (await denied.Content.ReadAsStringAsync()).Length == 0, "Restricted role can read EDL");
            }
            client.DefaultRequestHeaders.Authorization = administrator.DefaultRequestHeaders.Authorization;
            using (var allowed = await client.GetAsync("/api/security/edl/export?list=fixture"))
            {
                Check(allowed.StatusCode == HttpStatusCode.OK && allowed.Content.Headers.ContentType.MediaType == "text/plain", "Authorized EDL not plain text");
                Check(await allowed.Content.ReadAsStringAsync() == "https://fixture.example/path\n", "Authenticated EDL contains JSON, event data or lost path");
                Check(allowed.Headers.CacheControl.NoStore && allowed.Headers.GetValues("X-teQtanium-EDL-Action").Single() == "Monitor", "EDL freshness/action contract absent");
            }
            using (var missing = await client.GetAsync("/api/security/edl/export?list=missing")) Check(missing.StatusCode == HttpStatusCode.NotFound, "Unconfigured EDL not 404");
            using (var queryToken = await client.GetAsync("/api/security/edl/export?list=fixture&token=fixture")) Check(queryToken.StatusCode == HttpStatusCode.Unauthorized, "EDL accepted URL token");
            using (var proxy = await client.GetAsync("/api/security/edl/export?list=fixture&node=cluster")) Check(proxy.StatusCode == HttpStatusCode.Unauthorized, "EDL export allows arbitrary node proxy selection");
            client.DefaultRequestHeaders.Authorization = new("Bearer", "invalid-fixture");
            using (var invalid = await client.GetAsync("/api/security/edl/export?list=fixture")) Check(invalid.StatusCode == HttpStatusCode.Unauthorized, "Invalid EDL token accepted");
        }
        finally { security.RestorePolicy(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(before, DdiSecurityManager.JsonOptions)); File.WriteAllBytes(historyPath, history); await server.StopAsync(); }
        Console.WriteLine($"PASS: {checks} authenticated EDL HTTP/TLS boundary checks.");
        return checks;
    }
}
