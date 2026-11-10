using DnsServerCore.Auth;
using DnsServerCore.Dhcp;
using DnsServerCore.Security;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        internal Action<string> _migrationCheckpoint; // Owned native process interruption fixture only.
        readonly SemaphoreSlim _migrationAdmission = new(2, 2);
        readonly SemaphoreSlim _migrationGate = new(1, 1);
        readonly Dictionary<string, MigrationReview> _migrationReviews = new();
        sealed record MigrationReview(string User, DateTime Expires, string Fingerprint, byte[] Package);
        const int MigrationLimit = 16 * 1024 * 1024;
        static readonly HashSet<string> PortableDnsFields = new(("defaultRecordTtl defaultNsRecordTtl defaultSoaRecordTtl defaultResponsiblePerson useSoaSerialDateScheme minSoaRefresh minSoaRetry ipv6Mode preferIPv6 enableUdpSocketPool socketPoolExcludedPorts udpPayloadSize dnssecValidation eDnsClientSubnet eDnsClientSubnetIPv4PrefixLength eDnsClientSubnetIPv6PrefixLength eDnsClientSubnetIpv4Override eDnsClientSubnetIpv6Override qpmPrefixLimitsIPv4 qpmPrefixLimitsIPv6 qpmLimitSampleMinutes qpmLimitUdpTruncationPercentage qpmLimitBypassList clientTimeout tcpSendTimeout tcpReceiveTimeout quicIdleTimeout quicMaxInboundStreams listenBacklog udpSendBufferSizeKB udpReceiveBufferSizeKB maxConcurrentResolutionsPerCore recursion recursionNetworkACL randomizeName qnameMinimization locallyServedDnsZones resolverRetries resolverTimeout resolverConcurrency resolverMaxStackCount saveCache serveStale serveStaleTtl serveStaleAnswerTtl serveStaleResetTtl serveStaleMaxWaitTime cacheMaximumEntries cacheMinimumRecordTtl cacheMaximumRecordTtl cacheNegativeRecordTtl cacheFailureRecordTtl cachePrefetchEligibility cachePrefetchTrigger enableCachePrefetch enableBlocking allowTxtBlockingReport blockingBypassList blockingType blockingAnswerTtl customBlockingAddresses blockListUrls blockListUpdateIntervalHours forwarders forwarderProtocol concurrentForwarding forwarderRetries forwarderTimeout forwarderConcurrency").Split(' '), StringComparer.Ordinal);

        void RequireMigrationAdmin(HttpContext context)
        {
            var session = context.GetCurrentSession();
            User user = _authManager.GetUser(session.User.Username);
            if (session.Type != UserSessionType.Standard || _authManager.GetSession(session.Token) != session || session.HasExpired() || user is null || user.Disabled)
                throw new DnsWebServiceException("The administrator session is no longer authorized. Sign in again.");
            if (!_authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.View) ||
                !_authManager.IsPermitted(PermissionSection.Settings, user, PermissionFlag.Delete) ||
                !_authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.Delete))
                throw new DnsWebServiceException("Administrator access is required to migrate a deployment.");
        }

        DefaultHttpContext MigrationContext(HttpContext original, Utf8JsonWriter writer)
        {
            var copy = new DefaultHttpContext();
            copy.Items["session"] = original.GetCurrentSession(); copy.Items["jsonWriter"] = writer;
            copy.Connection.RemoteIpAddress = original.Connection.RemoteIpAddress;
            copy.Connection.RemotePort = original.Connection.RemotePort;
            copy.Request.Scheme = original.Request.Scheme;
            return copy;
        }

        byte[] PortableDns(HttpContext context = null)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject(); _settingsApi.WriteDnsSettings(writer); writer.WriteEndObject();
            }
            using var document = JsonDocument.Parse(stream.ToArray());
            using var output = new MemoryStream();
            using (var writer = new Utf8JsonWriter(output))
            {
                writer.WriteStartObject();
                foreach (var item in document.RootElement.EnumerateObject())
                    if (PortableDnsFields.Contains(item.Name) && item.Value.ValueKind != JsonValueKind.Null) item.WriteTo(writer);
                writer.WriteEndObject();
            }
            return output.ToArray();
        }

        static byte[] PortableSecurity(byte[] data)
        {
            var policy = JsonSerializer.Deserialize<SecurityPolicy>(data, DdiSecurityManager.JsonOptions) ?? throw new DnsWebServiceException("The security policy is missing.");
            return JsonSerializer.SerializeToUtf8Bytes(policy with { Mode = "Monitor", DeviceDnsResponse = "Monitor", DhcpResponse = "Observe", Misp = new MispSettings(), Llm = new LlmSettings(), EdlFeeds = [], EdlPublications = [] }, DdiSecurityManager.JsonOptions);
        }

        static void AddMigrationEntry(ZipArchive zip, string name, byte[] bytes)
        { using Stream entry = zip.CreateEntry(name, CompressionLevel.Optimal).Open(); entry.Write(bytes); }

        async Task ExportMigrationAsync(HttpContext context)
        {
            RequireMigrationAdmin(context);
            await _migrationGate.WaitAsync();
            byte[] bytes;
            try { RequireMigrationAdmin(context); bytes = await BuildMigrationPackageAsync(); } finally { _migrationGate.Release(); }
            RequireMigrationAdmin(context);
            context.Response.ContentType = "application/zip";
            context.Response.Headers.ContentDisposition = "attachment;filename=ddi-new-deployment.zip";
            context.Response.ContentLength = bytes.Length; await context.Response.Body.WriteAsync(bytes);
            _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] New-deployment package exported.");
        }

        async Task<byte[]> BuildMigrationPackageAsync()
        {
            MigrationCheckpoint.EnsureLocalPaths(_configFolder, ["zones", "scopes", "blocklists", "allowed.config", "blocked.config", "blocklist.config"]);
            using var native = new MemoryStream();
            await BackupConfigAsync(native, false, false, false, false, false, true, true, true, true, false, true, false, false);
            native.Position = 0;
            using var source = new ZipArchive(native, ZipArchiveMode.Read, true);
            using var output = new MemoryStream();
            var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
            using (var package = new ZipArchive(output, ZipArchiveMode.Create, true))
            {
                void Add(string name, byte[] data) { AddMigrationEntry(package, name, data); hashes.Add(name, Convert.ToHexString(SHA256.HashData(data))); }
                foreach (var entry in source.Entries)
                {
                    if (entry.FullName.StartsWith("zones/cluster-catalog.", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".zone", StringComparison.OrdinalIgnoreCase) || entry.FullName.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase)) continue;
                    using Stream input = entry.Open(); using var data = new MemoryStream(); input.CopyTo(data); Add(entry.FullName, data.ToArray());
                }
                foreach (var zone in _dnsServer.AuthZoneManager.GetZones(z => !z.Name.StartsWith("cluster-catalog.", StringComparison.OrdinalIgnoreCase)))
                { using var data = new MemoryStream(); _dnsServer.AuthZoneManager.WriteZoneTo(zone.Name, data); if (data.Length == 0) throw new DnsWebServiceException("A source zone changed. Retry the export."); Add("zones/" + zone.Name.ToLowerInvariant() + ".zone", data.ToArray()); }
                foreach (var scope in _dhcpServer.Scopes.Values)
                { using var data = new MemoryStream(); scope.WriteTo(data); Add("scopes/" + scope.Name + ".scope", data.ToArray()); }
                Add("portable-dns.json", PortableDns()); Add("ipam.json", _ipam.Export()); Add("security.json", PortableSecurity(_security.ExportPolicy()));
                AddMigrationEntry(package, "migration-manifest.json", JsonSerializer.SerializeToUtf8Bytes(new { format = 1, artifact = Guid.NewGuid().ToString("N"), createdUtc = DateTime.UtcNow, source = _dnsServer.ServerDomain, scope = "StandalonePortableConfiguration", consistency = "Per-component snapshots; concurrent configuration changes are not a global transaction.", hashes }));
            }
            byte[] bytes = output.ToArray();
            if (bytes.Length > MigrationLimit) throw new DnsWebServiceException("The migration package exceeds 16 MiB. Use selective configuration backups for this deployment.");
            ReadMigration(bytes);
            return bytes;
        }

        Dictionary<string, byte[]> ReadMigration(byte[] bytes)
        {
            try { return ReadMigrationFiles(bytes); }
            catch (DnsWebServiceException) { throw; }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or KeyNotFoundException or InvalidOperationException or EndOfStreamException or ArgumentException)
            { _log.Write(ex); throw new DnsWebServiceException("The ZIP file or its manifest is invalid. Select a valid backup or export a new package."); }
        }

        Dictionary<string, byte[]> ReadMigrationFiles(byte[] bytes)
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            if (bytes.Length > MigrationLimit) throw new DnsWebServiceException("The decrypted package exceeds 16 MiB.");
            if (zip.Entries.Count > 2048) throw new DnsWebServiceException("The package contains too many files.");
            var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase); long total = 0;
            foreach (var entry in zip.Entries)
            {
                if (entry.FullName == "dns.config") throw new DnsWebServiceException("Node-specific DNS settings are not portable. Export a new-deployment package.");
                if (entry.FullName.Length > 512 || entry.FullName.Split('/').Any(p => p.Length > 255 || p.EndsWith('.') || p.EndsWith(' ') || new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(p.Split('.')[0], StringComparer.OrdinalIgnoreCase))) throw new DnsWebServiceException("The package contains an unsupported file name.");
                if (entry.FullName is not ("migration-manifest.json" or "portable-dns.json" or "ipam.json" or "security.json" or "allowed.config" or "blocked.config" or "blocklist.config") && !MigrationCheckpoint.Allows(entry.FullName)) throw new DnsWebServiceException("The package contains unsupported data. Export a new-deployment package instead of importing node identity or allocation authority.");
                if (entry.FullName.IndexOfAny(['\\', ':', '<', '>', '"', '|', '?', '*', '\0']) >= 0 || entry.FullName.StartsWith('/') || entry.FullName.Split('/').Any(x => x is ".." or "." or "") || entry.FullName.Split('/').Length > 8 || ((entry.FullName.StartsWith("zones/", StringComparison.OrdinalIgnoreCase) || entry.FullName.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase) || entry.FullName.StartsWith("blocklists/", StringComparison.OrdinalIgnoreCase)) && entry.FullName.Split('/').Length != 2))
                    throw new DnsWebServiceException("The package contains an invalid file path.");
                total += entry.Length;
                if (entry.Length > MigrationLimit || total > 128L * 1024 * 1024) throw new DnsWebServiceException("The expanded package exceeds the migration limit.");
                using Stream input = entry.Open(); using var data = new MemoryStream();
                byte[] buffer = new byte[8192]; int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                { if (data.Length + read > MigrationLimit) throw new DnsWebServiceException("An expanded file exceeds the migration limit."); data.Write(buffer, 0, read); }
                if (data.Length != entry.Length) throw new DnsWebServiceException("The package contains a damaged file.");
                if (!files.TryAdd(entry.FullName, data.ToArray())) throw new DnsWebServiceException("The package contains duplicate files.");
            }
            if (files.TryGetValue("migration-manifest.json", out byte[] manifest))
            {
                using var doc = JsonDocument.Parse(manifest);
                if (doc.RootElement.GetProperty("format").GetInt32() != 1) throw new DnsWebServiceException("This migration package version is not supported.");
                var hashes = doc.RootElement.GetProperty("hashes");
                if (hashes.EnumerateObject().Count() != files.Count - 1) throw new DnsWebServiceException("The package manifest does not match its files.");
                foreach (var file in files.Where(x => x.Key != "migration-manifest.json"))
                    if (!hashes.TryGetProperty(file.Key, out var digest) || !Convert.ToHexString(SHA256.HashData(file.Value)).Equals(digest.GetString(), StringComparison.OrdinalIgnoreCase))
                        throw new DnsWebServiceException("Package verification failed. Export a new package from the source.");
            }
            if (files.TryGetValue("portable-dns.json", out byte[] portable))
            { using var doc = JsonDocument.Parse(portable); if (doc.RootElement.ValueKind != JsonValueKind.Object || doc.RootElement.EnumerateObject().Any(x => !PortableDnsFields.Contains(x.Name))) throw new DnsWebServiceException("The package contains deployment-specific DNS settings."); }
            foreach (var file in files.Where(x => x.Key.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase)))
            { if (!file.Key.EndsWith(".scope", StringComparison.OrdinalIgnoreCase)) throw new DnsWebServiceException("An unsupported DHCP file was found."); using var scope = new Scope(new MemoryStream(file.Value), _log, _dhcpServer); if (scope.Name != Path.GetFileNameWithoutExtension(file.Key)) throw new DnsWebServiceException("A DHCP scope name does not match its package file."); }
            return files;
        }

        string MigrationBlocker()
        {
            if (_clusterManager.ClusterInitialized) return "Use a standalone destination before joining a cluster.";
            if (_dnsServer.AuthZoneManager.GetZones(_ => true).Count > 0 || _dhcpServer.Scopes.Values.Any(s => s.Enabled || s.Leases.Count > 0 || s.Name != "Default"))
                return "Use a new deployment with no zones or configured DHCP scopes.";
            if (_allocation.Snapshot() is var authority && (authority.Plans.Length > 0 || authority.Replicas.Length > 0 || (authority.Bootstraps?.Length ?? 0) > 0 || (authority.NativeHolds?.Length ?? 0) > 0 || (authority.Changes?.Length ?? 0) > 0)) return "The destination already owns distributed DHCP capacity.";
            return null;
        }

        string MigrationFingerprint(HttpContext context)
        {
            MigrationCheckpoint.EnsureLocalPaths(_configFolder, ["zones", "scopes", "blocklists"]);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (string file in Directory.EnumerateFiles(_configFolder, "*", SearchOption.AllDirectories).Where(x => x.EndsWith(".zone", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".scope", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(x) is "dns.config" or "allowed.config" or "blocked.config" or "blocklist.config" || Path.GetDirectoryName(x) == Path.Combine(_configFolder, "blocklists")).OrderBy(x => x, StringComparer.Ordinal))
            { hash.AppendData(Encoding.UTF8.GetBytes(Path.GetRelativePath(_configFolder, file))); hash.AppendData(File.ReadAllBytes(file)); }
            hash.AppendData(PortableDns(context));
            hash.AppendData(Encoding.UTF8.GetBytes(_dnsServer.ServerDomain + string.Join(",", _dnsServer.LocalEndPoints)));
            foreach (var scope in _dhcpServer.Scopes.Values.OrderBy(s => s.Name, StringComparer.Ordinal))
            { using var encoded = new MemoryStream(); scope.WriteTo(encoded); hash.AppendData(encoded.ToArray()); }
            hash.AppendData(_ipam.Export()); hash.AppendData(_security.ExportPolicy()); hash.AppendData(_allocation.Export());
            return Convert.ToHexString(hash.GetHashAndReset());
        }

        async Task PreviewMigrationAsync(HttpContext context)
        {
            RequireMigrationAdmin(context);
            if (!await _migrationAdmission.WaitAsync(0)) throw new DnsWebServiceException("Two packages are being checked. Retry after a preview completes.");
            try
            {
            IFormFile file = context.Request.Form.Files.Count == 1 ? context.Request.Form.Files[0] : null;
            if (file is null || file.Length == 0 || file.Length > MigrationLimit + 40) throw new DnsWebServiceException("Select one ZIP file up to 16 MiB.");
            using var data = new MemoryStream();
            byte[] buffer = new byte[8192]; using (var input = file.OpenReadStream())
            { int read; while ((read = await input.ReadAsync(buffer)) > 0) { if (data.Length + read > MigrationLimit + 40) throw new DnsWebServiceException("The backup exceeds 16 MiB."); data.Write(buffer, 0, read); } }
            byte[] bytes = data.ToArray();
            if (EncryptedBackupStore.IsEncrypted(bytes))
            {
                byte[] key = EncryptedBackupStore.ParseKey(context.Request.Form["encryptionKey"]);
                try { bytes = EncryptedBackupStore.Decrypt(bytes, key); } finally { CryptographicOperations.ZeroMemory(key); }
            }
            RequireMigrationAdmin(context);
            var files = ReadMigration(bytes);
            if (!files.Keys.Any(x => x.StartsWith("zones/", StringComparison.OrdinalIgnoreCase) || x.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase)) && !files.ContainsKey("portable-dns.json"))
                throw new DnsWebServiceException("No DNS records or DHCP scopes were found in this package.");
            string blocker = MigrationBlocker();
            if (files.Keys.Any(x => x.StartsWith("zones/cluster-catalog.", StringComparison.OrdinalIgnoreCase))) blocker = "Export a new-deployment package to exclude cluster catalog identity.";
            string review = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            await _migrationGate.WaitAsync();
            try
            {
                RequireMigrationAdmin(context);
                foreach (string expired in _migrationReviews.Where(x => x.Value.Expires < DateTime.UtcNow || x.Value.User == GetSessionUser(context).Username).Select(x => x.Key).ToArray()) { CryptographicOperations.ZeroMemory(_migrationReviews[expired].Package); _migrationReviews.Remove(expired); }
                if (_migrationReviews.Count >= 4) throw new DnsWebServiceException("Too many packages are awaiting review. Retry after ten minutes.");
                _migrationReviews.Add(review, new(GetSessionUser(context).Username, DateTime.UtcNow.AddMinutes(10), MigrationFingerprint(context), bytes));
            }
            finally { _migrationGate.Release(); }
            var writer = context.GetCurrentJsonWriter();
            writer.WriteString("review", review); writer.WriteBoolean("canImport", blocker is null); if (blocker is not null) writer.WriteString("reason", blocker);
            writer.WriteNumber("zones", files.Keys.Count(x => x.StartsWith("zones/", StringComparison.OrdinalIgnoreCase) && x.EndsWith(".zone", StringComparison.OrdinalIgnoreCase)));
            writer.WriteNumber("scopes", files.Keys.Count(x => x.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase)));
            writer.WriteBoolean("dnsSettings", files.ContainsKey("portable-dns.json")); writer.WriteBoolean("inventory", files.ContainsKey("ipam.json")); writer.WriteBoolean("security", files.ContainsKey("security.json"));
            writer.WriteBoolean("verifiedManifest", files.ContainsKey("migration-manifest.json"));
            }
            finally { _migrationAdmission.Release(); }
        }

        async Task ImportMigrationAsync(HttpContext context)
        {
            RequireMigrationAdmin(context); string id = context.Request.GetQueryOrForm("review");
            byte[] consumed = null;
            await _migrationGate.WaitAsync();
            try
            {
                RequireMigrationAdmin(context);
                var previous = MigrationCheckpoint.GetReceipt(_configFolder);
                if (previous?.Operation == id && previous.Actor == GetSessionUser(context).Username && previous.State == "Committed")
                { context.GetCurrentJsonWriter().WriteString("operation", id); context.GetCurrentJsonWriter().WriteString("state", "Committed"); context.GetCurrentJsonWriter().WriteBoolean("dhcpDisabledAtCommit", true); context.GetCurrentJsonWriter().WriteBoolean("requiresCurrentReadback", true); return; }
                if (!_migrationReviews.TryGetValue(id, out var review) || review.User != GetSessionUser(context).Username || review.Expires < DateTime.UtcNow)
                    throw new DnsWebServiceException("The review expired. Preview the package again.");
                string blocker = MigrationBlocker(); if (blocker is not null) throw new DnsWebServiceException(blocker);
                if (review.Fingerprint != MigrationFingerprint(context)) throw new DnsWebServiceException("The destination changed. Preview the package again.");
                var files = ReadMigration(review.Package);
                if (files.Keys.Any(x => x.StartsWith("zones/cluster-catalog.", StringComparison.OrdinalIgnoreCase))) throw new DnsWebServiceException("Cluster catalog identity cannot be imported.");
                _migrationReviews.Remove(id); consumed = review.Package;
                string recovery = "migration-before-" + Guid.NewGuid().ToString("N") + ".zip";
                using var before = new MemoryStream();
                await BackupConfigAsync(before, false, false, false, true, false, true, true, true, true, false, true, false, false);
                byte[] recoveryBytes = MigrationCheckpoint.FilterNativeBackup(before.ToArray());
                before.SetLength(0); before.Write(recoveryBytes); before.Position = 0;
                RequireMigrationAdmin(context);
                var operation = new MigrationCheckpoint.Receipt(id, GetSessionUser(context).Username, Convert.ToHexString(SHA256.HashData(review.Package)), review.Fingerprint, DateTime.UtcNow, "Prepared");
                MigrationCheckpoint.Record(_configFolder, operation);
                MigrationCheckpoint.Prepare(_configFolder, recoveryBytes, files.Keys);
                operation = operation with { CheckpointSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(_configFolder, "migration-pending.zip")))) };
                MigrationCheckpoint.Record(_configFolder, operation);
                _migrationCheckpoint?.Invoke("Prepared");
                using (var backup = new FileStream(Path.Combine(_configFolder, recovery), FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { if (OperatingSystem.IsLinux()) File.SetUnixFileMode(Path.Combine(_configFolder, recovery), UnixFileMode.UserRead | UnixFileMode.UserWrite); await backup.WriteAsync(before.ToArray()); backup.Flush(true); }
                AllocationDurability.SyncDirectory(_configFolder);
                try
                {
                    RequireMigrationAdmin(context);
                    using var safe = new MemoryStream();
                    using (var zip = new ZipArchive(safe, ZipArchiveMode.Create, true))
                    {
                        foreach (var file in files)
                        {
                            if (file.Key.StartsWith("zones/", StringComparison.OrdinalIgnoreCase) || file.Key.StartsWith("blocklists/", StringComparison.OrdinalIgnoreCase) || file.Key is "allowed.config" or "blocked.config" or "blocklist.config") AddMigrationEntry(zip, file.Key, file.Value);
                            else if (file.Key.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase))
                            { using var scope = new Scope(new MemoryStream(file.Value), _log, _dhcpServer); using var encoded = new MemoryStream(); scope.WriteTo(encoded, true, false); AddMigrationEntry(zip, file.Key, encoded.ToArray()); }
                        }
                    }
                    safe.Position = 0;
                    await RestoreConfigAsync(safe, false, false, false, false, false, true, true, true, true, false, true, false, false, false);
                    _migrationCheckpoint?.Invoke("ComponentsApplied");
                    RequireMigrationAdmin(context);
                    if (files.TryGetValue("portable-dns.json", out byte[] settings))
                    {
                        using var doc = JsonDocument.Parse(settings);
                        if (doc.RootElement.EnumerateObject().Any(x => !PortableDnsFields.Contains(x.Name))) throw new DnsWebServiceException("The package contains deployment-specific DNS settings.");
                        using var discarded = new MemoryStream(); using var writer = new Utf8JsonWriter(discarded); writer.WriteStartObject();
                        var copy = MigrationContext(context, writer); copy.Request.ContentType = "application/json"; copy.Request.Body = new MemoryStream(settings);
                        await _settingsApi.SetDnsSettingsAsync(copy); writer.WriteEndObject();
                    }
                    RequireMigrationAdmin(context);
                    if (files.TryGetValue("ipam.json", out byte[] inventory)) _ipam.Restore(inventory);
                    if (files.TryGetValue("security.json", out byte[] policy)) _security.RestorePolicy(PortableSecurity(policy));
                    foreach (string name in files.Keys.Where(x => x.StartsWith("zones/", StringComparison.OrdinalIgnoreCase) && x.EndsWith(".zone", StringComparison.OrdinalIgnoreCase)))
                    {
                        var zone = _dnsServer.AuthZoneManager.GetAuthZoneInfo(Path.GetFileNameWithoutExtension(name));
                        if (zone is null) throw new DnsWebServiceException("A zone could not be loaded.");
                        if (zone.CatalogZoneName?.StartsWith("cluster-catalog.", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            zone.ApexZone.CatalogZoneName = null;
                            using var encoded = new MemoryStream(); _dnsServer.AuthZoneManager.WriteZoneTo(zone.Name, encoded);
                            string folder = Path.Combine(_configFolder, "zones"), destination = Path.Combine(folder, zone.Name.ToLowerInvariant() + ".zone");
                            string temporary = destination + ".migration-" + Guid.NewGuid().ToString("N");
                            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { encoded.Position = 0; encoded.CopyTo(output); output.Flush(true); }
                            File.Move(temporary, destination, true); AllocationDurability.SyncDirectory(folder);
                        }
                    }
                    foreach (string name in files.Keys.Where(x => x.StartsWith("scopes/", StringComparison.OrdinalIgnoreCase)))
                    { var scope = _dhcpServer.GetScope(Path.GetFileNameWithoutExtension(name)); if (scope is null || scope.Enabled) throw new DnsWebServiceException("A disabled DHCP scope could not be loaded."); }
                    // Restored zones need administrative permissions before the next startup.
                    InspectAndFixZonePermissions();
                    _dnsServer.SaveConfigFile(true);
                    RequireMigrationAdmin(context);
                    MigrationCheckpoint.Record(_configFolder, operation with { State = "Committed" });
                    MigrationCheckpoint.Complete(_configFolder);
                    _migrationCheckpoint?.Invoke("Committed");
                }
                catch
                {
                    before.Position = 0;
                    try { await RestoreConfigAsync(before, false, false, false, true, false, true, true, true, true, false, true, false, false, true); _dnsServer.SaveConfigFile(true); MigrationCheckpoint.Record(_configFolder, operation with { State = "RolledBack" }); MigrationCheckpoint.Complete(_configFolder); }
                    catch (Exception ex) { _log.Write(ex); throw new DnsWebServiceException("Migration and automatic recovery did not complete. Restore the retained pre-import backup before using this deployment."); }
                    throw new DnsWebServiceException("Migration did not complete. The destination configuration was restored; a recovery backup is retained in its configuration folder.");
                }
                _log.Write(GetRemoteEndPoint(context), "[" + GetSessionUser(context).Username + "] New-deployment migration completed; recovery backup: " + recovery);
                context.GetCurrentJsonWriter().WriteString("operation", id);
                context.GetCurrentJsonWriter().WriteString("state", "Committed");
                context.GetCurrentJsonWriter().WriteString("recoveryBackup", recovery);
                context.GetCurrentJsonWriter().WriteBoolean("dhcpDisabled", true);
            }
            finally { if (consumed is not null) CryptographicOperations.ZeroMemory(consumed); _migrationGate.Release(); }
        }
    }
}
