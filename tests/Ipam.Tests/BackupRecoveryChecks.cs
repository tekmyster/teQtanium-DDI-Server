// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using DnsServerCore;
using DnsServerCore.Dhcp;
using DnsServerCore.Dns;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static class BackupRecoveryChecks
{
    static int _checks;
    static void Check(bool value, string label) { if (!value) throw new Exception(label); _checks++; }
    static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    static string Repository => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
    static async Task<JsonElement> Call(HttpClient client, string path, params (string Key, string Value)[] fields)
    {
        using var content = new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value)));
        using var result = await client.PostAsync(path, content); using var doc = JsonDocument.Parse(await result.Content.ReadAsStringAsync()); return doc.RootElement.Clone();
    }
    static async Task<JsonElement> Preview(HttpClient client, byte[] artifact, string key = null)
    {
        using var content = new MultipartFormDataContent(); content.Add(new ByteArrayContent(artifact), "file", "backup.tqb");
        if (key is not null) content.Add(new StringContent(key), "encryptionKey");
        using var result = await client.PostAsync("/api/settings/migration/preview", content); using var doc = JsonDocument.Parse(await result.Content.ReadAsStringAsync()); return doc.RootElement.Clone();
    }
    static bool Ok(JsonElement value) => value.GetProperty("status").GetString() == "ok";
    static async Task<HttpClient> Login(string url, string password)
    {
        var client = new HttpClient { BaseAddress = new Uri(url), Timeout = TimeSpan.FromSeconds(15) };
        var login = await Call(client, "/api/user/login", ("user", "admin"), ("pass", password)); Check(Ok(login), "Fresh native administrator login");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString()); return client;
    }
    sealed class Native : IAsyncDisposable
    {
        public Process Process;
        public string Folder, Url;
        public int DnsPort;
        public Task<string> Output, Error;
        bool _closed;
        public async ValueTask DisposeAsync()
        {
            if (_closed) return; _closed = true;
            if (!Process.HasExited)
            {
                File.WriteAllText(Path.Combine(Folder, "stop"), "stop");
                try { await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12)); } catch (TimeoutException) { Process.Kill(true); await Process.WaitForExitAsync(); }
            }
            File.WriteAllText(Path.Combine(Folder, "native-" + Process.Id + ".log"), await Output + await Error);
            Console.WriteLine($"NATIVE_CLOSED pid={Process.Id} exit={Process.ExitCode}"); Process.Dispose();
        }
    }
    static async Task<Native> Start(string folder, string password, string phase = "none")
    {
        Directory.CreateDirectory(folder);
        foreach (string item in new[] { "ready.json", "checkpoint", "stop" }) File.Delete(Path.Combine(folder, item));
        var start = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add(typeof(BackupRecoveryChecks).Assembly.Location); start.ArgumentList.Add("--backup-native-child"); start.ArgumentList.Add(folder); start.ArgumentList.Add(phase);
        var process = Process.Start(start); var native = new Native { Process = process, Folder = folder, Output = process.StandardOutput.ReadToEndAsync(), Error = process.StandardError.ReadToEndAsync() };
        await process.StandardInput.WriteLineAsync(password); process.StandardInput.Close();
        for (int i = 0; i < 200 && !File.Exists(Path.Combine(folder, "ready.json")); i++) { if (process.HasExited) throw new Exception("Native child exited: " + await native.Output + await native.Error); await Task.Delay(50); }
        Check(File.Exists(Path.Combine(folder, "ready.json")), "Native ready within 10 seconds");
        using var ready = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(folder, "ready.json"))); native.Url = ready.RootElement.GetProperty("url").GetString(); native.DnsPort = ready.RootElement.GetProperty("dnsPort").GetInt32();
        Console.WriteLine($"NATIVE_READY pid={process.Id} startUtc={process.StartTime.ToUniversalTime():O} dns=127.0.0.1:{native.DnsPort} root={folder} coreSha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(DnsWebService).Assembly.Location)))}");
        return native;
    }
    public static async Task Child(string folder, string phase)
    {
        string password = await Console.In.ReadLineAsync(); int web = Port(), dnsPort = Port();
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", web.ToString());
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(Repository, "DnsServerCore/www"));
        if (!File.Exists(Path.Combine(folder, "dns.config")))
        {
            await using var log = new LogManager(true, folder); using var dns = new DnsServer(folder, Path.Combine(Repository, "DnsServerCore/dohwww"), log);
            dns.LoadConfigFile(); dns.ServerDomain = Path.GetFileName(folder) + ".backup.fixture.test"; dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true);
        }
        await using var service = new DnsWebService(true, folder); await service.StartAsync(true);
        var dnsServer = (DnsServer)typeof(DnsWebService).GetField("_dnsServer", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
        if (phase == "Captured") typeof(DnsWebService).GetField("_backupCheckpoint", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(service, (Action<string>)(point =>
        {
            File.WriteAllText(Path.Combine(folder, "checkpoint"), point); var until = DateTime.UtcNow.AddSeconds(10);
            while (!File.Exists(Path.Combine(folder, "release"))) { if (DateTime.UtcNow > until) throw new TimeoutException("Owned capture fixture was not released."); Thread.Sleep(25); }
        }));
        if (phase == "BackupFlushed")
        {
            object store = typeof(DnsWebService).GetField("_backups", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(service);
            typeof(EncryptedBackupStore).GetField("_checkpoint", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(store, (Action<string>)(point =>
            { File.WriteAllText(Path.Combine(folder, "checkpoint"), point); using var wait = new ManualResetEventSlim(); wait.Wait(); }));
        }
        if (phase is not ("none" or "Captured" or "BackupFlushed")) typeof(DnsWebService).GetField("_migrationCheckpoint", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(service, (Action<string>)(point =>
        {
            if (point != phase) return;
            File.WriteAllText(Path.Combine(folder, "checkpoint"), point);
            // The parent terminates this owned OS process at the persisted boundary.
            using var wait = new ManualResetEventSlim(); wait.Wait();
        }));
        File.WriteAllText(Path.Combine(folder, "ready.json"), JsonSerializer.Serialize(new { url = "http://127.0.0.1:" + service.WebServiceHttpPort, dnsPort = dnsServer.LocalEndPoints.Single().Port, pid = Environment.ProcessId }));
        while (!File.Exists(Path.Combine(folder, "stop"))) await Task.Delay(50);
    }
    static async Task Dns(Native native, string label)
    {
        var clock = Stopwatch.StartNew(); using var udp = new UdpClient(); udp.Connect(IPAddress.Loopback, native.DnsPort);
        var query = new DnsDatagram(4711, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("answer.backup.fixture.test", DnsResourceRecordType.A, DnsClass.IN)]);
        using var wire = new MemoryStream(); query.WriteTo(wire); await udp.SendAsync(wire.ToArray()); var packet = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));
        var answer = DnsDatagram.ReadFrom(new MemoryStream(packet.Buffer));
        Check(answer.RCODE == DnsResponseCode.NoError && answer.AuthoritativeAnswer && answer.Answer.Count == 1 && answer.Answer[0].RDATA is DnsARecordData a && a.Address.Equals(IPAddress.Parse("192.0.2.42")), "Authoritative native DNS " + label);
        Console.WriteLine($"DNS label={label} utc={DateTime.UtcNow:O} pid={native.Process.Id} source=127.0.0.1 observedResponseSource={packet.RemoteEndPoint} rcode=NoError aa=true value=192.0.2.42 elapsedMs={clock.Elapsed.TotalMilliseconds:F2}");
    }
    static async Task Zone(HttpClient client)
    {
        Check(Ok(await Call(client, "/api/zones/create", ("zone", "backup.fixture.test"), ("type", "Primary"))), "Native source zone");
        Check(Ok(await Call(client, "/api/zones/records/add", ("domain", "answer.backup.fixture.test"), ("zone", "backup.fixture.test"), ("type", "A"), ("ipAddress", "192.0.2.42"))), "Native source answer");
    }
    static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var data = new MemoryStream(); using (var zip = new ZipArchive(data, ZipArchiveMode.Create, true)) foreach (var item in entries) { using var file = zip.CreateEntry(item.Name).Open(); file.Write(item.Data); } return data.ToArray();
    }
    static async Task UnitBoundaries(string root, byte[] key)
    {
        byte[] zero = new byte[16], cipher = new byte[16], tag = new byte[16];
        using (var aes = new AesGcm(new byte[32], 16)) aes.Encrypt(new byte[12], zero, cipher, tag);
        Check(Convert.ToHexString(cipher) == "CEA7403D4D606B6E074EC5D3BAF39D18" && Convert.ToHexString(tag) == "D0D1C8A799996BF0265B98B5D48AB919", "NIST AES-256-GCM known-answer vector");
        byte[] one = EncryptedBackupStore.Encrypt(zero, key), two = EncryptedBackupStore.Encrypt(zero, key);
        Check(!one.AsSpan(4, 12).SequenceEqual(two.AsSpan(4, 12)) && EncryptedBackupStore.Decrypt(one, key).SequenceEqual(zero), "Fresh GCM nonce and wrapper roundtrip");
        foreach (int index in new[] { 0, 4, 16, 24, one.Length - 1 })
        {
            byte[] bad = (byte[])one.Clone(); bad[index] ^= 1;
            try { EncryptedBackupStore.Decrypt(bad, key); throw new Exception("Modified encrypted envelope accepted"); } catch (InvalidDataException) { _checks++; }
        }
        string inert = Path.Combine(root, "inert-preimage"); Directory.CreateDirectory(inert); byte[] authority = Encoding.UTF8.GetBytes("inert-newer-permanent-grant-and-epoch-do-not-load"); File.WriteAllBytes(Path.Combine(inert, "dhcp-allocation.json"), authority);
        byte[] backup = Zip(("dns.config", Encoding.UTF8.GetBytes("before")), ("dhcp-allocation.json", Encoding.UTF8.GetBytes("inert-stale-authority")));
        MigrationCheckpoint.Prepare(inert, backup, ["zones/new.zone"]); File.WriteAllText(Path.Combine(inert, "dns.config"), "partial"); Directory.CreateDirectory(Path.Combine(inert, "zones")); File.WriteAllText(Path.Combine(inert, "zones/new.zone"), "partial");
        Check(MigrationCheckpoint.Recover(inert) && File.ReadAllText(Path.Combine(inert, "dns.config")) == "before" && !File.Exists(Path.Combine(inert, "zones/new.zone")), "Idempotent authority-free preimage recovery");
        Check(File.ReadAllBytes(Path.Combine(inert, "dhcp-allocation.json")).SequenceEqual(authority) && !MigrationCheckpoint.Recover(inert), "Permanent grant/epoch inert bytes untouched; repeat recovery no-op");
        string concurrent = Path.Combine(root, "store-concurrency"); Directory.CreateDirectory(concurrent); var entered = new TaskCompletionSource(); var release = new TaskCompletionSource(); bool permitted = true;
        await using var store = new EncryptedBackupStore(concurrent, async authorize => { entered.TrySetResult(); await release.Task; return zero.ToArray(); }, b => Check(b.SequenceEqual(zero), "Captured archive fixture validation"));
        await store.UnlockAsync(key, () => { if (!permitted) throw new UnauthorizedAccessException(); });
        Task<string> first = store.RunAsync(() => { }); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        try { await store.RunAsync(() => { }); throw new Exception("Concurrent backup accepted"); } catch (InvalidOperationException) { _checks++; }
        permitted = false; release.SetResult(); try { await first; throw new Exception("Revoked backup committed"); } catch (UnauthorizedAccessException) { _checks++; }
        Check(!Directory.Exists(Path.Combine(concurrent, "encrypted-backups")) || Directory.GetFiles(Path.Combine(concurrent, "encrypted-backups"), "*.tqb").Length == 0, "Current authorization rechecked after capture wait");
    }
    public static async Task Run()
    {
        string root = Path.GetFullPath(Path.Combine(Repository, "../fixtures/backup-" + Guid.NewGuid().ToString("N"))); Directory.CreateDirectory(root);
        string password = Guid.NewGuid().ToString("N") + "Aa9!"; byte[] key = RandomNumberGenerator.GetBytes(32); string secret = Convert.ToBase64String(key);
        Console.WriteLine("OWNED_ROOT " + root);
        await UnitBoundaries(root, key);
        await using var source = await Start(Path.Combine(root, "source"), password); using var client = await Login(source.Url, password); await Zone(client);
        Check(Ok(await Call(client, "/api/settings/set", ("defaultRecordTtl", "601"))), "Current source setting"); await Dns(source, "before-schedule");
        using var anonymous = new HttpClient { BaseAddress = client.BaseAddress }; Check(!Ok(await Call(anonymous, "/api/settings/backups/status")), "Anonymous backup status denied");
        Check(Ok(await Call(client, "/api/settings/backups/configure", ("enabled", "true"), ("intervalHours", "1"), ("retain", "2"))), "Configure native schedule");
        Check(!Ok(await Call(client, "/api/settings/backups/run")), "Unavailable key does not downgrade encryption");
        Check(Ok(await Call(client, "/api/settings/backups/unlock", ("encryptionKey", secret))), "Unlock scheduled capture");
        JsonElement status = default;
        for (int i = 0; i < 100; i++) { status = (await Call(client, "/api/settings/backups/status")).GetProperty("response").GetProperty("backup"); if (status.GetProperty("files").GetArrayLength() == 1) break; await Dns(source, "scheduled-wait"); await Task.Delay(100); }
        Check(status.GetProperty("completed").GetInt64() == 1, "Real background timer captured due job without manual run");
        string artifactId = status.GetProperty("files")[0].GetString(); byte[] encrypted;
        using (var body = new FormUrlEncodedContent(new Dictionary<string, string> { ["artifact"] = artifactId })) using (var result = await client.PostAsync("/api/settings/backups/download", body)) encrypted = await result.Content.ReadAsByteArrayAsync();
        Check(EncryptedBackupStore.IsEncrypted(encrypted), "Native committed artifact encrypted");
        byte[] plain = EncryptedBackupStore.Decrypt(encrypted, key);
        using (var zip = new ZipArchive(new MemoryStream(plain))) Check(zip.GetEntry("dhcp-allocation.json") is null && zip.GetEntry("auth.config") is null && zip.GetEntry("cluster.config") is null && zip.GetEntry("syslog.json") is null && zip.GetEntry("portable-dns.json") is not null, "Explicit portable coverage excludes authority, identity, credentials, trust and spool");
        await Dns(source, "after-scheduled-commit");
        Check(Ok(await Call(client, "/api/settings/backups/configure", ("enabled", "false"), ("intervalHours", "1"), ("retain", "2"))), "Disable schedule");
        for (int i = 0; i < 3; i++) Check(Ok(await Call(client, "/api/settings/backups/run")), "Manual bounded retention capture");
        status = (await Call(client, "/api/settings/backups/status")).GetProperty("response").GetProperty("backup"); Check(status.GetProperty("files").GetArrayLength() == 2, "Retention preserves two verified encrypted archives");
        string obstacle = Path.Combine(source.Folder, "encrypted-backups"); string held = obstacle + ".retained"; Directory.Move(obstacle, held); File.WriteAllText(obstacle, "owned obstruction");
        try { Check(!Ok(await Call(client, "/api/settings/backups/run")), "Unavailable storage reported failure"); await Dns(source, "storage-failure"); }
        finally { File.Delete(obstacle); Directory.Move(held, obstacle); }
        // A fresh native process retains configuration but never an encryption key or browser capability.
        await source.DisposeAsync();
        await using var restarted = await Start(Path.Combine(root, "source"), password); using var sourceFresh = await Login(restarted.Url, password);
        status = (await Call(sourceFresh, "/api/settings/backups/status")).GetProperty("response").GetProperty("backup"); Check(!status.GetProperty("unlocked").GetBoolean() && status.GetProperty("schedule").GetProperty("Retain").GetInt32() == 2, "New process retains schedule settings and locks secret"); await Dns(restarted, "source-restarted");
        foreach (string phase in new[] { "Prepared", "ComponentsApplied", "Committed" })
        {
            string targetFolder = Path.Combine(root, "target-" + phase.ToLowerInvariant());
            await using var target = await Start(targetFolder, password, phase); using var destination = await Login(target.Url, password);
            Check(Ok(await Call(destination, "/api/settings/set", ("defaultRecordTtl", "902"))), "Destination preimage setting");
            Check(!Ok(await Preview(destination, encrypted, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)))) && !File.Exists(Path.Combine(targetFolder, "migration-pending.zip")), "Wrong key rejected before mutation");
            byte[] tampered = (byte[])encrypted.Clone(); tampered[^1] ^= 1; Check(!Ok(await Preview(destination, tampered, secret)), "Damaged encrypted tag rejected");
            Check(!Ok(await Preview(destination, encrypted[..^1], secret)), "Truncated encrypted artifact rejected");
            foreach (string path in new[] { "../escape.zone", "zones/CON.zone", "dhcp-allocation.json", "auth.config" }) Check(!Ok(await Preview(destination, Zip((path, [1])))), "Unsupported/traversing authority entry rejected: " + path);
            Check(!Ok(await Preview(destination, Zip(("allowed.config", [1]), ("ALLOWED.config", [2])))), "Case-insensitive archive alias rejected");
            if (phase == "Prepared")
            {
                Check(!Ok(await Preview(destination, Zip(("allowed.config", new byte[16 * 1024 * 1024 + 1])))), "Actual expanded file limit enforced");
                byte[] expanded = new byte[16 * 1024 * 1024];
                Check(!Ok(await Preview(destination, Zip(Enumerable.Range(0, 9).Select(i => ("blocklists/large-" + i + ".txt", expanded)).ToArray()))), "Actual total expanded byte limit enforced");
                Check(!Ok(await Preview(destination, Zip(Enumerable.Range(0, 2049).Select(i => ("blocklists/" + i + ".txt", new byte[] { 1 })).ToArray()))), "Archive entry count limit enforced");
                Check(!Ok(await Preview(destination, Zip(("migration-manifest.json", Encoding.UTF8.GetBytes("{\"format\":99,\"hashes\":{}}"))))), "Unknown portable schema version rejected");
            }
            var preview = await Preview(destination, encrypted, secret); Check(Ok(preview) && preview.GetProperty("response").GetProperty("canImport").GetBoolean(), "Authenticated native encrypted preview");
            string operation = preview.GetProperty("response").GetProperty("review").GetString();
            Task<JsonElement> request = Call(destination, "/api/settings/migration/import", ("review", operation));
            for (int i = 0; i < 100 && !File.Exists(Path.Combine(targetFolder, "checkpoint")); i++) { if (request.IsCompleted) throw new Exception("Import completed before interruption: " + (await request).GetProperty("status").GetString()); await Task.Delay(50); }
            Check(File.Exists(Path.Combine(targetFolder, "checkpoint")), "Reached persisted process boundary " + phase);
            await Dns(restarted, "source-during-" + phase); int oldPid = target.Process.Id; target.Process.Kill(true); await target.Process.WaitForExitAsync();
            try { await request; throw new Exception("Interrupted request produced successful reply"); } catch (HttpRequestException) { _checks++; } catch (TaskCanceledException) { _checks++; }
            await target.DisposeAsync();
            await using var recovered = await Start(targetFolder, password); Check(recovered.Process.Id != oldPid, "Distinct native restart PID"); using var current = await Login(recovered.Url, password);
            var receipt = await Call(current, "/api/settings/migration/status", ("operation", operation)); Check(Ok(receipt), "Actor reattached to durable operation");
            var settings = (await Call(current, "/api/settings/get")).GetProperty("response");
            Check(settings.GetProperty("dnsServerDomain").GetString() == Path.GetFileName(targetFolder) + ".backup.fixture.test" && settings.GetProperty("dnsServerLocalEndPoints")[0].GetString().EndsWith(":" + recovered.DnsPort), "Retained destination identity and DNS listener");
            if (phase == "Committed")
            {
                Check(receipt.GetProperty("response").GetProperty("state").GetString() == "Committed" && settings.GetProperty("defaultRecordTtl").GetInt32() == 601, "Lost reply rediscovered committed semantic settings");
                var paths = Directory.GetFiles(targetFolder, "*", SearchOption.AllDirectories).Where(p => p.EndsWith(".zone") || p.EndsWith(".scope") || Path.GetFileName(p) is "dns.config" or "ipam.json" or "security.json" or "migration-operation.json").ToArray();
                var identities = paths.ToDictionary(p => p, p => (Hash: Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))), Written: File.GetLastWriteTimeUtc(p)));
                var beforeInventory = (await Call(current, "/api/ipam/list")).GetProperty("response").GetProperty("inventory").GetRawText();
                Check(Ok(await Call(current, "/api/settings/migration/import", ("review", operation))), "Same committed operation returns receipt without reapplying");
                Check(paths.All(p => identities[p] == (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))), File.GetLastWriteTimeUtc(p))), "Receipt retry preserved exact native files, revisions and write times");
                Check((await Call(current, "/api/ipam/list")).GetProperty("response").GetProperty("inventory").GetRawText() == beforeInventory, "Receipt retry preserved semantic IPAM revision and contents"); await Dns(recovered, "lost-reply-committed-readback");
            }
            else
            {
                Check(receipt.GetProperty("response").GetProperty("state").GetString() == "RolledBackAfterInterruption" && settings.GetProperty("defaultRecordTtl").GetInt32() == 902, "Interrupted import rolled back actual native settings");
                Check((await Call(current, "/api/zones/list")).GetProperty("response").GetProperty("zones").GetArrayLength() == 0, "No partial imported zones after restart rollback");
                Check(!Ok(await Call(current, "/api/settings/migration/import", ("review", operation))), "Interrupted interactive authorization cannot resume application");
                preview = await Preview(current, encrypted, secret); string newOperation = preview.GetProperty("response").GetProperty("review").GetString();
                Check(newOperation != operation && Ok(await Call(current, "/api/settings/migration/import", ("review", newOperation))), "Fresh authorized preview applies after safe rollback"); await Dns(recovered, "fresh-restore-after-" + phase);
                Check((await Call(current, "/api/settings/get")).GetProperty("response").GetProperty("defaultRecordTtl").GetInt32() == 601, "Native restored settings readback");
            }
            Check(Ok(await Call(current, "/api/settings/set", ("defaultRecordTtl", "601"))), "Fresh administrator has required modification privileges after recovery");
            Check(!File.Exists(Path.Combine(targetFolder, "migration-pending.zip")), "Pending checkpoint resolved");
            Console.WriteLine($"RECOVERY phase={phase} oldPid={oldPid} newPid={recovered.Process.Id} operation={operation} nativeReadback=true");
        }
        await restarted.DisposeAsync();
        await using (var waiting = await Start(Path.Combine(root, "source"), password, "Captured"))
        {
            using var delegated = await Login(waiting.Url, password);
            Check(Ok(await Call(delegated, "/api/settings/backups/unlock", ("encryptionKey", secret))), "Native capture-wait key delegation");
            int beforeCount = Directory.GetFiles(Path.Combine(waiting.Folder, "encrypted-backups"), "*.tqb").Length;
            var pending = Call(delegated, "/api/settings/backups/run");
            for (int i = 0; i < 100 && !File.Exists(Path.Combine(waiting.Folder, "checkpoint")); i++) await Task.Delay(25);
            Check(File.Exists(Path.Combine(waiting.Folder, "checkpoint")), "Native backup captured before authorization wait"); await Dns(waiting, "authorization-wait");
            Check(Ok(await Call(delegated, "/api/user/logout")), "Revoke only owned ephemeral operator session");
            File.WriteAllText(Path.Combine(waiting.Folder, "release"), "release"); Check(!Ok(await pending), "Native current authorization denies commit after logout");
            Check(Directory.GetFiles(Path.Combine(waiting.Folder, "encrypted-backups"), "*.tqb").Length == beforeCount, "Revoked native capture persisted no backup");
            using var fresh = await Login(waiting.Url, password); var state = (await Call(fresh, "/api/settings/backups/status")).GetProperty("response").GetProperty("backup"); Check(!state.GetProperty("unlocked").GetBoolean(), "Revoked key delegation cleared in memory");
        }
        await using (var interrupted = await Start(Path.Combine(root, "source"), password, "BackupFlushed"))
        {
            using var current = await Login(interrupted.Url, password); Check(Ok(await Call(current, "/api/settings/backups/unlock", ("encryptionKey", secret))), "Native staged backup unlock");
            var request = Call(current, "/api/settings/backups/run");
            for (int i = 0; i < 100 && !File.Exists(Path.Combine(interrupted.Folder, "checkpoint")); i++) await Task.Delay(25);
            Check(File.Exists(Path.Combine(interrupted.Folder, "checkpoint")), "Encrypted staging flushed before rename"); await Dns(interrupted, "encrypted-staging-before-process-kill");
            interrupted.Process.Kill(true); await interrupted.Process.WaitForExitAsync();
            try { await request; throw new Exception("Interrupted backup returned success"); } catch (HttpRequestException) { _checks++; } catch (TaskCanceledException) { _checks++; }
        }
        await using (var final = await Start(Path.Combine(root, "source"), password))
        {
            using var current = await Login(final.Url, password); var state = (await Call(current, "/api/settings/backups/status")).GetProperty("response").GetProperty("backup");
            Check(!state.GetProperty("unlocked").GetBoolean() && state.GetProperty("interruptedPendingFiles").GetArrayLength() == 1, "New process exposes interrupted encrypted staging without claiming success"); await Dns(final, "after-backup-process-interruption");
            Check(Ok(await Call(current, "/api/settings/backups/unlock", ("encryptionKey", secret))) && Ok(await Call(current, "/api/settings/backups/run")), "Freshly authorized retry reconciles encrypted staging");
            Check(Directory.GetFiles(Path.Combine(final.Folder, "encrypted-backups"), "*.pending-*").Length == 0, "Only exact owned encrypted staging reconciled");
            var artifacts = Directory.GetFiles(Path.Combine(final.Folder, "encrypted-backups"), "*.tqb").Select(File.ReadAllBytes).ToArray(); Check(artifacts.Length == 2 && !artifacts[0].AsSpan(4, 12).SequenceEqual(artifacts[1].AsSpan(4, 12)), "Same-key nonces differ across retry/process restart");
        }
        foreach (string file in Directory.GetFiles(root, "*.log", SearchOption.AllDirectories).Concat(Directory.GetFiles(root, "backup-schedule.json", SearchOption.AllDirectories)))
        { string text = File.ReadAllText(file); Check(!text.Contains(secret, StringComparison.Ordinal) && !text.Contains(password, StringComparison.Ordinal), "No synthetic key/password in logs or persisted schedule"); }
        // Only redacted metadata are reported. Keep owned fixture evidence for the immutable private packet.
        CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plain);
        Console.WriteLine($"PASS backup-recovery checks={_checks}; root={root}; native scheduled encrypted artifact + authenticated preview + DNS/config restoration + three OS-process interruptions including lost response. Online replacement, DHCP packets and host power loss unqualified.");
    }
}
