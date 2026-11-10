// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Logging;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static partial class SyslogReliabilityChecks
{
    static int _checks;
    static void Check(bool value, string why) { if (!value) throw new Exception(why); Interlocked.Increment(ref _checks); }
    static async Task Until(Func<bool> ready, int seconds = 15) { using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(seconds)); while (!ready()) await Task.Delay(20, stop.Token); }
    static string Folder(string root, string name) { string folder = Path.Combine(root, name); Directory.CreateDirectory(folder); return folder; }
    static int Port() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
    sealed class Certificates : IDisposable
    {
        readonly RSA _key = RSA.Create(2048);
        public X509Certificate2 Ca { get; }
        public string Trust => Convert.ToBase64String(Ca.RawData);
        public Certificates() {
            var request = new CertificateRequest("CN=Owned syslog fixture CA", _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            Ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(2));
        }
        public X509Certificate2 Leaf(bool wrongName = false, bool expired = false) {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Owned syslog receiver", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); if (wrongName) san.AddDnsName("wrong.fixture.test"); else san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var leaf = request.Create(Ca, DateTimeOffset.UtcNow.AddDays(-1), expired ? DateTimeOffset.UtcNow.AddHours(-1) : DateTimeOffset.UtcNow.AddHours(2), RandomNumberGenerator.GetBytes(16));
            using var withKey = leaf.CopyWithPrivateKey(key);
            return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);
        }
        public void Dispose() { Ca.Dispose(); _key.Dispose(); }
    }
    sealed class Receiver : IAsyncDisposable
    {
        readonly TcpListener _listener;
        readonly CancellationTokenSource _stop = new();
        readonly Task _accept;
        readonly ConcurrentBag<Task> _clients = new();
        readonly X509Certificate2 _certificate;
        readonly string _mode;
        public readonly Channel<byte[]> Records = Channel.CreateUnbounded<byte[]>();
        public int Accepted, Handshakes, PartialBytes;
        public readonly ConcurrentBag<string> PeerAddresses = new();
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public Receiver(X509Certificate2 certificate, string mode = "Read", int port = 0) { _certificate = certificate; _mode = mode; _listener = new(IPAddress.Loopback, port); _listener.Start(); Console.WriteLine($"OWNED_RECEIVER mode={mode}; address=127.0.0.1; port={Port}; expectedPeer=127.0.0.1"); _accept = Accept(); }
        async Task Accept() {
            try { while (!_stop.IsCancellationRequested) { var client = await _listener.AcceptTcpClientAsync(_stop.Token); Interlocked.Increment(ref Accepted); PeerAddresses.Add(((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString()); _clients.Add(Read(client)); } }
            catch (Exception) when (_stop.IsCancellationRequested) { }
        }
        async Task Read(TcpClient client) {
            using (client) {
                try {
                    if (_mode == "NoHandshake") { await Task.Delay(Timeout.Infinite, _stop.Token); return; }
                    using var stream = new SslStream(client.GetStream(), false);
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate, EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 }, _stop.Token);
                    Interlocked.Increment(ref Handshakes);
                    if (_mode == "Hold") { await Task.Delay(Timeout.Infinite, _stop.Token); return; }
                    if (_mode == "Partial") { byte[] part = new byte[20]; await stream.ReadExactlyAsync(part, _stop.Token); PartialBytes = part.Length; client.Client.LingerState = new(true, 0); return; }
                    while (!_stop.IsCancellationRequested) {
                        int length = 0, digits = 0; byte[] one = new byte[1];
                        while (true) { await stream.ReadExactlyAsync(one, _stop.Token); if (one[0] == 32) break; Check(one[0] >= 48 && one[0] <= 57 && ++digits <= 5, "Invalid octet prefix"); length = length * 10 + one[0] - 48; }
                        Check(length is > 0 and <= 8192, "Invalid payload length"); byte[] bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, _stop.Token); await Records.Writer.WriteAsync(bytes, _stop.Token);
                    }
                } catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException or SocketException) { }
            }
        }
        public async Task<string> Next() => new UTF8Encoding(false, true).GetString(await Records.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15)));
        bool _disposed;
        public async ValueTask DisposeAsync() { if (_disposed) return; _disposed=true; int port=Port; _stop.Cancel(); _listener.Stop(); await _accept; await Task.WhenAll(_clients); _stop.Dispose(); Console.WriteLine($"OWNED_RECEIVER_CLOSED port={port}; clientsCompleted=true"); }
    }
    static SyslogSettings Settings(int port, string ca) => new(Enabled: true, Server: "127.0.0.1", Port: port, Transport: "Tls", TlsCaCertificate: ca);
    public static async Task Child(string folder, string phase) {
        await using var sender = new SyslogForwarder(folder, () => "child.fixture.test");
        if (phase == "persist") { Check(sender.RecordSystem("distinct-process-persisted-π"), "Child admission"); await Until(() => sender.Health.Persisted == 1); Console.WriteLine("PERSISTED pid=" + Environment.ProcessId); Console.Out.Flush(); Environment.Exit(73); }
        else { await Until(() => sender.Health.Sent == 1); Check(sender.Health.Replayed == 1, "Restart did not load persisted record"); Console.WriteLine("REPLAYED pid=" + Environment.ProcessId + " " + JsonSerializer.Serialize(sender.Health)); }
    }
    static async Task<(int Pid, int Exit, string Output)> Process(string folder, string phase) {
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add(typeof(SyslogReliabilityChecks).Assembly.Location); start.ArgumentList.Add("--syslog-child"); start.ArgumentList.Add(folder); start.ArgumentList.Add(phase);
        using var process = System.Diagnostics.Process.Start(start)!; var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25)); } catch { process.Kill(true); await process.WaitForExitAsync(); throw; }
        return (process.Id, process.ExitCode, await output + await error);
    }
    static async Task DnsFaultChecks(string folder, SyslogForwarder sender) {
        int port = Port(); await using var log = new LogManager(true, folder);
        await using var dns = new DnsServer(folder, Path.Combine(AppContext.BaseDirectory, "dohwww"), log);
        dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback, port)]; dns.Recursion = DnsServerRecursion.Deny; dns.EnableCheckForUpdate = false; dns.SyslogForwarder = sender;
        dns.AuthZoneManager.CreatePrimaryZone("syslog.fixture.test");
        dns.AuthZoneManager.SetRecord("syslog.fixture.test", new DnsResourceRecord("answer.syslog.fixture.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.42"))));
        await dns.StartAsync(true); var elapsed = Stopwatch.StartNew(); var timings = new List<double>();
        for (int i = 0; i < 50; i++) {
            using var client = new UdpClient(); client.Connect(IPAddress.Loopback, port);
            var query = new DnsDatagram((ushort)i, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("answer.syslog.fixture.test", DnsResourceRecordType.A, DnsClass.IN)]);
            using var wire = new MemoryStream(); query.WriteTo(wire); var timer = Stopwatch.StartNew(); await client.SendAsync(wire.ToArray());
            var response = await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3)); using var input = new MemoryStream(response.Buffer); var answer = DnsDatagram.ReadFrom(input); timings.Add(timer.Elapsed.TotalMilliseconds);
            Check(answer.RCODE == DnsResponseCode.NoError && answer.Answer.Count == 1 && answer.AuthoritativeAnswer && ((DnsARecordData)answer.Answer[0].RDATA).Address.Equals(IPAddress.Parse("192.0.2.42")), "Native authoritative DNS answer changed during syslog fault");
        }
        Console.WriteLine($"DNS fault: {timings.Count}/50 authoritative answers; elapsedMs={elapsed.Elapsed.TotalMilliseconds:F1}; maxMs={timings.Max():F1}; meanMs={timings.Average():F1}; collectorFailed={sender.Health.Failed}");
    }
    public static async Task Run() {
        string root = Folder(Path.GetTempPath(), "syslog-reliability-" + Guid.NewGuid().ToString("N"));
        Console.WriteLine($"OWNED_RUNTIME pid={Environment.ProcessId}; root={root}; runtime={Environment.Version}; coreSha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(SyslogForwarder).Assembly.Location)))}; testSha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(SyslogReliabilityChecks).Assembly.Location)))}");
        using var certs = new Certificates(); using var certificate = certs.Leaf();
        try {
            string positive = Folder(root, "positive");
            await using (var receiver = new Receiver(certificate))
            await using (var sender = new SyslogForwarder(positive, () => "tls.fixture.test")) {
                await sender.ConfigureAsync(Settings(receiver.Port, certs.Trust), 0);
                Check(sender.RecordSystem("TLS π\r\nrecord"), "TLS admission"); string wire = await receiver.Next(); await Until(() => sender.Health.Sent == 1);
                Check(wire.StartsWith("<134>1 ") && wire.Contains(" tls.fixture.test teQtanium ") && wire.Contains("system - \uFEFFTLS π\\r\\nrecord"), "TLS RFC 5424 content/readback");
                Check(sender.Health.Persisted == 1 && sender.Health.DurableQueued == 0 && sender.Health.ReceiptSemantics == "NoApplicationReceipt", "Persistence/socket/receipt separation");
                bool rejected = false; try { await sender.ConfigureAsync(sender.Settings with { TcpFraming = "LineDelimited" }, 1); } catch (ArgumentException) { rejected = true; }
                Check(rejected && sender.Settings.Revision == 1, "TLS nonstandard framing accepted");
                await using var duplicateOwner = new SyslogForwarder(positive, () => "duplicate"); Check(duplicateOwner.Health.Failed > 0 && !duplicateOwner.SendTest(), "Concurrent spool ownership admitted");
                // Bounded measured burst; actual receiver readback, unique application content denominator.
                var timer = Stopwatch.StartNew(); int admitted = 0; const int offered = 512;
                Parallel.For(0, offered, i => { if (sender.RecordSystem("throughput-" + i)) Interlocked.Increment(ref admitted); }); double producerMs = timer.Elapsed.TotalMilliseconds;
                var seen = new HashSet<string>(); for (int i = 0; i < admitted; i++) { string frame = await receiver.Next(); seen.Add(frame[(frame.IndexOf("throughput-", StringComparison.Ordinal))..]); }
                await Until(() => sender.Health.Queued == 0); Check(admitted == offered && seen.Count == offered, "Concurrent receiver-visible throughput lost/duplicated content");
                Console.WriteLine($"TLS throughput: offered={offered}; admitted={admitted}; receiverUnique={seen.Count}; producerMs={producerMs:F1}; drainMs={timer.Elapsed.TotalMilliseconds:F1}; receiverRecordsPerSecond={admitted/timer.Elapsed.TotalSeconds:F1}");
            }
            foreach (string negative in new[] { "UnknownCa", "WrongName", "Expired" }) {
                using var leaf = certs.Leaf(wrongName: negative == "WrongName", expired: negative == "Expired");
                await using var receiver = new Receiver(leaf); await using var sender = new SyslogForwarder(Folder(root, negative), () => "negative");
                await sender.ConfigureAsync(Settings(receiver.Port, negative == "UnknownCa" ? "" : certs.Trust), 0); sender.SendTest(); await Until(() => sender.Health.Failed > 0 && sender.Health.DurableQueued == 1);
                Check(sender.Health.Sent == 0 && !receiver.Records.Reader.TryRead(out _) && sender.Health.NextRetryUtc > DateTime.UtcNow, negative + " validation did not fail closed");
                Console.WriteLine($"TLS negative {negative}: receiverRecords=0; durable=1; failed={sender.Health.Failed}");
            }
            // Native process termination after actual durable flush, not object reconstruction.
            string restart = Folder(root, "restart"); int restartPort = Port();
            await using (var setup = new SyslogForwarder(restart, () => "setup")) await setup.ConfigureAsync(Settings(restartPort, certs.Trust), 0);
            var first = await Process(restart, "persist"); Check(first.Exit == 73 && Directory.GetFiles(Path.Combine(restart, "syslog-spool"), "*.json").Length == 1, "First process did not leave a durable record");
            await using (var receiver = new Receiver(certificate, port: restartPort)) {
                var second = Process(restart, "replay"); string readback = await receiver.Next(); var result = await second;
                Check(result.Exit == 0 && first.Pid != result.Pid && readback.Contains("distinct-process-persisted-π"), "Distinct native process replay readback failed");
                Console.WriteLine($"Process restart: persistedPid={first.Pid}; exit={first.Exit}; replayPid={result.Pid}; exit={result.Exit}; receiverReadback=1/1; {result.Output.Trim()}");
            }
            string outage = Folder(root, "outage"); int closed = Port();
            await using (var sender = new SyslogForwarder(outage, () => "outage")) {
                await sender.ConfigureAsync(Settings(closed, certs.Trust) with { DnsQueries = true }, 0);
                var timer = Stopwatch.StartNew(); int admitted = 0; const int offered = 5000;
                for (int i = 0; i < offered; i++) if (sender.RecordSystem("outage-" + i)) admitted++;
                double producerMs = timer.Elapsed.TotalMilliseconds; await Until(() => sender.Health.Persisted == admitted && sender.Health.Failed > 0);
                var health = sender.Health;
                Check(admitted == SyslogForwarder.QueueCapacity && health.Dropped == offered - admitted && health.DurableQueued == admitted && health.SpoolBytes <= 16384L * SyslogForwarder.QueueCapacity, "Outage capacity/drop/durable bound");
                Check(producerMs < 3000 && health.OldestAgeSeconds > 0, "Outage blocked producer or lag missing");
                await DnsFaultChecks(Folder(root, "dns-outage"), sender);
                Console.WriteLine($"Unavailable: offered={offered}; admitted={admitted}; dropped={offered-admitted}; producerMs={producerMs:F1}; durable={health.DurableQueued}; bytes={health.SpoolBytes}; nextRetry={health.NextRetryUtc:O}");
                await sender.ConfigureAsync(sender.Settings with { Enabled = false }, 1); Check(sender.Health.DurableQueued == admitted && !sender.SendTest(), "Disabled replay not retained/paused");
                await sender.ConfigureAsync(sender.Settings with { Enabled = true, Port = Port() }, 2); Check(sender.Health.BindingDropped == admitted && sender.Health.Queued == 0, "Endpoint change redirected old data");
            }
            foreach (string mode in new[] { "NoHandshake", "Hold", "Partial" }) {
                await using var receiver = new Receiver(certificate, mode); await using var sender = new SyslogForwarder(Folder(root, mode), () => mode);
                await sender.ConfigureAsync(Settings(receiver.Port, certs.Trust) with { DnsQueries = true }, 0);
                var timer = Stopwatch.StartNew(); int admitted = 0;
                for (int i = 0; i < 5000; i++) if (sender.RecordSystem(i + new string('漢', 1900))) admitted++;
                Check(timer.Elapsed.TotalSeconds < 5, mode + " blocked admission");
                await Until(() => sender.Health.Failed > 0, 20);
                Check(sender.Health.Queued <= SyslogForwarder.QueueCapacity && sender.Health.Dropped > 0 && !receiver.Records.Reader.TryRead(out _), mode + " bounds/readback");
                if (mode == "Partial") Check(receiver.PartialBytes == 20 && sender.Health.Sent > 0, "Partial socket submission truth not exercised");
                await DnsFaultChecks(Folder(root, "dns-" + mode), sender);
                Console.WriteLine($"Fault {mode}: admitted={admitted}/5000; receiverFullRecords=0; partialBytes={receiver.PartialBytes}; health={JsonSerializer.Serialize(sender.Health)}");
            }
            string neighbor=Folder(root,"corrupt-neighbor");
            await using(var staging=new SyslogForwarder(neighbor,()=>"neighbor")) { await staging.ConfigureAsync(Settings(Port(),certs.Trust),0); staging.SendTest(); await Until(()=>staging.Health.Persisted==1); }
            string neighborSpool=Path.Combine(neighbor,"syslog-spool"); File.WriteAllText(Path.Combine(neighborSpool,"partial.tmp"),"{interrupted"); File.WriteAllText(Path.Combine(neighborSpool,"corrupt.json"),"{corrupt");
            await using(var recovered=new SyslogForwarder(neighbor,()=>"neighbor")) Check(recovered.Health.Replayed==1 && recovered.Health.Queued==1 && recovered.Health.Dropped==1 && !File.Exists(Path.Combine(neighborSpool,"partial.tmp")),"Corrupt/partial neighbor erased a valid durable record");
            // Expiry, corruption and privacy binding are exercised against actual stored records.
            foreach (string mutation in new[] { "Age", "Corrupt", "Trust", "Framing", "Selection" }) {
                string folder = Folder(root, "spool-" + mutation); int port = Port();
                await using (var sender = new SyslogForwarder(folder, () => "store")) { await sender.ConfigureAsync(Settings(port, certs.Trust), 0); sender.SendTest(); await Until(() => sender.Health.Persisted == 1); }
                string path = Directory.GetFiles(Path.Combine(folder, "syslog-spool"), "*.json").Single();
                if (mutation == "Age") { var record = JsonNode.Parse(File.ReadAllText(path)); record["createdUtc"] = DateTime.UtcNow.AddDays(-2); File.WriteAllText(path, record.ToJsonString()); }
                if (mutation == "Corrupt") File.WriteAllText(path, "{partial");
                await using var reopened = new SyslogForwarder(folder, () => "reopened");
                if (mutation is "Trust" or "Framing" or "Selection") {
                    var settings = reopened.Settings with { Enabled = false };
                    if (mutation == "Trust") settings = settings with { TlsCaCertificate = "" };
                    if (mutation == "Framing") settings = settings with { Transport = "Tcp", TcpFraming = "LineDelimited" };
                    if (mutation == "Selection") settings = settings with { SecurityEvents = false };
                    await reopened.ConfigureAsync(settings, 1);
                }
                Check(reopened.Health.Queued == 0 && reopened.Health.Dropped == 1, mutation + " stored replay was not discarded");
                Check(mutation != "Age" || reopened.Health.Expired == 1, "Expired counter");
                Check(mutation is "Age" or "Corrupt" || reopened.Health.BindingDropped == 1, "Binding drop counter");
                Console.WriteLine($"Stored {mutation}: queued=0; dropped=1; expired={reopened.Health.Expired}; bindingDropped={reopened.Health.BindingDropped}");
            }
            // Storage failure is isolated without permissions/ACL changes.
            string blocked = Folder(root, "blocked-spool"); File.WriteAllText(Path.Combine(blocked, "syslog-spool"), "owned fixture obstruction");
            File.WriteAllText(Path.Combine(blocked, "syslog.json"), JsonSerializer.Serialize(Settings(Port(), certs.Trust), SyslogForwarder.JsonOptions));
            await using (var sender = new SyslogForwarder(blocked, () => "blocked")) { Check(sender.Health.Failed > 0 && !sender.SendTest(), "Unavailable spool blocked startup/accepted nondurable records"); await DnsFaultChecks(Folder(root, "dns-store-failure"), sender); }
            await NativeApiChecks(Folder(root, "native-api"), certs, certificate);
            await NativeProcessChecks(Folder(root, "native-process"), certs, certificate);
            await NativeApiChecks(Folder(root, "native-store-startup"), certs, certificate, storeBlocked:true);
            Console.WriteLine($"PASS: {_checks} assertions; native TLS positives/negatives, receiver bytes, bounded concurrency/outage, native process restart, durable privacy/expiry/corruption, and authoritative DNS during faults. No Wazuh instance or DHCP authority exercised.");
        } finally { Directory.Delete(root, true); Console.WriteLine($"OWNED_CLEANUP root={root}; absent={!Directory.Exists(root)}; onlyThisFixtureRoot=true"); }
    }
}
