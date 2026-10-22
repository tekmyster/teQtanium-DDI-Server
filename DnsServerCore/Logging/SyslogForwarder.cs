// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using System;
using System.Globalization;
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DnsServerCore.Security;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Logging;

public sealed record SyslogSettings(bool Enabled = false, string Server = "", int Port = 514,
    string Transport = "Udp", int Facility = 16, bool SystemEvents = true, bool SecurityEvents = true,
    bool DnsQueries = false, string TcpFraming = "OctetCounting", long Revision = 0, string TlsCaCertificate = "", int MaxAgeSeconds = 86400);
public sealed record SyslogHealth(string State, long Queued, long Sent, long Dropped, long Failed,
    DateTime? LastSentUtc, string LastError, long Persisted = 0, long DurableQueued = 0, long SpoolBytes = 0,
    long Replayed = 0, long Expired = 0, long BindingDropped = 0, double OldestAgeSeconds = 0,
    DateTime? NextRetryUtc = null, string ReceiptSemantics = "NoApplicationReceipt", long WriteAttempts = 0, long SentBytes = 0, long MemoryBytes = 0);

/// <summary>Bounded forwarding with asynchronous durable staging. Producers never wait for disk or network.</summary>
public sealed class SyslogForwarder : IAsyncDisposable
{
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    public const int QueueCapacity = 1024;
    readonly string _path;
    readonly Func<string> _hostname;
    readonly SemaphoreSlim _configure = new(1);
    readonly object _healthLock = new();
    SyslogSettings _settings = new();
    RunSession _run;
    long _sent, _dropped, _failed, _persisted, _replayed, _expired, _bindingDropped, _writeAttempts, _sentBytes;
    DateTime? _lastSent;
    string _lastError = "";
    bool _disposed;

    public SyslogForwarder(string configFolder, Func<string> hostname)
    {
        _path = Path.Combine(configFolder, "syslog.json"); _hostname = hostname;
        bool loaded = false;
        try {
            if (File.Exists(_path)) {
                if (new FileInfo(_path).Length > 4096) throw new ArgumentException("Syslog settings are too large.");
                _settings = Validate(JsonSerializer.Deserialize<SyslogSettings>(File.ReadAllBytes(_path), JsonOptions) ?? throw new ArgumentException("Missing syslog settings."));
                loaded = true;
            }
        } catch { _lastError = "Saved syslog settings could not be loaded. Configure forwarding again."; }
        if (loaded) StartRun();
    }
    internal Action BeforeSpoolFlush { get; set; }
    internal Func<string, CancellationToken, Task> AfterSocketWrite { get; set; }
    internal Action BeforeConfigureWait { get; set; }
    public SyslogSettings ExportSettings() { var settings = Settings; return settings with { TlsCaCertificate = settings.TlsCaCertificate.Length == 0 ? "" : "Retain" }; }
    public string TlsCaSha256 { get { var ca = Settings.TlsCaCertificate; return ca.Length == 0 ? "" : Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(ca))); } }
    public SyslogSettings Settings => Volatile.Read(ref _settings);
    public SyslogHealth Health {
        get {
            var run = Volatile.Read(ref _run);
            lock (_healthLock) return new(!Settings.Enabled ? "Disabled" : _lastError.Length > 0 ? "Error" : _lastSent is null ? "Waiting" : "Sending",
                run?.Pending ?? 0, Interlocked.Read(ref _sent), Interlocked.Read(ref _dropped), Interlocked.Read(ref _failed), _lastSent, _lastError,
                Interlocked.Read(ref _persisted), run?.DurableCount ?? 0, run?.SpoolBytes ?? 0, Interlocked.Read(ref _replayed),
                Interlocked.Read(ref _expired), Interlocked.Read(ref _bindingDropped), run?.OldestAge ?? 0, run?.NextRetry, "NoApplicationReceipt", Interlocked.Read(ref _writeAttempts), Interlocked.Read(ref _sentBytes), run?.MemoryBytes ?? 0);
        }
    }
    void StartRun()
    {
        try { Volatile.Write(ref _run, new RunSession(this, Settings)); }
        catch { lock (_healthLock) _lastError = "Syslog spool is unavailable or already owned. Check the configuration folder and restart forwarding."; Interlocked.Increment(ref _failed); }
    }
    static SyslogSettings Validate(SyslogSettings settings)
    {
        string server = (settings.Server ?? "").Trim();
        if (server.Length > 253 || server.Any(char.IsControl) || server.Any(char.IsWhiteSpace) ||
            server.Length > 0 && !IPAddress.TryParse(server, out _) && Uri.CheckHostName(server) == UriHostNameType.Unknown)
            throw new ArgumentException("Enter a hostname or IP address without a scheme, path or port.");
        if (settings.Enabled && server.Length == 0) throw new ArgumentException("Enter the syslog server address before enabling forwarding.");
        if (settings.Port < 1 || settings.Port > 65535) throw new ArgumentException("Syslog port must be between 1 and 65535.");
        if (settings.Transport is not ("Udp" or "Tcp" or "Tls")) throw new ArgumentException("Choose UDP, TCP or TLS for syslog forwarding.");
        if (settings.TcpFraming is not ("OctetCounting" or "LineDelimited")) throw new ArgumentException("Choose octet counting or line delimited TCP framing.");
        if (settings.Facility < 0 || settings.Facility > 23) throw new ArgumentException("Choose a valid syslog facility.");
        if (settings.Enabled && !settings.SystemEvents && !settings.SecurityEvents && !settings.DnsQueries) throw new ArgumentException("Select at least one event type to forward.");
        if (settings.Revision < 0) throw new ArgumentException("Invalid syslog settings revision.");
        if (settings.Transport == "Tls" && settings.TcpFraming != "OctetCounting") throw new ArgumentException("TLS requires octet counting framing.");
        if (settings.MaxAgeSeconds < 60 || settings.MaxAgeSeconds > 604800) throw new ArgumentException("Replay age must be between 60 and 604800 seconds.");
        string ca = settings.TlsCaCertificate ?? "";
        if (ca.Length > 2800) throw new ArgumentException("Collector CA certificate is too large (maximum 2800 base64 characters).");
        if (ca.Length > 0) {
            try { using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(ca));
                if (!cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority)) throw new ArgumentException(); }
            catch { throw new ArgumentException("Enter a base64 DER CA certificate for the collector trust anchor."); }
        }
        return settings with { Server = server, TlsCaCertificate = ca };
    }
    public async Task ConfigureAsync(SyslogSettings settings, long expectedRevision, CancellationToken cancellationToken = default, Action authorize = null)
    {
        if (settings.TlsCaCertificate == "Retain") {
            if (Settings.TlsCaCertificate.Length == 0) throw new ArgumentException("Provision the collector CA before restoring or retaining custom trust.");
            settings = settings with { TlsCaCertificate = Settings.TlsCaCertificate };
        }
        settings = Validate(settings);
        BeforeConfigureWait?.Invoke();
        await _configure.WaitAsync(cancellationToken);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            authorize?.Invoke();
            if (Settings.Revision != expectedRevision) throw new InvalidOperationException("Syslog settings changed. Reload them before saving.");
            settings = settings with { Revision = checked(Settings.Revision + 1) };
            var previous = Interlocked.Exchange(ref _run, null);
            if (previous is not null) await previous.DisposeAsync();
            string temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try {
                authorize?.Invoke();
                using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    file.Write(JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions)); file.Flush(true);
                }
                File.Move(temp, _path, true);
            } catch { StartRun(); throw; }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            Volatile.Write(ref _settings, settings);
            lock (_healthLock) { _lastSent = null; _lastError = ""; }
            StartRun();
        } finally { _configure.Release(); }
    }
    public bool RecordSystem(string message, int severity = 6) => Settings.SystemEvents && Queue("system", message, severity);
    public async Task RestoreAsync(Stream source, CancellationToken cancellationToken = default, Action authorize = null)
    {
        byte[] buffer = new byte[4097]; int count = 0;
        while (count < buffer.Length) { int read = await source.ReadAsync(buffer.AsMemory(count), cancellationToken); if (read == 0) break; count += read; }
        if (count > 4096) throw new ArgumentException("Syslog settings are too large.");
        var settings = JsonSerializer.Deserialize<SyslogSettings>(buffer.AsSpan(0, count), JsonOptions) ?? throw new ArgumentException("Enter syslog settings.");
        await ConfigureAsync(settings, Settings.Revision, cancellationToken, authorize);
    }
    public void RecordSecurity(SecurityEvent item)
    {
        if (!Settings.Enabled || !Settings.SecurityEvents) return;
        try {
        string message = JsonSerializer.Serialize(new { item.Id, item.Timestamp, item.Node, item.Service, item.ClientAddress, item.Query,
            item.QueryType, item.ResponseCode, item.Action, score = item.Behavior?.Score, reason = Limit(item.Reason, 512),
            device = item.Device is null ? null : new { scope = Limit(item.Device.Scope,128), clientIdentifier = Limit(item.Device.ClientIdentifier,128),
                hardwareAddress = Limit(item.Device.HardwareAddress,64), hostName = Limit(item.Device.HostName,253), site = Limit(item.Device.Site,64), item.Device.Vlan },
            indicators = (item.Matches ?? []).Take(4).Select(m => new { m.Kind, value = Limit(m.Value, 253), source = Limit(m.Source, 64) }),
            additionalMatches = item.AdditionalMatches + Math.Max(0, (item.Matches?.Length ?? 0) - 4) }, JsonOptions);
        if (Encoding.UTF8.GetByteCount(message) > 7000) message = JsonSerializer.Serialize(new { item.Id, item.Timestamp, item.Service,
            item.ClientAddress, item.Query, item.Action, score = item.Behavior?.Score, detailsLimited = true }, JsonOptions);
        Queue("security", message, item.Action is "Block" or "DenyNewLease" ? 4 : 6, true);
        } catch { Interlocked.Increment(ref _dropped); }
    }
    public void RecordDnsQuery(IPEndPoint client, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response)
    {
        if (!Settings.Enabled || !Settings.DnsQueries) return;
        try {
        var question = request?.Question.FirstOrDefault();
        Queue("dns", JsonSerializer.Serialize(new { clientAddress = client?.Address.ToString(), transport = protocol.ToString(),
            query = question?.Name, queryType = question?.Type.ToString(), responseCode = response?.RCODE.ToString() ?? "NoResponse" }, JsonOptions), response is null ? 3 : 6, true);
        } catch { Interlocked.Increment(ref _dropped); }
    }
    public bool SendTest() => Queue("test", "teQtanium syslog forwarding test", 6);
    bool Queue(string category, string message, int severity, bool structured = false)
    {
        try { return QueueCore(category, message, severity, structured); }
        catch { Interlocked.Increment(ref _dropped); return false; }
    }
    bool QueueCore(string category, string message, int severity, bool structured)
    {
        var run = Volatile.Read(ref _run);
        if (run is null || !run.Settings.Enabled || category == "system" && !run.Settings.SystemEvents || category == "security" && !run.Settings.SecurityEvents || category == "dns" && !run.Settings.DnsQueries) return false;
        // Normalize control characters so one event cannot inject another RFC 5424 message or line-delimited frame.
        message = (structured ? message : Limit(message, 2000)).Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "\\0");
        string host = new string((_hostname() ?? "-").Take(255).Select(c => c is >= '!' and <= '~' ? c : '_').ToArray());
        if (host.Length == 0) host = "-";
        string header = "<" + (run.Settings.Facility * 8 + Math.Clamp(severity, 0, 7)) + ">1 " + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture) + " " + host + " teQtanium " + Environment.ProcessId + " " + category + " - \uFEFF";
        string payload = header + message;
        byte[] buffer = new byte[Math.Min(8192, Encoding.UTF8.GetByteCount(payload))];
        Encoding.UTF8.GetEncoder().Convert(payload.AsSpan(), buffer, true, out _, out int bytesUsed, out _);
        bool queued = run.Enqueue(bytesUsed == buffer.Length ? buffer : buffer[..bytesUsed]);
        if (!queued) Interlocked.Increment(ref _dropped);
        return queued;
    }
    static string Limit(string value, int count) => value is null ? "" : value.Length <= count ? value : value[..count];
    public async ValueTask DisposeAsync()
    {
        await _configure.WaitAsync();
        try { if (_disposed) return; _disposed = true; var run = Interlocked.Exchange(ref _run, null); if (run is not null) await run.DisposeAsync(); }
        finally { _configure.Release(); }
    }
    sealed record SpoolRecord(string Id, DateTime CreatedUtc, string Binding, byte[] Payload, string Sha256, long SettingsRevision);
    sealed class RunSession : IAsyncDisposable
    {
        readonly SyslogForwarder _owner;
        readonly Channel<SpoolRecord> _ingress = Channel.CreateBounded<SpoolRecord>(new BoundedChannelOptions(QueueCapacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
        readonly Channel<SpoolRecord> _ready = Channel.CreateUnbounded<SpoolRecord>(new UnboundedChannelOptions { SingleReader = true });
        readonly ConcurrentDictionary<string, SpoolRecord> _durable = new();
        readonly CancellationTokenSource _stop = new();
        readonly string _folder, _binding;
        readonly FileStream _lease;
        readonly Task _writer, _sender;
        Socket _udp;
        TcpClient _tcp;
        Stream _stream;
        long _pending, _spoolBytes, _retryTicks, _memoryBytes;
        public SyslogSettings Settings { get; }
        public long Pending => Math.Max(0, Interlocked.Read(ref _pending));
        public long DurableCount => _durable.Count;
        public long MemoryBytes => Math.Max(0, Interlocked.Read(ref _memoryBytes));
        public long SpoolBytes => Math.Max(0, Interlocked.Read(ref _spoolBytes));
        public double OldestAge { get { var items = _durable.Values.ToArray(); return items.Length == 0 ? 0 : Math.Max(0, (DateTime.UtcNow - items.Min(x => x.CreatedUtc)).TotalSeconds); } }
        public DateTime? NextRetry { get { long ticks = Interlocked.Read(ref _retryTicks); return ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc); } }
        public RunSession(SyslogForwarder owner, SyslogSettings settings)
        {
            _owner = owner; Settings = settings; _folder = Path.Combine(Path.GetDirectoryName(owner._path), "syslog-spool");
            _binding = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { server = settings.Server.ToLowerInvariant(), settings.Port, settings.Transport, settings.TcpFraming, settings.TlsCaCertificate, settings.SystemEvents, settings.SecurityEvents, settings.DnsQueries })));
            Directory.CreateDirectory(_folder);
            _lease = new FileStream(Path.Combine(_folder, "owner.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try { Recover(); } catch { _lease.Dispose(); throw; }
            _writer = Task.Run(PersistAsync); _sender = settings.Enabled ? Task.Run(SendAsync) : Task.CompletedTask;
        }
        string PathFor(SpoolRecord item) => Path.Combine(_folder, item.Id + ".json");
        bool Expired(SpoolRecord item) => item.CreatedUtc > DateTime.UtcNow.AddMinutes(5) || DateTime.UtcNow - item.CreatedUtc >= TimeSpan.FromSeconds(Settings.MaxAgeSeconds);
        void Recover()
        {
            foreach (string path in Directory.EnumerateFiles(_folder, "*.tmp")) File.Delete(path);
            foreach (string path in Directory.EnumerateFiles(_folder, "*.json").OrderBy(x => x, StringComparer.Ordinal)) {
                try {
                    if (new FileInfo(path).Length > 16384) throw new IOException();
                    var item = JsonSerializer.Deserialize<SpoolRecord>(File.ReadAllBytes(path), JsonOptions);
                    if (item is null || item.Payload is null || item.Payload.Length is < 1 or > 8192 ||
                        item.Id.Length != 52 || !item.Id.All(char.IsAsciiHexDigit) || PathFor(item) != path || item.Sha256 != Convert.ToHexString(SHA256.HashData(item.Payload))) throw new IOException();
                    if (item.Binding != _binding) { Interlocked.Increment(ref _owner._bindingDropped); throw new IOException(); }
                    if (Expired(item)) { Interlocked.Increment(ref _owner._expired); throw new IOException(); }
                    if (_pending >= QueueCapacity) throw new IOException();
                    _pending++; _durable[item.Id] = item; _spoolBytes += new FileInfo(path).Length;
                    _ready.Writer.TryWrite(item); Interlocked.Increment(ref _owner._replayed);
                } catch { File.Delete(path); Interlocked.Increment(ref _owner._dropped); }
            }
        }
        public bool Enqueue(byte[] bytes)
        {
            if (Interlocked.Increment(ref _pending) > QueueCapacity) { Interlocked.Decrement(ref _pending); return false; }
            var now = DateTime.UtcNow;
            var item = new SpoolRecord(now.Ticks.ToString("x20") + Guid.NewGuid().ToString("N"), now, _binding, bytes, Convert.ToHexString(SHA256.HashData(bytes)), Settings.Revision);
            Interlocked.Add(ref _memoryBytes, bytes.Length);
            if (_ingress.Writer.TryWrite(item)) return true;
            Interlocked.Add(ref _memoryBytes, -bytes.Length);
            Interlocked.Decrement(ref _pending); return false;
        }
        async Task PersistAsync()
        {
            await foreach (var item in _ingress.Reader.ReadAllAsync()) {
                string path = PathFor(item), temp = path + ".tmp";
                try {
                    byte[] data = JsonSerializer.SerializeToUtf8Bytes(item, JsonOptions);
                    if (data.Length > 16384) throw new IOException();
                    using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                        await file.WriteAsync(data); _owner.BeforeSpoolFlush?.Invoke(); file.Flush(true);
                    }
                    File.Move(temp, path); _durable[item.Id] = item; Interlocked.Add(ref _spoolBytes, data.Length);
                    Interlocked.Increment(ref _owner._persisted); _ready.Writer.TryWrite(item);
                } catch {
                    Interlocked.Increment(ref _owner._failed); Interlocked.Increment(ref _owner._dropped); Interlocked.Decrement(ref _pending);
                    lock (_owner._healthLock) _owner._lastError = "Could not persist syslog record. Check free space and configuration folder access.";
                    try { File.Delete(temp); } catch { }
                } finally { Interlocked.Add(ref _memoryBytes, -item.Payload.Length); }
            }
            _ready.Writer.TryComplete();
        }
        void Remove(SpoolRecord item)
        {
            string path = PathFor(item); long size = new FileInfo(path).Length; File.Delete(path);
            _durable.TryRemove(item.Id, out _); Interlocked.Add(ref _spoolBytes, -size); Interlocked.Decrement(ref _pending);
        }
        void CloseConnection() { _stream?.Dispose(); _stream = null; _tcp?.Dispose(); _tcp = null; _udp?.Dispose(); _udp = null; }
        async Task WriteAsync(byte[] bytes, CancellationToken token)
        {
            if (Settings.Transport == "Udp") {
                if (_udp is null) {
                    var addresses = await System.Net.Dns.GetHostAddressesAsync(Settings.Server, token);
                    var address = addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
                    _udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp); _udp.Connect(new IPEndPoint(address, Settings.Port));
                }
                if (await _udp.SendAsync(bytes, SocketFlags.None, token) != bytes.Length) throw new IOException("Incomplete UDP submission.");
                return;
            }
            if (_tcp is null) {
                _tcp = new TcpClient(); await _tcp.ConnectAsync(Settings.Server, Settings.Port, token); _stream = _tcp.GetStream();
                if (Settings.Transport == "Tls") {
                    var tls = new SslStream(_stream, false); _stream = tls;
                    var options = new SslClientAuthenticationOptions { TargetHost = Settings.Server, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 };
                    using var ca = Settings.TlsCaCertificate.Length == 0 ? null : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Settings.TlsCaCertificate));
                    if (ca is not null) {
                        options.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true };
                        options.CertificateChainPolicy.CustomTrustStore.Add(ca);
                        options.CertificateChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                    }
                    await tls.AuthenticateAsClientAsync(options, token);
                }
            }
            byte[] frame = Settings.TcpFraming == "OctetCounting" ? Encoding.ASCII.GetBytes(bytes.Length.ToString(CultureInfo.InvariantCulture) + " ").Concat(bytes).ToArray() : bytes.Concat(new byte[] { 10 }).ToArray();
            await _stream.WriteAsync(frame, token);
        }
        async Task SendAsync()
        {
            try {
                await foreach (var item in _ready.Reader.ReadAllAsync(_stop.Token)) {
                    int failures = 0;
                    while (!_stop.IsCancellationRequested) {
                        try {
                            if (Expired(item)) { Remove(item); Interlocked.Increment(ref _owner._expired); Interlocked.Increment(ref _owner._dropped); break; }
                            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                            Interlocked.Increment(ref _owner._writeAttempts);
                            await WriteAsync(item.Payload, timeout.Token);
                            // Only local socket submission: no syslog application acknowledgement exists here.
                            Interlocked.Increment(ref _owner._sent); Interlocked.Add(ref _owner._sentBytes, item.Payload.Length);
                            if (_owner.AfterSocketWrite is { } afterWrite) await afterWrite(item.Id, _stop.Token);
                            Remove(item);
                            lock (_owner._healthLock) { _owner._lastSent = DateTime.UtcNow; _owner._lastError = ""; }
                            Interlocked.Exchange(ref _retryTicks, 0); break;
                        } catch (Exception) when (_stop.IsCancellationRequested) { throw; }
                        catch {
                            CloseConnection(); Interlocked.Increment(ref _owner._failed);
                            lock (_owner._healthLock) _owner._lastError = "Syslog forwarding delayed. Check collector availability, certificate name and trust, or spool access.";
                            int seconds = 1 << Math.Min(failures++, 5);
                            Interlocked.Exchange(ref _retryTicks, DateTime.UtcNow.AddSeconds(seconds).Ticks);
                            await Task.Delay(TimeSpan.FromSeconds(seconds), _stop.Token);
                        }
                    }
                }
            } catch (Exception) when (_stop.IsCancellationRequested) { }
            finally { CloseConnection(); }
        }
        public async ValueTask DisposeAsync()
        {
            _ingress.Writer.TryComplete(); _stop.Cancel();
            try { await Task.WhenAll(_writer, _sender); }
            finally { _lease.Dispose(); _stop.Dispose(); }
        }
    }
}
