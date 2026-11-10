// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Logging;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

static partial class SyslogReliabilityChecks
{
    static T Field<T>(object value, string name) => (T)value.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(value)!;
    static string Json(object value) => JsonSerializer.Serialize(value, SyslogForwarder.JsonOptions);
    static async Task<JsonElement> Call(HttpClient client, string path, params (string Key, string Value)[] values) {
        using var content = new FormUrlEncodedContent(values.Select(x => new KeyValuePair<string, string>(x.Key, x.Value)));
        using var response = await client.PostAsync(path, content); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
    }
    static async Task Login(HttpClient client, string password) {
        var result = await Call(client, "/api/user/login", ("user", "admin"), ("pass", password)); Check(result.GetProperty("status").GetString() == "ok", "Owned native login failed");
        client.DefaultRequestHeaders.Authorization = new("Bearer", result.GetProperty("token").GetString());
    }
    static HttpClient Client(int port) => new() { BaseAddress = new Uri("http://127.0.0.1:" + port), Timeout = TimeSpan.FromSeconds(15) };
    static async Task NativeAnswers(int port, int count, string phase) {
        var timer = Stopwatch.StartNew();
        for (int i = 0; i < count; i++) {
            using var client = new UdpClient(); client.Connect(IPAddress.Loopback, port);
            var question = new DnsDatagram((ushort)i, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("answer.syslog.fixture.test", DnsResourceRecordType.A, DnsClass.IN)]);
            using var wire = new MemoryStream(); question.WriteTo(wire); await client.SendAsync(wire.ToArray());
            var packet = await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3)); using var input = new MemoryStream(packet.Buffer); var answer = DnsDatagram.ReadFrom(input);
            Check(answer.RCODE == DnsResponseCode.NoError && answer.AuthoritativeAnswer && answer.Answer.Count == 1 && ((DnsARecordData)answer.Answer[0].RDATA).Address.Equals(IPAddress.Parse("192.0.2.42")), "Native process DNS failed at " + phase + "; rcode=" + answer.RCODE + "; authoritative=" + answer.AuthoritativeAnswer + "; answerCount=" + answer.Answer.Count);
        }
        Console.WriteLine($"Native DNS {phase}: {count}/{count}; elapsedMs={timer.Elapsed.TotalMilliseconds:F1}; source=127.0.0.1; targetPort={port}");
    }
    static void Zone(DnsServer dns) {
        Directory.CreateDirectory(Path.Combine(dns.ConfigFolder,"zones"));
        dns.AuthZoneManager.CreatePrimaryZone("syslog.fixture.test");
        dns.AuthZoneManager.SetRecord("syslog.fixture.test", new DnsResourceRecord("answer.syslog.fixture.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.42"))));
        dns.AuthZoneManager.SaveZoneFile("syslog.fixture.test");
    }
    static async Task<string> Matching(Receiver receiver, string text) {
        for (int i = 0; i < 20; i++) { string wire = await receiver.Next(); if (wire.Contains(text)) return wire; } throw new Exception("Expected receiver content missing: " + text);
    }
    static async Task NativeApiChecks(string folder, Certificates certs, X509Certificate2 certificate, bool storeBlocked = false) {
        int http = Port(), dnsPort = Port(); string password = Guid.NewGuid().ToString("N") + "Aa9!";
        var env = new Dictionary<string,string> { ["DNS_SERVER_ADMIN_PASSWORD"] = password, ["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] = "127.0.0.1", ["DNS_SERVER_WEB_SERVICE_HTTP_PORT"] = http.ToString() };
        var before = env.Keys.ToDictionary(x => x, Environment.GetEnvironmentVariable); foreach (var value in env) Environment.SetEnvironmentVariable(value.Key, value.Value);
        try {
            await using (var log = new LogManager(true, folder)) using (var dns = new DnsServer(folder, Path.Combine(AppContext.BaseDirectory,"dohwww"), log)) { dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback,dnsPort)]; dns.EnableCheckForUpdate = false; dns.Recursion = DnsServerRecursion.Deny; Zone(dns); dns.SaveConfigFile(true); }
            if(storeBlocked) { File.WriteAllText(Path.Combine(folder,"syslog-spool"),"owned obstruction"); File.WriteAllText(Path.Combine(folder,"syslog.json"),Json(Settings(Port(),certs.Trust) with { SystemEvents=false })); }
            await using var service = new DnsWebService(true, folder); await service.StartAsync(true);
            using var original = Client(http); using var fresh = Client(http); await Login(original, password); await Login(fresh, password);
            var auth = Field<AuthManager>(service, "_authManager"); var sender = Field<SyslogForwarder>(service, "_syslog");
            if(storeBlocked) {
                await NativeAnswers(dnsPort,20,"native-startup-spool-path-conflict");
                Check(sender.Health.Failed>0 && !sender.SendTest(),"Native path-conflict falsely admitted record");
                Check((await Call(fresh,"/api/logging/syslog/get")).GetProperty("status").GetString()=="ok","Native path-conflict API unavailable");
                File.Delete(Path.Combine(folder,"syslog-spool"));
                Check((await Call(fresh,"/api/logging/syslog/set",("revision","0"),("settings",Json(sender.Settings)))).GetProperty("status").GetString()=="ok","Native spool path recovery failed");
                Check(sender.SendTest(),"Native repaired spool still rejects admission"); await Until(()=>sender.Health.Persisted==1);
                Console.WriteLine($"Native startup/store path: pid={Environment.ProcessId}; authoritativeDNS=20/20; startup=available; testBeforeRepair=rejected; persistedBeforeRepair=0; testAfterRepair=1/1 persisted; API=responsive");
                return;
            }
            var freshSession = auth.GetSession(fresh.DefaultRequestHeaders.Authorization!.Parameter);
            Check(freshSession.LastSeenRemoteAddress.Equals(IPAddress.Loopback), "Native fresh source address mismatch");
            using var anonymous = Client(http); Check((await Call(anonymous,"/api/logging/syslog/get")).GetProperty("status").GetString() == "invalid-token", "Anonymous status disclosure");
            // Test-only ephemeral user/session objects in the owned configuration; no real ACL/credentials are changed.
            var limitedUser = auth.CreateUser("Owned restricted fixture", "syslog-limited", Guid.NewGuid().ToString("N") + "Aa9!");
            var limitedSession = auth.CreateSession(UserSessionType.Standard, null, limitedUser, IPAddress.Loopback, "owned fixture");
            using var limited = Client(http); limited.DefaultRequestHeaders.Authorization = new("Bearer", limitedSession.Token);
            Check((await Call(limited,"/api/logging/syslog/get")).GetProperty("status").GetString() == "error", "Restricted status disclosure");
            await using var receiver = new Receiver(certificate);
            var configured = Settings(receiver.Port, certs.Trust) with { DnsQueries = true };
            Check((await Call(fresh,"/api/logging/syslog/set",("revision","0"),("settings",Json(configured)))).GetProperty("status").GetString() == "ok", "Fresh administrator lacks required native privileges");
            Check((await Call(limited,"/api/logging/syslog/test")).GetProperty("status").GetString() == "error", "Restricted test export");
            var clusterSession = auth.CreateSession(UserSessionType.ClusterApiToken, "owned fixture", "admin", IPAddress.Loopback, "owned fixture");
            using var cluster = Client(http); cluster.DefaultRequestHeaders.Authorization = new("Bearer", clusterSession.Token);
            Check((await Call(cluster,"/api/logging/syslog/set",("revision","1"),("settings",Json(configured)))).GetProperty("status").GetString() == "error", "Cluster token redirected native syslog");
            var status = await Call(fresh,"/api/logging/syslog/get"); string statusJson = status.GetRawText();
            Check(!statusJson.Contains(certs.Trust) && status.GetProperty("response").GetProperty("settings").GetProperty("tlsCaCertificate").GetString() == "Retain", "CA disclosed in native status");
            Check((await Call(fresh,"/api/logging/syslog/test")).GetProperty("response").GetProperty("queued").GetBoolean(), "Native test not queued");
            await Matching(receiver,"teQtanium syslog forwarding test"); Field<LogManager>(service,"_log").Write("native system hook π"); await Matching(receiver,"native system hook π");
            await NativeAnswers(dnsPort, 10, "API-TLS-enabled"); await Matching(receiver,"answer.syslog.fixture.test");
            Check(receiver.PeerAddresses.All(x => x == "127.0.0.1"), "Receiver transport peer mismatch");
            await Until(()=>sender.Health.Queued==0); while(receiver.Records.Reader.TryRead(out _)) { }
            {
                const int offered=512; long persistedStart=sender.Health.Persisted, sentStart=sender.Health.Sent, dropsStart=sender.Health.Dropped;
                var timer=Stopwatch.StartNew(); int admitted=0;
                Parallel.For(0,offered,i=>{if(sender.RecordSystem("measured-native-"+i)) Interlocked.Increment(ref admitted);});
                double producerMs=timer.Elapsed.TotalMilliseconds; var dnsSamples=NativeAnswers(dnsPort,20,"native-throughput-window");
                var unique=new HashSet<string>(); long bytes=0; int minimum=int.MaxValue,maximum=0,dnsRecords=0;
                for(int i=0;i<admitted+20;i++) { string frame=await receiver.Next(); int size=Encoding.UTF8.GetByteCount(frame); bytes+=size; minimum=Math.Min(minimum,size); maximum=Math.Max(maximum,size); int marker=frame.IndexOf("measured-native-",StringComparison.Ordinal); if(marker>=0) unique.Add(frame[marker..]); else if(frame.Contains("answer.syslog.fixture.test")) dnsRecords++; }
                await dnsSamples; await Until(()=>sender.Health.Queued==0); double seconds=timer.Elapsed.TotalSeconds;
                Check(admitted==offered && unique.Count==offered && dnsRecords==20 && sender.Health.Persisted-persistedStart==532 && sender.Health.Sent-sentStart==532 && sender.Health.Dropped==dropsStart,"Native throughput offered/persisted/receiver denominator mismatch");
                Console.WriteLine($"Native measured TLS: warmup=precedingAPI/test/DNS; offeredSystem={offered}; admittedSystem={admitted}; rejectedSystem={offered-admitted}; actualDNSOffered=20; actualDNSNoErrorAA=20; durableNew={sender.Health.Persisted-persistedStart}; socketNew={sender.Health.Sent-sentStart}; receiverSystemUnique={unique.Count}; receiverSystemDuplicates={admitted-unique.Count}; receiverDNS={dnsRecords}; receiverTotal=532; receiverBytes={bytes}; payloadMin={minimum}; payloadMax={maximum}; producerMs={producerMs:F3}; producerRecordsPerSecond={admitted/(producerMs/1000):F1}; windowSeconds={seconds:F6}; receiverRecordsPerSecond={532/seconds:F1}; receiverBytesPerSecond={bytes/seconds:F1}; pendingEnd=0; droppedDelta=0; nativePid={Environment.ProcessId}");
            }
            // Native settings-only backup: config is included, public anchor bytes and pending payloads are excluded.
            using var backupResponse = await fresh.GetAsync("/api/settings/backup?logSettings=true"); byte[] backup = await backupResponse.Content.ReadAsByteArrayAsync();
            using (var archive = new ZipArchive(new MemoryStream(backup))) {
                var config = archive.GetEntry("syslog.json"); Check(config is not null && !archive.Entries.Any(x => x.FullName.Contains("syslog-spool")), "Syslog backup coverage differs");
                using var read = new StreamReader(config!.Open()); string saved = await read.ReadToEndAsync(); Check(!saved.Contains(certs.Trust) && saved.Contains("Retain"), "CA anchor leaked into backup");
            }
            await Until(() => sender.Health.Queued == 0);
            using (var restore = new MultipartFormDataContent()) { restore.Add(new StringContent("true"),"logSettings"); restore.Add(new ByteArrayContent(backup),"file","syslog-owned.zip"); using var response = await fresh.PostAsync("/api/settings/restore",restore); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); Check(json.RootElement.GetProperty("status").GetString() == "ok", "Syslog-only native backup round trip failed"); }
            Check(sender.Settings.Revision == 2 && sender.Settings.TlsCaCertificate == certs.Trust, "Backup restore lost destination trust/revision");
            // Pause after native endpoint authorization but before config-lock acquisition; revoke/expire only the ephemeral request session.
            var gate = Field<SemaphoreSlim>(sender,"_configure");
            foreach (string loss in new[] { "Revoked", "Expired" }) {
                using var waiting = Client(http); await Login(waiting,password); string token = waiting.DefaultRequestHeaders.Authorization!.Parameter!;
                await gate.WaitAsync(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); sender.BeforeConfigureWait = () => entered.TrySetResult();
                var request = Call(waiting,"/api/logging/syslog/set",("revision","2"),("settings",Json(configured with { Port = Port() })));
                try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); if (loss == "Revoked") auth.DeleteSession(token); else typeof(UserSession).GetField("_lastSeen",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(auth.GetSession(token),DateTime.UtcNow.AddDays(-8)); }
                finally { sender.BeforeConfigureWait = null; gate.Release(); }
                var result = await request; Check(result.GetProperty("status").GetString() == "error" && sender.Settings.Revision == 2 && sender.Settings.Port == receiver.Port, loss + " waiter changed current endpoint");
                Console.WriteLine($"Native API {loss} during lock wait: denied; endpoint/revision unchanged=2");
            }
            Check((await Call(fresh,"/api/logging/syslog/set",("revision","1"),("settings",Json(configured)))).GetProperty("status").GetString() == "error", "Native stale revision accepted");
            var current = sender.Settings with { SystemEvents = false, SecurityEvents = false };
            Check((await Call(fresh,"/api/logging/syslog/set",("revision","2"),("settings",Json(current)))).GetProperty("status").GetString() == "ok", "Category selection failed");
            long admittedBefore = sender.Health.Persisted; Check(!sender.RecordSystem("excluded-system"), "Excluded system entered queue");
            sender.RecordSecurity(new("excluded",DateTime.UtcNow,"owned","DNS","127.0.0.1","benign.fixture.test","A","NoError","Monitor",0,null,[],null,"benign"));
            await NativeAnswers(dnsPort, 1, "selected-DNS-only"); await Matching(receiver,"answer.syslog.fixture.test"); await Until(() => sender.Health.Queued == 0);
            Check(sender.Health.Persisted == admittedBefore + 1, "Excluded security/system retained or exported");
            current = sender.Settings with { Port = Port() };
            Check((await Call(fresh,"/api/logging/syslog/set",("revision","3"),("settings",Json(current)))).GetProperty("status").GetString() == "ok", "Outage native configure failed");
            await NativeAnswers(dnsPort, 20, "API-collector-outage"); await Until(() => sender.Health.Failed > 0);
            Check((await Call(fresh,"/api/logging/syslog/get")).GetProperty("status").GetString() == "ok", "Native management unresponsive during outage");
            Check((await Call(original,"/api/logging/syslog/get")).GetProperty("status").GetString() == "ok", "Original native admin session not retained");
            await using (var hold = new Receiver(certificate,"Hold")) {
                var fullSettings = sender.Settings with { Port=hold.Port,SystemEvents=true };
                Check((await Call(fresh,"/api/logging/syslog/set",("revision",sender.Settings.Revision.ToString()),("settings",Json(fullSettings)))).GetProperty("status").GetString()=="ok","Native backpressure configure");
                long failureBefore=sender.Health.Failed;
                int admitted=0; const int offered=5000; var timer=Stopwatch.StartNew();
                for(int i=0;i<offered;i++) if(sender.RecordSystem("native-full-"+i+new string('漢',1900))) admitted++;
                await Until(()=>sender.Health.Failed>failureBefore && sender.Health.Dropped>0 && sender.Health.DurableQueued>0);
                await NativeAnswers(dnsPort,20,"API-backpressure-full");
                Check((await Call(fresh,"/api/logging/syslog/get")).GetProperty("status").GetString()=="ok","Native management blocked by backpressure");
                Console.WriteLine($"Native full/backpressure: offered={offered}; admitted={admitted}; rejected={offered-admitted}; elapsedMs={timer.Elapsed.TotalMilliseconds:F1}; API=responsive; queued={sender.Health.Queued}; durable={sender.Health.DurableQueued}; receipt=NoApplicationReceipt");
                int samePort=hold.Port;
                await sender.ConfigureAsync(sender.Settings with {Enabled=false},sender.Settings.Revision);
                long retained=sender.Health.DurableQueued; Check(retained>0,"No retained records for drain");
                await hold.DisposeAsync();
                await using var recovered=new Receiver(certificate,port:samePort);
                await sender.ConfigureAsync(sender.Settings with {Enabled=true},sender.Settings.Revision);
                for(int i=0;i<retained;i++) await recovered.Next();
                await Until(()=>sender.Health.Queued==0);
                Check(sender.RecordSystem("capacity-recovered"),"Capacity did not reopen after drain"); await Matching(recovered,"capacity-recovered");
                await NativeAnswers(dnsPort,10,"API-after-backpressure-drain");
                Console.WriteLine($"Native drain: retained={retained}; receiverParsed={retained}; pendingAtDrainEnd=0; subsequentAdmission=1/1; endpointUnchanged=true");
            }
            await using (var storageReceiver=new Receiver(certificate)) {
                Check((await Call(fresh,"/api/logging/syslog/set",("revision",sender.Settings.Revision.ToString()),("settings",Json(sender.Settings with {Port=storageReceiver.Port})))).GetProperty("status").GetString()=="ok","Native storage fault configure");
                await Until(()=>sender.Health.Queued==0); long persistedBefore=sender.Health.Persisted, droppedBefore=sender.Health.Dropped;
                sender.BeforeSpoolFlush=()=>throw new IOException("Owned simulated storage flush failure");
                try {
                    Check((await Call(fresh,"/api/logging/syslog/test")).GetProperty("response").GetProperty("queued").GetBoolean(),"Memory admission rejected simulated flush case");
                    await NativeAnswers(dnsPort,10,"API-spool-flush-failure");
                    await Until(()=>sender.Health.Dropped>=droppedBefore+11 && sender.Health.Queued==0);
                    Check(sender.Health.Persisted==persistedBefore,"Flush failure falsely acknowledged persistence");
                    Check((await Call(fresh,"/api/logging/syslog/get")).GetProperty("status").GetString()=="ok","API blocked by flush failure");
                    Console.WriteLine("Native spool flush seam: testMemoryQueued=1; DNSProduced=10; failedPersistenceDropped=11; persistedDelta=0; queuedAtWindowEnd=0; authoritativeDNS=10/10; API=responsive");
                } finally { sender.BeforeSpoolFlush=null; }
                Check(sender.RecordSystem("storage-recovered"),"Storage recovery admission"); await Matching(storageReceiver,"storage-recovered"); await Until(()=>sender.Health.Queued==0);
            }
            Console.WriteLine($"Native API: pid={Environment.ProcessId}; API/TLS source=127.0.0.1; positive/restricted/cluster/revoked/expired/stale checks, hook receiver readback, settings-only backup round trip; revision={sender.Settings.Revision}; trustSha256={sender.TlsCaSha256}");
        } finally { foreach (var value in before) Environment.SetEnvironmentVariable(value.Key, value.Value); }
    }
    public static async Task NativeChild(string folder) {
        await using var service = new DnsWebService(true, folder);
        if (Environment.GetEnvironmentVariable("TEQTANIUM_OWNED_SYSLOG_CHECKPOINT") == "after-write")
            Field<SyslogForwarder>(service,"_syslog").AfterSocketWrite = async (id, token) => { Console.WriteLine("NATIVE_AFTER_WRITE " + id); Console.Out.Flush(); await Task.Delay(Timeout.Infinite, token); };
        await service.StartAsync(true);
        string core = typeof(SyslogForwarder).Assembly.Location;
        Console.WriteLine("NATIVE_READY " + Json(new { pid = Environment.ProcessId, startedUtc = System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime(), coreSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(core))), runtime = Environment.Version.ToString() })); Console.Out.Flush();
        while (Console.ReadLine() is string command) { if (command == "stop") return; }
    }
    static async Task NativeProcessChecks(string folder, Certificates certs, X509Certificate2 certificate) {
        int http = Port(), dnsPort = Port(), collectorPort = Port(); string password = Guid.NewGuid().ToString("N") + "Aa9!";
        await using (var log = new LogManager(true, folder)) using (var dns = new DnsServer(folder,Path.Combine(AppContext.BaseDirectory,"dohwww"),log)) { dns.LoadConfigFile(); dns.LocalEndPoints = [new(IPAddress.Loopback,dnsPort)]; dns.EnableCheckForUpdate = false; dns.Recursion = DnsServerRecursion.Deny; Zone(dns); dns.SaveConfigFile(true); }
        async Task<(System.Diagnostics.Process Process, string Ready)> Start(bool checkpoint = false) {
            var start = new ProcessStartInfo("dotnet") { UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true, RedirectStandardInput=true };
            start.ArgumentList.Add(typeof(SyslogReliabilityChecks).Assembly.Location); start.ArgumentList.Add("--syslog-native-child"); start.ArgumentList.Add(folder);
            start.Environment["DNS_SERVER_ADMIN_PASSWORD"] = password; start.Environment["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] = "127.0.0.1"; start.Environment["DNS_SERVER_WEB_SERVICE_HTTP_PORT"] = http.ToString();
            if (checkpoint) start.Environment["TEQTANIUM_OWNED_SYSLOG_CHECKPOINT"] = "after-write";
            var process = System.Diagnostics.Process.Start(start)!;
            try { string ready = (await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)))!; Check(ready?.StartsWith("NATIVE_READY ") == true, "Native app failed readiness: " + ready); return (process,ready!); }
            catch { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); process.Dispose(); throw; }
        }
        var first = await Start();
        try {
            using var admin = Client(http); await Login(admin,password); await NativeAnswers(dnsPort,10,"process-before-outage");
            Check((await Call(admin,"/api/logging/syslog/set",("revision","0"),("settings",Json(Settings(collectorPort,certs.Trust) with { SystemEvents=false,DnsQueries=true })))).GetProperty("status").GetString() == "ok", "Native child config failed");
            Check((await Call(admin,"/api/logging/syslog/test")).GetProperty("response").GetProperty("queued").GetBoolean(), "Native child test admission failed");
            await NativeAnswers(dnsPort,20,"process-during-outage");
            JsonElement health = default;
            for (int i=0;i<100;i++) { var result=await Call(admin,"/api/logging/syslog/get"); health=result.GetProperty("response").GetProperty("health"); if(health.GetProperty("persisted").GetInt64()==21 && health.GetProperty("failed").GetInt64()>0) break; await Task.Delay(20); }
            Check(health.GetProperty("durableQueued").GetInt64()==21, "Native app did not persist actual API/DNS hook records");
            Check((await Call(admin,"/api/logging/syslog/set",("revision","1"),("settings",Json(Settings(collectorPort,certs.Trust) with { Enabled=false,SystemEvents=false,DnsQueries=true })))).GetProperty("status").GetString()=="ok","Native pause before restart failed");
            first.Process.Kill(true); await first.Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await using var receiver = new Receiver(certificate,port:collectorPort);
            var interrupted = await Start(checkpoint: true);
            string observedBeforeCrash;
            try {
                using var interim = Client(http); await Login(interim,password);
                Check((await Call(interim,"/api/logging/syslog/set",("revision","2"),("settings",Json(Settings(collectorPort,certs.Trust) with { SystemEvents=false,DnsQueries=true })))).GetProperty("status").GetString()=="ok","Native resume after restart failed");
                observedBeforeCrash = await receiver.Next();
                string checkpoint = (await interrupted.Process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)))!;
                Check(checkpoint.StartsWith("NATIVE_AFTER_WRITE "), "Native in-flight checkpoint not reached");
                Check((await Call(interim,"/api/logging/syslog/get")).GetProperty("response").GetProperty("health").GetProperty("durableQueued").GetInt64()==21,"Native socket write removed durable record before checkpoint");
                interrupted.Process.Kill(true); await interrupted.Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                Console.WriteLine($"Native interrupted write: pid={interrupted.Process.Id}; checkpoint={checkpoint}; receiverObserved=1; durableBeforeKill=21; receiverObservationIsNotSenderAck=true");
            } finally { if(!interrupted.Process.HasExited) { interrupted.Process.Kill(true); await interrupted.Process.WaitForExitAsync(); } interrupted.Process.Dispose(); }
            var second = await Start();
            try {
                Check(first.Process.Id != second.Process.Id,"Native restart PID unchanged"); using var fresh = Client(http); await Login(fresh,password);
                var records = new List<string>(); for(int i=0;i<21;i++) records.Add(await receiver.Next());
                Check(records.Count(x=>x.Contains("syslog forwarding test"))==1 && records.Count(x=>x.Contains("answer.syslog.fixture.test"))==20,"Native restarted receiver replay content/count mismatch");
                Check(records.Contains(observedBeforeCrash),"Interrupted write did not preserve exact original payload/time on duplicate replay");
                await Until(() => Directory.GetFiles(Path.Combine(folder,"syslog-spool"),"*.json").Length==0);
                var result=await Call(fresh,"/api/logging/syslog/get"); var current=result.GetProperty("response").GetProperty("health"); Check(current.GetProperty("replayed").GetInt64()==21 && current.GetProperty("queued").GetInt64()==0,"Native restarted spool did not drain");
                await NativeAnswers(dnsPort,20,"process-after-replay");
                Console.WriteLine($"Full native process replay: first={first.Ready}; final={second.Ready}; offered=21; persisted=21; receiverReadbackAcrossInterrupt=22; replayWindow=21; observedDuplicateAfterInterrupt=1; testRecordsInFinalWindow=1; DNSRecordsInFinalWindow=20; peer={string.Join(',',receiver.PeerAddresses.Distinct())}; pendingAtReplayEnd=0; gracefulFinalStop=true");
            } finally {
                if(!second.Process.HasExited) { await second.Process.StandardInput.WriteLineAsync("stop"); try { await second.Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); } catch { second.Process.Kill(true); await second.Process.WaitForExitAsync(); throw; } }
                Check(second.Process.ExitCode==0,"Native graceful shutdown failed"); second.Process.Dispose();
            }
        } finally { if(!first.Process.HasExited) { first.Process.Kill(true); await first.Process.WaitForExitAsync(); } first.Process.Dispose(); }
    }
}
