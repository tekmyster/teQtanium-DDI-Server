// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Ipam;
using System.Net;
using System.Net.Sockets;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;

static class DiscoveryScopeChecks
{
    static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    public static async Task Run(bool baseline, bool serve)
    {
        string folder = Path.Combine(Path.GetTempPath(), "discovery-scope-repair-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
        string repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        int port = Port(), dnsPort = Port(), checks = 0;
        string password = Guid.NewGuid().ToString("N") + "Aa9!";
        Environment.SetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD", password);
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "127.0.0.1");
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT", port.ToString());
        Environment.SetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH", Path.Combine(repository, "DnsServerCore/www"));
        Environment.SetEnvironmentVariable("DDI_DISCOVERY_SCOPE_FIXTURE", "fixture-read-only");
        await using (var log = new LogManager(true, folder))
        using (var dns = new DnsServer(folder, Path.Combine(repository, "DnsServerCore/dohwww"), log))
        { dns.LoadConfigFile(); dns.LocalEndPoints = [new IPEndPoint(IPAddress.Loopback, dnsPort)]; dns.EnableCheckForUpdate = false; dns.SaveConfigFile(true); }
        var service = new DnsWebService(true, folder);
        await using var snmp = new DiscoveryChecks.SnmpFixture();
        using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + port), Timeout = TimeSpan.FromSeconds(40) };
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
        async Task<JsonElement> Call(HttpClient c, string path, params (string Key, string Value)[] values)
        {
            using var content = new FormUrlEncodedContent(values.Select(v => new KeyValuePair<string,string>(v.Key,v.Value)));
            using var response = await c.PostAsync("/api/" + path, content); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone();
        }
        bool Ok(JsonElement value) => value.GetProperty("status").GetString() == "ok";
        async Task<JsonElement> Inventory() => (await Call(client,"ipam/list")).GetProperty("response").GetProperty("inventory");
        async Task<string> Revision() => (await Inventory()).GetProperty("revision").GetInt64().ToString();
        async Task<JsonElement> Status() => (await Call(client,"ipam/discovery/status")).GetProperty("response");
        async Task<JsonElement> Save(IpamDiscoverySource source) => await Call(client,"ipam/discovery/sources/set",("revision",await Revision()),("source",JsonSerializer.Serialize(source,JsonOptions)));
        async Task<JsonElement> RunSource(string sourceId) => await Call(client,"ipam/discovery/run",("sourceId",sourceId),("qualify","true"));
        try
        {
            await service.StartAsync(true);
            var login=await Call(client,"user/login",("user","admin"),("pass",password),("includeInfo","true")); Check(Ok(login),"native scoped-repair admin authentication");
            client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",login.GetProperty("token").GetString());
            var manager=(IpamManager)typeof(DnsWebService).GetField("_ipam",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(service);
            var subnet=await Call(client,"ipam/subnets/set",("revision",await Revision()),("prefix","127.0.0.0/24"),("name","Scope repair fixture")); Check(Ok(subnet),"native parent subnet created");
            string subnetId=subnet.GetProperty("response").GetProperty("subnet").GetProperty("id").GetString();
            async Task<JsonElement> Parent(string prefix="127.0.0.0/24",string view="default",string name="Scope repair fixture") => await Call(client,"ipam/subnets/set",("revision",await Revision()),("id",subnetId),("prefix",prefix),("viewId",view),("name",name));
            var source=new IpamDiscoverySource("","Parent-bound SNMP fixture","SnmpArp",subnetId,"127.0.0.1",snmp.Port,"DDI_DISCOVERY_SCOPE_FIXTURE","","",16,5000,300,"isolated-scope-repair-only");
            var saved=await Save(source);Check(Ok(saved),"scoped source saved disabled");source=saved.GetProperty("response").GetProperty("source").Deserialize<IpamDiscoverySource>(JsonOptions);
            var qualified=await RunSource(source.Id);Check(Ok(qualified)&&qualified.GetProperty("response").GetProperty("run").GetProperty("status").GetString()=="Complete","actual SNMP complete qualification");
            var initial=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
            if (baseline)
            {
                var idle=await Parent("127.0.0.0/25");var enabled=await Save(source with {Enabled=true});
                var reused=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                Check(Ok(idle)&&Ok(enabled)&&initial.LastSuccess==reused.LastSuccess&&initial.AttemptedAt==reused.AttemptedAt,"baseline reproduces qualification reused after parent-prefix change");
                Check(Ok(await Parent()),"baseline scope restored");Check(Ok(await Save(source)),"baseline source disabled");
                snmp.Mode="silent";var running=RunSource(source.Id);
                for(int n=0;n<100&&manager.ActiveDiscoveryIds().Length==0;n++)await Task.Delay(10);
                var edited=await Parent("127.0.0.0/25");var result=await running;
                var terminal=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                var cancelled=await Call(client,"ipam/discovery/cancel",("sourceId",source.Id));var sourceEdit=await Save(source with {Name="Recover source"});
                Check(Ok(edited)&&!Ok(result)&&terminal.Status=="Running"&&manager.ActiveDiscoveryIds().Length==0&&!cancelled.GetProperty("response").GetProperty("cancellationRequested").GetBoolean()&&!Ok(sourceEdit),"baseline reproduces phantom Running after in-flight parent change");
                var receipt=new {parentEdit=edited.GetProperty("status").GetString(),run=result.GetProperty("status").GetString(),persisted=terminal.Status,active=manager.ActiveDiscoveryIds(),cancelRequested=false,sourceEditDenied=true,qualificationReused=true,scopePrefix="127.0.0.0/25",core=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(typeof(IpamManager).Assembly.Location))).ToLowerInvariant(),productionTouched=false};
                File.WriteAllText(Path.Combine(repository,"../BASELINE-REPRO.json"),JsonSerializer.Serialize(receipt,new JsonSerializerOptions{WriteIndented=true}));
                Check(Ok(await Parent()),"baseline restored prefix for explicit recovery");snmp.Mode="normal";Check(Ok(await RunSource(source.Id)),"baseline same-ID explicit retry recovers original fixture");
            }
            else await RepairedChecks();
            async Task RepairedChecks()
            {
                Check(initial.Configuration.Contains("127.0.0.0/24") && initial.Configuration.Contains("viewId"), "qualification persists exact parent prefix and view binding");
                var inventoryBefore=manager.Export();
                var viewReply=await Call(client,"ipam/views/set",("revision",await Revision()),("name","Independent repair view"));Check(Ok(viewReply),"independent native network view created");
                string otherView=viewReply.GetProperty("response").GetProperty("view").GetProperty("id").GetString();
                var prefixReply=await Parent("127.0.0.0/25");
                Check(!Ok(prefixReply)&&prefixReply.GetProperty("errorMessage").GetString().Contains("Remove the subnet's discovery sources"),"idle parent prefix edit refused with actionable source-removal guidance");
                Check(!Ok(await Parent(view:otherView)),"idle parent network-view edit refused while source exists");
                Check(!Ok(await Call(client,"ipam/subnets/set",("revision",await Revision()),("id",subnetId),("prefix","127.0.0.0/24"),("name","Container conversion"),("container","true"))),"idle parent container conversion refused");
                Check(!Ok(await Call(client,"ipam/delete",("revision",await Revision()),("kind","subnet"),("id",subnetId))),"idle parent deletion refused while source exists");
                Check(manager.Snapshot().Subnets.Single(s=>s.Id==subnetId).Prefix=="127.0.0.0/24"&&manager.Snapshot().Subnets.Single(s=>s.Id==subnetId).ViewId=="default","refused parent edits leave actual qualification context unchanged");
                Check(Ok(await Save(source with {Enabled=true})),"qualification can enable only its unchanged parent context");Check(Ok(await Save(source)),"source disabled before in-flight mutation tests");
                snmp.Mode="silent";var running=RunSource(source.Id);
                for(int n=0;n<100&&manager.ActiveDiscoveryIds().Length==0;n++)await Task.Delay(10);
                Check(manager.ActiveDiscoveryIds().Contains(source.Id),"real native SNMP job is active before parent mutations");
                Check(!Ok(await Parent("127.0.0.0/25")),"in-flight parent prefix edit refused atomically");
                Check(!Ok(await Parent(view:otherView)),"in-flight parent view edit refused atomically");
                Check(!Ok(await Call(client,"ipam/subnets/set",("revision",await Revision()),("id",subnetId),("prefix","127.0.0.0/24"),("name","In-flight container"),("container","true"))),"in-flight parent container conversion refused");
                Check(!Ok(await Call(client,"ipam/delete",("revision",await Revision()),("kind","subnet"),("id",subnetId))),"in-flight parent deletion refused");
                Check(!Ok(await Save(source with {Name="Unsupported concurrent edit"})),"in-flight source edit refused");
                Check(!Ok(await Call(client,"ipam/discovery/sources/delete",("revision",await Revision()),("sourceId",source.Id))),"in-flight source removal refused");
                bool restoreDenied=false;try{manager.Restore(manager.Export());}catch(InvalidOperationException){restoreDenied=true;}Check(restoreDenied,"restore refuses a live source job");
                Check(!Ok(await RunSource(source.Id)),"competing collection rejected without overlap");
                Check(Ok(await Call(client,"ipam/discovery/cancel",("sourceId",source.Id))),"operator cancellation acknowledged after denied parent edit");
                var stopped=await running;Check(Ok(stopped)&&stopped.GetProperty("response").GetProperty("run").GetProperty("status").GetString()=="Cancelled","original job reaches a durable terminal cancelled outcome");
                Check(manager.ActiveDiscoveryIds().Length==0&&manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id).Status=="Cancelled","persisted status and active IDs agree after rejected scope edit");
                Check(Ok(await Save(source)),"source is editable after cancellation without restoring old prefix");
                snmp.Mode="normal";Check(Ok(await RunSource(source.Id)),"same source explicitly recollects after cancellation");
                var lastGood=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                // Force a real terminal-save failure, after the Running marker is durable.
                snmp.Mode="silent";var blockedRun=RunSource(source.Id);
                for(int n=0;n<100&&manager.ActiveDiscoveryIds().Length==0;n++)await Task.Delay(10);
                using(var fileLock=new FileStream(Path.Combine(folder,"ipam.json.write-lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))
                {
                    Check(Ok(await Call(client,"ipam/discovery/cancel",("sourceId",source.Id))),"cancel admitted while terminal persistence is blocked");
                    var blockedResult=await blockedRun;
                    Check(!Ok(blockedResult)&&blockedResult.GetProperty("errorMessage").GetString().Contains("outcome could not be saved"),"terminal write failure returns actionable pending-save error");
                    var pending=await Status();
                    Check(pending.GetProperty("pendingPersistence").EnumerateArray().Any(v=>v.GetString()==source.Id)&&pending.GetProperty("active").EnumerateArray().Any(v=>v.GetString()==source.Id),"storage failure retains a real pending job and admission claim");
                    Check(manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id).Status=="Running","disk Running remains truthful while terminal save is pending");
                    bool pendingRestoreDenied=false;try{manager.Restore(manager.Export());}catch(InvalidOperationException){pendingRestoreDenied=true;}Check(pendingRestoreDenied,"pending terminal save also protects inventory restore");
                    Check(!Ok(await Save(source)),"pending-save source cannot be edited underneath its job");
                    Check((await Call(client,"ipam/discovery/cancel",("sourceId",source.Id))).GetProperty("response").GetProperty("cancellationRequested").GetBoolean(),"pending-save cancellation does not report a nonexistent job");
                    Check(!Ok(await RunSource(source.Id)),"pending outcome blocks a competing network collection");
                }
                int requestsBeforeRetry=snmp.Requests;
                var recovered=await Status();
                Check(recovered.GetProperty("active").GetArrayLength()==0&&recovered.GetProperty("pendingPersistence").GetArrayLength()==0,"reload finishes terminal persistence after storage recovers");
                var persisted=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                Check(persisted.Status=="Cancelled"&&persisted.LastSuccess==lastGood.LastSuccess&&persisted.Evidence.SequenceEqual(lastGood.Evidence),"cancelled save recovery retains complete last-known evidence and original timestamp");
                Check(snmp.Requests==requestsBeforeRetry,"terminal retry sends no new SNMP request");Check(Ok(await Save(source)),"source edit recovers after durable finalization");
                // A successful complete snapshot is also retained until its save can finish.
                snmp.Mode="normal";snmp.ResponseDelayMs=100;var successRun=RunSource(source.Id);
                for(int n=0;n<100&&manager.ActiveDiscoveryIds().Length==0;n++)await Task.Delay(10);
                using(var fileLock=new FileStream(Path.Combine(folder,"ipam.json.write-lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))
                {
                    Check(!Ok(await successRun),"successful transport reports unconfirmed storage instead of false completion");
                    Check(manager.PendingDiscoveryPersistenceIds().Contains(source.Id),"successful unsaved result remains owned by a pending job");
                }
                snmp.ResponseDelayMs=0;requestsBeforeRetry=snmp.Requests;await Status();
                Check(manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id).Status=="Complete"&&manager.ActiveDiscoveryIds().Length==0,"successful pending result becomes durable Complete after reload");
                Check(snmp.Requests==requestsBeforeRetry,"successful save retry does not repeat the collector");
                // Restart retires a pending save; an obsolete instance cannot resurrect it.
                snmp.Mode="silent";var restartRun=RunSource(source.Id);
                for(int n=0;n<100&&manager.ActiveDiscoveryIds().Length==0;n++)await Task.Delay(10);
                using(var fileLock=new FileStream(Path.Combine(folder,"ipam.json.write-lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))
                {await Call(client,"ipam/discovery/cancel",("sourceId",source.Id));Check(!Ok(await restartRun),"restart fixture has a real unsaved terminal result");}
                int requestsAtRestart=snmp.Requests;var obsolete=manager;
                await service.DisposeAsync();service=new DnsWebService(true,folder);await service.StartAsync(true);
                var restartedLogin=await Call(client,"user/login",("user","admin"),("pass",password));Check(Ok(restartedLogin),"fresh native admin authentication after pending-job restart");client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",restartedLogin.GetProperty("token").GetString());
                manager=(IpamManager)typeof(DnsWebService).GetField("_ipam",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(service);
                Check(manager.ActiveDiscoveryIds().Length==0&&manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id).Status=="Interrupted","restart durably retires unfinished persistence without phantom activity");
                var fileBefore=File.ReadAllBytes(Path.Combine(folder,"ipam.json"));obsolete.RetryDiscoveryPersistence();Check(fileBefore.SequenceEqual(File.ReadAllBytes(Path.Combine(folder,"ipam.json"))),"obsolete pending instance cannot overwrite restarted inventory");
                Check(snmp.Requests==requestsAtRestart,"restart and obsolete finalization send no new collector traffic");
                snmp.Mode="normal";Check(Ok(await RunSource(source.Id)),"explicit same-source qualification recovers after pending-job restart");
                var oldQualification=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                Check(Ok(await Call(client,"ipam/discovery/sources/delete",("revision",await Revision()),("sourceId",source.Id))),"authorized source removal completes before a parent scope change");
                Check(Ok(await Parent("127.0.0.0/25",otherView)),"parent prefix and view can change after all discovery sources are removed");
                var changedState=manager.Snapshot();
                var forged=changedState with {DiscoverySources=[source],DiscoveryRuns=[oldQualification]};
                bool forgedDenied=false;try{manager.Restore(JsonSerializer.SerializeToUtf8Bytes(forged,JsonOptions));}catch(ArgumentException){forgedDenied=true;}
                Check(forgedDenied,"restore rejects qualification bound to a different prefix or network view");
                var legacyOptions=new JsonSerializerOptions(JsonOptions){WriteIndented=true};
                var legacy=forged with {DiscoveryRuns=[oldQualification with {Configuration=JsonSerializer.Serialize(source with {Enabled=false},legacyOptions)}]};
                manager.Restore(JsonSerializer.SerializeToUtf8Bytes(legacy,JsonOptions));
                var legacyRun=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                Check(legacyRun.Status=="Interrupted"&&legacyRun.OutcomeReason=="ScopeReviewRequired"&&!manager.Snapshot().DiscoverySources.Single(s=>s.Id==source.Id).Enabled,"legacy subnet-ID-only qualification is disabled and marked for scope review");
                Check(legacyRun.Evidence.SequenceEqual(oldQualification.Evidence)&&manager.DiscoveryEvidence(subnetId,true).Length==0,"legacy historical rows are retained but cannot become evidence in the changed view");
                Check(!Ok(await Save(source with {Enabled=true})),"legacy successful timestamp cannot enable the changed parent scope");
                int legacyRequests=snmp.Requests;Check(!Ok(await Call(client,"ipam/discovery/run",("sourceId",source.Id),("qualify","false")))&&snmp.Requests==legacyRequests,"legacy ordinary collection refused without target traffic");
                var reviewStatus=await Status();Check(!reviewStatus.GetProperty("runs").EnumerateArray().Single(r=>r.GetProperty("sourceId").GetString()==source.Id).GetProperty("scopeCurrent").GetBoolean(),"native status explicitly labels unbound legacy scope");
                source=source with {Name="Reviewed new scope",ApprovalReference="isolated-reviewed-new-prefix-and-view"};Check(Ok(await Save(source)),"operator records the new scope disabled before requalification");
                Check(Ok(await RunSource(source.Id)),"explicit new-context qualification succeeds");
                var newQualification=manager.Snapshot().DiscoveryRuns.Single(r=>r.SourceId==source.Id);
                Check(newQualification.Configuration.Contains("127.0.0.0/25")&&newQualification.Configuration.Contains(otherView)&&IpamManager.DiscoveryScopeCurrent(manager.Snapshot(),newQualification),"new qualification binds exact changed prefix and independent view identity");
                Check(Ok(await Save(source with {Enabled=true})),"only requalified current context can enable manual collection");Check(Ok(await Save(source)),"reviewed source left disabled for browser recovery tests");
                Check(manager.Snapshot().Assignments.All(a=>a.SubnetId!=subnetId),"scope lifecycle repair creates no static assignment");

            }
            using(var fresh=new HttpClient {BaseAddress=client.BaseAddress})
            {
                var freshLogin=await Call(fresh,"user/login",("user","admin"),("pass",password));Check(Ok(freshLogin),"separate fresh scoped-repair admin authentication");fresh.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",freshLogin.GetProperty("token").GetString());
                var inv=await Call(fresh,"ipam/list");Check(Ok(inv),"fresh admin reads repaired inventory");Check(Ok(await Call(fresh,"ipam/views/set",("revision",inv.GetProperty("response").GetProperty("inventory").GetProperty("revision").GetInt64().ToString()),("name","Fresh scope-repair access"))),"fresh admin performs actual modification while original remains open");
                var sessions=(await Call(fresh,"admin/sessions/list")).GetProperty("response").GetProperty("sessions");Check(sessions.EnumerateArray().Single(s=>s.GetProperty("isCurrentSession").GetBoolean()).GetProperty("lastSeenRemoteAddress").GetString()=="127.0.0.1","target sees fresh affected source loopback");Check(Ok(await Call(client,"ipam/discovery/status")),"original admin remains usable after fresh proof");
            }
            if(serve)
            {
                snmp.ControlFile=Path.Combine(folder,"snmp-mode.txt");File.WriteAllText(snmp.ControlFile,"normal");
                string storageControl=Path.Combine(folder,"storage-control.txt"),storageStatus=Path.Combine(folder,"storage-status.txt");File.WriteAllText(storageControl,"release");
                using var controlStop=new CancellationTokenSource();
                var controlTask=Task.Run(async()=>
                {
                    FileStream held=null;
                    try
                    {
                        while(!controlStop.IsCancellationRequested)
                        {
                            string command=File.ReadAllText(storageControl).Trim();
                            if(command=="lock"&&held is null) { try { held=new FileStream(Path.Combine(folder,"ipam.json.write-lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None); } catch(IOException) {} }
                            if(command!="lock"&&held is not null) {held.Dispose();held=null;}
                            File.WriteAllText(storageStatus,held is null?"released":"locked");await Task.Delay(50,controlStop.Token);
                        }
                    }
                    catch(OperationCanceledException){}
                    finally {held?.Dispose();}
                });
                File.WriteAllText(Path.Combine(repository,"../scope-ui-session.json"),JsonSerializer.Serialize(new{url=client.BaseAddress.AbsoluteUri,user="admin",password,root=folder,sourceId=source.Id,subnetId,snmpControlFile=snmp.ControlFile,snmpPort=snmp.Port,storageControl,storageStatus},JsonOptions));Console.WriteLine("SERVING scope repair fixture; ENTER stops.");Console.ReadLine();controlStop.Cancel();await controlTask;File.Delete(Path.Combine(repository,"../scope-ui-session.json"));
            }
            Console.WriteLine("PASS "+checks+" scoped discovery "+(baseline?"baseline reproduction":"repair")+" checks");
        }
        finally {await service.DisposeAsync();Environment.SetEnvironmentVariable("DDI_DISCOVERY_SCOPE_FIXTURE",null);}
    }
}
