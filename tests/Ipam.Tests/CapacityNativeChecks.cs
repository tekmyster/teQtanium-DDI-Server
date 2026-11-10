// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;

static partial class DistributedTransportChecks
{
    static string NativeCapacityManifest(Scope scope)
    {
        using var config=new MemoryStream();scope.WriteTo(config,false,false);
        var leases=scope.Leases.Values.Select(lease=>{using var bytes=new MemoryStream();lease.WriteTo(new BinaryWriter(bytes));return Convert.ToBase64String(bytes.ToArray());}).Order(StringComparer.Ordinal).ToArray();
        return JsonSerializer.Serialize(new {configuration=Convert.ToBase64String(config.ToArray()),leases},DistributedAllocation.JsonOptions);
    }
    static DhcpMessage CapacityPacket(byte client,byte type=1,IPAddress address=null)
    {
        byte[] wire=new byte[244];wire[0]=1;wire[1]=1;wire[2]=6;wire[7]=client;wire[28]=2;wire[33]=client;
        address?.GetAddressBytes().CopyTo(wire,12);new byte[]{99,130,83,99,53,1,type,255}.CopyTo(wire,236);return new(new MemoryStream(wire));
    }
    static async Task CapacityAck(DnsWebService service,DhcpServer server,Scope scope,DistributedAllocation store,string name,uint address,string client,DateTime expiry,Action<bool,string> check)
    {
        var ip=AllocationSequence.Address(address);
        scope.LeaseTimeDays=0;scope.LeaseTimeHours=1;scope.LeaseTimeMinutes=0; // a shorter renewal must preserve the exact prior protected lifetime
        using var sender=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);using var receiver=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        sender.Bind(new IPEndPoint(IPAddress.Loopback,0));receiver.Bind(new IPEndPoint(ip,68));scope.SetEnabled(true);typeof(Scope).GetField("_interfaceAddress",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(scope,IPAddress.Loopback);
        try
        {
            await ((Task)typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(server,[CapacityPacket(88,3,ip),new IPEndPoint(ip,68),default(IPPacketInformation),sender])).WaitAsync(deadline.Token);
            byte[] wire=new byte[4096];int length=await receiver.ReceiveAsync(wire.AsMemory(),SocketFlags.None,deadline.Token);var response=new DhcpMessage(new MemoryStream(wire,0,length));
            check(response.DhcpMessageType.Type==DhcpMessageType.Ack&&response.YourClientIpAddress.Equals(ip),"fresh native process real handler emits protected borrower UDP ACK");
            check(store.FindLease(name,client).Expires==expiry&&scope.Leases.Values.Single(l=>l.Address.Equals(ip)).LeaseExpires==expiry,"protected borrower ACK retains exact pre-kill native expiry");
        }
        finally{scope.SetEnabled(false);}
    }
    static async Task CheckCapacity(List<DnsWebService> services, List<HttpClient> originals, List<HttpClient> admins, List<HttpClient> peers,
        string[] names, Dictionary<(int Source,int Target),PinnedHandler> links, Action<bool,string> check)
    {
        const string scopeName="Capacity";
        string Json<T>(T v)=>JsonSerializer.Serialize(v,DistributedAllocation.JsonOptions);
        bool Ok(JsonElement r)=>r.GetProperty("status").GetString()=="ok";
        async Task Good(Task<JsonElement> call,string label) { var r=await call;check(Ok(r),label+": "+r);Console.WriteLine("OK "+label); }
        async Task Bad(Task<JsonElement> call,string label) { var r=await call;check(!Ok(r),label+": "+r);Console.WriteLine("REFUSED "+label); }
        var servers=services.Select(s=>Field<DhcpServer>(s,"_dhcpServer")).ToArray();
        var stores=services.Select(s=>Field<DistributedAllocation>(s,"_allocation")).ToArray();
        var scopes=new Scope[3];
        string evidence=Environment.GetEnvironmentVariable("TEQTANIUM_CAPACITY_EVIDENCE"); int step=0;
        void Evidence(string label)
        {
            if(evidence is null)return;Directory.CreateDirectory(evidence);
            File.WriteAllText(Path.Combine(evidence,$"{++step:D3}-{label}.json"),Json(new { label, process=Environment.ProcessId,utc=DateTime.UtcNow, nodes=stores.Select((s,i)=>new {node=names[i], state=s.Snapshot(),nativeFile=Convert.ToBase64String(File.ReadAllBytes(Path.Combine(Field<string>(servers[i],"_scopesFolder"),scopeName+".scope"))), leases=scopes[i].Leases.Values.Select(l=>new {address=l.Address.ToString(),client=l.ClientIdentifier.ToString(),expires=l.LeaseExpires}),http=originals[i].BaseAddress,https=admins[i].BaseAddress,dns=services[i].DnsServer.LocalEndPoints.Select(e=>e.ToString())}) }));
        }
        long Seq(int n)=>stores[n].Snapshot().Replicas.SingleOrDefault(r=>r.Scope==scopeName&&r.Node==names[n])?.Sequence??0;
        async Task Mesh()
        {
            foreach(int receiver in Enumerable.Range(0,3))foreach(int sender in Enumerable.Range(0,3))if(receiver!=sender)
                await Good(Call(peers[receiver],"/api/ddi/dhcp/state/ingest",("state",Json(stores[sender].Snapshot()))),$"HTTPS mesh {sender}->{receiver}");
        }
        foreach(var s in stores) { Field<CancellationTokenSource>(s,"_stop").Cancel();await Field<Task>(s,"_worker"); }
        string killRoot=Environment.GetEnvironmentVariable("TEQTANIUM_CAPACITY_ROOT");
        bool resume=killRoot is not null && File.Exists(Path.Combine(killRoot,"surrender.ready"));
        if(resume)
        {
            for(int i=0;i<3;i++)scopes[i]=servers[i].GetScope(scopeName)??throw new Exception("Native scope did not reopen");
            var saved=JsonDocument.Parse(File.ReadAllText(Path.Combine(killRoot,"capacity-resume.json"))).RootElement;
            string epoch=saved.GetProperty("epoch").GetString(),rid=saved.GetProperty("id").GetString(),gid=saved.GetProperty("grantId").GetString();uint address=saved.GetProperty("address").GetUInt32();
            string nativeManifest=saved.TryGetProperty("nativeScopeManifest",out var nativeManifestValue)?nativeManifestValue.GetString():NativeCapacityManifest(scopes[1]);
            Evidence("whole-native-reopened-before-retry");
            check(scopes.All(s=>!s.Enabled),"whole native process restart retains paused scopes");
            check(!stores[0].HasAuthority(scopeName,address)&&!stores[1].HasAuthority(scopeName,address),"reopened surrender has no usable authority before donor acknowledgement");
            check(stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns.Single().Id==rid,"fresh native service reopens exact durable return receipt");
            check(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(Field<string>(servers[1],"_scopesFolder"),scopeName+".scope"))))==saved.GetProperty("nativeScopeHash").GetString(),"fresh native scope bytes exactly match pre-kill saved bindings");
            await Good(Call(admins[1],"/api/ddi/dhcp/grants/return",("scope",scopeName),("epoch",epoch),("owner",names[0]),("address",AllocationSequence.Address(address).ToString()),("grantId",gid),("requestId",rid),("expectedSequence","-1"),("expectedHash",DistributedAllocation.GrantReviewHash(scopeName,epoch,names[0],stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns.Single().Grant))),"fresh-process exact surrender retry");
            await Mesh();await Good(Call(admins[0],"/api/ddi/dhcp/grants/reclaim",("scope",scopeName),("epoch",epoch),("borrower",names[1]),("requestId",rid),("expectedSequence",Seq(0).ToString()),("expectedHash",DistributedAllocation.GrantReturnHash(scopeName,epoch,stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns.Single()))),"fresh-process original donor acknowledgement");await Mesh();
            check(stores[0].HasAuthority(scopeName,address)&&!stores[1].HasAuthority(scopeName,address),"whole native kill/reopen resumes one authority");
            var protectedExpiry=saved.GetProperty("protectedExpiry").GetDateTime();uint resumedProtectedAddress=saved.GetProperty("protectedAddress").GetUInt32();string protectedClient=saved.GetProperty("protectedClient").GetString();
            check(stores[1].FindLease(scopeName,protectedClient).Expires==protectedExpiry,"fresh durable authority retains protected binding exact expiry");
            Evidence("whole-native-after-retry-before-ack");
            check(NativeCapacityManifest(scopes[1])==nativeManifest,"post-retry native readback preserves exact serialized binding fields independent of dictionary order");
            await CapacityAck(services[1],servers[1],scopes[1],stores[1],scopeName,resumedProtectedAddress,protectedClient,protectedExpiry,check);
            var staleReplay=Call(peers[0],"/api/ddi/dhcp/state/ingest",("state",File.ReadAllText(Path.Combine(killRoot,"pre-surrender-donor.json"))));
            if(saved.TryGetProperty("staleEpoch",out var staleEpoch)&&staleEpoch.GetBoolean()) await Bad(staleReplay,"pre-successor donor epoch replay after reopen");
            else await Good(staleReplay,"pre-kill stale donor replay after acknowledgement");
            check(stores[0].HasAuthority(scopeName,address)&&!stores[1].HasAuthority(scopeName,address),"pre-kill stale grant cannot resurrect borrower");
            Evidence("whole-native-resumed-terminal");return;
        }
        for(int i=0;i<3;i++)
        {
            scopes[i]=new Scope(scopeName,false,IPAddress.Parse("127.0.0.10"),IPAddress.Parse("127.0.0.90"),IPAddress.Parse("255.255.255.0"),Field<LogManager>(services[i],"_log"),servers[i]);
            await servers[i].AddScopeAsync(scopes[i]);
            await Good(Call(admins[i],"/api/dhcp/scopes/set",("name",scopeName),("dnsUpdates","false"),("pingCheckEnabled","false"),("ignoreClientIdentifierOption","true"),("domainName","capacity.test")),"paused native scope "+i);
        }
        await Good(Call(admins[0],"/api/ddi/dhcp/plan/set",("scope",scopeName),("owners",string.Join(',',names))),"actual native initial ownership bootstrap");
        var plan=stores[0].Plan(scopeName);
        string id=Guid.NewGuid().ToString("N");
        var borrowMethod=typeof(DnsWebService).GetMethod("BorrowAllocation",BindingFlags.Instance|BindingFlags.NonPublic);
        typeof(DnsWebService).GetField("_capacityDonorCursor",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(services[1],-1);
        links[(1,0)].LoseCapacityResponse=true;links[(1,2)].Disconnected=true;
        var lost=await (Task<byte[]>)borrowMethod.Invoke(services[1],[scopeName,names[1]]);
        check(lost is null,"native borrowing preserves pending outcome after lost HTTPS grant reply");
        var pendingRequests=stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).BorrowRequests;
        string request=pendingRequests.Single(r=>r.Donor==names[0]).Id;
        var donor=Field<ClusterManager>(services[1],"_clusterManager").ClusterNodes.Values.Single(n=>n.Name==names[0]);
        var grant=stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).Entries.Single(e=>e.GrantId==request);
        check(!stores[0].HasAuthority(scopeName,grant.Address),"lost grant reply cannot restore donor authority");
        var retry=await (Task<byte[]>)borrowMethod.Invoke(services[1],[scopeName,names[1]]);
        check(retry is not null&&stores[1].HasAuthority(scopeName,grant.Address),"production borrowing retries persisted original donor ID and imports outcome");
        check(stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).Entries.Count(e=>e.State=="Grant")==1,"same stable HTTPS retry creates one grant");
        links[(1,2)].Disconnected=false;
        string pendingOther=stores[1].CapacityRequest(scopeName,names[2]);
        var donorOther=Field<ClusterManager>(services[1],"_clusterManager").ClusterNodes.Values.Single(n=>n.Name==names[2]);
        stores[1].Merge(await donorOther.GrantAllocationAsync(scopeName,names[1],pendingOther));stores[1].CompleteCapacityRequest(scopeName,names[2],pendingOther);
        var before=stores.Select(s=>s.Export()).ToArray();
        Task<JsonElement> Return(HttpClient actor=null,string epoch=null,string returnId=null,long? seq=null,uint? address=null)=>Call(actor??admins[1],"/api/ddi/dhcp/grants/return",("scope",scopeName),("epoch",epoch??plan.Epoch),("owner",names[0]),("address",AllocationSequence.Address(address??grant.Address).ToString()),("grantId",grant.GrantId),("requestId",returnId??id),("expectedSequence",(seq??Seq(1)).ToString()),("expectedHash",DistributedAllocation.GrantReviewHash(scopeName,epoch??plan.Epoch,names[0],grant)));
        Task<JsonElement> Reclaim(string borrower=null,long? seq=null,HttpClient actor=null)=>Call(actor??admins[0],"/api/ddi/dhcp/grants/reclaim",("scope",scopeName),("epoch",plan.Epoch),("borrower",borrower??names[1]),("requestId",id),("expectedSequence",(seq??Seq(0)).ToString()),("expectedHash",DistributedAllocation.GrantReturnHash(scopeName,plan.Epoch,stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns?.SingleOrDefault(r=>r.Id==id))));
        await Bad(Return(originals[1]),"plaintext administrative return");await Bad(Return(peers[1]),"cluster token cannot surrender borrower");
        await Bad(Call(admins[1],"/api/ddi/dhcp/grants/return?actingUser=admin",("scope",scopeName)),"proxied actor cannot surrender borrower");
        var selfNode=Field<ClusterManager>(services[1],"_clusterManager").GetSelfNode();
        typeof(ClusterNode).GetField("_fenced",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(selfNode,true);
        try { await Bad(Return(),"fenced authoritative borrower cannot change grants"); }
        finally { typeof(ClusterNode).GetField("_fenced",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(selfNode,false); }
        await Bad(Call(admins[1],"/api/ddi/dhcp/grants/return",("scope",scopeName),("epoch",plan.Epoch),("owner",names[0]),("address",AllocationSequence.Address(grant.Address).ToString()),("grantId",grant.GrantId),("requestId",id),("expectedSequence",Seq(1).ToString()),("expectedHash","changed")),"exact grant review hash mismatch");
        await Bad(Return(epoch:"stale"),"native stale epoch");await Bad(Return(seq:-2),"native stale borrower sequence");
        await Bad(Reclaim(),"donor cannot infer relinquishment from missing receipt");
        string nativePath=Path.Combine(Field<string>(servers[1],"_scopesFolder"),scopeName+".scope");
        using(var held=new FileStream(nativePath,FileMode.Open,FileAccess.Read,FileShare.Read)) await Bad(Return(),"strict native save failure earns no surrender");
        check((stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns?.Length??0)==0&&stores[1].HasAuthority(scopeName,grant.Address),"failed native save keeps borrower authority and no receipt");
        // Separate protected handoff survives the unused-grant surrender crash.
        var protectedNative=await scopes[2].GetOfferAsync(CapacityPacket(88));scopes[2].CommitLease(protectedNative);
        uint untouched=AllocationSequence.Number(protectedNative.Address);
        stores[2].Commit(scopeName,untouched,protectedNative.ClientIdentifier.ToString(),BitConverter.ToString(protectedNative.HardwareAddress),protectedNative.HostName,protectedNative.LeaseExpires);
        stores[2].Handoff(scopeName,[untouched],names[1],Guid.NewGuid().ToString("N"),Seq(2));await Mesh();
        scopes[1].LeaseTimeDays=0;scopes[1].LeaseTimeHours=1;scopes[1].LeaseTimeMinutes=0;
        var inherited=stores[1].FindLease(scopeName,protectedNative.ClientIdentifier.ToString());scopes[1].CommitLease(Lease.Recover(inherited,false));servers[1].SaveScope(scopeName);
        check(scopes[1].Leases.Values.Single(l=>l.Address.Equals(protectedNative.Address)).LeaseExpires==protectedNative.LeaseExpires,"unaffected protected handoff exact native expiry before surrender");
        using(var nativeFile=File.OpenRead(nativePath))using(var nativeRead=new Scope(nativeFile,Field<LogManager>(services[1],"_log"),servers[1]))
        {
            foreach(var l in nativeRead.Leases.Values)Console.WriteLine("NATIVE-READBACK persisted="+l.LeaseExpires.ToString("O")+" current="+scopes[1].Leases.Values.Single(v=>v.Address.Equals(l.Address)).LeaseExpires.ToString("O")+" identity="+l.ClientIdentifier.Equals(scopes[1].Leases.Values.Single(v=>v.Address.Equals(l.Address)).ClientIdentifier));
        }
        Evidence("before-surrender");
        var borrowerCert=(System.Security.Cryptography.X509Certificates.X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(services[1]);
        using(var lostReplyClient=new HttpClient(new PinnedHandler(borrowerCert){LoseLifecycleResponse="return"}){BaseAddress=admins[1].BaseAddress})
        {
            lostReplyClient.DefaultRequestHeaders.Authorization=admins[1].DefaultRequestHeaders.Authorization;
            try {await Return(lostReplyClient);throw new Exception("Expected lost surrender reply");}
            catch(HttpRequestException){check(stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).GrantReturns.Single().Id==id,"actual HTTPS surrender reply loss occurs after durable receipt");}
        }
        check(!stores[0].HasAuthority(scopeName,grant.Address)&&!stores[1].HasAuthority(scopeName,grant.Address),"both withheld before donor acknowledgment");
        var terminalReturn=stores[1].Export();await Good(Return(seq:-1),"lost return reply exact retry");
        await Bad(Return(address:grant.Address+1),"same return ID changed address");
        await Bad(Return(returnId:Guid.NewGuid().ToString("N")),"alternate recovery ID");
        Evidence("surrendered-before-donor-ack");
        async Task Checkpoint(string epoch,string returnId,AllocationEntry checkpointGrant,bool staleEpoch)
        {
            File.WriteAllText(Path.Combine(killRoot,"capacity-resume.json"),Json(new {epoch,id=returnId,grantId=checkpointGrant.GrantId,address=checkpointGrant.Address,protectedAddress=untouched,protectedClient=protectedNative.ClientIdentifier.ToString(),protectedExpiry=protectedNative.LeaseExpires,nativeScopeHash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(nativePath))),nativeScopeManifest=NativeCapacityManifest(scopes[1]),staleEpoch}));
            File.WriteAllBytes(Path.Combine(killRoot,"pre-surrender-donor.json"),before[0]);
            File.WriteAllText(Path.Combine(killRoot,"surrender.ready"),staleEpoch?"carried borrower surrender under committed successor; original donor not acknowledged":"durable borrower surrender; original donor not acknowledged");Console.WriteLine("CAPACITY-DURABLE-SURRENDER");Console.Out.Flush();await Task.Delay(Timeout.Infinite);
        }
        if(killRoot is not null&&Environment.GetEnvironmentVariable("TEQTANIUM_CAPACITY_KILL_PHASE")!="carried") await Checkpoint(plan.Epoch,id,grant,false);
        await Mesh();
        await Bad(Call(admins[0],"/api/ddi/dhcp/grants/reclaim",("scope",scopeName),("epoch",plan.Epoch),("borrower",names[1]),("requestId",id),("expectedSequence",Seq(0).ToString()),("expectedHash","changed")),"exact durable surrender hash mismatch");
        var donorCert=(System.Security.Cryptography.X509Certificates.X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(services[0]);
        using(var lostAckClient=new HttpClient(new PinnedHandler(donorCert){LoseLifecycleResponse="reclaim"}){BaseAddress=admins[0].BaseAddress})
        {
            lostAckClient.DefaultRequestHeaders.Authorization=admins[0].DefaultRequestHeaders.Authorization;
            try {await Reclaim(actor:lostAckClient);throw new Exception("Expected lost donor acknowledgment");}
            catch(HttpRequestException){check(stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).GrantReclaims.Single().Id==id,"actual HTTPS donor acknowledgment lost after durable reclamation");}
        }
        var terminal=stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]);
        check(terminal.GrantReclaims.Single().Grant==grant&&stores[0].HasAuthority(scopeName,grant.Address)&&!stores[1].HasAuthority(scopeName,grant.Address),"terminal exact grant identity and single usable authority");
        await Good(Reclaim(seq:-1),"duplicate donor acknowledgment");
        var retiredRetry=await donor.GrantAllocationAsync(scopeName,names[1],request);
        check(retiredRetry is not null&&stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).Entries.All(e=>e.GrantId!=request),"retired request retry returns terminal state without allocating another address");await Bad(Reclaim(names[2]),"alternate receiver reclaim");
        await Mesh();
        await Good(Call(peers[1],"/api/ddi/dhcp/state/ingest",("state",System.Text.Encoding.UTF8.GetString(before[0]))),"stale donor replay after terminal");
        await Good(Call(peers[0],"/api/ddi/dhcp/state/ingest",("state",System.Text.Encoding.UTF8.GetString(terminalReturn))),"delayed borrower surrender publication");
        check(stores[0].HasAuthority(scopeName,grant.Address)&&!stores[1].HasAuthority(scopeName,grant.Address),"stale and delayed messages cannot resurrect borrower");
        Evidence("reclaimed");
        // Actual native lease and admitted renewal on a second grant. Return must
        // wait for the ACK then refuse without shortening its final expiry.
        string protectedId=Guid.NewGuid().ToString("N"); byte[] second=await donor.GrantAllocationAsync(scopeName,names[1],protectedId);stores[1].Merge(second);
        var protectedGrant=stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).Entries.Single(e=>e.GrantId==protectedId);
        uint protectedAddress=protectedGrant.Address;var ip=AllocationSequence.Address(protectedAddress);
        string client="1-02000000004D";
        check(stores[1].Hold(scopeName,protectedAddress,client,"02-00-00-00-00-4D","protected",DateTime.UtcNow.AddMinutes(2)),"actual borrower offer authority");
        var native=Lease.Recover(stores[1].FindOffer(scopeName,client),false);scopes[1].CommitLease(native);var expiry=native.LeaseExpires;
        string protectedReturnId=Guid.NewGuid().ToString("N");
        Task<JsonElement> ProtectedReturn(HttpClient actor=null)=>Call(actor??admins[1],"/api/ddi/dhcp/grants/return",("scope",scopeName),("epoch",plan.Epoch),("owner",names[0]),("address",ip.ToString()),("grantId",protectedId),("requestId",protectedReturnId),("expectedSequence",Seq(1).ToString()),("expectedHash",DistributedAllocation.GrantReviewHash(scopeName,plan.Epoch,names[0],protectedGrant)));
        await Bad(ProtectedReturn(),"actual native lease cannot return");check(native.LeaseExpires==expiry,"refused lease return preserves exact native lifetime");
        DhcpMessage Packet(byte type=3)
        {
            byte[] wire=new byte[244];wire[0]=1;wire[1]=1;wire[2]=6;wire[7]=77;wire[28]=2;wire[33]=77;ip.GetAddressBytes().CopyTo(wire,12);new byte[]{99,130,83,99,53,1,type,255}.CopyTo(wire,236);return new(new MemoryStream(wire));
        }
        using(var gate=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp))
        using(var sender=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp))
        using(var receiver=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp))
        using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15)))
        {
            gate.Bind(new IPEndPoint(IPAddress.Loopback,0));sender.Bind(new IPEndPoint(IPAddress.Loopback,0));receiver.Bind(new IPEndPoint(ip,68));
            var dns=services[1].DnsServer;var originalForwarders=dns.Forwarders;dns.Forwarders=[NameServerAddress.Parse("127.0.0.1:"+((IPEndPoint)gate.LocalEndPoint).Port)];
            scopes[1].NtpServerDomainNames=["capacity-inflight-"+Guid.NewGuid().ToString("N")+".example.net"];scopes[1].SetEnabled(true);typeof(Scope).GetField("_interfaceAddress",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(scopes[1],IPAddress.Loopback);
            byte[] query=new byte[4096];var waiting=gate.ReceiveFromAsync(query.AsMemory(),SocketFlags.None,new IPEndPoint(IPAddress.Any,0),deadline.Token);
            var renewal=(Task)typeof(DhcpServer).GetMethod("ProcessDhcpRequestAsync",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(servers[1],[Packet(),new IPEndPoint(ip,68),default(IPPacketInformation),sender]);
            try
            {
                var received=await waiting;check(!renewal.IsCompleted,"admitted native renewal held before UDP ACK");scopes[1].SetEnabled(false);
                var pending=ProtectedReturn();
                var until=DateTime.UtcNow.AddSeconds(3);while(!scopes[1].MigrationCapturing&&DateTime.UtcNow<until)await Task.Delay(10,deadline.Token);
                check(scopes[1].MigrationCapturing&&!pending.IsCompleted,"native return admission waits for admitted ACK");
                await Bad(ProtectedReturn(),"concurrent return cannot bypass admission drain");
                query[2]=0x81;query[3]=0x83;await gate.SendToAsync(query.AsMemory(0,received.ReceivedBytes),SocketFlags.None,received.RemoteEndPoint,deadline.Token);
                await renewal.WaitAsync(deadline.Token);byte[] wire=new byte[4096];int length=await receiver.ReceiveAsync(wire.AsMemory(),SocketFlags.None,deadline.Token);
                check(new DhcpMessage(new MemoryStream(wire,0,length)).DhcpMessageType.Type==DhcpMessageType.Ack,"actual parsed native request emits UDP ACK before return decision");
                DateTime finalAckExpiry=scopes[1].Leases.Values.Single(l=>l.Address.Equals(ip)).LeaseExpires;
                await Bad(pending,"drained renewal remains protected");check(scopes[1].Leases.Values.Single(l=>l.Address.Equals(ip)).LeaseExpires==finalAckExpiry&&finalAckExpiry>=expiry,"drained return preserves exact final native ACK expiry");
            }
            finally {dns.Forwarders=originalForwarders;scopes[1].SetEnabled(false);}
        }
        await Mesh();Evidence("protected-ack-return-refused");
        // Strict post-await privilege validation while admission is drained.
        var auth=Field<AuthManager>(services[1],"_authManager");var actor=auth.CreateUser("Capacity fixture","capacity-actor","Capacity-Fixture-Actor1!");var full=PermissionFlag.View|PermissionFlag.Modify|PermissionFlag.Delete;
        auth.SetPermission(PermissionSection.DhcpServer,actor,full);auth.SetPermission(PermissionSection.Administration,actor,full);
        var cert=(System.Security.Cryptography.X509Certificates.X509Certificate2)typeof(DnsWebService).GetProperty("WebServiceTlsCertificate",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(services[1]);
        using(var actorClient=new HttpClient(new PinnedHandler(cert)){BaseAddress=admins[1].BaseAddress})
        {
            var login=await Call(actorClient,"/api/user/login",("user",actor.Username),("pass","Capacity-Fixture-Actor1!"));check(Ok(login),"capacity actor authenticates");actorClient.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",login.GetProperty("token").GetString());
            auth.SetPermission(PermissionSection.DhcpServer,actor,PermissionFlag.View);await Bad(ProtectedReturn(actorClient),"view-only actor return denied");
            auth.SetPermission(PermissionSection.DhcpServer,actor,full);
            typeof(Scope).GetField("_servingRequests",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(scopes[1],1);
            var pending=ProtectedReturn(actorClient);var until=DateTime.UtcNow.AddSeconds(3);while(!scopes[1].MigrationCapturing&&DateTime.UtcNow<until)await Task.Delay(10);
            auth.SetPermission(PermissionSection.Administration,actor,PermissionFlag.View);
            typeof(Scope).GetMethod("ExitServingRequest",BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public).Invoke(scopes[1],null);
            var denied=await pending;check(!Ok(denied)&&denied.GetProperty("errorMessage").GetString().Contains("direct HTTPS administrator"),"post-await refusal is authorization failure before native protection checks");Console.WriteLine("REFUSED post-await administrator privilege revocation");
            auth.SetPermission(PermissionSection.Administration,actor,full);
            typeof(Scope).GetField("_servingRequests",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(scopes[1],1);
            var membershipPending=ProtectedReturn(actorClient);until=DateTime.UtcNow.AddSeconds(3);while(!scopes[1].MigrationCapturing&&DateTime.UtcNow<until)await Task.Delay(10);
            var membership=Field<ClusterManager>(services[1],"_clusterManager");var nodes=Field<Dictionary<int,ClusterNode>>(membership,"_clusterNodes");
            typeof(ClusterManager).GetField("_clusterNodes",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(membership,nodes.Where(p=>p.Value.Name!=names[0]).ToDictionary(p=>p.Key,p=>p.Value));
            try
            {
                typeof(Scope).GetMethod("ExitServingRequest",BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public).Invoke(scopes[1],null);
                var removed=await membershipPending;check(!Ok(removed)&&removed.GetProperty("errorMessage").GetString().Contains("enrolled"),"post-await donor membership loss refuses before surrender");
            }
            finally { typeof(ClusterManager).GetField("_clusterNodes",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(membership,nodes); }
            auth.SetPermission(PermissionSection.Administration,actor,PermissionFlag.View);
            using(var proof=new HttpClient(new PinnedHandler(cert)){BaseAddress=admins[1].BaseAddress})
            {
                // The original fixture administrator remains open through fresh proof.
                var manager=Field<AuthManager>(services[1],"_authManager");
                var adminUser=manager.GetUser("admin");
                string pass=Environment.GetEnvironmentVariable("TEQTANIUM_CAPACITY_ADMIN_PROOF");
                // Password supplied by the owning fixture, never copied into evidence.
                var proofLogin=await Call(proof,"/api/user/login",("user","admin"),("pass",pass));check(Ok(proofLogin),"fresh admin authentication after capacity ACL changes");
                proof.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",proofLogin.GetProperty("token").GetString());
                await Good(Call(proof,"/api/dhcp/scopes/set",("name","Default"),("domainName","capacity-proof.test")),"fresh admin required native write");
                var sessions=await Call(proof,"/api/admin/sessions/list");check(sessions.GetProperty("response").GetProperty("sessions").EnumerateArray().Single(s=>s.GetProperty("isCurrentSession").GetBoolean()).GetProperty("lastSeenRemoteAddress").GetString()=="127.0.0.1","target-seen fresh admin source is loopback");
                check(Ok(await Call(originals[1],"/api/ddi/dhcp/state/get")),"original administrative session retained after fresh proof");
                using var reader=new HttpClient(new PinnedHandler(cert)){BaseAddress=admins[1].BaseAddress};
                var readerLogin=await Call(reader,"/api/user/login",("user",actor.Username),("pass","Capacity-Fixture-Actor1!"));check(Ok(readerLogin),"separate fresh restricted actor authenticates");reader.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",readerLogin.GetProperty("token").GetString());
                await Good(Call(reader,"/api/ddi/dhcp/state/get"),"fresh restricted actor intended DHCP view");await Bad(ProtectedReturn(reader),"fresh restricted actor cannot surrender after admin privilege revocation");
            }
        }
        // Terminal ordinary grant receipts are archived in the immutable old epoch.
        // Removing this returned address now succeeds without dropping active grants.
        foreach(var s in scopes)s.SetEnabled(false);
        using var desiredBytes=new MemoryStream();scopes[0].WriteTo(desiredBytes,false,false);desiredBytes.Position=0;
        using var desiredScope=new Scope(desiredBytes,Field<LogManager>(services[0],"_log"),servers[0]);
        desiredScope.Exclusions=[new Exclusion(AllocationSequence.Address(grant.Address),AllocationSequence.Address(grant.Address))];
        string successorId=Guid.NewGuid().ToString("N");using var desiredConfig=new MemoryStream();desiredScope.WriteTo(desiredConfig,false,false);
        var desired=desiredScope.BuildAllocationPlan(successorId,successorId,names) with {Configuration=Convert.ToBase64String(desiredConfig.ToArray())};
        var preview=await Call(admins[0],"/api/ddi/dhcp/changes/preview",("plan",Json(desired)),("expectedEpoch",plan.Epoch));check(Ok(preview),"terminal returned address eligibility successor preview: "+preview);
        var review=preview.GetProperty("response").GetProperty("state").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions);
        check(review.Frozen.Single(f=>f.Node==names[0]).Replica.GrantReclaims.Single().Grant==grant,"successor review archives exact terminal original grant");
        await Good(Call(admins[0],"/api/ddi/dhcp/changes/prepare",("change",Json(review)),("expectedHash",DistributedAllocation.ChangeHash(review))),"terminal receipt successor native prepare");
        await Good(Call(admins[0],"/api/ddi/dhcp/changes/commit",("scope",scopeName),("id",review.Id),("expectedHash",DistributedAllocation.ChangeHash(review))),"terminal receipt successor native commit");
        check(stores.All(s=>s.Plan(scopeName).Epoch==review.Id&&!s.HasAuthority(scopeName,grant.Address)),"completed return permits eligibility removal with no resurrected authority");
        await Bad(Call(peers[1],"/api/ddi/dhcp/state/ingest",("state",System.Text.Encoding.UTF8.GetString(before[0]))),"old grant-bearing epoch replay after terminal successor");
        await Bad(Return(),"old return request epoch after successor");
        // Pending borrow and return journals each need a valid continuation after
        // partial freeze. No participant/address guard is bypassed by that path.
        var currentPlan=stores[0].Plan(scopeName);string carryRequest=stores[1].CapacityRequest(scopeName,names[0]);
        stores[1].Merge(await donor.GrantAllocationAsync(scopeName,names[1],carryRequest));
        var carryGrant=stores[0].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[0]).Entries.Single(e=>e.GrantId==carryRequest);
        async Task<AllocationChangeInput> Carry(string label)
        {
            var oldPlan=stores[0].Plan(scopeName);using var bytes=new MemoryStream();scopes[0].WriteTo(bytes,false,false);bytes.Position=0;
            using var source=new Scope(bytes,Field<LogManager>(services[0],"_log"),servers[0]);string epoch=Guid.NewGuid().ToString("N");using var config=new MemoryStream();source.WriteTo(config,false,false);
            var desiredCarry=source.BuildAllocationPlan(epoch,epoch,names) with {Configuration=Convert.ToBase64String(config.ToArray())};
            Task<JsonElement> PreviewCarry()=>Call(admins[0],"/api/ddi/dhcp/changes/preview",("plan",Json(desiredCarry)),("expectedEpoch",oldPlan.Epoch));
            links[(0,2)].Disconnected=true;
            try {await Bad(PreviewCarry(),label+" disconnected final peer leaves partial durable freeze");}
            finally {links[(0,2)].Disconnected=false;}
            check(stores[0].ChangePending(scopeName)&&stores[1].ChangePending(scopeName)&&!stores[2].ChangePending(scopeName),label+" partial frozen lineage retained");
            var previewCarry=await PreviewCarry();check(Ok(previewCarry),label+" same frozen review resumes: "+previewCarry);
            var input=previewCarry.GetProperty("response").GetProperty("state").Deserialize<AllocationChangeInput>(DistributedAllocation.JsonOptions);
            await Good(Call(admins[0],"/api/ddi/dhcp/changes/prepare",("change",Json(input)),("expectedHash",DistributedAllocation.ChangeHash(input))),label+" prepare preserves exact journals");
            await Good(Call(admins[0],"/api/ddi/dhcp/changes/commit",("scope",scopeName),("id",input.Id),("expectedHash",DistributedAllocation.ChangeHash(input))),label+" committed continuation releases freeze");return input;
        }
        var borrowReview=await Carry("pending borrow");
        check(stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).BorrowRequests.Single().Id==carryRequest&&stores[1].HasAuthority(scopeName,carryGrant.Address)&&!stores[0].HasAuthority(scopeName,carryGrant.Address),"pending borrow identity and unique borrower authority survive successor");
        typeof(DnsWebService).GetField("_capacityDonorCursor",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(services[1],-1);
        var borrowedRetry=await (Task<byte[]>)borrowMethod.Invoke(services[1],[scopeName,names[1]]);
        check(borrowedRetry is not null&&(stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]).BorrowRequests?.Length??0)==0,"production retry completes carried pending borrow from original donor outcome");
        currentPlan=stores[0].Plan(scopeName);string carryId=Guid.NewGuid().ToString("N");
        Task<JsonElement> CarryReturn(string epoch,uint address)=>Call(admins[1],"/api/ddi/dhcp/grants/return",("scope",scopeName),("epoch",epoch),("owner",names[0]),("address",AllocationSequence.Address(address).ToString()),("grantId",carryRequest),("requestId",carryId),("expectedSequence",Seq(1).ToString()),("expectedHash",DistributedAllocation.GrantReviewHash(scopeName,epoch,names[0],carryGrant)));
        await Good(CarryReturn(currentPlan.Epoch,carryGrant.Address),"independent pending return durably surrendered");await Mesh();
        var returnReview=await Carry("pending return");
        var carried=stores[1].Snapshot().Replicas.Single(r=>r.Scope==scopeName&&r.Node==names[1]);
        check(carried.GrantReturns.Single().Grant==carryGrant&&(carried.BorrowRequests?.Length??0)==0&&!stores[0].HasAuthority(scopeName,carryGrant.Address)&&!stores[1].HasAuthority(scopeName,carryGrant.Address),"pending return receipt survives successor with both withheld");
        await Bad(CarryReturn(currentPlan.Epoch,carryGrant.Address),"old return epoch after pending successor");
        await Bad(CarryReturn(returnReview.Id,carryGrant.Address+1),"same pending return ID changed content after successor");
        if(killRoot is not null)await Checkpoint(returnReview.Id,carryId,carryGrant,true);
        await Good(Call(admins[0],"/api/ddi/dhcp/grants/reclaim",("scope",scopeName),("epoch",returnReview.Id),("borrower",names[1]),("requestId",carryId),("expectedSequence",Seq(0).ToString()),("expectedHash",DistributedAllocation.GrantReturnHash(scopeName,returnReview.Id,carried.GrantReturns.Single()))),"same pending return reclaims under current successor authority");
        stores[1].Merge(await donor.GrantAllocationAsync(scopeName,names[1],carryRequest));
        check(stores[0].HasAuthority(scopeName,carryGrant.Address)&&!stores[1].HasAuthority(scopeName,carryGrant.Address),"terminal carried return cannot recreate borrower authority");
        Evidence("final-native");
    }
}
