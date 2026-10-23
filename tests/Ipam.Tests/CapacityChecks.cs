// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Dhcp;
using System.Text.Json;

static class CapacityChecks
{
    static string Json<T>(T v) => JsonSerializer.Serialize(v, DistributedAllocation.JsonOptions);
    public static async Task Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "ddi-capacity-model-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        int checks = 0;
        void Check(bool b, string m) { if (!b) throw new Exception(m); checks++; Console.WriteLine("OK " + m); }
        void Bad(Action a, string m) { try { a(); } catch (Exception e) when(e is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException) { checks++; Console.WriteLine("REFUSED " + m); return; } throw new Exception("Accepted " + m); }
        var plan = new AllocationPlan("capacity", Guid.NewGuid().ToString("N"), 100, 199, "test", ["a","b","c"], [], Algorithm: "interleaved-v1");
        var stores = new List<DistributedAllocation>();
        DistributedAllocation Open(string n) { var store = new DistributedAllocation(Path.Combine(root,n+".json")) { NodeName=()=>n }; stores.Add(store); return store; }
        try
        {
            var a=Open("a"); var b=Open("b"); var c=Open("c"); foreach(var s in stores) s.AddPlan(plan);
            long Seq(DistributedAllocation s,string n) => s.Snapshot().Replicas.SingleOrDefault(r=>r.Node==n)?.Sequence ?? 0;
            AllocationFrozenOwner[] Frozen()=>stores.Select(s=>new AllocationFrozenOwner(s.NodeName(),plan,s.Snapshot().Replicas.SingleOrDefault(r=>r.Node==s.NodeName())??new AllocationReplica(plan.Scope,plan.Epoch,s.NodeName(),0,[]))).ToArray();
            void Mesh() { foreach(var receiver in stores) foreach(var sender in stores) if(receiver!=sender) receiver.Merge(sender.Export()); }
            uint address = new AllocationSequence(plan).Candidates("a").First(); string grantId=b.CapacityRequest(plan.Scope,"a");
            Check(b.CapacityRequest(plan.Scope,"a")==grantId,"same pending donor request is stable");
            await b.DisposeAsync(); stores.Remove(b); b=Open("b"); Check(b.CapacityRequest(plan.Scope,"a")==grantId,"pending request identity survives independent reopen");
            string pendingRemovalId=Guid.NewGuid().ToString("N");
            Bad(()=>DistributedAllocation.BuildChange(pendingRemovalId,"a",plan with {Epoch=pendingRemovalId,Owners=["a","c"]},Frozen()),"pending borrow cannot remove original request participant");
            a.Grant(plan.Scope,address,"b",grantId); var oldDonor=a.Export();
            Check(!a.HasAuthority(plan.Scope,address),"donor loses authority before response"); Mesh();
            Check(b.HasAuthority(plan.Scope,address),"borrower receives exact durable donor grant");
            b.CompleteCapacityRequest(plan.Scope,"a",grantId); Check(!(b.Snapshot().Replicas.Single(r=>r.Node=="b").BorrowRequests??[]).Any(),"only durable matching outcome completes request");
            string id=Guid.NewGuid().ToString("N"); long expected=Seq(b,"b");
            Bad(()=>a.ReclaimGrant(plan.Scope,plan.Epoch,"b",id,Seq(a,"a")),"missing borrower or partition is not surrender");
            Bad(()=>b.RelinquishGrant(plan.Scope,"stale","a",address,grantId,id,expected),"stale epoch return");
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"c",address,grantId,id,expected),"alternate donor return");
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,"changed",id,expected),"wrong grant identity");
            DateTime expiry=DateTime.UtcNow.AddHours(1); Check(b.Hold(plan.Scope,address,"1-0201","02-01","binding",expiry),"borrower native-style offer");
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,grantId,id,Seq(b,"b")),"live offer retains exact authority");
            b.Commit(plan.Scope,address,"1-0201","02-01","binding",expiry);
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,grantId,id,Seq(b,"b")),"live lease cannot return");
            Check(b.FindLease(plan.Scope,"1-0201").Expires==expiry,"refused return preserves exact lease expiry");
            b.Release(plan.Scope,address,"1-0201"); Mesh(); var oldBorrower=b.Export();
            var results=await Task.WhenAll(Enumerable.Range(0,12).Select(_=>Task.Run(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,grantId,id,Seq(b,"b")))));
            Check(results.Distinct().Count()==1,"concurrent identical returns commit one immutable receipt");
            var receipt=results[0];
            string returnRemovalId=Guid.NewGuid().ToString("N");
            Bad(()=>DistributedAllocation.BuildChange(returnRemovalId,"a",plan with {Epoch=returnRemovalId,Owners=["a","c"]},Frozen()),"pending return cannot remove original borrower");
            Bad(()=>DistributedAllocation.BuildChange(returnRemovalId,"a",plan with {Epoch=returnRemovalId,Excluded=[new AllocationRange(address,address)]},Frozen()),"pending return cannot remove address eligibility");
            Check(!b.HasAuthority(plan.Scope,address)&&!a.HasAuthority(plan.Scope,address),"surrender before acknowledgment leaves both withheld");
            Check(b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,grantId,id,-1)==receipt,"lost surrender reply retries exact durable receipt");
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address+1,grantId,id,Seq(b,"b")),"same ID changed return content");
            Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"a",address,grantId,Guid.NewGuid().ToString("N"),Seq(b,"b")),"alternate return ID refuses");
            Check(!b.Hold(plan.Scope,address,"1-0202","02-02","wrong",expiry),"surrendered borrower cannot allocate");
            a.Merge(b.Export()); var terminal=a.ReclaimGrant(plan.Scope,plan.Epoch,"b",id,Seq(a,"a"));
            Check(terminal==receipt&&a.HasAuthority(plan.Scope,address)&&!b.HasAuthority(plan.Scope,address),"donor reclaims only exact persisted surrender");
            Check(a.ReclaimGrant(plan.Scope,plan.Epoch,"b",id,-1)==receipt,"lost donor acknowledgment retries without sequence advance");
            Bad(()=>a.ReclaimGrant(plan.Scope,plan.Epoch,"c",id,Seq(a,"a")),"reclaim alternate borrower");
            Mesh(); a.Merge(oldDonor); b.Merge(oldBorrower); Mesh(); Check(a.HasAuthority(plan.Scope,address)&&!b.HasAuthority(plan.Scope,address),"stale donor and borrower replay cannot resurrect");
            var current=b.Snapshot(); var br=current.Replicas.Single(r=>r.Node=="b");
            var divergent=current with { Replicas=current.Replicas.Select(r=>r.Node=="b"?r with { GrantReturns=[] }:r).ToArray() };
            Bad(()=>c.Merge(System.Text.Encoding.UTF8.GetBytes(Json(divergent))),"equal sequence surrender erasure rejected");
            var newer=divergent with { Replicas=divergent.Replicas.Select(r=>r.Node=="b"?r with { Sequence=r.Sequence+100 }:r).ToArray() };
            Bad(()=>c.Merge(System.Text.Encoding.UTF8.GetBytes(Json(newer))),"numerically newer borrower cannot erase surrender");
            Bad(()=>a.Grant(plan.Scope,address,"c",Guid.NewGuid().ToString("N")),"terminal capacity cannot be regranted in this epoch");
            Bad(()=>a.Grant(plan.Scope,new AllocationSequence(plan).Candidates("a").Skip(1).First(),"b",grantId),"retired grant request cannot create a different address");
            Check(a.Hold(plan.Scope,address,"1-0203","02-03","reclaimed",expiry),"reclaimed donor capacity supports allocation");
            Mesh(); Check(b.FindLease(plan.Scope,"1-0203") is null,"borrower cannot inherit reclaimed donor lease");
            foreach(var s in stores.ToArray()) { await s.DisposeAsync(); stores.Remove(s); } a=Open("a"); b=Open("b"); c=Open("c"); Mesh();
            Check(a.HasAuthority(plan.Scope,address)&&!b.HasAuthority(plan.Scope,address),"terminal receipt survives all owner reopens");
            Check(a.Snapshot().Replicas.Single(r=>r.Node=="a").GrantReclaims.Single()==receipt,"terminal tombstone preserves exact grant protection and identity");
            string next=b.CapacityRequest(plan.Scope,"a"); Check(next!=grantId&&b.CapacityRequest(plan.Scope,"a")==next,"next bounded request differs only after prior completion");
            Bad(()=>b.CompleteCapacityRequest(plan.Scope,"a",next),"missing donor outcome cannot complete or reroute pending request");
            string path=Path.Combine(root,"fault.json"); await using(var fault=new DistributedAllocation(path) { NodeName=()=>"a" })
            {
                fault.AddPlan(plan); Directory.CreateDirectory(path+".tmp");
                Bad(()=>fault.CapacityRequest(plan.Scope,"b"),"actual persistence failure earns no request identity"); Check(fault.RecoveryRequired&&!fault.HasAuthority(plan.Scope,address),"failed durability withholds serving authority");
            }
            // Every original protection remains intact after an attempted return.
            foreach(string state in new[]{"Offer","Lease","Declined"})
            {
                uint target=new AllocationSequence(plan).Candidates("c").First(x=>c.Available(plan.Scope,x));string operation=Guid.NewGuid().ToString("N");
                c.Hold(plan.Scope,target,"1-0204","02-04",state,expiry);
                if(state=="Lease")c.Commit(plan.Scope,target,"1-0204","02-04",state,expiry);
                if(state=="Declined")c.Decline(plan.Scope,target,"1-0204");
                c.Handoff(plan.Scope,[target],"b",operation,Seq(c,"c"));Mesh();
                var protectedGrant=c.Snapshot().Replicas.Single(r=>r.Node=="c").Entries.Single(e=>e.Address==target);
                Bad(()=>b.RelinquishGrant(plan.Scope,plan.Epoch,"c",target,protectedGrant.GrantId,Guid.NewGuid().ToString("N"),Seq(b,"b")),"unexpired inherited "+state+" protection cannot return");
                Check(c.Snapshot().Replicas.Single(r=>r.Node=="c").Entries.Single(e=>e.Address==target)==protectedGrant,"refused "+state+" keeps exact original protection");
            }
            uint expired=new AllocationSequence(plan).Candidates("c").First(x=>c.Available(plan.Scope,x));string expiredGrant=Guid.NewGuid().ToString("N");c.Grant(plan.Scope,expired,"b",expiredGrant);Mesh();
            b.Hold(plan.Scope,expired,"1-0205","02-05","expired",DateTime.UtcNow.AddSeconds(-1));string expiredId=Guid.NewGuid().ToString("N");
            b.RelinquishGrant(plan.Scope,plan.Epoch,"c",expired,expiredGrant,expiredId,Seq(b,"b"));c.Merge(b.Export());c.ReclaimGrant(plan.Scope,plan.Epoch,"b",expiredId,Seq(c,"c"));Mesh();
            Check(c.HasAuthority(plan.Scope,expired)&&!b.HasAuthority(plan.Scope,expired),"expired borrower offer permits terminal return without delay");
            // Real failure before donor watermark publication: no acknowledgement,
            // independent reopen retains the original grant until the same retry.
            uint faultAddress=new AllocationSequence(plan).Candidates("c").First(x=>c.Available(plan.Scope,x)&&!c.IsRetiredGrant(plan.Scope,x));string faultGrant=Guid.NewGuid().ToString("N");c.Grant(plan.Scope,faultAddress,"b",faultGrant);Mesh();string faultId=Guid.NewGuid().ToString("N");
            b.RelinquishGrant(plan.Scope,plan.Epoch,"c",faultAddress,faultGrant,faultId,Seq(b,"b"));c.Merge(b.Export());long originalSeq=Seq(c,"c");
            string barrier=Path.Combine(root,"c.json.required.tmp");Directory.CreateDirectory(barrier);
            Bad(()=>c.ReclaimGrant(plan.Scope,plan.Epoch,"b",faultId,originalSeq),"actual reclaim watermark failure earns no acknowledgement");
            Check(c.RecoveryRequired&&!c.HasAuthority(plan.Scope,faultAddress)&&!b.HasAuthority(plan.Scope,faultAddress),"failed reclaim keeps both withheld");
            await c.DisposeAsync();stores.Remove(c);Directory.Delete(barrier);c=Open("c");
            Check(!c.HasAuthority(plan.Scope,faultAddress),"independent reopen after failed reclaim retains original donor grant");
            c.ReclaimGrant(plan.Scope,plan.Epoch,"b",faultId,originalSeq);Mesh();Check(c.HasAuthority(plan.Scope,faultAddress)&&!b.HasAuthority(plan.Scope,faultAddress),"same failed reclaim retry completes once");
            // Original offline recovery divisions retain their complete immutable mapping
            // even after one grant receives a terminal return tombstone.
            string divisionId=Guid.NewGuid().ToString("N");c.RecoverUnusedCapacity(plan.Scope,["a","b"],divisionId,Seq(c,"c"));Mesh();
            var division=c.Snapshot().Replicas.Single(r=>r.Node=="c").UnusedRecoveries.Single(x=>x.Id==divisionId);
            uint divided=division.Addresses.First();var divisionGrant=c.Snapshot().Replicas.Single(r=>r.Node=="c").Entries.Single(e=>e.Address==divided);
            var receiver=divisionGrant.Borrower=="a"?a:b;string divisionReturn=Guid.NewGuid().ToString("N");var divisionBefore=c.Export();
            receiver.RelinquishGrant(plan.Scope,plan.Epoch,"c",divided,divisionGrant.GrantId,divisionReturn,Seq(receiver,divisionGrant.Borrower));c.Merge(receiver.Export());c.ReclaimGrant(plan.Scope,plan.Epoch,divisionGrant.Borrower,divisionReturn,Seq(c,"c"));Mesh();
            Check(c.HasAuthority(plan.Scope,divided)&&!receiver.HasAuthority(plan.Scope,divided),"original recovery division grant returns to original donor only after surrender");
            Check(Json(c.Snapshot().Replicas.Single(r=>r.Node=="c").UnusedRecoveries.Single(x=>x.Id==divisionId))==Json(division),"terminal return preserves exact original recovery receivers and addresses");
            foreach(var s in stores)s.Merge(divisionBefore);Mesh();
            Check(c.HasAuthority(plan.Scope,divided)&&!receiver.HasAuthority(plan.Scope,divided),"old recovery division replay cannot revive returned capacity");
            c.RecoverUnusedCapacity(plan.Scope,["a","b"],divisionId,-1);Mesh();
            Check(c.HasAuthority(plan.Scope,divided)&&!receiver.HasAuthority(plan.Scope,divided),"same offline recovery ID retry retains terminal outcome");
            Bad(()=>c.RecoverUnusedCapacity(plan.Scope,["a"],divisionId,Seq(c,"c")),"same recovery ID cannot choose alternate receivers");
            // The surviving pending request is resolved before checking the separate
            // conservative migration guard for terminal offline division records.
            uint pendingAddress=new AllocationSequence(plan).Candidates("a").First(x=>a.Available(plan.Scope,x)&&!a.IsRetiredGrant(plan.Scope,x));a.Grant(plan.Scope,pendingAddress,"b",next);b.Merge(a.Export());b.CompleteCapacityRequest(plan.Scope,"a",next);Mesh();
            string successorId=Guid.NewGuid().ToString("N");var desired=plan with {Epoch=successorId,Excluded=[new AllocationRange(divided,divided)]};var frozen=stores.Select(s=>new AllocationFrozenOwner(s.NodeName(),plan,s.Snapshot().Replicas.Single(r=>r.Node==s.NodeName()))).ToArray();
            try {DistributedAllocation.BuildChange(successorId,"a",desired,frozen);throw new Exception("Terminal recovery division migration accepted");}
            catch(InvalidOperationException e) {Check(e.Message.Contains("offline recovery divisions"),"returned offline recovery division successor is explicitly refused");}
            var unchanged=plan with {Epoch=successorId};var unchangedReview=DistributedAllocation.BuildChange(successorId,"a",unchanged,frozen);
            Check(unchangedReview.Plan.Pins.Any(p=>p.Address==divided&&p.Owner=="c"),"offline terminal journal has unchanged-eligibility pinned continuation");
            Console.WriteLine($"PASS: {checks} capacity store checks");
        }
        finally { foreach(var s in stores) await s.DisposeAsync(); Directory.Delete(root,true); }
    }
}

