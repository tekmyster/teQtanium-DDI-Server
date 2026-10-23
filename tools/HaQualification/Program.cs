// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Tekmyster Industries, LLC.
// Owned synthetic native-process fixture; no DNS listeners, remote API or service.
using DnsServerCore.Dhcp;
using System.Text.Json;

if (args.Length != 2) throw new ArgumentException("Use phase and owned fixture directory.");
string phase = args[0], root = Path.GetFullPath(args[1]);
Directory.CreateDirectory(root);
var plan = new AllocationPlan("synthetic", "11111111111111111111111111111111", 3221225985, 3221226004, "ha-fixture", ["a", "b", "c"], [], Algorithm: "interleaved-v1");
var sequence = new AllocationSequence(plan);
uint live = sequence.Candidates("a").First(), unused = sequence.Candidates("a").Skip(1).First();
const string transfer = "22222222222222222222222222222222", recovery = "33333333333333333333333333333333", returned = "44444444444444444444444444444444";
var stores = new List<DistributedAllocation>();
var checks = new List<string>();
DistributedAllocation Open(string name) { var s = new DistributedAllocation(Path.Combine(root, name + ".json")) { NodeName = () => name }; stores.Add(s); return s; }
void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks.Add(reason); }
void Refuse(Action call, string reason)
{
    try { call(); } catch (Exception e) when (e is InvalidOperationException or InvalidDataException or ArgumentException or IOException) { checks.Add(reason); return; }
    throw new Exception("Unexpected success: " + reason);
}
long Seq(DistributedAllocation s, string name) => s.Snapshot().Replicas.SingleOrDefault(r => r.Node == name)?.Sequence ?? 0;
try
{
    var a = Open("a"); var b = Open("b"); var c = Open("c");
    if (phase == "hold")
    {
        Console.WriteLine("owned-native-writer-held"); Console.Out.Flush();
        Console.ReadLine();
        checks.Add("owned native writer released after separate-process exclusion check");
    }
    else if (phase == "seed")
    {
        foreach (var s in stores) s.AddPlan(plan);
        var expires = DateTime.UtcNow.AddHours(4);
        Check(a.Hold(plan.Scope, live, "client-live", "02-00-00-00-00-01", "synthetic", expires), "original live offer durable");
        a.Commit(plan.Scope, live, "client-live", "02-00-00-00-00-01", "synthetic", expires);
        File.WriteAllBytes(Path.Combine(root, "before.json"), a.Export());
        File.WriteAllText(Path.Combine(root, "live.json"), JsonSerializer.Serialize(a.Snapshot().Replicas.Single(r => r.Node == "a").Entries.Single(e => e.Address == live), DistributedAllocation.JsonOptions));
        b.Merge(a.Export()); c.Merge(a.Export());
        Check(a.HasAuthority(plan.Scope, live) && !b.HasAuthority(plan.Scope, live), "partition retains immutable original ownership");
    }
    else if (phase == "unused")
    {
        a.RecoverUnusedCapacity(plan.Scope, ["b", "c"], recovery, Seq(a, "a"));
        var division = a.Snapshot().Replicas.Single(r => r.Node == "a").UnusedRecoveries.Single();
        Check(!division.Addresses.Contains(live), "offline unused recovery excludes live lease");
        Check(a.HasAuthority(plan.Scope, live) && !b.HasAuthority(plan.Scope, unused), "partition cannot invent receiver authority");
        var export = a.Export();
        a.RecoverUnusedCapacity(plan.Scope, ["c", "b"], recovery, -1);
        Check(export.SequenceEqual(a.Export()), "same recovery retry preserves exact durable division");
        Refuse(() => a.RecoverUnusedCapacity(plan.Scope, ["b"], recovery, -1), "changed recovery receivers refused");
        File.WriteAllBytes(Path.Combine(root, "unused-export.json"), export);
    }
    else if (phase == "handoff")
    {
        a.Handoff(plan.Scope, [live], "b", transfer, Seq(a, "a"));
        Check(!a.HasAuthority(plan.Scope, live) && !b.HasAuthority(plan.Scope, live), "lost handoff reply withholds both before import");
        var grant = a.Snapshot().Replicas.Single(r => r.Node == "a").Entries.Single(e => e.Address == live);
        var old = JsonSerializer.Deserialize<AllocationEntry>(File.ReadAllBytes(Path.Combine(root, "live.json")), DistributedAllocation.JsonOptions);
        Check(grant.Client == old.Client && grant.Hardware == old.Hardware && grant.Host == old.Host && grant.Protection.State == "Lease" && grant.Protection.Expires == old.Expires, "connected handoff retains exact client and lease protection");
        var export = a.Export();
        a.Handoff(plan.Scope, [live], "b", transfer, -1);
        Check(export.SequenceEqual(a.Export()), "lost handoff reply retries exact snapshot");
        File.WriteAllBytes(Path.Combine(root, "handoff-export.json"), export);
    }
    else if (phase == "import")
    {
        var snapshot = File.ReadAllBytes(Path.Combine(root, "handoff-export.json"));
        b.Merge(snapshot); c.Merge(snapshot);
        Check(!a.HasAuthority(plan.Scope, live) && b.HasAuthority(plan.Scope, live) && !c.HasAuthority(plan.Scope, live), "fresh receiver process imports one exact authority");
        var inherited = b.FindLease(plan.Scope, "client-live");
        Check(inherited?.Address == live && inherited.Expires > DateTime.UtcNow, "receiver finds original protected live lease");
        Check(!b.Hold(plan.Scope, live, "other-client", "02-00-00-00-00-02", "conflict", DateTime.UtcNow.AddHours(1)), "other client cannot consume inherited live binding");
        var grant = a.Snapshot().Replicas.Single(r => r.Node == "a").Entries.Single(e => e.Address == live);
        Refuse(() => b.RelinquishGrant(plan.Scope, plan.Epoch, "a", live, grant.GrantId, returned, Seq(b, "b")), "failback cannot erase unexpired lease protection");
        Refuse(() => a.ReclaimGrant(plan.Scope, plan.Epoch, "b", returned, Seq(a, "a")), "failback requires durable borrower surrender");
    }
    else if (phase == "restart")
    {
        Check(!a.HasAuthority(plan.Scope, live) && b.HasAuthority(plan.Scope, live), "new original and receiver processes retain grant after restart");
        a.Merge(File.ReadAllBytes(Path.Combine(root, "before.json")));
        b.Merge(File.ReadAllBytes(Path.Combine(root, "before.json")));
        Check(!a.HasAuthority(plan.Scope, live) && b.HasAuthority(plan.Scope, live), "stale pre-handoff replay cannot restore donor authority");
        var state = a.Snapshot(); var replica = state.Replicas.Single(r => r.Node == "a");
        var changed = state with { Replicas = state.Replicas.Select(r => r.Node == "a" ? r with { Sequence = r.Sequence + 100, Entries = r.Entries.Where(e => e.Address != live).ToArray() } : r).ToArray() };
        Refuse(() => c.Merge(JsonSerializer.SerializeToUtf8Bytes(changed, DistributedAllocation.JsonOptions)), "newer numeric state cannot erase permanent grant");
        Refuse(() => Open("a"), "concurrent process/store writer denied");
        File.WriteAllBytes(Path.Combine(root, "final-export.json"), a.Export());
    }
    else if (phase == "return")
    {
        var grant = a.Snapshot().Replicas.Single(r => r.Node == "a").Entries.Single(e => e.Address == unused);
        Check(grant.Borrower == "b" && grant.Protection is null, "unused grant return fixture has no live protection");
        File.WriteAllBytes(Path.Combine(root, "borrower-before-return.json"), b.Export());
        b.RelinquishGrant(plan.Scope, plan.Epoch, "a", unused, grant.GrantId, returned, Seq(b, "b"));
        Check(!b.HasAuthority(plan.Scope, unused) && !a.HasAuthority(plan.Scope, unused), "durable borrower return withholds both until donor receives receipt");
        var export = b.Export();
        b.RelinquishGrant(plan.Scope, plan.Epoch, "a", unused, grant.GrantId, returned, -1);
        Check(export.SequenceEqual(b.Export()), "lost return reply retries exact persisted tombstone");
    }
    else if (phase == "reclaim")
    {
        Check(!b.HasAuthority(plan.Scope, unused) && !a.HasAuthority(plan.Scope, unused), "return tombstone survives fresh borrower process");
        a.Merge(b.Export());
        a.ReclaimGrant(plan.Scope, plan.Epoch, "b", returned, Seq(a, "a"));
        var export = a.Export();
        a.ReclaimGrant(plan.Scope, plan.Epoch, "b", returned, -1);
        Check(export.SequenceEqual(a.Export()), "lost reclaim reply retries exact terminal receipt");
        b.Merge(a.Export()); c.Merge(a.Export());
        Check(a.HasAuthority(plan.Scope, unused) && !b.HasAuthority(plan.Scope, unused), "explicit unused grant return/reclaim restores only original owner");
        Check(!a.HasAuthority(plan.Scope, live) && b.HasAuthority(plan.Scope, live), "unused return leaves active protected grant unchanged");
    }
    else if (phase == "returned-restart")
    {
        a.Merge(File.ReadAllBytes(Path.Combine(root, "handoff-export.json")));
        b.Merge(File.ReadAllBytes(Path.Combine(root, "borrower-before-return.json")));
        Check(a.HasAuthority(plan.Scope, unused) && !b.HasAuthority(plan.Scope, unused), "terminal return/reclaim survives restart and stale replay");
        Check(a.Snapshot().Replicas.Single(r => r.Node == "a").UnusedRecoveries.Single().Id == recovery, "original recovery division remains after explicit return");
        Refuse(() => a.Grant(plan.Scope, unused, "c", "77777777777777777777777777777777"), "terminal returned capacity cannot be regranted in same epoch");
        string fault = Path.Combine(root, "missing-watermark"); Directory.CreateDirectory(fault);
        File.Copy(Path.Combine(root, "a.json"), Path.Combine(fault, "a.json"));
        Refuse(() => new DistributedAllocation(Path.Combine(fault, "a.json")), "copied original state without durable watermark cannot reopen");
    }
    else throw new ArgumentException("Unknown fixture phase.");
    Console.WriteLine(JsonSerializer.Serialize(new { phase, process = Environment.ProcessId, checks, scope = "Synthetic accepted-core grant mechanics only; no physical fence or client packet continuity" }));
}
finally { foreach (var s in stores) await s.DisposeAsync(); }
