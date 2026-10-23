// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Dhcp;
using System.Diagnostics;
using System.Net;
using System.Text.Json;

static class OwnershipChecks
{
    static uint Ip(string value) => AllocationSequence.Number(IPAddress.Parse(value));
    static AllocationPlan Initial() => new("change", "00000000000000000000000000000011", Ip("192.0.2.10"), Ip("192.0.2.90"), "initial", ["a", "b"], [], Ip("255.255.255.0"), Algorithm: "interleaved-v1");
    static string Json<T>(T value) => JsonSerializer.Serialize(value, DistributedAllocation.JsonOptions);
    static async Task<(DistributedAllocation[], AllocationChangeInput)> Prepared(string folder, string phase)
    {
        var old = Initial(); var names = new[] { "a", "b", "c" };
        var stores = names.Select(n => new DistributedAllocation(Path.Combine(folder, n + ".json")) { NodeName = () => n }).ToArray();
        stores[0].AddPlan(old); stores[1].AddPlan(old);
        stores[0].Commit(old.Scope, old.First, "1-0201", "02-01", "current", DateTime.UtcNow.AddHours(2));
        stores[1].Hold(old.Scope, old.First + 1, "1-0202", "02-02", "offer", DateTime.UtcNow.AddMinutes(20));
        string id = "00000000000000000000000000000022";
        var desired = old with { Epoch = id, First = old.First + 5, Last = old.Last + 5, Owners = names, Excluded = [new(old.First + 9, old.First + 10)] };
        var frozen = stores.Select(s => s.FreezeChange(id, old)).ToArray();
        var input = DistributedAllocation.BuildChange(id, "a", desired, frozen);
        if (phase != "frozen") foreach (var store in stores) { store.PrepareChange(input); store.ConfirmChangeConfiguration(old.Scope, id, DistributedAllocation.ChangeHash(input)); }
        if (phase == "committed")
        {
            foreach (string name in names.Skip(1)) stores[0].AcknowledgeChange(old.Scope, id, DistributedAllocation.ChangeHash(input), name);
            foreach (var store in stores.Skip(1)) store.CommitChange(old.Scope, id, DistributedAllocation.ChangeHash(input), names);
            stores[0].CommitChange(old.Scope, id, DistributedAllocation.ChangeHash(input));
        }
        await Task.CompletedTask; return (stores, input);
    }
    public static async Task Crash(string folder, string phase)
    {
        Directory.CreateDirectory(folder);
        var fixture = await Prepared(folder, phase);
        File.WriteAllText(Path.Combine(folder, "input.json"), Json(fixture.Item2));
        Console.WriteLine("OWNERSHIP-DURABLE-" + phase); Console.Out.Flush();
        await Task.Delay(Timeout.Infinite);
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-ownership-model-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
        int checks = 0;
        void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; Console.WriteLine("OK " + reason); }
        void Reject(Action action, string reason) { try { action(); } catch (Exception e) when (e is ArgumentException or InvalidOperationException or IOException) { checks++; Console.WriteLine("REFUSED " + reason); return; } throw new Exception("Accepted: " + reason); }
        try
        {
            foreach (string phase in new[] { "frozen", "prepared", "committed" })
            {
                string crashFolder = Path.Combine(folder, "kill-" + phase);
                var launch = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                launch.ArgumentList.Add(typeof(OwnershipChecks).Assembly.Location); launch.ArgumentList.Add("--ownership-crash"); launch.ArgumentList.Add(crashFolder); launch.ArgumentList.Add(phase);
                using var child = Process.Start(launch);
                try
                {
                    string signal = await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
                    if (signal != "OWNERSHIP-DURABLE-" + phase) throw new Exception("Crash fixture failed: " + signal + " " + await child.StandardError.ReadToEndAsync());
                    child.Kill(true); await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                }
                finally { if (!child.HasExited) child.Kill(true); }
                var input = JsonSerializer.Deserialize<AllocationChangeInput>(File.ReadAllText(Path.Combine(crashFolder, "input.json")), DistributedAllocation.JsonOptions);
                foreach (string name in new[] { "a", "b", "c" })
                {
                    await using var reopened = new DistributedAllocation(Path.Combine(crashFolder, name + ".json")) { NodeName = () => name };
                    Check(reopened.Change("change").Phase.Equals(phase, StringComparison.OrdinalIgnoreCase), "real process kill/reopen preserves " + phase + " " + name);
                    if (phase != "committed")
                    {
                        Check(!reopened.HasAuthority("change", input.Plan.First) && reopened.FindLease("change", "1-0201") is null, "pending restart withholds allocation and renewal " + name);
                        reopened.PrepareChange(input); Check(reopened.Change("change").Phase == "Prepared", "exact prepare resumes after kill " + name);
                    }
                    else Check(reopened.Plan("change").Epoch == input.Id, "committed restart keeps successor epoch " + name);
                }
            }
            var old = Initial(); string id = Guid.NewGuid().ToString("N");
            var names = new[] { "a", "b" }; var stores = names.Select(n => new DistributedAllocation(Path.Combine(folder, "grant-" + n + ".json")) { NodeName = () => n }).ToArray();
            try
            {
                foreach (var store in stores) store.AddPlan(old);
                uint grantAddress = old.First; var grant = stores[0].Grant(old.Scope, grantAddress, "b", Guid.NewGuid().ToString("N"));
                stores[1].Merge(stores[0].Export()); stores[1].Commit(old.Scope, grantAddress, "1-0203", "02-03", "borrowed", DateTime.UtcNow.AddHours(2));
                stores[0].Merge(stores[1].Export());
                DateTime historicalTime = DateTime.UtcNow;
                var frozen = stores.Select(s => s.FreezeChange(id, old)).ToArray();
                var desired = old with { Epoch = id, Last = old.Last + 10 };
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { Owners = ["a"] }, [frozen[0], frozen[1]]), "permanent borrower removal");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { First = old.First + 1 }, frozen), "range shrink across permanent grant");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { Excluded = [new(grantAddress, grantAddress)] }, frozen), "exclusion over permanent grant");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { Reservations = [new(grantAddress, "1-0209")] }, frozen), "reservation steals permanent grant");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired, [frozen[0]]), "missing frozen original owner");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { First = Ip("198.51.100.1"), Last = Ip("198.51.100.10") }, frozen), "off-subnet range");
                Reject(() => DistributedAllocation.BuildChange(id, "a", desired with { First = desired.Last + 1 }, frozen), "reversed range");
                var input = DistributedAllocation.BuildChange(id, "a", desired, frozen); string hash = DistributedAllocation.ChangeHash(input);
                var staleFrozen = frozen.Select(f => f.Node == "b" ? f with { Replica = f.Replica with { Sequence = f.Replica.Sequence - 1, Entries = [], History = [] } } : f).ToArray();
                var staleInput = DistributedAllocation.BuildChange(id, "a", desired, staleFrozen);
                Reject(() => stores[0].PrepareChange(staleInput), "original owner older than already observed peer authority");
                var competing = Task.Run(() => { try { stores[0].FreezeChange(Guid.NewGuid().ToString("N"), old); return true; } catch (InvalidOperationException) { return false; } });
                Check(!await competing, "conflicting concurrent change refused");
                foreach (var store in stores) { store.PrepareChange(input); store.ConfirmChangeConfiguration(old.Scope, id, hash); }
                Reject(() => stores[0].CommitChange(old.Scope, id, hash), "commit before participant receipt");
                stores[0].AcknowledgeChange(old.Scope, id, hash, "b");
                stores[0].Snapshot().Changes[^1].PreparedNodes[0] = "forged";
                Check(stores[0].Change(old.Scope).PreparedNodes[0] == "a", "snapshot cannot mutate ownership receipts");
                stores[1].CommitChange(old.Scope, id, hash, names); stores[0].CommitChange(old.Scope, id, hash);
                Check(stores[0].Snapshot().Replicas.Single(r => r.Node == "a").Entries.Single(e => e.State == "Grant") == grant, "permanent grant byte semantics and ID preserved");
                Check(stores[1].FindLease(old.Scope, "1-0203")?.Address == grantAddress && !stores[0].HasAuthority(old.Scope, grantAddress), "borrower lease protected and donor remains surrendered");
                Check(stores[0].Snapshot().Replicas.All(r => r.Sequence > frozen.Max(f => f.Replica.Sequence)), "successor sequences exceed all frozen originals");
                Reject(() => stores[0].Merge(JsonSerializer.SerializeToUtf8Bytes(new AllocationState(1, [old], frozen.Select(f => f.Replica).ToArray()), DistributedAllocation.JsonOptions)), "stale epoch ordinary replication");
                Check(stores[0].Change(old.Scope).Frozen == Json(frozen[0]), "old original authority remains immutable in journal");
                Check(stores[0].ResolveAt(grantAddress, historicalTime)?.Node == "b", "historical lookup retains original epoch borrower binding");
            }
            finally { foreach (var store in stores) await store.DisposeAsync(); }
            string failFolder = Path.Combine(folder, "failed-persist"); Directory.CreateDirectory(failFolder);
            var (faultStores, faultInput) = await Prepared(failFolder, "frozen");
            try
            {
                using (var locked = new FileStream(Path.Combine(failFolder, "a.json.tmp"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                    Reject(() => faultStores[0].PrepareChange(faultInput), "actual filesystem write failure during prepare");
                Check(faultStores[0].RecoveryRequired && !faultStores[0].HasAuthority("change", faultInput.Plan.First), "failed persistence withholds authority");
            }
            finally { foreach (var store in faultStores) await store.DisposeAsync(); }
            await using (var reopened = new DistributedAllocation(Path.Combine(failFolder, "a.json")) { NodeName = () => "a" })
                Check(reopened.Change("change").Phase == "Frozen", "failed prepare reopens exact frozen barrier");
            Console.WriteLine($"PASS: {checks} ownership storage/real-kill/fault checks");
        }
        finally { Directory.Delete(folder, true); }
    }
}
