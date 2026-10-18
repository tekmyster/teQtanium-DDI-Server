using DnsServerCore.Ipam;
using System.Collections.Concurrent;
using System.Net;
using System.Numerics;

if (args.Length > 0 && (args[0] == "--package" || args[0] == "--prepare-package")) { await PackageChecks.Run(args); return; }
if (args.Length == 4 && args[0] == "--bootstrap-crash") { await DistributedDhcpChecks.CrashFixture(args[1], args[2], args[3]); return; }

if (args.Contains("--migration")) { await MigrationChecks.Run(args.Contains("--serve")); return; }
if (args.Contains("--syslog")) { await SyslogChecks.Run(); return; }

if (args.Contains("--transport")) { await DistributedTransportChecks.Run(args.Contains("--serve")); return; }
if (args.Contains("--api") || args.Contains("--serve")) { await ApiChecks.Run(args.Contains("--serve")); return; }
if (args.Contains("--llm")) { await LlmChecks.Run(); return; }
if (args.Contains("--llm-metrics")) { await LlmTelemetryChecks.Run(); return; }
if (args.Contains("--security-analytics")) { await SecurityAnalyticsChecks.Run(); return; }
if (args.Contains("--security")) { await SecurityChecks.Run(); return; }
if (args.Contains("--udp-listeners")) { await DistributedDhcpChecks.RunUdpListeners(); return; }
if (args.Contains("--dhcp")) { await DistributedDhcpChecks.Run(); return; }
if (args.Contains("--netbox")) { await NetBoxChecks.Run(); return; }
if (args.Contains("--security-ops")) { await SecurityOperationsChecks.Run(); return; }

string folder = Path.Combine(Path.GetTempPath(), "ddi-ipam-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
int passed = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); passed++; }
void Reject(Action action, string message)
{
    try { action(); } catch (ArgumentException) { passed++; return; } catch (InvalidOperationException) { passed++; return; } catch (InvalidDataException) { passed++; return; }
    throw new Exception(message);
}
IpamSubnet AddSubnet(IpamManager manager, string view, string prefix, bool container = false) => manager.PutSubnet(manager.Snapshot().Revision, "test", "", view, prefix, prefix, "East", 20, "", "", container);
try
{
    string file = Path.Combine(folder, "ipam.json");
    IpamManager manager = new IpamManager(file);
    var root = AddSubnet(manager, "default", "10.0.0.0/8", true);
    var subnet = AddSubnet(manager, "default", "10.20.0.43/24");
    Check(subnet.Prefix == "10.20.0.0/24", "Canonical prefix");
    Reject(() => AddSubnet(manager, "default", "10.20.0.0/25"), "Overlapping leaf prefix accepted");
    var view = manager.PutView(manager.Snapshot().Revision, "test", "", "West", "Independent routing domain");
    var overlapping = AddSubnet(manager, view.Id, "10.20.0.0/24");
    var first = manager.PutAssignment(manager.Snapshot().Revision, "test", "", subnet.Id, "10.20.0.1", "device.example", "NetOps", "Assigned", "");
    manager.PutAssignment(manager.Snapshot().Revision, "test", "", overlapping.Id, "10.20.0.1", "other.example", "NetOps", "Assigned", "");
    Reject(() => manager.PutAssignment(manager.Snapshot().Revision, "test", "", subnet.Id, "10.20.0.1", "", "", "Assigned", ""), "Duplicate address accepted");
    Reject(() => manager.PutAssignment(manager.Snapshot().Revision, "test", "", subnet.Id, "10.20.0.0", "", "", "Assigned", ""), "Network address accepted");
    Reject(() => manager.PutAssignment(manager.Snapshot().Revision, "test", "", subnet.Id, "10.20.0.255", "", "", "Assigned", ""), "Broadcast accepted");
    Reject(() => manager.PutAssignment(manager.Snapshot().Revision, "test", "", subnet.Id, "10.21.0.1", "", "", "Assigned", ""), "Out of subnet address accepted");
    Check(manager.NextAvailable(subnet.Id, ["10.20.0.2", "10.20.0.3", "192.0.2.1"]) == "10.20.0.4", "Observed usage not excluded");
    Reject(() => manager.NextAvailable(root.Id, []), "Container allocation accepted");
    var tiny = AddSubnet(manager, "default", "192.0.2.0/31");
    Check(manager.NextAvailable(tiny.Id, []) == "192.0.2.0", "/31 first endpoint unavailable");
    Check(manager.NextAvailable(tiny.Id, ["192.0.2.0"]) == "192.0.2.1", "/31 second endpoint unavailable");
    Reject(() => manager.NextAvailable(tiny.Id, ["192.0.2.0", "192.0.2.1"]), "Exhausted pool returned address");
    var ipv6 = AddSubnet(manager, "default", "2001:db8::/64");
    Check(new IpamNetwork(ipv6.Prefix).Capacity == (BigInteger.One << 64) - 1, "IPv6 capacity overflow");
    Check(manager.NextAvailable(ipv6.Id, ["2001:db8::1"]) == "2001:db8::2", "IPv6 next available failed");
    Reject(() => new IpamNetwork("fe80::1%2/64"), "Scoped address accepted");
    Reject(() => manager.Delete(manager.Snapshot().Revision, "test", "view", "default"), "Default view deleted");
    Reject(() => manager.Delete(manager.Snapshot().Revision, "test", "subnet", root.Id), "Nonempty container deleted");
    Reject(() => manager.Delete(manager.Snapshot().Revision, "test", "subnet", subnet.Id), "Nonempty subnet deleted");
    Reject(() => manager.PutView(0, "test", "", "Stale", ""), "Stale revision accepted");
    var reloaded = new IpamManager(file);
    Check(reloaded.Snapshot().Revision == manager.Snapshot().Revision && reloaded.Snapshot().Assignments.Length == 2, "Durable reload failed");
    Check(manager.Snapshot().Changes.Any(c => c.After?.Contains("device.example") == true), "Assignment history lacks values");
    var findings = manager.Reconcile(subnet.Id, [new IpamObservation("10.20.0.1", "DhcpLease", "scope", "wrong.example", "client1", DateTime.UtcNow.AddHours(1)), new IpamObservation("10.20.0.1", "DhcpLease", "scope", "wrong.example", "client2", DateTime.UtcNow.AddHours(1)), new IpamObservation("10.20.0.2", "DnsRecord", "example", "new.example", "", null)]);
    Check(findings.Any(f => f.Kind == "DuplicateLease") && findings.Any(f => f.Kind == "HostNameDrift") && findings.Any(f => f.Kind == "Unmanaged"), "Reconciliation findings incomplete");
    long revision = manager.Snapshot().Revision;
    ConcurrentBag<string> results = [];
    Parallel.For(0, 8, i => { try { manager.PutAssignment(revision, "test", "", subnet.Id, "10.20.0.10", "", "", "Reserved", ""); results.Add("ok"); } catch (InvalidOperationException) { results.Add("stale"); } });
    Check(results.Count(r => r == "ok") == 1 && results.Count(r => r == "stale") == 7, "Concurrent updates not serialized");
    byte[] snapshot = manager.Export();
    manager.Restore(snapshot);
    Check(manager.Snapshot().Revision == revision + 1, "Backup restore changed revision");
    Reject(() => manager.Restore(System.Text.Encoding.UTF8.GetBytes("{\"version\":99,\"revision\":0,\"views\":[],\"subnets\":[],\"assignments\":[],\"changes\":[]}")), "Unknown schema accepted");
    Check(manager.Snapshot().Revision == revision + 1, "Failed restore corrupted state");
    manager.Delete(manager.Snapshot().Revision, "test", "subnet", tiny.Id);
    Check(!manager.Snapshot().Subnets.Any(s => s.Id == tiny.Id), "Subnet deletion failed");
    string failingPath = Path.Combine(folder, "not-a-directory");
    File.WriteAllText(failingPath, "file");
    IpamManager failing = new IpamManager(Path.Combine(failingPath, "ipam.json"));
    try { failing.PutView(0, "test", "", "NeverSaved", ""); throw new Exception("Save unexpectedly succeeded"); } catch (IOException) { passed++; }
    Check(failing.Snapshot().Revision == 0 && failing.Snapshot().Views.Length == 1, "Failed save changed in-memory state");
    var automatic = new IpamManager(Path.Combine(folder, "automatic.json"));
    IpamDiscoveredNetwork[] discoveredNetworks = [new("10.20.30.0/24", "Servers", "Servers", "example", "DhcpScope")];
    IpamDiscoveredAddress[] discoveredAddresses = [new("10.20.30.10", "reserved.example", "client1", "Reserved", "DhcpReservation"), new("10.20.30.11", "static.example", "example", "Assigned", "DnsRecord"), new("203.0.113.10", "outside.example", "example", "Assigned", "DnsRecord")];
    Check(automatic.SynchronizeDiscovery(discoveredNetworks, discoveredAddresses), "Empty inventory was not automatically populated");
    Check(automatic.Snapshot().Subnets.Length == 1 && automatic.Snapshot().Assignments.Length == 2, "Discovery inferred an unknown subnet or omitted known addresses");
    var autoState = automatic.Snapshot();
    Check(!automatic.SynchronizeDiscovery(discoveredNetworks, discoveredAddresses) && automatic.Snapshot().Revision == autoState.Revision, "Unchanged discovery invalidated allocation revisions");
    Check(new IpamManager(Path.Combine(folder, "automatic.json")).Snapshot().Assignments.Length == 2, "Discovery was not durable");
    Check(automatic.SynchronizeDiscovery(discoveredNetworks, discoveredAddresses.Take(1)), "Deleted DNS record remained assigned");
    Check(automatic.Snapshot().Assignments.Single().Id == autoState.Assignments.Single(a => a.Source == "DhcpReservation").Id, "Discovery changed stable assignment identity");
    var autoSubnet = automatic.Snapshot().Subnets.Single();
    automatic.PutAssignment(automatic.Snapshot().Revision, "operator", "", autoSubnet.Id, "10.20.30.12", "intent.example", "Operations", "Assigned", "Powered off server");
    automatic.SynchronizeDiscovery(discoveredNetworks, []);
    Check(automatic.Snapshot().Assignments.Single().HostName == "intent.example", "Discovery deleted operator allocation intent");
    Check(automatic.NextAvailable(autoSubnet.Id, ["10.20.30.1"], [new("10.20.30.2", "10.20.30.200", "DhcpPool")]) == "10.20.30.201", "Static allocation entered the DHCP pool");
    Reject(() => automatic.NextAvailable(autoSubnet.Id, [], [new("10.20.30.1", "10.20.30.254", "DhcpPool")]), "Full DHCP pool returned a static candidate");
    var preserved = automatic.Export();
    Reject(() => automatic.SynchronizeDiscovery(discoveredNetworks, [new("invalid", "", "", "Assigned", "DnsRecord")]), "Malformed discovery was accepted");
    Check(preserved.SequenceEqual(automatic.Export()), "Failed source snapshot changed inventory");
    var offNetwork = AddSubnet(automatic, "default", "10.50.0.0/16");
    automatic.SynchronizeDiscovery([new("10.50.1.0/24", "Overlap", "Overlap", "", "DhcpScope")], []);
    Check(!automatic.Snapshot().Subnets.Any(s => s.DhcpScope == "Overlap"), "Discovery silently merged overlapping leaf networks");
    var moved = new IpamManager(Path.Combine(folder, "scope-move.json"));
    moved.SynchronizeDiscovery(discoveredNetworks, discoveredAddresses.Take(1));
    string scopeIdentity = moved.Snapshot().Subnets.Single().Id;
    moved.SynchronizeDiscovery([new("10.20.31.0/24", "Servers", "Servers", "example", "DhcpScope")], [new("10.20.31.10", "reserved.example", "client1", "Reserved", "DhcpReservation")]);
    Check(moved.Snapshot().Subnets.Single().Id == scopeIdentity && moved.Snapshot().Subnets.Single().Prefix == "10.20.31.0/24", "Changed DHCP subnet was not synchronized with stable identity");
    Check(moved.Snapshot().Assignments.Single().Address == "10.20.31.10", "Old reservation remained after DHCP subnet change");
    Console.WriteLine($"PASS: {passed} IPAM checks");
}
finally
{
    // The target is the unique directory created by this test under the OS temp directory.
    if (Path.GetDirectoryName(folder) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)) throw new Exception("Unexpected test directory");
    Directory.Delete(folder, true);
}
