using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Ipam;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net;
using System.Text.Json;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        readonly object _ipamDiscoveryLock = new object();
        System.Threading.Timer _ipamDiscoveryTimer;

        void RefreshIpamDiscovery()
        {
            lock (_ipamDiscoveryLock)
            {
                if (_dhcpServer is null || _dnsServer is null || _clusterManager is null) return;
                // Replicas receive coordinator inventory through existing cluster configuration sync.
                if (_clusterManager.ClusterInitialized && _clusterManager.GetSelfNode().Type != ClusterNodeType.Primary) return;
                List<IpamDiscoveredNetwork> networks = [];
                List<IpamDiscoveredAddress> addresses = [];
                HashSet<string> dynamicAddresses = [];
                var scopes = _dhcpServer.Scopes.Values.ToArray();
                foreach (Scope scope in scopes)
                {
                    int length = 0;
                    bool zero = false;
                    foreach (byte value in scope.SubnetMask.GetAddressBytes())
                        for (int bit = 7; bit >= 0; bit--)
                        {
                            bool one = (value & (1 << bit)) != 0;
                            if (one && zero) throw new InvalidOperationException("DHCP scope has a non-contiguous subnet mask.");
                            if (one) length++; else zero = true;
                        }
                    string zone = (scope.DomainName ?? "").TrimEnd('.').ToLowerInvariant();
                    if (_dnsServer.AuthZoneManager.GetAuthZoneInfo(zone) is null) zone = "";
                    networks.Add(new(scope.NetworkAddress + "/" + length, scope.Name, scope.Name, zone, "DhcpScope"));
                    foreach (Lease lease in scope.Leases.Values)
                        if (lease.LeaseExpires > DateTime.UtcNow) dynamicAddresses.Add(lease.Address.ToString());
                    foreach (Lease lease in scope.ReservedLeases)
                    {
                        string host = lease.HostName ?? "";
                        if (host.Length > 0 && !host.Contains('.') && !string.IsNullOrEmpty(scope.DomainName)) host += "." + scope.DomainName.TrimEnd('.');
                        addresses.Add(new(lease.Address.ToString(), host, lease.ClientIdentifier.ToString(), "Reserved", "DhcpReservation"));
                    }
                    if (scope.RouterAddress is not null && !scope.RouterAddress.Equals(IPAddress.Any))
                        addresses.Add(new(scope.RouterAddress.ToString(), "", scope.Name, "Reserved", "DhcpGateway"));
                }
                foreach (var device in scopes.SelectMany(scope => _allocation.LiveLeases(scope.Name))) dynamicAddresses.Add(AllocationSequence.Address(device.Lease.Address).ToString());
                foreach (var zone in _dnsServer.AuthZoneManager.GetAllZones())
                {
                    if (zone.Disabled || (zone.Type != AuthZoneType.Primary && zone.Type != AuthZoneType.Secondary)) continue;
                    string prefix = ReverseZonePrefix(zone.Name);
                    if (prefix is not null) networks.Add(new(prefix, zone.Name, "", zone.Name, "DnsReverseZone"));
                    List<DnsResourceRecord> records = [];
                    _dnsServer.AuthZoneManager.ListAllZoneRecords(zone.Name, [DnsResourceRecordType.A, DnsResourceRecordType.AAAA, DnsResourceRecordType.PTR], records);
                    foreach (var record in records)
                    {
                        if (record.GetAuthGenericRecordInfo().Disabled) continue;
                        IPAddress address = RecordAddress(record);
                        if (address is null || IPAddress.IsLoopback(address) || dynamicAddresses.Contains(address.ToString())) continue;
                        // A lingering DNS record in a dynamic pool must not become static intent after lease expiry.
                        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && scopes.Any(s => IpamNetwork.Number(address) >= IpamNetwork.Number(s.StartingAddress) && IpamNetwork.Number(address) <= IpamNetwork.Number(s.EndingAddress) && !s.IsAddressExcluded(address))) continue;
                        addresses.Add(new(address.ToString(), record.RDATA is DnsPTRRecordData ptr ? ptr.Domain : record.Name, zone.Name, "Assigned", "DnsRecord"));
                    }
                }
                if (_ipam.SynchronizeDiscovery(networks, addresses) && _clusterManager.ClusterInitialized)
                    _clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }
        }

        static string ReverseZonePrefix(string name)
        {
            if (name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
            {
                var labels = name[..^13].Split('.');
                if (labels.Length < 1 || labels.Length > 4 || labels.Any(l => !byte.TryParse(l, out _))) return null;
                var bytes = labels.Reverse().Select(byte.Parse).Concat(Enumerable.Repeat((byte)0, 4 - labels.Length)).ToArray();
                if (bytes[0] == 127 || bytes[0] == 0) return null;
                return new IpamNetwork(new IPAddress(bytes) + "/" + labels.Length * 8).Prefix;
            }
            if (name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
            {
                var labels = name[..^9].Split('.');
                if (labels.Length < 1 || labels.Length > 32 || labels.Any(l => l.Length != 1 || !Uri.IsHexDigit(l[0]))) return null;
                string hex = string.Concat(labels.Reverse()).PadRight(32, '0');
                return new IpamNetwork(new IPAddress(Convert.FromHexString(hex)) + "/" + labels.Length * 4).Prefix;
            }
            return null;
        }

        static IPAddress RecordAddress(DnsResourceRecord record)
        {
            if (record.RDATA is DnsARecordData a) return a.Address;
            if (record.RDATA is DnsAAAARecordData aaaa) return aaaa.Address;
            if (record.RDATA is DnsPTRRecordData)
            {
                string prefix = ReverseZonePrefix(record.Name);
                if (prefix is not null && (prefix.EndsWith("/32", StringComparison.Ordinal) || prefix.EndsWith("/128", StringComparison.Ordinal)))
                    return IPAddress.Parse(prefix.Split('/')[0]);
            }
            return null;
        }

        void TryRefreshIpamDiscovery()
        {
            try { RefreshIpamDiscovery(); }
            catch (Exception ex) { _log.Write("IPAM automatic discovery failed; existing inventory was retained.", ex); }
        }

        sealed class WebServiceIpamApi
        {
            readonly DnsWebService _service;
            static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            public WebServiceIpamApi(DnsWebService service) { _service = service; }

            User Authorize(HttpContext context, PermissionFlag permission)
            {
                User user = _service.GetSessionUser(context);
                // Reuse existing Settings permissions; no existing ACL is silently expanded.
                if (!_service._authManager.IsPermitted(PermissionSection.Settings, user, permission)) throw new DnsWebServiceException("Access was denied.");
                if (permission != PermissionFlag.View && _service._clusterManager.ClusterInitialized && _service._clusterManager.GetSelfNode().Type != ClusterNodeType.Primary)
                    throw new DnsWebServiceException("IPAM changes must be made on the cluster primary node.");
                return user;
            }

            void Write(HttpContext context, string name, object value)
            {
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();
                writer.WritePropertyName(name);
                JsonSerializer.Serialize(writer, value, value.GetType(), JsonOptions);
            }
            long Revision(HttpContext context) => long.Parse(context.Request.GetQueryOrForm("revision"));
            void Changed(HttpContext context, User user, string operation)
            {
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] IPAM " + operation + "; revision " + _service._ipam.Snapshot().Revision);
                if (_service._clusterManager.ClusterInitialized) _service._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }
            NativeProvisioning ProvisioningAccess(HttpContext context, PermissionFlag permission, IpamProvisioning operation = null)
            {
                var user = Authorize(context, permission);
                if (permission != PermissionFlag.View && _service._clusterManager.ClusterInitialized) throw new InvalidOperationException("Provisioning currently supports standalone servers. Cluster destinations require a separate coordinated allocation workflow.");
                if (operation is not null && operation.Actor != user.Username) throw new InvalidOperationException("This provisioning request belongs to another operator.");
                return new NativeProvisioning(this, user);
            }
            public void ListProvisioning(HttpContext context)
            {
                var user = Authorize(context, PermissionFlag.View);
                var visible = new List<IpamProvisioning>();
                foreach (var operation in _service._ipam.ProvisioningOperations().Where(p => p.Actor == user.Username))
                {
                    if (_service._authManager.IsPermitted(PermissionSection.DhcpServer, user, PermissionFlag.View) && _service._authManager.IsPermitted(PermissionSection.Zones, operation.Subnet.DnsZone, user, PermissionFlag.View)) visible.Add(operation);
                }
                Write(context, "operations", visible.OrderByDescending(p => p.Updated).ToArray());
            }
            public void PreviewProvisioning(HttpContext context)
            {
                var native = ProvisioningAccess(context, PermissionFlag.Modify);
                var r = context.Request;
                string operationId = r.GetQueryOrForm("operationId");
                var intent = new IpamProvisioningIntent(r.GetQueryOrForm("subnetId"), r.GetQueryOrForm("address"), r.GetQueryOrForm("hostName"), r.GetQueryOrForm("hardwareAddress"), r.GetQueryOrForm("owner", ""));
                var previous = _service._ipam.ProvisioningOperations().SingleOrDefault(p => p.Id == operationId);
                if (previous is not null && previous.Actor != native.User.Username) throw new InvalidOperationException("This provisioning request belongs to another operator.");
                var destination = previous?.Subnet ?? _service._ipam.GetSubnets().SingleOrDefault(s => s.Id == intent.SubnetId) ?? throw new ArgumentException("Unknown subnet.");
                // A cached result still discloses destination data. Authorize its original
                // destinations before entering any idempotent manager early return.
                native.Permissions(destination, PermissionFlag.Modify);
                var result = _service._ipam.PreviewProvisioning(Revision(context), operationId, native.User.Username, intent, native.Check);
                Write(context, "operation", result);
            }
            public void ProvisioningResult(HttpContext context)
            {
                var p = _service._ipam.ProvisioningResult(context.Request.GetQueryOrForm("operationId"));
                ProvisioningAccess(context, PermissionFlag.View, p).Permissions(p, PermissionFlag.View);
                Write(context, "operation", p);
            }
            public async Task ApproveProvisioning(HttpContext context)
            {
                var p = _service._ipam.ProvisioningResult(context.Request.GetQueryOrForm("operationId"));
                var native = ProvisioningAccess(context, PermissionFlag.Modify, p);
                native.Permissions(p, PermissionFlag.Modify);
                var scope = _service._dhcpServer.GetScope(p.Subnet.DhcpScope) ?? throw new InvalidOperationException("Original DHCP scope is unavailable.");
                using var guard = await scope.BeginProvisioningApprovalAsync(context.RequestAborted);
                if (!ReferenceEquals(_service._dhcpServer.GetScope(p.Subnet.DhcpScope), scope)) throw new InvalidOperationException("DHCP scope was replaced during approval. Review a new preview.");
                native.Permissions(p, PermissionFlag.Modify); // Recheck after the bounded drain.
                Write(context, "operation", _service._ipam.ApproveProvisioning(p.Id, native.User.Username, context.Request.GetQueryOrForm("digest"), native.Check));
            }
            public void CancelProvisioning(HttpContext context)
            {
                var p = _service._ipam.ProvisioningResult(context.Request.GetQueryOrForm("operationId"));
                var native = ProvisioningAccess(context, PermissionFlag.Modify, p);
                native.Permissions(p, PermissionFlag.Modify);
                Write(context, "operation", _service._ipam.CancelProvisioning(p.Id, native.User.Username));
            }
            public async Task ApplyProvisioning(HttpContext context)
            {
                var p = _service._ipam.ProvisioningResult(context.Request.GetQueryOrForm("operationId"));
                var native = ProvisioningAccess(context, PermissionFlag.Modify, p);
                bool recover = bool.Parse(context.Request.GetQueryOrForm("recover", "false"));
                native.Permissions(p, PermissionFlag.Modify);
                if (recover) native.Permissions(p, PermissionFlag.Delete);
                Write(context, "operation", await _service._ipam.ApplyProvisioning(p.Id, native.User.Username, context.Request.GetQueryOrForm("digest"), native, recover));
            }
            sealed class NativeProvisioning : IIpamProvisioningDestination
            {
                readonly WebServiceIpamApi _api;
                DnsWebService Service => _api._service;
                public User User { get; }
                public NativeProvisioning(WebServiceIpamApi api, User user) { _api = api; User = user; }
                string Marker(IpamProvisioning p) => "IPAM operation " + p.Id;
                DnsResourceRecord Record(IpamProvisioning p)
                {
                    var record = new DnsResourceRecord(p.Intent.HostName, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse(p.Intent.Address)));
                    record.GetAuthGenericRecordInfo().Comments = Marker(p);
                    return record;
                }
                Lease Reservation(IpamProvisioning p) => new Lease(LeaseType.Reserved, p.Intent.HostName, DhcpMessageHardwareAddressType.Ethernet, p.Intent.HardwareAddress, IPAddress.Parse(p.Intent.Address), Marker(p));
                public void Permissions(IpamProvisioning p, PermissionFlag permission) => Permissions(p.Subnet, permission);
                public void Permissions(IpamSubnet destination, PermissionFlag permission)
                {
                    if (!Service._authManager.IsPermitted(PermissionSection.DhcpServer, User, PermissionFlag.View) ||
                        !Service._authManager.IsPermitted(PermissionSection.DhcpServer, User, permission) ||
                        !Service._authManager.IsPermitted(PermissionSection.Zones, destination.DnsZone, User, PermissionFlag.View) ||
                        !Service._authManager.IsPermitted(PermissionSection.Zones, destination.DnsZone, User, permission))
                        throw new DnsWebServiceException("Current DHCP and destination DNS zone view and action permissions are required for provisioning.");
                }
                public string Check(IpamProvisioning p)
                {
                    Permissions(p, PermissionFlag.Modify);
                    if (Service._ipam.DiscoveryEvidence(p.Subnet.Id, false).Any(e => e.Address == p.Intent.Address)) throw new InvalidOperationException("Current active discovery reports this address in use. Review its evidence before provisioning.");
                    if (Service._clusterManager.ClusterInitialized || p.Subnet.ViewId != "default" || p.Subnet.DhcpScope.Length == 0 || p.Subnet.DnsZone.Length == 0)
                        throw new InvalidOperationException("Select a standalone default-view subnet linked to a local DNS zone and DHCP scope.");
                    if (!System.Text.RegularExpressions.Regex.IsMatch(p.Intent.HardwareAddress, "^[0-9A-F]{2}(-[0-9A-F]{2}){5}$")) throw new ArgumentException("Enter six hardware-address bytes separated by hyphens.");
                    if (p.Intent.HostName == p.Subnet.DnsZone || !p.Intent.HostName.EndsWith("." + p.Subnet.DnsZone, StringComparison.OrdinalIgnoreCase) || !p.Intent.HostName.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' && label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')))
                        throw new ArgumentException("Enter a full host name within the linked DNS zone.");
                    var zone = Service._dnsServer.AuthZoneManager.GetAuthZoneInfo(p.Subnet.DnsZone);
                    if (zone?.ApexZone is not PrimaryZone primary || primary.Disabled || primary.DnssecStatus != AuthZoneDnssecStatus.Unsigned || primary.Update != AuthZoneUpdate.Deny || !Service._dnsServer.AuthZoneManager.IsProvisioningAuthority(p.Subnet.DnsZone, p.Intent.HostName))
                        throw new InvalidOperationException("Provisioning requires an enabled, unsigned local primary zone with dynamic updates denied.");
                    var scope = Service._dhcpServer.GetScope(p.Subnet.DhcpScope) ?? throw new InvalidOperationException("Linked DHCP scope is unavailable.");
                    var ip = IPAddress.Parse(p.Intent.Address);
                    if (scope.DnsUpdates || Service._allocation.Plan(scope.Name) is not null || Service._allocation.BootstrapPending(scope.Name) || Service._allocation.ProtectedByOtherPlan(scope.Name, AllocationSequence.Number(scope.StartingAddress), AllocationSequence.Number(scope.EndingAddress)) || Service._allocation.NativeProtected(scope.Name, AllocationSequence.Number(ip), Reservation(p).ClientIdentifier.ToString()) || !scope.IsAddressInRange(ip) || scope.IsAddressExcluded(ip) || scope.RouterAddress?.Equals(ip) == true || scope.DnsServers?.Contains(ip) == true || scope.WinsServers?.Contains(ip) == true || scope.NtpServers?.Contains(ip) == true)
                        throw new InvalidOperationException("Use an eligible address in an unshared local scope with DNS updates disabled. Exclusions and gateways cannot be provisioned.");
                    if (Service._dhcpServer.Scopes.Values.Any(s => s.Name != scope.Name && s.IsAddressInRange(ip))) throw new InvalidOperationException("Another local scope covers this address.");
                    if (Service._allocation.NativeHolds(scope.Name).Any(e => e.Address == AllocationSequence.Number(ip) || e.Client == Reservation(p).ClientIdentifier.ToString()))
                        throw new InvalidOperationException("An existing native lease, offer or quarantine protects this address or client. Review it before provisioning.");
                    var reservation = Reservation(p);
                    if (scope.Leases.Values.Any(l => l.Address.Equals(ip) || l.ClientIdentifier.Equals(reservation.ClientIdentifier)) || scope.ReservedLeases.Any(l => (l.Address.Equals(ip) || l.ClientIdentifier.Equals(reservation.ClientIdentifier)) && (l.Address.ToString() != p.Intent.Address || l.HostName != p.Intent.HostName || l.Comments != Marker(p))))
                        throw new InvalidOperationException("The address or client already has a DHCP lease or reservation.");
                    foreach (var candidate in Service._dnsServer.AuthZoneManager.GetAllZones())
                    {
                        var records = new List<DnsResourceRecord>();
                        Service._dnsServer.AuthZoneManager.ListAllZoneRecords(candidate.Name, [DnsResourceRecordType.A, DnsResourceRecordType.AAAA, DnsResourceRecordType.PTR, DnsResourceRecordType.CNAME], records);
                        if (records.Any(r => (r.Name == p.Intent.HostName || RecordAddress(r)?.Equals(ip) == true) && !(candidate.Name == p.Subnet.DnsZone && r.Name == p.Intent.HostName && r.Type == DnsResourceRecordType.A && RecordAddress(r)?.Equals(ip) == true && r.OriginalTtlValue == 300 && r.GetAuthGenericRecordInfo().Comments == Marker(p) && !r.GetAuthGenericRecordInfo().Disabled)))
                            throw new InvalidOperationException("DNS already contains this address or host name. Review existing records first.");
                    }
                    return JsonSerializer.Serialize(new { subnet = p.Subnet, scope = scope.Name, start = scope.StartingAddress.ToString(), end = scope.EndingAddress.ToString(), mask = scope.SubnetMask.ToString(), scope.Enabled, scope.DnsUpdates, scope.DomainName, scope.IgnoreClientIdentifierOption, scope.AllowOnlyReservedLeases, serverAddress = scope.ServerAddress?.ToString(), gateway = scope.RouterAddress?.ToString(), exclusions = scope.Exclusions?.Select(e => new { start = e.StartingAddress.ToString(), end = e.EndingAddress.ToString() }), zone = zone.Name, type = zone.Type.ToString(), primary.Update, primary.DnssecStatus }, JsonOptions);
                }
                public string EnsureDns(IpamProvisioning p)
                {
                    if (Check(p) != p.Preconditions) throw new InvalidOperationException("Destination configuration changed.");
                    if (!Service._dnsServer.AuthZoneManager.ProvisionAddress(p.Subnet.DnsZone, Record(p), Marker(p), false)) throw new InvalidOperationException("DNS changed before the conditional write.");
                    if (Check(p) != p.Preconditions) throw new InvalidOperationException("DNS readback found a conflict or changed destination.");
                    return "Address record persisted and read back";
                }
                public string EnsureDhcp(IpamProvisioning p)
                {
                    if (Check(p) != p.Preconditions) throw new InvalidOperationException("Destination configuration changed.");
                    var scope = Service._dhcpServer.GetScope(p.Subnet.DhcpScope);
                    using var change = scope.BeginAdministrativeChange();
                    if (!scope.ProvisionReservation(Reservation(p), Marker(p), false)) throw new InvalidOperationException("DHCP lease, offer or reservation changed before the conditional write.");
                    var persisted = Service._dhcpServer.SaveProvisionedScope(scope.Name);
                    if (!persisted.ReservedLeases.Any(l => l.Address.ToString() == p.Intent.Address && l.HostName == p.Intent.HostName && l.Comments == Marker(p) && l.HardwareAddress.SequenceEqual(Lease.ParseHardwareAddress(p.Intent.HardwareAddress))))
                        throw new IOException("DHCP did not acknowledge the reservation on disk.");
                    if (Check(p) != p.Preconditions) throw new InvalidOperationException("DHCP destination changed during readback.");
                    return "Reservation persisted and read back; client lease not verified";
                }
                public bool Compensate(IpamProvisioning p)
                {
                    Permissions(p, PermissionFlag.Modify);
                    var scope = Service._dhcpServer.GetScope(p.Subnet.DhcpScope) ?? throw new InvalidOperationException("Original DHCP scope is unavailable.");
                    using var change = scope.BeginAdministrativeChange();
                    if (!scope.ProvisionReservation(Reservation(p), Marker(p), true)) return false;
                    var persisted = Service._dhcpServer.SaveProvisionedScope(scope.Name);
                    if (persisted.ReservedLeases.Any(l => l.Comments == Marker(p))) return false;
                    return Service._dnsServer.AuthZoneManager.ProvisionAddress(p.Subnet.DnsZone, Record(p), Marker(p), true);
                }
            }

            User DiscoveryAccess(HttpContext context, PermissionFlag permission)
            {
                var user = Authorize(context, permission);
                Authorize(context, PermissionFlag.View);
                if (!_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.View) || !_service._authManager.IsPermitted(PermissionSection.Administration, user, permission)) throw new DnsWebServiceException("Administration and Settings permissions are required for active discovery.");
                if (permission != PermissionFlag.View && _service._clusterManager.ClusterInitialized) throw new InvalidOperationException("Active discovery currently supports standalone servers. Cluster collection requires coordinated source ownership.");
                return user;
            }
            public void DiscoveryStatus(HttpContext context)
            {
                DiscoveryAccess(context, PermissionFlag.View);
                _service._ipam.RetryDiscoveryPersistence();
                var state = _service._ipam.Snapshot();
                Write(context, "sources", state.DiscoverySources ?? []);
                Write(context, "runs", (state.DiscoveryRuns ?? []).Select(r => new { r.SourceId, r.Actor, r.AttemptedAt, r.LastSuccess, r.Status, r.Detail, r.Evidence, r.OutcomeReason, r.Truncated, scopeCurrent = IpamManager.DiscoveryScopeCurrent(state, r) }).ToArray());
                Write(context, "active", _service._ipam.ActiveDiscoveryIds());
                Write(context, "pendingPersistence", _service._ipam.PendingDiscoveryPersistenceIds());
                Write(context, "canDelete", _service._authManager.IsPermitted(PermissionSection.Administration, _service.GetSessionUser(context), PermissionFlag.Delete) && _service._authManager.IsPermitted(PermissionSection.Settings, _service.GetSessionUser(context), PermissionFlag.Delete));
                Write(context, "canModify", _service._authManager.IsPermitted(PermissionSection.Administration, _service.GetSessionUser(context), PermissionFlag.Modify) && _service._authManager.IsPermitted(PermissionSection.Settings, _service.GetSessionUser(context), PermissionFlag.Modify));
            }
            public void SetDiscoverySource(HttpContext context)
            {
                var user = DiscoveryAccess(context, PermissionFlag.Modify);
                var source = JsonSerializer.Deserialize<IpamDiscoverySource>(context.Request.GetQueryOrForm("source"), JsonOptions) ?? throw new ArgumentException("Discovery configuration is required.");
                Write(context, "source", _service._ipam.PutDiscoverySource(Revision(context), user.Username, source));
                Changed(context, user, "discovery source set");
            }
            public void DeleteDiscoverySource(HttpContext context)
            {
                var user = DiscoveryAccess(context, PermissionFlag.Delete);
                _service._ipam.DeleteDiscoverySource(Revision(context), user.Username, context.Request.GetQueryOrForm("sourceId"));
                Changed(context, user, "discovery source deleted");
            }
            public async Task RunDiscovery(HttpContext context)
            {
                var user = DiscoveryAccess(context, PermissionFlag.Modify);
                var run = await _service._ipam.RunDiscovery(context.Request.GetQueryOrForm("sourceId"), user.Username, bool.Parse(context.Request.GetQueryOrForm("qualify", "false")), context.RequestAborted, () => DiscoveryAccess(context, PermissionFlag.Modify));
                Write(context, "run", new { run.SourceId, run.AttemptedAt, run.LastSuccess, run.Status, run.Detail, run.Evidence, run.OutcomeReason, run.Truncated });
                Changed(context, user, "discovery run " + run.Status);
            }
            public void CancelDiscovery(HttpContext context)
            {
                var user = DiscoveryAccess(context, PermissionFlag.Modify);
                Write(context, "cancellationRequested", _service._ipam.CancelDiscovery(context.Request.GetQueryOrForm("sourceId")));
                _service._log.Write(_service.GetRemoteEndPoint(context), "[" + user.Username + "] IPAM discovery cancellation requested.");
            }

            public void List(HttpContext context)
            {
                Authorize(context, PermissionFlag.View);
                _service.RefreshIpamDiscovery();
                var inventory = _service._ipam.Snapshot();
                Write(context, "inventory", inventory with { Provisioning = null, DiscoverySources = null, DiscoveryRuns = null, NetBoxImports = null, Changes = inventory.Changes.Where(c => !c.Operation.StartsWith("netbox.import:", StringComparison.Ordinal) && !c.Operation.StartsWith("provisioning.", StringComparison.Ordinal) && (c.Operation == "discovery.sync" || !c.Operation.StartsWith("discovery.", StringComparison.Ordinal))).ToArray() });
            }
            public void SetView(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                var r = context.Request;
                Write(context, "view", _service._ipam.PutView(Revision(context), user.Username, r.GetQueryOrForm("id", ""), r.GetQueryOrForm("name"), r.GetQueryOrForm("description", "")));
                Changed(context, user, "view set");
            }
            public void SetSubnet(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                var r = context.Request;
                string dhcpScope = r.GetQueryOrForm("dhcpScope", "");
                string dnsZone = r.GetQueryOrForm("dnsZone", "").TrimEnd('.').ToLowerInvariant();
                IpamNetwork network = new IpamNetwork(r.GetQueryOrForm("prefix"));
                if (dhcpScope.Length > 0)
                {
                    if (!_service._authManager.IsPermitted(PermissionSection.DhcpServer, user, PermissionFlag.View)) throw new DnsWebServiceException("DHCP view permission is required to link a scope.");
                    Scope scope = _service._dhcpServer.GetScope(dhcpScope) ?? throw new ArgumentException("Unknown DHCP scope.");
                    if (!network.Contains(scope.StartingAddress) || !network.Contains(scope.EndingAddress)) throw new ArgumentException("Linked DHCP range must be contained in the subnet.");
                }
                if (dnsZone.Length > 0)
                {
                    if (!_service._authManager.IsPermitted(PermissionSection.Zones, dnsZone, user, PermissionFlag.View)) throw new DnsWebServiceException("DNS zone view permission is required to link a zone.");
                    if (_service._dnsServer.AuthZoneManager.GetAuthZoneInfo(dnsZone) is null) throw new ArgumentException("Unknown DNS zone.");
                }
                string vlan = r.GetQueryOrForm("vlan", "");
                Write(context, "subnet", _service._ipam.PutSubnet(Revision(context), user.Username, r.GetQueryOrForm("id", ""), r.GetQueryOrForm("viewId", "default"), network.Prefix, r.GetQueryOrForm("name"), r.GetQueryOrForm("site", ""), vlan.Length == 0 ? null : int.Parse(vlan), dhcpScope, dnsZone, bool.Parse(r.GetQueryOrForm("container", "false"))));
                Changed(context, user, "subnet set");
            }
            public void SetAssignment(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Modify);
                var r = context.Request;
                Write(context, "assignment", _service._ipam.PutAssignment(Revision(context), user.Username, r.GetQueryOrForm("id", ""), r.GetQueryOrForm("subnetId"), r.GetQueryOrForm("address"), r.GetQueryOrForm("hostName", ""), r.GetQueryOrForm("owner", ""), r.GetQueryOrForm("status", "Assigned"), r.GetQueryOrForm("description", "")));
                Changed(context, user, "assignment set");
            }
            public void Delete(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.Delete);
                _service._ipam.Delete(Revision(context), user.Username, context.Request.GetQueryOrForm("kind"), context.Request.GetQueryOrForm("id"));
                Changed(context, user, "object deleted");
            }

            List<IpamObservation> Observations(IpamSubnet subnet, User user)
            {
                IpamNetwork network = new IpamNetwork(subnet.Prefix);
                List<IpamObservation> result = [];
                if (!string.IsNullOrEmpty(subnet.DhcpScope))
                {
                    if (!_service._authManager.IsPermitted(PermissionSection.DhcpServer, user, PermissionFlag.View)) throw new DnsWebServiceException("DHCP view permission is required for this subnet's observations.");
                    Scope scope = _service._dhcpServer.GetScope(subnet.DhcpScope) ?? throw new InvalidOperationException("Linked DHCP scope is unavailable on this node.");
                    foreach (Lease lease in scope.Leases.Values)
                        if (lease.LeaseExpires > DateTime.UtcNow && network.Contains(lease.Address)) result.Add(new IpamObservation(lease.Address.ToString(), "DhcpLease", scope.Name, lease.HostName, lease.ClientIdentifier.ToString(), lease.LeaseExpires));
                    foreach (Lease lease in scope.ReservedLeases)
                        if (network.Contains(lease.Address)) result.Add(new IpamObservation(lease.Address.ToString(), "DhcpReservation", scope.Name, lease.HostName, lease.ClientIdentifier.ToString(), null));
                    if (scope.RouterAddress is not null && !scope.RouterAddress.Equals(IPAddress.Any) && network.Contains(scope.RouterAddress))
                        result.Add(new IpamObservation(scope.RouterAddress.ToString(), "DhcpGateway", scope.Name, "", "", null));
                    foreach (var device in _service._allocation.LiveLeases(subnet.DhcpScope))
                    {
                        var lease = device.Lease;
                        if (network.Contains(AllocationSequence.Address(lease.Address)) && !result.Any(o => o.Source == "DhcpLease" && o.Address == AllocationSequence.Address(lease.Address).ToString() && o.ClientIdentifier == lease.Client))
                            result.Add(new(AllocationSequence.Address(lease.Address).ToString(), "DhcpLease", device.Scope, lease.Host, lease.Client, lease.Expires));
                    }
                }
                if (!string.IsNullOrEmpty(subnet.DnsZone))
                {
                    if (!_service._authManager.IsPermitted(PermissionSection.Zones, subnet.DnsZone, user, PermissionFlag.View)) throw new DnsWebServiceException("DNS zone view permission is required for this subnet's observations.");
                    if (_service._dnsServer.AuthZoneManager.GetAuthZoneInfo(subnet.DnsZone) is null) throw new InvalidOperationException("Linked DNS zone is unavailable on this node.");
                }
                foreach (var zone in _service._dnsServer.AuthZoneManager.GetAllZones())
                {
                    if (zone.Disabled || (zone.Type != AuthZoneType.Primary && zone.Type != AuthZoneType.Secondary) || !_service._authManager.IsPermitted(PermissionSection.Zones, zone.Name, user, PermissionFlag.View)) continue;
                    List<DnsResourceRecord> records = [];
                    _service._dnsServer.AuthZoneManager.ListAllZoneRecords(zone.Name, [DnsResourceRecordType.A, DnsResourceRecordType.AAAA, DnsResourceRecordType.PTR], records);
                    foreach (DnsResourceRecord record in records)
                    {
                        if (record.GetAuthGenericRecordInfo().Disabled) continue;
                        IPAddress address = RecordAddress(record);
                        if (address is not null && network.Contains(address)) result.Add(new IpamObservation(address.ToString(), "DnsRecord", zone.Name, record.RDATA is DnsPTRRecordData ptr ? ptr.Domain : record.Name, "", null));
                    }
                }
                if (_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.View))
                    result.AddRange(_service._ipam.DiscoveryEvidence(subnet.Id, false).Select(e => new IpamObservation(e.Address, e.Source, e.SourceId, e.HostName, e.ClientIdentifier, e.Expires)));
                return result;
            }

            public void Inspect(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.View);
                _service.RefreshIpamDiscovery();
                string subnetId = context.Request.GetQueryOrForm("subnetId");
                IpamSnapshot state = _service._ipam.Snapshot();
                IpamSubnet subnet = state.Subnets.SingleOrDefault(s => s.Id == subnetId) ?? throw new ArgumentException("Unknown subnet.");
                List<IpamObservation> observations = Observations(subnet, user);
                IpamNetwork network = new IpamNetwork(subnet.Prefix);
                string[] intended = state.Assignments.Where(a => a.SubnetId == subnetId).Select(a => a.Address).ToArray();
                int used = intended.Concat(observations.Select(o => o.Address)).Distinct().Count();
                Write(context, "subnet", subnet);
                Write(context, "observations", observations);
                if (_service._authManager.IsPermitted(PermissionSection.Administration, user, PermissionFlag.View)) Write(context, "discoveryEvidence", _service._ipam.DiscoveryEvidence(subnetId, true));
                Write(context, "ranges", AddressRanges(subnet, user));
                Write(context, "findings", _service._ipam.Reconcile(subnetId, observations));
                var assets = state.Assignments.Where(a => a.SubnetId == subnetId).Select(a => (a.Address, a.HostName, Source: "IPAM intent"))
                    .Concat(observations.Select(o => (o.Address, o.HostName, Source: o.Source))).Distinct().ToArray();
                var securityFindings = new List<object>();
                foreach (var asset in assets)
                {
                    Security.SecurityDecision decision;
                    try { decision = _service._security.Evaluate(IPAddress.Parse(asset.Address), asset.HostName, [], [IPAddress.Parse(asset.Address)]); }
                    catch (ArgumentException) { decision = _service._security.Evaluate(IPAddress.Parse(asset.Address), null, [], [IPAddress.Parse(asset.Address)]); }
                    if (decision.Matches.Any(i => i.Action != "Allow")) securityFindings.Add(new { address = asset.Address, source = asset.Source, action = decision.Action, reason = decision.Reason, indicators = decision.Matches.Select(i => i.Value).ToArray() });
                }
                Write(context, "securityFindings", securityFindings);
                Write(context, "utilization", new { usableAddresses = network.Capacity.ToString(), intendedAddresses = intended.Length, observedAddresses = observations.Select(o => o.Address).Distinct().Count(), knownUsedAddresses = used });
            }

            public void NextAvailable(HttpContext context)
            {
                User user = Authorize(context, PermissionFlag.View);
                _service.RefreshIpamDiscovery();
                string subnetId = context.Request.GetQueryOrForm("subnetId");
                IpamSubnet subnet = _service._ipam.Snapshot().Subnets.SingleOrDefault(s => s.Id == subnetId) ?? throw new ArgumentException("Unknown subnet.");
                // A suggestion is not a DHCP claim or a reservation. Revision checks protect intent writes.
                Write(context, "address", _service._ipam.NextAvailable(subnetId, Observations(subnet, user).Select(o => o.Address), AddressRanges(subnet, user)));
                Write(context, "revision", _service._ipam.Snapshot().Revision);
            }

            IpamAddressRange[] AddressRanges(IpamSubnet subnet, User user)
            {
                var network = new IpamNetwork(subnet.Prefix);
                List<IpamAddressRange> ranges = [];
                foreach (var scope in _service._dhcpServer.Scopes.Values)
                {
                    if (!network.Contains(scope.StartingAddress) && !network.Contains(scope.EndingAddress) && !(new IpamNetwork(scope.NetworkAddress + "/32").Bits == network.Bits && IpamNetwork.Number(scope.StartingAddress) <= network.First && IpamNetwork.Number(scope.EndingAddress) >= network.Last)) continue;
                    if (!_service._authManager.IsPermitted(PermissionSection.DhcpServer, user, PermissionFlag.View)) throw new DnsWebServiceException("DHCP view permission is required to check dynamic pools.");
                    ranges.Add(new(scope.StartingAddress.ToString(), scope.EndingAddress.ToString(), "DhcpPool"));
                    foreach (var exclusion in scope.Exclusions ?? []) ranges.Add(new(exclusion.StartingAddress.ToString(), exclusion.EndingAddress.ToString(), "DhcpExclusion"));
                    if (scope.RouterAddress is not null && !scope.RouterAddress.Equals(IPAddress.Any)) ranges.Add(new(scope.RouterAddress.ToString(), scope.RouterAddress.ToString(), "Gateway"));
                }
                return ranges.ToArray();
            }
        }
    }
}
