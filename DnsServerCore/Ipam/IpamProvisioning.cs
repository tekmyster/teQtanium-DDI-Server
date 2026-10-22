// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Ipam
{
    public sealed record IpamProvisioningIntent(string SubnetId, string Address, string HostName, string HardwareAddress, string Owner);
    public sealed record IpamProvisioning(string Id, string Actor, IpamProvisioningIntent Intent, IpamSubnet Subnet,
        long Revision, string Preconditions, string Digest, DateTime Expires, string State,
        string DnsOutcome, string DhcpOutcome, string Detail, DateTime Updated);

    // Implementations must reconcile operation-owned objects before attempting another write.
    // A thrown/unknown write never releases a claim. No generic rollback of destination snapshots.
    public interface IIpamProvisioningDestination
    {
        string Check(IpamProvisioning operation);
        string EnsureDns(IpamProvisioning operation);
        string EnsureDhcp(IpamProvisioning operation);
        bool Compensate(IpamProvisioning operation);
    }

    public sealed partial class IpamManager
    {
        readonly ConcurrentDictionary<string, SemaphoreSlim> _provisioningGates = new();
        static bool HoldsAddress(IpamProvisioning p) => p.State is "Approved" or "Applying" or "RecoveryRequired";
        static bool SameAddress(IpamSnapshot state, IpamProvisioning p, string subnetId, string address)
            => p.Intent.Address == address && state.Subnets.Any(s => s.Id == subnetId && s.ViewId == p.Subnet.ViewId);
        static void ValidateProvisioning(IpamSnapshot state)
        {
            var operations = state.Provisioning ?? [];
            if (operations.Length > 10000 || operations.Any(p => p is null || !Guid.TryParseExact(p.Id, "N", out _) || p.Intent is null || p.Subnet is null || p.Digest?.Length != 64 || p.Revision < 0 || p.Expires == default ||
                p.State is not ("Preview" or "Approved" or "Applying" or "Completed" or "RecoveryRequired" or "Cancelled" or "Compensated")) || operations.Select(p => p.Id).Distinct().Count() != operations.Length)
                throw new InvalidDataException("Invalid provisioning journal.");
            var held = operations.Where(HoldsAddress).ToArray();
            if (held.Select(p => p.Subnet.ViewId + "|" + p.Intent.Address).Distinct().Count() != held.Length)
                throw new InvalidDataException("Conflicting provisioning claims.");
            foreach (var p in held)
            {
                if (!state.Subnets.Contains(p.Subnet)) throw new InvalidOperationException("Resolve provisioning before changing its network or service links.");
                if (state.Assignments.Any(a => SameAddress(state, p, a.SubnetId, a.Address)))
                    throw new InvalidOperationException("Address is held by provisioning " + p.Id + ".");
            }
        }
        public bool ProvisioningAddressHeld(string scope, System.Net.IPAddress address)
        { lock (_sync) return (_state.Provisioning ?? []).Any(p => HoldsAddress(p) && p.Subnet.DhcpScope == scope && p.Intent.Address == address.ToString()); }
        public IpamProvisioning ProvisioningResult(string id)
        { lock (_sync) return (_state.Provisioning ?? []).SingleOrDefault(p => p.Id == id) ?? throw new ArgumentException("Unknown provisioning operation."); }
        public IpamProvisioning[] ProvisioningOperations()
        { lock (_sync) return (_state.Provisioning ?? []).ToArray(); }
        void SaveProvisioning(IpamProvisioning operation, IpamAssignment assignment = null)
        {
            var next = _state with { Revision = checked(_state.Revision + 1),
                Provisioning = (_state.Provisioning ?? []).Where(p => p.Id != operation.Id).Append(operation).ToArray(),
                Assignments = assignment is null ? _state.Assignments : _state.Assignments.Append(assignment).ToArray() };
            next = next with { Changes = next.Changes.Append(new IpamChange(next.Revision, DateTime.UtcNow, operation.Actor,
                "provisioning." + operation.State, operation.Id, null, JsonSerializer.Serialize(operation, JsonOptions))).ToArray() };
            Validate(next); Save(next); _state = next;
        }
        public IpamProvisioning PreviewProvisioning(long revision, string id, string actor, IpamProvisioningIntent intent, Func<IpamProvisioning, string> check)
        {
            if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("Use a new operation reference for a new request.");
            intent = intent with { Address = Address(intent.Address).ToString(), HostName = Required(intent.HostName, "Host name").TrimEnd('.').ToLowerInvariant(), HardwareAddress = Required(intent.HardwareAddress, "Hardware address").ToUpperInvariant(), Owner = Text(intent.Owner) };
            lock (_sync)
            {
                var previous = (_state.Provisioning ?? []).SingleOrDefault(p => p.Id == id);
                if (previous is not null)
                {
                    if (previous.Intent != intent || previous.Actor != actor) throw new InvalidOperationException("This operation reference already belongs to another request.");
                    return previous;
                }
                if (revision != _state.Revision) throw new InvalidOperationException("Inventory changed. Refresh and review a new preview.");
                var subnet = _state.Subnets.SingleOrDefault(s => s.Id == intent.SubnetId) ?? throw new ArgumentException("Unknown subnet.");
                var network = new IpamNetwork(subnet.Prefix); var address = Address(intent.Address);
                if (subnet.Container || subnet.ViewId != "default" || network.Bits != 32 || !network.Contains(address) || IpamNetwork.Number(address) < network.FirstUsable || IpamNetwork.Number(address) > network.LastUsable)
                    throw new ArgumentException("Provisioning supports usable IPv4 addresses in the default network view.");
                if (_state.Assignments.Any(a => a.Address == intent.Address && _state.Subnets.Any(s => s.Id == a.SubnetId && s.ViewId == subnet.ViewId)) || (_state.Provisioning ?? []).Any(p => HoldsAddress(p) && SameAddress(_state, p, subnet.Id, intent.Address)))
                    throw new InvalidOperationException("Address is assigned or held by another operation.");
                if ((_state.Provisioning ?? []).Length >= 10000) throw new InvalidOperationException("Provisioning journal capacity reached. Contact the administrator.");
                var now = DateTime.UtcNow;
                var draft = new IpamProvisioning(id, Required(actor, "Actor"), intent, subnet, _state.Revision + 1, "", "", now.AddMinutes(10), "Preview", "Not submitted", "Not submitted", "Review the address, host and service destinations before approval.", now);
                string preconditions = check(draft);
                string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(draft with { Preconditions = preconditions }, JsonOptions))));
                var result = draft with { Preconditions = preconditions, Digest = digest };
                SaveProvisioning(result); return result;
            }
        }
        public IpamProvisioning ApproveProvisioning(string id, string actor, string digest, Func<IpamProvisioning, string> check)
        {
            lock (_sync)
            {
                var p = ProvisioningResult(id);
                if (p.Actor != actor || p.Digest != digest) throw new InvalidOperationException("Approval does not match this request.");
                if (p.State == "Approved") return p;
                if (p.State != "Preview" || DateTime.UtcNow > p.Expires || p.Revision != _state.Revision || !_state.Subnets.Contains(p.Subnet) || check(p) != p.Preconditions)
                    throw new InvalidOperationException("Preview expired or inventory/service configuration changed. Review a new preview.");
                p = p with { State = "Approved", Detail = "Address held. Apply this approved request to configure the local services.", Updated = DateTime.UtcNow };
                SaveProvisioning(p); return p;
            }
        }
        public IpamProvisioning CancelProvisioning(string id, string actor)
        {
            lock (_sync)
            {
                var p = ProvisioningResult(id);
                if (p.Actor != actor || p.State is not ("Preview" or "Approved")) throw new InvalidOperationException("Only an unsubmitted request owned by you can be cancelled.");
                p = p with { State = "Cancelled", Detail = "Cancelled before service submission.", Updated = DateTime.UtcNow };
                SaveProvisioning(p); return p;
            }
        }
        public async Task<IpamProvisioning> ApplyProvisioning(string id, string actor, string digest, IIpamProvisioningDestination destination, bool compensate = false)
        {
            var gate = _provisioningGates.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync();
            try
            {
                using var operationLock = new FileStream(_path + ".provisioning-" + id + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                IpamProvisioning p;
                lock (_sync)
                {
                    p = ProvisioningResult(id);
                    if (p.Actor != actor || p.Digest != digest) throw new InvalidOperationException("Apply does not match this approved request.");
                    if (p.State is "Completed" or "Compensated") return p;
                    if (p.State is not ("Approved" or "Applying" or "RecoveryRequired")) throw new InvalidOperationException("Approve this request before applying it.");
                    if (p.State == "Approved" && DateTime.UtcNow > p.Expires) throw new InvalidOperationException("Approval expired. Cancel this request and review a new preview.");
                    p = p with { State = "Applying", Detail = "Reconciling current service state before any write.", Updated = DateTime.UtcNow };
                    SaveProvisioning(p); // durable hold and before-effect intent
                }
                try
                {
                    if (compensate)
                    {
                        if (!destination.Compensate(p)) throw new InvalidOperationException("A destination changed or could not acknowledge recovery. The address remains held.");
                        lock (_sync) { p = p with { State = "Compensated", Detail = "Operation-owned changes removed and persisted. Other writers were preserved.", Updated = DateTime.UtcNow }; SaveProvisioning(p); }
                        return p;
                    }
                    if (destination.Check(p) != p.Preconditions) throw new InvalidOperationException("Destination configuration changed. Reconcile or recover this same request; do not create a replacement.");
                    string dns = destination.EnsureDns(p);
                    lock (_sync) { p = p with { DnsOutcome = dns, Updated = DateTime.UtcNow }; SaveProvisioning(p); }
                    string dhcp = destination.EnsureDhcp(p);
                    lock (_sync)
                    {
                        p = p with { DhcpOutcome = dhcp, State = "Completed", Detail = "Local DNS record and DHCP reservation persisted and read back. Client lease acquisition is separate.", Updated = DateTime.UtcNow };
                        SaveProvisioning(p, new IpamAssignment(p.Id, p.Subnet.Id, p.Intent.Address, p.Intent.HostName, p.Intent.Owner, "Reserved", "Provisioned by operation " + p.Id));
                    }
                    return p;
                }
                catch (Exception ex)
                {
                    lock (_sync)
                    {
                        p = p with { State = "RecoveryRequired", Detail = "Service outcome needs reconciliation. Retry or recover this same request. " + ex.Message, Updated = DateTime.UtcNow };
                        SaveProvisioning(p);
                    }
                    return p;
                }
            }
            finally { gate.Release(); }
        }
    }
}
