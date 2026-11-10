/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.Dhcp.Options;
using DnsServerCore.Dns;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dhcp
{
    public sealed class Scope : IComparable<Scope>, IDisposable
    {
        #region variables

        //required parameters
        string _name;
        bool _enabled;
        IPAddress _startingAddress;
        IPAddress _endingAddress;
        IPAddress _subnetMask;
        ushort _leaseTimeDays = 1; //default 1 day lease
        byte _leaseTimeHours = 0;
        byte _leaseTimeMinutes = 0;
        ushort _offerDelayTime;

        readonly LogManager _log;
        readonly DhcpServer _dhcpServer;

        bool _pingCheckEnabled;
        ushort _pingCheckTimeout = 1000;
        byte _pingCheckRetries = 2;

        //dhcp options
        string _domainName;
        IReadOnlyCollection<string> _domainSearchList;
        bool _dnsUpdates = true;
        bool _dnsOverwriteForDynamicLease = false;
        uint _dnsTtl = 900;
        IPAddress _serverAddress;
        string _serverHostName;
        string _bootFileName;
        IPAddress _routerAddress;
        bool _useThisDnsServer;
        IReadOnlyCollection<IPAddress> _dnsServers;
        IReadOnlyCollection<IPAddress> _winsServers;
        IReadOnlyCollection<IPAddress> _ntpServers;
        IReadOnlyCollection<string> _ntpServerDomainNames;
        IReadOnlyCollection<ClasslessStaticRouteOption.Route> _staticRoutes;
        IReadOnlyDictionary<string, VendorSpecificInformationOption> _vendorInfo;
        IReadOnlyCollection<IPAddress> _capwapAcIpAddresses;
        IReadOnlyCollection<IPAddress> _tftpServerAddreses;

        //advanced options
        IReadOnlyCollection<DhcpOption> _genericOptions;
        IReadOnlyCollection<Exclusion> _exclusions;
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _reservedLeases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        bool _allowOnlyReservedLeases;
        bool _blockLocallyAdministeredMacAddresses;
        bool _ignoreClientIdentifierOption;

        //leases
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _leases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();

        //internal computed parameters
        IPAddress _networkAddress;
        IPAddress _broadcastAddress;

        //internal parameters
        const int OFFER_EXPIRY_SECONDS = 60; //1 mins offer expiry
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _offers = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        readonly ConcurrentDictionary<string, DateTime> _peerSelections = new();
        IPAddress _lastAddressOffered;
        readonly SemaphoreSlim _lastAddressOfferedLock = new SemaphoreSlim(1, 1);
        readonly object _requestGate = new();
        int _servingRequests;
        bool _migrationCapturing;
        TaskCompletionSource _requestsDrained;
        IPAddress _interfaceAddress;
        int _interfaceIndex;
        DateTime _lastModified = DateTime.UtcNow;

        #endregion

        #region constructor

        public Scope(string name, bool enabled, IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask, LogManager log, DhcpServer dhcpServer)
        {
            ValidateScopeName(name);

            _name = name;
            _enabled = enabled;

            ChangeNetwork(startingAddress, endingAddress, subnetMask);

            _log = log;
            _dhcpServer = dhcpServer;
        }

        public Scope(Stream s, LogManager log, DhcpServer dhcpServer)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "SC")
                throw new InvalidDataException("DhcpServer scope file format is invalid.");

            _log = log;
            _dhcpServer = dhcpServer;

            BinaryReader bR = new BinaryReader(s);

            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                    _name = s.ReadShortString();
                    _enabled = bR.ReadBoolean();

                    ChangeNetwork(IPAddressExtensions.ReadFrom(bR), IPAddressExtensions.ReadFrom(bR), IPAddressExtensions.ReadFrom(bR));

                    _leaseTimeDays = bR.ReadUInt16();
                    _leaseTimeHours = bR.ReadByte();
                    _leaseTimeMinutes = bR.ReadByte();

                    _offerDelayTime = bR.ReadUInt16();

                    if (version >= 5)
                    {
                        _pingCheckEnabled = bR.ReadBoolean();
                        _pingCheckTimeout = bR.ReadUInt16();
                        _pingCheckRetries = bR.ReadByte();
                    }

                    _domainName = s.ReadShortString();
                    if (string.IsNullOrWhiteSpace(_domainName))
                        _domainName = null;

                    if (version >= 7)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            string[] domainSearchStrings = new string[count];

                            for (int i = 0; i < count; i++)
                                domainSearchStrings[i] = s.ReadShortString();

                            _domainSearchList = domainSearchStrings;
                        }

                        _dnsUpdates = bR.ReadBoolean();
                    }

                    if (version >= 10)
                        _dnsOverwriteForDynamicLease = bR.ReadBoolean();

                    _dnsTtl = bR.ReadUInt32();

                    if (version >= 2)
                    {
                        _serverAddress = IPAddressExtensions.ReadFrom(bR);
                        if (_serverAddress.Equals(IPAddress.Any))
                            _serverAddress = null;
                    }

                    if (version >= 3)
                    {
                        _serverHostName = s.ReadShortString();
                        if (string.IsNullOrEmpty(_serverHostName))
                            _serverHostName = null;

                        _bootFileName = s.ReadShortString();
                        if (string.IsNullOrEmpty(_bootFileName))
                            _bootFileName = null;
                    }

                    _routerAddress = IPAddressExtensions.ReadFrom(bR);
                    if (_routerAddress.Equals(IPAddress.Any))
                        _routerAddress = null;

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            if (count == 255)
                            {
                                _useThisDnsServer = true;
                                FindThisDnsServerAddress();
                            }
                            else
                            {
                                IPAddress[] dnsServers = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    dnsServers[i] = IPAddressExtensions.ReadFrom(bR);

                                _dnsServers = dnsServers;
                            }
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] winsServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                winsServers[i] = IPAddressExtensions.ReadFrom(bR);

                            _winsServers = winsServers;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] ntpServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                ntpServers[i] = IPAddressExtensions.ReadFrom(bR);

                            _ntpServers = ntpServers;
                        }
                    }

                    if (version >= 7)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            string[] ntpServerDomainNames = new string[count];

                            for (int i = 0; i < count; i++)
                                ntpServerDomainNames[i] = s.ReadShortString();

                            _ntpServerDomainNames = ntpServerDomainNames;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            ClasslessStaticRouteOption.Route[] staticRoutes = new ClasslessStaticRouteOption.Route[count];

                            for (int i = 0; i < count; i++)
                                staticRoutes[i] = new ClasslessStaticRouteOption.Route(bR.BaseStream);

                            _staticRoutes = staticRoutes;
                        }
                    }

                    if (version >= 4)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            Dictionary<string, VendorSpecificInformationOption> vendorInfo = new Dictionary<string, VendorSpecificInformationOption>(count);

                            for (int i = 0; i < count; i++)
                            {
                                string vendorClassIdentifier = s.ReadShortString();
                                VendorSpecificInformationOption vendorSpecificInformation = new VendorSpecificInformationOption(bR.ReadBuffer());

                                vendorInfo.Add(vendorClassIdentifier, vendorSpecificInformation);
                            }

                            _vendorInfo = vendorInfo;
                        }
                    }

                    if (version >= 7)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] capwapAcIpAddresses = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                capwapAcIpAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                            _capwapAcIpAddresses = capwapAcIpAddresses;
                        }
                    }

                    if (version >= 8)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] tftpServerAddreses = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                tftpServerAddreses[i] = IPAddressExtensions.ReadFrom(bR);

                            _tftpServerAddreses = tftpServerAddreses;
                        }
                    }

                    if (version >= 8)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            DhcpOption[] genericOptions = new DhcpOption[count];

                            for (int i = 0; i < count; i++)
                            {
                                DhcpOptionCode code = (DhcpOptionCode)bR.ReadByte();
                                short length = bR.ReadInt16();
                                byte[] value = s.ReadExactly(length);

                                genericOptions[i] = new DhcpOption(code, value);
                            }

                            _genericOptions = genericOptions;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            Exclusion[] exclusions = new Exclusion[count];

                            for (int i = 0; i < count; i++)
                                exclusions[i] = new Exclusion(IPAddressExtensions.ReadFrom(bR), IPAddressExtensions.ReadFrom(bR));

                            _exclusions = exclusions;
                        }
                    }

                    {
                        int count = bR.ReadInt32();
                        if (count > 0)
                        {
                            for (int i = 0; i < count; i++)
                            {
                                Lease reservedLease = new Lease(bR);
                                _reservedLeases.TryAdd(reservedLease.ClientIdentifier, reservedLease);
                            }
                        }

                        _allowOnlyReservedLeases = bR.ReadBoolean();
                    }

                    if (version >= 6)
                        _blockLocallyAdministeredMacAddresses = bR.ReadBoolean();
                    else
                        _blockLocallyAdministeredMacAddresses = false;

                    if (version >= 9)
                        _ignoreClientIdentifierOption = bR.ReadBoolean();
                    else
                        _ignoreClientIdentifierOption = false;

                    {
                        int count = bR.ReadInt32();
                        if (count > 0)
                        {
                            for (int i = 0; i < count; i++)
                            {
                                Lease lease = new Lease(bR);

                                _leases.TryAdd(lease.ClientIdentifier, lease);
                            }
                        }
                    }

                    break;

                default:
                    throw new InvalidDataException("Scope data format version not supported.");
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _lastAddressOfferedLock?.Dispose();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region static

        internal static void ValidateScopeName(string name)
        {
            foreach (char invalidChar in Path.GetInvalidFileNameChars())
            {
                if (name.Contains(invalidChar))
                    throw new DhcpServerException("The scope name contains an invalid character: " + invalidChar);
            }
        }

        private static bool IsAddressInRange(IPAddress address, IPAddress startingAddress, IPAddress endingAddress)
        {
            uint addressNumber = address.ConvertIpToNumber();
            uint startingAddressNumber = startingAddress.ConvertIpToNumber();
            uint endingAddressNumber = endingAddress.ConvertIpToNumber();

            return (startingAddressNumber <= addressNumber) && (addressNumber <= endingAddressNumber);
        }

        private static void ValidateIpv4(IReadOnlyCollection<IPAddress> value, string paramName)
        {
            if (value is not null)
            {
                foreach (IPAddress ip in value)
                {
                    if (ip.AddressFamily != AddressFamily.InterNetwork)
                        throw new ArgumentException("The address must be an IPv4 address: " + ip.ToString(), paramName);
                }
            }
        }

        private static void ValidateIpv4(IPAddress value, string paramName)
        {
            if ((value is not null) && (value.AddressFamily != AddressFamily.InterNetwork))
                throw new ArgumentException("The address must be an IPv4 address: " + value.ToString(), paramName);
        }

        #endregion

        #region private

        private async Task<AddressStatus> IsAddressAvailableAsync(IPAddress address)
        {
            if (_dhcpServer.ProvisioningAddressHeld?.Invoke(_name, address) == true) return AddressStatus.FALSE;
            if (address.Equals(_routerAddress))
                return AddressStatus.FALSE;

            if ((_dnsServers != null) && _dnsServers.Contains(address))
                return AddressStatus.FALSE;

            if ((_winsServers != null) && _winsServers.Contains(address))
                return AddressStatus.FALSE;

            if ((_ntpServers != null) && _ntpServers.Contains(address))
                return AddressStatus.FALSE;

            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(address, exclusion.StartingAddress, exclusion.EndingAddress))
                        return new AddressStatus(false, exclusion.EndingAddress);
                }
            }

            if (_dhcpServer.Allocation?.NativeProtected(_name, AllocationSequence.Number(address)) == true) return AddressStatus.FALSE;
            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedLease in _reservedLeases)
            {
                if (address.Equals(reservedLease.Value.Address))
                    return AddressStatus.FALSE;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (address.Equals(lease.Value.Address))
                    return AddressStatus.FALSE;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (address.Equals(offer.Value.Address))
                    return AddressStatus.FALSE;
            }

            if (_pingCheckEnabled)
            {
                try
                {
                    using (Ping ping = new Ping())
                    {
                        int retry = 0;
                        do
                        {
                            PingReply reply = await ping.SendPingAsync(address, _pingCheckTimeout);
                            if (reply.Status == IPStatus.Success)
                                return AddressStatus.FALSE; //address is in use
                        }
                        while (++retry < _pingCheckRetries);
                    }
                }
                catch
                { }
            }

            return AddressStatus.TRUE;
        }

        private bool IsAddressAlreadyAllocated(IPAddress address, ClientIdentifierOption clientIdentifier)
        {
            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (address.Equals(lease.Value.Address))
                    return !lease.Key.Equals(clientIdentifier);
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (address.Equals(offer.Value.Address))
                    return !offer.Key.Equals(clientIdentifier);
            }

            return false;
        }

        private ClientFullyQualifiedDomainNameOption GetClientFullyQualifiedDomainNameOption(DhcpMessage request, string reservedLeaseHostName)
        {
            ClientFullyQualifiedDomainNameFlags responseFlags = ClientFullyQualifiedDomainNameFlags.None;

            if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat))
                responseFlags |= ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat;

            if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.NoDnsUpdate))
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
                responseFlags |= ClientFullyQualifiedDomainNameFlags.OverrideByServer;
            }
            else if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns))
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
            }
            else
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
                responseFlags |= ClientFullyQualifiedDomainNameFlags.OverrideByServer;
            }

            string clientDomainName;

            if (!string.IsNullOrWhiteSpace(reservedLeaseHostName))
            {
                //domain name override by server
                clientDomainName = DhcpServer.GetSanitizedHostName(reservedLeaseHostName) + "." + _domainName;
            }
            else if (string.IsNullOrWhiteSpace(request.ClientFullyQualifiedDomainName.DomainName))
            {
                //client domain empty and expects server for a fqdn domain name
                if ((request.HostName is null) || string.IsNullOrWhiteSpace(request.HostName.HostName))
                    return null; //server unable to decide a name for client

                clientDomainName = DhcpServer.GetSanitizedHostName(request.HostName.HostName) + "." + _domainName;
            }
            else if (request.ClientFullyQualifiedDomainName.DomainName.Contains('.'))
            {
                //client domain is fqdn
                if (request.ClientFullyQualifiedDomainName.DomainName.EndsWith("." + _domainName, StringComparison.OrdinalIgnoreCase))
                {
                    clientDomainName = request.ClientFullyQualifiedDomainName.DomainName;
                }
                else
                {
                    string[] parts = request.ClientFullyQualifiedDomainName.DomainName.Split('.');
                    clientDomainName = parts[0] + "." + _domainName;
                }
            }
            else
            {
                //client domain is just hostname
                clientDomainName = request.ClientFullyQualifiedDomainName.DomainName + "." + _domainName;
            }

            return new ClientFullyQualifiedDomainNameOption(responseFlags, 255, 255, clientDomainName);
        }

        private void ConvertToReservedLease(Lease lease)
        {
            //convert dynamic to reserved lease
            lease.ConvertToReserved();

            //add reserved lease
            Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, lease.HardwareAddress, lease.Address, null);
            _reservedLeases[reservedLease.ClientIdentifier] = reservedLease;

            //update DNS
            _dhcpServer.AddDnsEntries(this, lease);
        }

        private void ConvertToDynamicLease(Lease lease)
        {
            //convert reserved to dynamic lease
            lease.ConvertToDynamic();

            //remove reserved lease
            Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, lease.HardwareAddress, lease.Address, null);
            _reservedLeases.TryRemove(reservedLease.ClientIdentifier, out _);

            //update DNS
            _dhcpServer.AddDnsEntries(this, lease);

            //remove any old single address exclusion entry
            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (exclusion.StartingAddress.Equals(lease.Address) && exclusion.EndingAddress.Equals(lease.Address))
                    {
                        //remove single address exclusion entry
                        if (_exclusions.Count == 1)
                        {
                            _exclusions = null;
                        }
                        else
                        {
                            List<Exclusion> exclusions = new List<Exclusion>();

                            foreach (Exclusion exc in _exclusions)
                            {
                                if (exc.Equals(exclusion))
                                    continue;

                                exclusions.Add(exc);
                            }

                            _exclusions = exclusions;
                        }

                        break;
                    }
                }
            }
        }

        #endregion

        #region internal

        internal bool FindInterface()
        {
            //find network with static ip address in scope range
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        uint addressNumber = ip.Address.ConvertIpToNumber();

                        if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                        {
                            //found interface for this scope range

                            //check if interface has dynamic ipv4 address assigned via dhcp
                            if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
                            {
                                foreach (IPAddress dhcpServerAddress in ipInterface.DhcpServerAddresses)
                                {
                                    if (dhcpServerAddress.AddressFamily == AddressFamily.InterNetwork)
                                        throw new DhcpServerException("DHCP Server requires static IP address to work correctly but the network interface was found to have a dynamic IP address [" + ip.Address.ToString() + "] assigned by another DHCP server: " + dhcpServerAddress.ToString());
                                }
                            }

                            _interfaceAddress = ip.Address;
                            _interfaceIndex = ipInterface.GetIPv4Properties().Index;
                            return true;
                        }
                    }
                }
            }

            if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
            {
                //check if at least one interface has static ip address
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties ipInterface = nic.GetIPProperties();

                    foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            //check if address is static
                            if (ipInterface.DhcpServerAddresses.Count < 1)
                            {
                                //found static ip address so this scope can be activated
                                //using ANY ip address for this scope interface since we dont know the relay agent network 
                                _interfaceAddress = IPAddress.Any;
                                _interfaceIndex = -1;
                                return true;
                            }
                        }
                    }
                }
            }

            //server has no static ip address configured
            return false;
        }

        internal void FindThisDnsServerAddress()
        {
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();

            DnsServer dnsServer = _dhcpServer.DnsServer;
            if (dnsServer is not null)
            {
                bool dnsOnAny = false;

                foreach (IPEndPoint localEP in dnsServer.LocalEndPoints)
                {
                    if (localEP.Address.Equals(IPAddress.Any))
                    {
                        dnsOnAny = true;
                        break;
                    }
                }

                if (!dnsOnAny)
                {
                    //find local EP in scope network range
                    foreach (IPEndPoint localEP in dnsServer.LocalEndPoints)
                    {
                        if (localEP.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            uint addressNumber = localEP.Address.ConvertIpToNumber();

                            if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                            {
                                //found address in this scope range to use as dns server
                                _dnsServers = new IPAddress[] { localEP.Address };
                                return;
                            }
                        }
                    }

                    //find any local EP available
                    foreach (IPEndPoint localEP in dnsServer.LocalEndPoints)
                    {
                        if ((localEP.Address.AddressFamily == AddressFamily.InterNetwork) && !IPAddress.IsLoopback(localEP.Address))
                        {
                            //found address to use as dns server
                            _dnsServers = new IPAddress[] { localEP.Address };
                            return;
                        }
                    }

                    //no useable address was found
                    _dnsServers = null;
                    return;
                }
            }

            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            //find interface in current scope network range
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        uint addressNumber = ip.Address.ConvertIpToNumber();

                        if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                        {
                            //found address in this scope range to use as dns server
                            _dnsServers = new IPAddress[] { ip.Address };
                            return;
                        }
                    }
                }
            }

            //find unicast ip address on an interface which has gateway
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                if (ipInterface.GatewayAddresses.Count > 0)
                {
                    foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            //use this address for dns
                            _dnsServers = new IPAddress[] { ip.Address };
                            return;
                        }
                    }
                }
            }

            //find any unicast ip address available
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        //use this address for dns
                        _dnsServers = new IPAddress[] { ip.Address };
                        return;
                    }
                }
            }

            //no useable address was found
            _dnsServers = null;
        }

        internal uint GetLeaseTime()
        {
            return Convert.ToUInt32((_leaseTimeDays * 24 * 60 * 60) + (_leaseTimeHours * 60 * 60) + (_leaseTimeMinutes * 60));
        }

        internal bool IsAddressInRange(IPAddress address)
        {
            return IsAddressInRange(address, _startingAddress, _endingAddress);
        }

        internal bool IsAddressInNetwork(IPAddress address)
        {
            uint addressNumber = address.ConvertIpToNumber();
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint broadcastAddressNumber = _broadcastAddress.ConvertIpToNumber();

            return (networkAddressNumber < addressNumber) && (addressNumber < broadcastAddressNumber);
        }

        internal bool IsAddressExcluded(IPAddress address)
        {
            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(address, exclusion.StartingAddress, exclusion.EndingAddress))
                        return true;
                }
            }

            return false;
        }

        internal bool IsAddressReserved(IPAddress address)
        {
            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedLease in _reservedLeases)
            {
                if (address.Equals(reservedLease.Value.Address))
                    return true;
            }

            return false;
        }

        internal Lease GetReservedLease(DhcpMessage request)
        {
            return GetReservedLease(new ClientIdentifierOption((byte)request.HardwareAddressType, request.ClientHardwareAddress), request.GetClientIdentifier(_ignoreClientIdentifierOption));
        }

        private Lease GetReservedLease(ClientIdentifierOption reservedLeasesClientIdentifier, ClientIdentifierOption clientIdentifier)
        {
            if (_reservedLeases.TryGetValue(reservedLeasesClientIdentifier, out Lease reservedLease))
            {
                //reserved address exists
                if (IsAddressAlreadyAllocated(reservedLease.Address, clientIdentifier))
                {
                    //reserved lease address is already allocated so ignore reserved lease
                    _log.Write("DHCP Server cannot allocate reserved lease [" + reservedLease.Address.ToString() + "] to " + BitConverter.ToString(reservedLeasesClientIdentifier.Identifier) + " for scope '" + _name + "': The IP address is already allocated.");

                    return null;
                }

                return reservedLease;
            }

            return null;
        }

        internal bool HasReservedLeaseHostName(Lease lease)
        {
            ClientIdentifierOption reservedLeasesClientIdentifier = new ClientIdentifierOption((byte)DhcpMessageHardwareAddressType.Ethernet, lease.HardwareAddress);

            if (_reservedLeases.TryGetValue(reservedLeasesClientIdentifier, out Lease reservedLease) && reservedLease.Address.Equals(lease.Address))
                return !string.IsNullOrWhiteSpace(reservedLease.HostName);

            return false;
        }

        internal async Task<Lease> GetOfferAsync(DhcpMessage request)
        {
            if (_dhcpServer.Allocation?.ProtectedByOtherPlan(_name, AllocationSequence.Number(_startingAddress), AllocationSequence.Number(_endingAddress)) == true) return null;
            ClientIdentifierOption clientIdentifier = request.GetClientIdentifier(_ignoreClientIdentifierOption);

            if (_dhcpServer.Allocation?.Plan(_name) is null) RecoverNativeLeases(_dhcpServer.Allocation);

            if (_dhcpServer.SecurityManager?.ObserveDhcp(_name, clientIdentifier.ToString(), BitConverter.ToString(request.ClientHardwareAddress), request.HostName?.HostName, _leases.TryGetValue(clientIdentifier, out Lease securityLease) && securityLease.LeaseExpires > DateTime.UtcNow || _dhcpServer.Allocation?.FindLease(_name, clientIdentifier.ToString()) is not null) == true)
            {
                _log.Write("DHCP security policy withheld a new offer for scope '" + _name + "'.");
                return null;
            }

            if (_dhcpServer.Allocation?.Plan(_name) is not null)
                return await GetDistributedOfferAsync(request, clientIdentifier);

            if (_leases.TryGetValue(clientIdentifier, out Lease existingLease))
            {
                if (_dhcpServer.ProvisioningAddressHeld?.Invoke(_name, existingLease.Address) == true) return null;
                //lease already exists
                if (existingLease.Type == LeaseType.Reserved)
                {
                    Lease existingReservedLease = GetReservedLease(request);
                    if ((existingReservedLease is not null) && (existingReservedLease.Address == existingLease.Address))
                        return existingLease; //return existing reserved lease

                    //reserved lease address was changed; proceed to offer new lease
                }
                else
                {
                    //is dynamic lease
                    if (IsAddressExcluded(existingLease.Address))
                    {
                        //remove existing dynamic lease; proceed to offer new lease
                        ReleaseLease(existingLease);
                    }
                    else
                    {
                        if (_blockLocallyAdministeredMacAddresses)
                        {
                            if ((request.HardwareAddressType == DhcpMessageHardwareAddressType.Ethernet) && ((request.ClientHardwareAddress[0] & 0x02) > 0))
                            {
                                _log.Write("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + " for scope '" + _name + "': the scope does not allow locally administered MAC addresses.");

                                //prevent renewing existing dynamic lease
                                return null;
                            }
                        }

                        //return existing dynamic lease
                        return existingLease;
                    }
                }
            }

            Lease reservedLease = GetReservedLease(request);
            if (reservedLease != null)
            {
                if (_dhcpServer.ProvisioningAddressHeld?.Invoke(_name, reservedLease.Address) == true) return null;
                Lease reservedOffer = new Lease(LeaseType.Reserved, clientIdentifier, null, request.ClientHardwareAddress, reservedLease.Address, null, GetLeaseTime());
                ProtectNativeOffer(reservedOffer);
                _offers[clientIdentifier] = reservedOffer;
                return reservedOffer;
            }

            if (_allowOnlyReservedLeases)
            {
                _log.Write("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + " for scope '" + _name + "': the scope allows only reserved lease allocations.");

                return null;
            }

            if (_blockLocallyAdministeredMacAddresses)
            {
                if ((request.HardwareAddressType == DhcpMessageHardwareAddressType.Ethernet) && ((request.ClientHardwareAddress[0] & 0x02) > 0))
                {
                    _log.Write("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + " for scope '" + _name + "': the scope does not allow locally administered MAC addresses.");

                    return null;
                }
            }

            Lease dummyOffer = new Lease(LeaseType.None, null, null, null, null, null, 0);
            var durableNativeOffer = _dhcpServer.Allocation?.NativeHolds(_name).SingleOrDefault(entry => entry.State == "Offer" && entry.Client == clientIdentifier.ToString());
            if (durableNativeOffer is not null && IsAddressInRange(AllocationSequence.Address(durableNativeOffer.Address)) && !IsAddressExcluded(AllocationSequence.Address(durableNativeOffer.Address)))
                return Lease.Recover(durableNativeOffer, false);
            Lease existingOffer = _offers.GetOrAdd(clientIdentifier, dummyOffer);

            if (dummyOffer != existingOffer)
            {
                if (existingOffer.Type == LeaseType.None)
                    return null; //dummy offer so another thread is handling offer; do nothing

                //offer already exists
                existingOffer.ExtendLease(GetLeaseTime());

                return _dhcpServer.ProvisioningAddressHeld?.Invoke(_name, existingOffer.Address) == true ? null : existingOffer;
            }

            //find offer ip address
            IPAddress offerAddress = null;

            if (request.RequestedIpAddress != null)
            {
                //client wish to get this address
                IPAddress requestedAddress = request.RequestedIpAddress.Address;

                if (IsAddressInRange(requestedAddress))
                {
                    AddressStatus addressStatus = await IsAddressAvailableAsync(requestedAddress);
                    if (addressStatus.IsAddressAvailable)
                        offerAddress = requestedAddress;
                }
            }

            if (offerAddress is null)
            {
                await _lastAddressOfferedLock.WaitAsync();
                try
                {
                    //find free address from scope
                    offerAddress = _lastAddressOffered;
                    uint endingAddressNumber = _endingAddress.ConvertIpToNumber();
                    bool offerAddressWasResetFromEnd = false;

                    while (true)
                    {
                        uint nextOfferAddressNumber = offerAddress.ConvertIpToNumber() + 1u;

                        if (nextOfferAddressNumber > endingAddressNumber)
                        {
                            if (offerAddressWasResetFromEnd)
                            {
                                _log.Write("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + " for scope '" + _name + "': address unavailable due to address pool exhaustion.");

                                return null;
                            }

                            offerAddress = IPAddressExtensions.ConvertNumberToIp(_startingAddress.ConvertIpToNumber() - 1u);
                            offerAddressWasResetFromEnd = true;
                            continue;
                        }

                        offerAddress = IPAddressExtensions.ConvertNumberToIp(nextOfferAddressNumber);

                        AddressStatus addressStatus = await IsAddressAvailableAsync(offerAddress);
                        if (addressStatus.IsAddressAvailable)
                            break;

                        if (addressStatus.NewAddress is not null)
                            offerAddress = addressStatus.NewAddress;
                    }

                    _lastAddressOffered = offerAddress;
                }
                finally
                {
                    _lastAddressOfferedLock.Release();
                }
            }

            Lease offerLease = new Lease(LeaseType.Dynamic, clientIdentifier, null, request.ClientHardwareAddress, offerAddress, null, GetLeaseTime());
            ProtectNativeOffer(offerLease);
            return _offers[clientIdentifier] = offerLease;
        }

        void ProtectNativeOffer(Lease offer)
        {
            _dhcpServer.Allocation?.ProtectNative(_name, new(AllocationSequence.Number(offer.Address), offer.ClientIdentifier.ToString(), BitConverter.ToString(offer.HardwareAddress), offer.HostName, "Offer", offer.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS)));
        }

        public AllocationPlan BuildAllocationPlan(string epoch, string seed, string[] owners, string algorithm = "interleaved-v1")
        {
            var excluded = (_exclusions ?? []).Select(e => new AllocationRange(AllocationSequence.Number(e.StartingAddress), AllocationSequence.Number(e.EndingAddress))).ToList();
            foreach (var address in new[] { _networkAddress, _broadcastAddress, _routerAddress }.Where(a => a is not null))
            { uint value = AllocationSequence.Number(address); excluded.Add(new(value, value)); }
            var reservations = _reservedLeases.Values.Select(l => new AllocationReservation(AllocationSequence.Number(l.Address), l.ClientIdentifier.ToString())).OrderBy(r => r.Address).ToArray();
            if (reservations.Length > 0 && !_ignoreClientIdentifierOption) throw new InvalidOperationException("Distributed reservations currently require hardware-based client identifiers.");
            foreach (var reservation in reservations) excluded.Add(new(reservation.Address, reservation.Address));
            return new(_name, epoch, AllocationSequence.Number(_startingAddress), AllocationSequence.Number(_endingAddress), seed, owners.Order(StringComparer.Ordinal).ToArray(), excluded.OrderBy(e => e.First).ThenBy(e => e.Last).ToArray(), AllocationSequence.Number(_subnetMask), reservations, Algorithm: algorithm);
        }
        internal bool MatchesAllocationPlan(AllocationPlan plan)
        { return System.Text.Json.JsonSerializer.Serialize(plan with { Configuration = null, HaGroups = null, Pins = null }, DistributedAllocation.JsonOptions) == System.Text.Json.JsonSerializer.Serialize(BuildAllocationPlan(plan.Epoch, plan.Seed, plan.Owners, plan.Algorithm), DistributedAllocation.JsonOptions); }
        public int DistributedOfferDelayMilliseconds
        {
            get
            {
                var plan = _dhcpServer.Allocation?.Plan(_name); var groups = plan?.HaGroups ?? [];
                for (int index = 0; index < groups.Length; index++)
                {
                    if (groups[index].Primary == _dhcpServer.Allocation.NodeName()) return index * 1500;
                    if (groups[index].Secondary == _dhcpServer.Allocation.NodeName()) return index * 1500 + 500;
                }
                return groups.Length == 0 ? 0 : groups.Length * 1500;
            }
        }
        public bool CanInitializeAllocation => !_enabled && _leases.Count == 0 && _offers.Count == 0;
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        internal bool TryEnterServingRequest()
        {
            lock (_requestGate)
            {
                if (_migrationCapturing || _dhcpServer.Allocation?.BootstrapPending(_name) == true) return false;
                _servingRequests++; return true;
            }
        }
        internal void ExitServingRequest()
        { lock (_requestGate) { if (--_servingRequests == 0) _requestsDrained?.TrySetResult(); } }
        internal bool MigrationCapturing { get { lock (_requestGate) return _migrationCapturing; } }
        sealed class AdministrativeChange : IDisposable
        {
            Scope _scope;
            public AdministrativeChange(Scope scope) => _scope = scope;
            public void Dispose() => Interlocked.Exchange(ref _scope, null)?.ExitServingRequest();
        }
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        // Drain supported native/API requests before committing an IPAM hold. Once released,
        // allocator eligibility consults that durable hold; no synthetic lease is created.
        sealed class ProvisioningApprovalGuard : IDisposable
        {
            Scope _scope;
            public ProvisioningApprovalGuard(Scope scope) => _scope = scope;
            public void Dispose()
            {
                var scope = Interlocked.Exchange(ref _scope, null);
                if (scope is not null) lock (scope._requestGate) { scope._migrationCapturing = false; scope._requestsDrained = null; }
            }
        }
        internal async Task<IDisposable> BeginProvisioningApprovalAsync(CancellationToken cancellationToken)
        {
            Task drained;
            lock (_requestGate)
            {
                if (_migrationCapturing || _dhcpServer.Allocation?.BootstrapPending(_name) == true)
                    throw new InvalidOperationException("Another scope change is in progress. Retry approval after it completes.");
                _migrationCapturing = true;
                drained = _servingRequests == 0 ? Task.CompletedTask : (_requestsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
            }
            var guard = new ProvisioningApprovalGuard(this);
            try { await drained.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken); return guard; }
            catch { guard.Dispose(); throw; }
        }
        internal IDisposable BeginAdministrativeChange()
        {
            if (!TryEnterServingRequest()) throw new InvalidOperationException("DHCP ownership migration is in progress; retry after it commits.");
            return new AdministrativeChange(this);
        }
        internal async Task<AllocationNativeSnapshot> CaptureNativeAllocationAsync(string node, CancellationToken cancellationToken,
            Func<AllocationNativeSnapshot, Task> prepare = null)
        {
            Task drained;
            lock (_requestGate)
            {
                if (_enabled || _migrationCapturing) throw new InvalidOperationException("Pause this DHCP scope before capturing live allocation ownership.");
                _migrationCapturing = true;
                drained = _servingRequests == 0 ? Task.CompletedTask : (_requestsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
            }
            try
            {
                await drained.WaitAsync(cancellationToken);
                AllocationNativeSnapshot snapshot;
                await _lastAddressOfferedLock.WaitAsync(cancellationToken);
                try
                {
                    using var config = new MemoryStream(); WriteTo(config, false, false);
                    var leases = _leases.Values.Select(l => new AllocationEntry(AllocationSequence.Number(l.Address), l.ClientIdentifier.ToString(), BitConverter.ToString(l.HardwareAddress), l.HostName, "Lease", l.LeaseExpires));
                    var offers = _offers.Values.Where(l => l.Address is not null && l.ClientIdentifier is not null).Select(l => new AllocationEntry(AllocationSequence.Number(l.Address), l.ClientIdentifier.ToString(), BitConverter.ToString(l.HardwareAddress), l.HostName, "Offer", l.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS))).ToArray();
                    _dhcpServer.Allocation?.ProtectNativeOffers(_name, offers);
                    _dhcpServer.SaveScope(_name);
                    snapshot = new(node, _name, Convert.ToBase64String(config.ToArray()), leases.Concat(offers).Concat(_dhcpServer.Allocation?.NativeHolds(_name) ?? []).OrderBy(e => e.Address).ThenBy(e => e.Client, StringComparer.Ordinal).ThenBy(e => e.State, StringComparer.Ordinal).ToArray());
                }
                finally { _lastAddressOfferedLock.Release(); }
                cancellationToken.ThrowIfCancellationRequested();
                if (prepare is not null) await prepare(snapshot); // Keep admission closed through the durable transition; never hold this guard across peer network I/O.
                return snapshot;
            }
            finally { lock (_requestGate) { _migrationCapturing = false; _requestsDrained = null; } }
        }
        internal async Task ApplySharedOptionsAsync(Scope source, AllocationPlan plan, Action validate = null, bool replaceEligibility = false)
        {
            if (!source.MatchesAllocationPlan(plan)) throw new InvalidOperationException("Configuration changes allocation eligibility; fenced migration required.");
            await _lastAddressOfferedLock.WaitAsync();
            try
            {
                validate?.Invoke();
                if (replaceEligibility)
                { ChangeNetwork(source.StartingAddress, source.EndingAddress, source.SubnetMask, true); _reservedLeases.Clear(); }
                _leaseTimeDays = source._leaseTimeDays; _leaseTimeHours = source._leaseTimeHours; _leaseTimeMinutes = source._leaseTimeMinutes; _offerDelayTime = source._offerDelayTime;
                _pingCheckEnabled = source._pingCheckEnabled; _pingCheckTimeout = source._pingCheckTimeout; _pingCheckRetries = source._pingCheckRetries;
                _domainName = source._domainName; _domainSearchList = source._domainSearchList;
                _dnsUpdates = source._dnsUpdates; _dnsOverwriteForDynamicLease = source._dnsOverwriteForDynamicLease; _dnsTtl = source._dnsTtl;
                _serverAddress = source._serverAddress; _serverHostName = source._serverHostName; _bootFileName = source._bootFileName;
                _routerAddress = source._routerAddress; _useThisDnsServer = source._useThisDnsServer; _dnsServers = source._dnsServers;
                _winsServers = source._winsServers; _ntpServers = source._ntpServers; _ntpServerDomainNames = source._ntpServerDomainNames;
                _staticRoutes = source._staticRoutes; _vendorInfo = source._vendorInfo; _capwapAcIpAddresses = source._capwapAcIpAddresses; _tftpServerAddreses = source._tftpServerAddreses; _genericOptions = source._genericOptions;
                _allowOnlyReservedLeases = source._allowOnlyReservedLeases; _blockLocallyAdministeredMacAddresses = source._blockLocallyAdministeredMacAddresses; _ignoreClientIdentifierOption = source._ignoreClientIdentifierOption;
                _exclusions = source._exclusions;
                foreach (var reserved in source._reservedLeases) _reservedLeases[reserved.Key] = reserved.Value;
                if (_useThisDnsServer) FindThisDnsServerAddress();
                _lastModified = DateTime.UtcNow; // serving enablement and local interface selection remain local
            }
            finally { _lastAddressOfferedLock.Release(); }
        }
        internal bool CanRespondToDistributedRequest(IPAddress address)
        {
            var plan = _dhcpServer.Allocation?.Plan(_name);
            return plan is null || MatchesAllocationPlan(plan) && _dhcpServer.Allocation.HasAuthority(_name, AllocationSequence.Number(address));
        }
        internal bool HasRetainedBinding(IPAddress address, string client = null)
        {
            var store = _dhcpServer.Allocation;
            uint value = AllocationSequence.Number(address);
            if (store?.Plan(_name)?.Pins?.Any(p => p.Address == value && p.Client is not null && (client is null || p.Client == client)) != true) return false;
            return store.LiveLeases(_name).Any(d => d.Lease.Address == value && (client is null || d.Lease.Client == client)) ||
                client is not null && store.FindOffer(_name, client)?.Address == value;
        }
        internal async Task ApplyOwnershipChangeAsync(Scope source, AllocationPlan plan, Action validate)
        {
            if (_enabled || !_dhcpServer.Allocation.ChangePending(_name) || source.Enabled || source.Name != _name || !source.MatchesAllocationPlan(plan)) throw new InvalidOperationException("Apply reviewed ownership only to a frozen, paused scope.");
            await ApplySharedOptionsAsync(source, plan, validate, true);
        }
        string TransactionKey(DhcpMessage request) => request.GetClientIdentifier(_ignoreClientIdentifierOption).ToString() + ":" + Convert.ToHexString(request.TransactionId);
        bool PeerSelected(DhcpMessage request) => _peerSelections.TryGetValue(TransactionKey(request), out var until) && until > DateTime.UtcNow;
        internal void ObservePeerSelection(DhcpMessage request)
        {
            if (_dhcpServer.Allocation?.Plan(_name) is null) return;
            _peerSelections[TransactionKey(request)] = DateTime.UtcNow.AddSeconds(OFFER_EXPIRY_SECONDS);
            foreach (var old in _peerSelections.Where(p => p.Value <= DateTime.UtcNow)) _peerSelections.TryRemove(old.Key, out _);
            if (_peerSelections.Count > 4096) _peerSelections.TryRemove(_peerSelections.MinBy(p => p.Value).Key, out _);
            var client = request.GetClientIdentifier(_ignoreClientIdentifierOption);
            _offers.TryRemove(client, out _); _dhcpServer.Allocation.ReleaseOffer(_name, client.ToString());
            Interlocked.Exchange(ref _overflowRequestedTicks, 0);
        }

        long _overflowRequestedTicks;
        public DateTime? OverflowRequestedUtc { get { long ticks = Interlocked.Read(ref _overflowRequestedTicks); return ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc); } }
        async Task<Lease> GetDistributedOfferAsync(DhcpMessage request, ClientIdentifierOption clientIdentifier)
        {
            var store = _dhcpServer.Allocation; var plan = store.Plan(_name);
            if (store.RecoveryRequired || store.BootstrapPending(_name)) return null;
            if (PeerSelected(request)) return null;
            if (!MatchesAllocationPlan(plan)) throw new InvalidOperationException("Scope differs from its immutable allocation plan; service withheld.");
            if (!plan.Owners.Contains(store.NodeName())) return null;
            string client = clientIdentifier.ToString();
            await _lastAddressOfferedLock.WaitAsync();
            try
            {
                if (store.BootstrapPending(_name) || store.Plan(_name).Epoch != plan.Epoch || !MatchesAllocationPlan(plan)) return null;
                var reserved = GetReservedLease(request);
                if (reserved is null && _blockLocallyAdministeredMacAddresses && request.HardwareAddressType == DhcpMessageHardwareAddressType.Ethernet && (request.ClientHardwareAddress[0] & 2) != 0) return null;
                var existing = store.FindLease(_name, client);
                if (existing is not null) return Lease.Recover(existing, reserved?.Address.Equals(AllocationSequence.Address(existing.Address)) == true);
                if (reserved is not null)
                {
                    if (!store.Hold(_name, AllocationSequence.Number(reserved.Address), client, BitConverter.ToString(request.ClientHardwareAddress), request.HostName?.HostName, DateTime.UtcNow.AddSeconds(OFFER_EXPIRY_SECONDS))) return null;
                    return _offers[clientIdentifier] = new(LeaseType.Reserved, clientIdentifier, null, request.ClientHardwareAddress, reserved.Address, null, GetLeaseTime());
                }
                if (_allowOnlyReservedLeases || _blockLocallyAdministeredMacAddresses && request.HardwareAddressType == DhcpMessageHardwareAddressType.Ethernet && (request.ClientHardwareAddress[0] & 2) != 0) return null;
                var recoveredOffer = store.FindOffer(_name, client);
                if (recoveredOffer is not null)
                {
                    store.Hold(_name, recoveredOffer.Address, client, recoveredOffer.Hardware, recoveredOffer.Host, DateTime.UtcNow.AddSeconds(OFFER_EXPIRY_SECONDS));
                    return _offers[clientIdentifier] = Lease.Recover(recoveredOffer, false);
                }
                var sequence = new AllocationSequence(plan);
                async Task<Lease> TryAddress(uint candidate)
                {
                    if (!store.Available(_name, candidate, client)) return null;
                    IPAddress address = AllocationSequence.Address(candidate);
                    if (!(await IsAddressAvailableAsync(address)).IsAddressAvailable) return null;
                    // Durability precedes the offer; ACKs persist the full lease lifetime separately.
                    if (PeerSelected(request) || !store.Hold(_name, candidate, client, BitConverter.ToString(request.ClientHardwareAddress), request.HostName?.HostName, DateTime.UtcNow.AddSeconds(OFFER_EXPIRY_SECONDS))) return null;
                    if (PeerSelected(request)) { store.ReleaseOffer(_name, client); return null; }
                    Interlocked.Exchange(ref _overflowRequestedTicks, 0);
                    return _offers[clientIdentifier] = new(LeaseType.Dynamic, clientIdentifier, null, request.ClientHardwareAddress, address, null, GetLeaseTime());
                }
                if (request.RequestedIpAddress is not null && sequence.Owner(AllocationSequence.Number(request.RequestedIpAddress.Address)) == store.NodeName())
                { var preferred = await TryAddress(AllocationSequence.Number(request.RequestedIpAddress.Address)); if (preferred is not null) return preferred; }
                foreach (uint candidate in sequence.Candidates(store.NodeName()))
                { var selected = await TryAddress(candidate); if (selected is not null) return selected; }
                // Own sequence is exhausted. Previously acknowledged grants remain valid offline.
                foreach (uint granted in store.GrantedAddresses(_name))
                { var selected = await TryAddress(granted); if (selected is not null) return selected; }
                // The external fencing controller observes demand only after this
                // actual client request exhausted local and already-granted capacity.
                Interlocked.CompareExchange(ref _overflowRequestedTicks, DateTime.UtcNow.Ticks, 0);
                if (_dhcpServer.BorrowCapacity is not null)
                {
                    // Do not hold our scope mutex while asking another owner to lock its scope.
                    _lastAddressOfferedLock.Release();
                    byte[] donorState;
                    try { donorState = await _dhcpServer.BorrowCapacity(_name, store.NodeName()); }
                    finally { await _lastAddressOfferedLock.WaitAsync(); }
                    if (donorState is not null) store.Merge(donorState);
                    // A release may have made local capacity available while donor I/O
                    // ran outside the mutex. Prefer that capacity before overflow.
                    foreach (uint candidate in sequence.Candidates(store.NodeName()))
                    { var selected = await TryAddress(candidate); if (selected is not null) return selected; }
                    // A fenced recovery can arrive through another session while
                    // donor I/O is in flight, including when that I/O returns null.
                    foreach (uint granted in store.GrantedAddresses(_name))
                    { var selected = await TryAddress(granted); if (selected is not null) return selected; }
                }
                return null;
            }
            finally { _lastAddressOfferedLock.Release(); }
        }
        public async Task<byte[]> GrantCapacityAsync(string borrower, string requestId)
        {
            await _lastAddressOfferedLock.WaitAsync();
            try
            {
                var store = _dhcpServer.Allocation; var plan = store?.Plan(_name);
                if (plan is null || !MatchesAllocationPlan(plan)) throw new InvalidOperationException("Matching allocation plan is required.");
                // Retrying a lost response must return the same permanent donor hold.
                if (store.Snapshot().Replicas.Any(r => r.Scope == _name && r.Node == store.NodeName() && (r.Entries.Any(e => e.State == "Grant" && e.GrantId == requestId && e.Borrower == borrower) || (r.GrantReclaims ?? []).Any(x => x.Grant.GrantId == requestId && x.Grant.Borrower == borrower)))) return store.Export();
                foreach (uint address in new AllocationSequence(plan).Candidates(store.NodeName()))
                    if (!store.IsRetiredGrant(_name, address) && store.Available(_name, address) && (await IsAddressAvailableAsync(AllocationSequence.Address(address))).IsAddressAvailable)
                    { store.Grant(_name, address, borrower, requestId); return store.Export(); }
                return null;
            }
            finally { _lastAddressOfferedLock.Release(); }
        }

        internal Lease GetExistingLeaseOrOffer(DhcpMessage request)
        {
            if (_dhcpServer.Allocation?.ProtectedByOtherPlan(_name, AllocationSequence.Number(_startingAddress), AllocationSequence.Number(_endingAddress)) == true) return null;
            ClientIdentifierOption clientIdentifier = request.GetClientIdentifier(_ignoreClientIdentifierOption);

            var allocation = _dhcpServer.Allocation;
            var plan = allocation?.Plan(_name);
            if (plan is not null)
            {
                if (!MatchesAllocationPlan(plan)) return null;
                var recovered = allocation.FindLease(_name, clientIdentifier.ToString());
                if (recovered is not null) return Lease.Recover(recovered, GetReservedLease(request)?.Address.Equals(AllocationSequence.Address(recovered.Address)) == true);
                var recoveredOffer = allocation.FindOffer(_name, clientIdentifier.ToString());
                if (recoveredOffer is not null) return Lease.Recover(recoveredOffer, GetReservedLease(request)?.Address.Equals(AllocationSequence.Address(recoveredOffer.Address)) == true);
                if (_offers.TryGetValue(clientIdentifier, out var durableOffer) && durableOffer.Address is not null && allocation.HasLiveOffer(_name, AllocationSequence.Number(durableOffer.Address), clientIdentifier.ToString())) return durableOffer;
                return null;
            }

            var native = allocation?.NativeHolds(_name).Where(e => e.Client == clientIdentifier.ToString() && (e.State == "Lease" || e.State == "Offer")).OrderByDescending(e => e.State == "Offer").ThenByDescending(e => e.Expires).FirstOrDefault();
            if (native is not null) return Lease.Recover(native, IsAddressReserved(AllocationSequence.Address(native.Address)));

            //check for lease offer first since it may have a different IP address to offer
            if (_offers.TryGetValue(clientIdentifier, out Lease existingOffer))
                return existingOffer;

            if (_leases.TryGetValue(clientIdentifier, out Lease existingLease))
                return existingLease;

            return null;
        }

        internal void RecoverNativeLeases(DistributedAllocation allocation)
        {
            if (allocation?.Plan(_name) is not null) return;
            foreach (var entry in allocation?.NativeHolds(_name).Where(entry => entry.State == "Lease") ?? [])
            {
                var recovered = Lease.Recover(entry, IsAddressReserved(AllocationSequence.Address(entry.Address)));
                if (!_leases.TryGetValue(recovered.ClientIdentifier, out var existing) || existing.LeaseExpires < recovered.LeaseExpires)
                    _leases[recovered.ClientIdentifier] = recovered;
            }
        }

        internal async Task<List<DhcpOption>> GetOptionsAsync(DhcpMessage request, IPAddress serverIdentifierAddress, string reservedLeaseHostName, DnsServer dnsServer)
        {
            List<DhcpOption> options = new List<DhcpOption>();

            switch (request.DhcpMessageType.Type)
            {
                case DhcpMessageType.Discover:
                    options.Add(new DhcpMessageTypeOption(DhcpMessageType.Offer));
                    break;

                case DhcpMessageType.Request:
                case DhcpMessageType.Inform:
                    options.Add(new DhcpMessageTypeOption(DhcpMessageType.Ack));
                    break;

                default:
                    return null;
            }

            options.Add(new ServerIdentifierOption(serverIdentifierAddress));

            switch (request.DhcpMessageType.Type)
            {
                case DhcpMessageType.Discover:
                case DhcpMessageType.Request:
                    uint leaseTime = GetLeaseTime();

                    options.Add(new IpAddressLeaseTimeOption(leaseTime));
                    options.Add(new RenewalTimeValueOption(leaseTime / 2));
                    options.Add(new RebindingTimeValueOption(Convert.ToUInt32(leaseTime * 0.875)));
                    break;
            }

            if (request.ParameterRequestList is null)
            {
                options.Add(new SubnetMaskOption(_subnetMask));
                options.Add(new BroadcastAddressOption(_broadcastAddress));

                if (!string.IsNullOrEmpty(_domainName))
                {
                    options.Add(new DomainNameOption(_domainName));

                    if (request.ClientFullyQualifiedDomainName != null)
                        options.Add(GetClientFullyQualifiedDomainNameOption(request, reservedLeaseHostName));
                }

                if (_domainSearchList is not null)
                    options.Add(new DomainSearchOption(_domainSearchList));

                if (_routerAddress is not null)
                    options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                if (_dnsServers is not null)
                    options.Add(new DomainNameServerOption(_dnsServers));

                if (_winsServers is not null)
                    options.Add(new NetBiosNameServerOption(_winsServers));

                if ((_ntpServers is not null) || (_ntpServerDomainNames is not null))
                    options.Add(await GetNetworkTimeProtocolServersOptionAsync(dnsServer));

                if (_staticRoutes is not null)
                    options.Add(new ClasslessStaticRouteOption(_staticRoutes));
            }
            else
            {
                foreach (DhcpOptionCode optionCode in request.ParameterRequestList.OptionCodes)
                {
                    switch (optionCode)
                    {
                        case DhcpOptionCode.SubnetMask:
                            options.Add(new SubnetMaskOption(_subnetMask));
                            options.Add(new BroadcastAddressOption(_broadcastAddress));
                            break;

                        case DhcpOptionCode.HostName:
                            if (!string.IsNullOrWhiteSpace(reservedLeaseHostName))
                                options.Add(new HostNameOption(reservedLeaseHostName));

                            break;

                        case DhcpOptionCode.DomainName:
                            if (!string.IsNullOrEmpty(_domainName))
                            {
                                options.Add(new DomainNameOption(_domainName));

                                if (request.ClientFullyQualifiedDomainName != null)
                                    options.Add(GetClientFullyQualifiedDomainNameOption(request, reservedLeaseHostName));
                            }

                            break;

                        case DhcpOptionCode.DomainSearch:
                            if (_domainSearchList is not null)
                                options.Add(new DomainSearchOption(_domainSearchList));

                            break;

                        case DhcpOptionCode.Router:
                            if (_routerAddress is not null)
                                options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                            break;

                        case DhcpOptionCode.DomainNameServer:
                            if (_dnsServers is not null)
                                options.Add(new DomainNameServerOption(_dnsServers));

                            break;

                        case DhcpOptionCode.NetBiosOverTcpIpNameServer:
                            if (_winsServers is not null)
                                options.Add(new NetBiosNameServerOption(_winsServers));

                            break;

                        case DhcpOptionCode.NetworkTimeProtocolServers:
                            if ((_ntpServers is not null) || (_ntpServerDomainNames is not null))
                                options.Add(await GetNetworkTimeProtocolServersOptionAsync(dnsServer));

                            break;

                        case DhcpOptionCode.ClasslessStaticRoute:
                            if (_staticRoutes is not null)
                                options.Add(new ClasslessStaticRouteOption(_staticRoutes));

                            break;

                        case DhcpOptionCode.CAPWAPAccessControllerAddresses:
                            if (_capwapAcIpAddresses is not null)
                                options.Add(new CAPWAPAccessControllerOption(_capwapAcIpAddresses));

                            break;

                        case DhcpOptionCode.TftpServerAddress:
                            if (_tftpServerAddreses is not null)
                                options.Add(new TftpServerAddressOption(_tftpServerAddreses));

                            break;

                        default:
                            if (_genericOptions is not null)
                            {
                                foreach (DhcpOption genericOption in _genericOptions)
                                {
                                    if (optionCode == genericOption.Code)
                                    {
                                        options.Add(genericOption);
                                        break;
                                    }
                                }
                            }

                            break;
                    }
                }
            }

            if ((_vendorInfo is not null) && (request.VendorClassIdentifier is not null))
            {
                if (_vendorInfo.TryGetValue(request.VendorClassIdentifier.Identifier, out VendorSpecificInformationOption vendorSpecificInformationOption) || _vendorInfo.TryGetValue("", out vendorSpecificInformationOption))
                {
                    options.Add(new VendorClassIdentifierOption(request.VendorClassIdentifier.Identifier));
                    options.Add(vendorSpecificInformationOption);
                }
                else
                {
                    string match = "substring(vendor-class-identifier,";

                    foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in _vendorInfo)
                    {
                        if (entry.Key.StartsWith(match, StringComparison.Ordinal))
                        {
                            int i = entry.Key.IndexOf(')', match.Length);
                            if (i < match.Length)
                                continue;

                            string[] parts = entry.Key.Substring(match.Length, i - match.Length).Split(',');

                            if (parts.Length != 2)
                                continue;

                            if (!int.TryParse(parts[0], out int startIndex))
                                continue;

                            if (!int.TryParse(parts[1], out int length))
                                continue;

                            if ((startIndex + length) > request.VendorClassIdentifier.Identifier.Length)
                                continue;

                            int j = entry.Key.IndexOf("==", i);
                            if (j < i)
                                continue;

                            string value = entry.Key.Substring(j + 2);
                            value = value.Trim();
                            value = value.Trim('"');

                            if (request.VendorClassIdentifier.Identifier.Substring(startIndex, length).Equals(value, StringComparison.Ordinal))
                            {
                                options.Add(new VendorClassIdentifierOption(value));
                                options.Add(entry.Value);
                                break;
                            }
                        }
                    }
                }
            }

            options.Add(DhcpOption.CreateEndOption());

            return options;
        }

        private async Task<NetworkTimeProtocolServersOption> GetNetworkTimeProtocolServersOptionAsync(DnsServer dnsServer)
        {
            if (_ntpServerDomainNames is not null)
            {
                Task<DnsDatagram>[] tasks = new Task<DnsDatagram>[_ntpServerDomainNames.Count];
                int i = 0;

                foreach (string ntpServerDomainName in _ntpServerDomainNames)
                    tasks[i++] = dnsServer.DirectQueryAsync(new DnsQuestionRecord(ntpServerDomainName, DnsResourceRecordType.A, DnsClass.IN), 1000);

                List<IPAddress> ntpServers = new List<IPAddress>(_ntpServerDomainNames.Count + (_ntpServers is null ? 0 : _ntpServers.Count));

                if (_ntpServers is not null)
                    ntpServers.AddRange(_ntpServers);

                foreach (Task<DnsDatagram> task in tasks)
                {
                    try
                    {
                        ntpServers.AddRange(DnsClient.ParseResponseA(await task));
                    }
                    catch
                    { }
                }

                return new NetworkTimeProtocolServersOption(ntpServers);
            }
            else
            {
                return new NetworkTimeProtocolServersOption(_ntpServers);
            }
        }

        internal void CommitLease(Lease lease)
        {
            if (_dhcpServer.ProvisioningAddressHeld?.Invoke(_name, lease.Address) == true) throw new InvalidOperationException("Address is held by pending IPAM provisioning.");
            if (_dhcpServer.Allocation?.ProtectedByOtherPlan(_name, AllocationSequence.Number(_startingAddress), AllocationSequence.Number(_endingAddress)) == true) throw new InvalidOperationException("Scope overlaps distributed ownership.");
            var plan = _dhcpServer.Allocation?.Plan(_name);
            var authority = _dhcpServer.Allocation?.FindLease(_name, lease.ClientIdentifier.ToString());
            bool existingLease = plan is null ? _leases.TryGetValue(lease.ClientIdentifier, out var prior) && prior.LeaseExpires > DateTime.UtcNow && prior.Address.Equals(lease.Address) : authority is not null && authority.Address == AllocationSequence.Number(lease.Address);
            if (_dhcpServer.SecurityManager?.DenyDhcpCommit(_name, lease.ClientIdentifier.ToString(), BitConverter.ToString(lease.HardwareAddress), lease.HostName, existingLease) == true) throw new InvalidOperationException("Shared security policy withheld a new lease acknowledgement.");

            if (plan is not null)
            {
                if (!MatchesAllocationPlan(plan)) throw new InvalidOperationException("Scope differs from its immutable allocation plan.");
                _dhcpServer.Allocation.Commit(_name, AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString(), BitConverter.ToString(lease.HardwareAddress), lease.HostName, DateTime.UtcNow.AddSeconds(GetLeaseTime()));
            }
            if (plan is null && _dhcpServer.Allocation?.NativeProtected(_name, AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString()) == true) throw new InvalidOperationException("Native lease conflicts with durable protection.");
            DateTime acknowledgedUntil = lease.LeaseExpires;
            lease.ExtendLease(GetLeaseTime());
            if (lease.LeaseExpires < acknowledgedUntil) lease.PreserveExpiry(acknowledgedUntil);
            if (plan is null)
            {
                _dhcpServer.Allocation?.ProtectNative(_name, new(AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString(), BitConverter.ToString(lease.HardwareAddress), lease.HostName, "Lease", lease.LeaseExpires));
                var durable = _dhcpServer.Allocation?.NativeHolds(_name).SingleOrDefault(e => e.Address == AllocationSequence.Number(lease.Address));
                if (durable is not null) lease.PreserveExpiry(durable.Expires);
            }

            _leases[lease.ClientIdentifier] = lease;
            _dhcpServer.SecurityManager?.DeviceContextChanged?.Invoke();
            _offers.TryRemove(lease.ClientIdentifier, out _);

            _dhcpServer.AddDnsEntries(this, lease);

            _lastModified = DateTime.UtcNow;
        }

        internal void ReleaseLease(Lease lease)
        {
            Interlocked.Exchange(ref _overflowRequestedTicks, 0);
            if (_dhcpServer.Allocation?.Plan(_name) is not null)
                _dhcpServer.Allocation.Release(_name, AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString());
            else
                _dhcpServer.Allocation?.ReleaseNative(_name, AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString());
            _leases.TryRemove(lease.ClientIdentifier, out _);
            _offers.TryRemove(lease.ClientIdentifier, out _);
            _dhcpServer.SecurityManager?.DeviceContextChanged?.Invoke();

            _dhcpServer.RemoveDnsEntries(this, lease);

            _lastModified = DateTime.UtcNow;
        }
        internal void DeclineLease(Lease lease)
        {
            if (_dhcpServer.Allocation?.Plan(_name) is null)
            {
                _dhcpServer.Allocation?.ProtectNative(_name, new(AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString(), BitConverter.ToString(lease.HardwareAddress), lease.HostName, "Declined", DateTime.UtcNow.AddMinutes(10)));
                ReleaseLease(lease); return;
            }
            _dhcpServer.Allocation.Decline(_name, AllocationSequence.Number(lease.Address), lease.ClientIdentifier.ToString());
            _leases.TryRemove(lease.ClientIdentifier, out _); _offers.TryRemove(lease.ClientIdentifier, out _);
            _dhcpServer.SecurityManager?.DeviceContextChanged?.Invoke();
            _dhcpServer.SecurityManager?.ObserveDhcpConflict(_name, lease.ClientIdentifier.ToString(), BitConverter.ToString(lease.HardwareAddress), lease.HostName, lease.Address.ToString());
            _dhcpServer.RemoveDnsEntries(this, lease); _lastModified = DateTime.UtcNow;
        }

        internal void SetEnabled(bool enabled)
        {
            lock (_requestGate)
            {
                if (enabled && (_migrationCapturing || _dhcpServer.Allocation?.BootstrapPending(_name) == true)) throw new InvalidOperationException("Commit the prepared ownership migration before activating DHCP.");
                _enabled = enabled;
                if (!enabled)
                {
                    _interfaceAddress = null;
                    _interfaceIndex = 0;
                }
            }
        }

        internal void RemoveExpiredOffers()
        {
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (utcNow > offer.Value.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS))
                {
                    //offer expired
                    _offers.TryRemove(offer.Key, out _);
                }
            }
        }

        internal int RemoveExpiredLeases()
        {
            int expiredLeases = 0;
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (utcNow > lease.Value.LeaseExpires)
                {
                    //lease expired
                    if (_leases.TryRemove(lease.Key, out Lease expiredLease))
                    {
                        expiredLeases++;
                        _dhcpServer.RemoveDnsEntries(this, expiredLease);
                    }
                }
            }

            if (expiredLeases > 0)
                _lastModified = utcNow;

            return expiredLeases;
        }

        #endregion

        #region public

        public void ChangeNetwork(IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask)
            => ChangeNetwork(startingAddress, endingAddress, subnetMask, false);
        void ChangeNetwork(IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask, bool offerLockHeld)
        {
            if (startingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("The address must be an IPv4 address: " + startingAddress.ToString(), nameof(startingAddress));

            if (endingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("The address must be an IPv4 address: " + endingAddress.ToString(), nameof(endingAddress));

            if (subnetMask.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("The address must be an IPv4 address: " + subnetMask.ToString(), nameof(subnetMask));

            uint startingAddressNumber = startingAddress.ConvertIpToNumber();
            uint endingAddressNumber = endingAddress.ConvertIpToNumber();

            if (startingAddressNumber >= endingAddressNumber)
                throw new ArgumentException("Ending address must be greater than starting address.");

            _startingAddress = startingAddress;
            _endingAddress = endingAddress;
            _subnetMask = subnetMask;

            //compute other parameters
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();
            uint networkAddressNumber = startingAddressNumber & subnetMaskNumber;
            uint broadcastAddressNumber = networkAddressNumber | ~subnetMaskNumber;

            if (networkAddressNumber == startingAddressNumber)
                throw new ArgumentException("Starting address cannot be same as the network address.");

            if (broadcastAddressNumber == endingAddressNumber)
                throw new ArgumentException("Ending address cannot be same as the broadcast address.");

            _networkAddress = IPAddressExtensions.ConvertNumberToIp(networkAddressNumber);
            _broadcastAddress = IPAddressExtensions.ConvertNumberToIp(broadcastAddressNumber);

            if (!offerLockHeld) _lastAddressOfferedLock.Wait();
            try
            {
                _lastAddressOffered = IPAddressExtensions.ConvertNumberToIp(startingAddressNumber - 1u);
            }
            finally
            {
                if (!offerLockHeld) _lastAddressOfferedLock.Release();
            }
        }
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        internal bool ProvisionReservation(Lease desired, string marker, bool remove)
        {
            _lastAddressOfferedLock.Wait();
            try
            {
                lock (_provisioningReservationSync)
                {
                    if (_dnsUpdates || _dhcpServer.Allocation?.Plan(_name) is not null || _dhcpServer.Allocation?.BootstrapPending(_name) == true || _dhcpServer.Allocation?.ProtectedByOtherPlan(_name, AllocationSequence.Number(_startingAddress), AllocationSequence.Number(_endingAddress)) == true || _dhcpServer.Allocation?.NativeProtected(_name, AllocationSequence.Number(desired.Address), desired.ClientIdentifier.ToString()) == true || !IsAddressInRange(desired.Address) || IsAddressExcluded(desired.Address))
                        throw new InvalidOperationException("Provisioning requires an unshared local scope with DNS updates disabled and an eligible in-range address.");
                    if (_reservedLeases.TryGetValue(desired.ClientIdentifier, out var current))
                    {
                        lock (current)
                        {
                            if (!current.Address.Equals(desired.Address) || current.HostName != desired.HostName || current.Comments != marker) return false;
                            if (remove && (_leases.Values.Any(l => l.Address.Equals(desired.Address) || l.ClientIdentifier.Equals(desired.ClientIdentifier)) || _offers.Values.Any(l => desired.Address.Equals(l.Address) || desired.ClientIdentifier.Equals(l.ClientIdentifier)))) return false;
                            return !remove || ((ICollection<KeyValuePair<ClientIdentifierOption, Lease>>)_reservedLeases).Remove(new(desired.ClientIdentifier, current));
                        }
                    }
                    if (remove) return true;
                    if (_reservedLeases.Values.Any(l => l.Address.Equals(desired.Address)) || _leases.Values.Any(l => l.Address.Equals(desired.Address) || l.ClientIdentifier.Equals(desired.ClientIdentifier)) || _offers.Values.Any(l => desired.Address.Equals(l.Address) || desired.ClientIdentifier.Equals(l.ClientIdentifier))) return false;
                    return _reservedLeases.TryAdd(desired.ClientIdentifier, desired);
                }
            }
            finally { _lastAddressOfferedLock.Release(); }
        }
        readonly object _provisioningReservationSync = new object();

        public bool TryAddReservedLease(Lease reservedLease)
        {
            lock (_provisioningReservationSync)
            {
            if (_reservedLeases.TryAdd(reservedLease.ClientIdentifier, reservedLease))
            {
                _dhcpServer.AddDnsEntries(this, reservedLease);

                return true;
            }

            return false;
            }
        }

        public bool TryRemoveReservedLease(string hardwareAddress)
        {
            lock (_provisioningReservationSync)
            {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);
            ClientIdentifierOption reservedLeaseClientIdentifier = new ClientIdentifierOption((byte)DhcpMessageHardwareAddressType.Ethernet, hardwareAddressBytes);

            if (_reservedLeases.TryRemove(reservedLeaseClientIdentifier, out Lease removedLease))
            {
                _dhcpServer.RemoveDnsEntries(this, removedLease, true);

                return true;
            }

            return false;
            }
        }

        public Lease RemoveLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                if (entry.Value.HardwareAddress.SequenceEqual(hardwareAddressBytes))
                    return RemoveLease(entry.Key);
            }

            throw new DhcpServerException("No lease was found for hardware address: " + hardwareAddress);
        }

        public Lease RemoveLease(ClientIdentifierOption clientIdentifier)
        {
            if (!_leases.TryRemove(clientIdentifier, out Lease removedLease))
                throw new DhcpServerException("No lease was found for client identifier: " + clientIdentifier.ToString());
            if (_dhcpServer.Allocation?.Plan(_name) is null) _dhcpServer.Allocation?.ReleaseNative(_name, AllocationSequence.Number(removedLease.Address), removedLease.ClientIdentifier.ToString());

            if (removedLease.Type == LeaseType.Reserved)
            {
                //remove reserved lease
                ClientIdentifierOption reservedLeaseClientIdentifier = new ClientIdentifierOption((byte)DhcpMessageHardwareAddressType.Ethernet, removedLease.HardwareAddress);
                if (_reservedLeases.TryGetValue(reservedLeaseClientIdentifier, out Lease existingReservedLease))
                {
                    //remove reserved lease only if the IP addresses match
                    if (existingReservedLease.Address.Equals(removedLease.Address))
                    {
                        if (_reservedLeases.TryRemove(reservedLeaseClientIdentifier, out Lease removedExistingLease))
                        {
                            _dhcpServer.RemoveDnsEntries(this, removedLease, true); //remove DNS entries for allocated lease
                            _dhcpServer.RemoveDnsEntries(this, removedExistingLease, true); //remove DNS entries for reserved lease hostname, if any
                        }
                    }
                }
            }
            else
            {
                //remove DNS entries if any
                _dhcpServer.RemoveDnsEntries(this, removedLease);
            }

            return removedLease;
        }

        public void ConvertToReservedLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                Lease lease = entry.Value;

                if ((lease.Type == LeaseType.Dynamic) && lease.HardwareAddress.SequenceEqual(hardwareAddressBytes))
                {
                    ConvertToReservedLease(lease);
                    return;
                }
            }

            throw new DhcpServerException("No dynamic lease was found for hardware address: " + hardwareAddress);
        }

        public void ConvertToReservedLease(ClientIdentifierOption clientIdentifier)
        {
            if (!_leases.TryGetValue(clientIdentifier, out Lease lease) || (lease.Type != LeaseType.Dynamic))
                throw new DhcpServerException("No dynamic lease was found for client identifier: " + clientIdentifier.ToString());

            ConvertToReservedLease(lease);
        }

        public void ConvertToDynamicLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                Lease lease = entry.Value;

                if ((lease.Type == LeaseType.Reserved) && lease.HardwareAddress.SequenceEqual(hardwareAddressBytes))
                {
                    ConvertToDynamicLease(lease);
                    return;
                }
            }

            throw new DhcpServerException("No reserved lease was found for hardware address: " + hardwareAddress);
        }

        public void ConvertToDynamicLease(ClientIdentifierOption clientIdentifier)
        {
            if (!_leases.TryGetValue(clientIdentifier, out Lease lease) || (lease.Type != LeaseType.Reserved))
                throw new DhcpServerException("No reserved lease was found for client identifier: " + clientIdentifier.ToString());

            ConvertToDynamicLease(lease);
        }

        public void WriteTo(Stream s, bool includeLeases = true, bool? enabled = null)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("SC"));
            bW.Write((byte)10); //version

            s.WriteShortString(_name);
            bW.Write(enabled ?? _enabled);
            _startingAddress.WriteTo(bW);
            _endingAddress.WriteTo(bW);
            _subnetMask.WriteTo(bW);
            bW.Write(_leaseTimeDays);
            bW.Write(_leaseTimeHours);
            bW.Write(_leaseTimeMinutes);
            bW.Write(_offerDelayTime);

            bW.Write(_pingCheckEnabled);
            bW.Write(_pingCheckTimeout);
            bW.Write(_pingCheckRetries);

            if (string.IsNullOrWhiteSpace(_domainName))
                bW.Write((byte)0);
            else
                s.WriteShortString(_domainName);

            if (_domainSearchList is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_domainSearchList.Count));

                foreach (string domainSearchString in _domainSearchList)
                    s.WriteShortString(domainSearchString);
            }

            bW.Write(_dnsUpdates);
            bW.Write(_dnsOverwriteForDynamicLease);
            bW.Write(_dnsTtl);

            if (_serverAddress is null)
                IPAddress.Any.WriteTo(bW);
            else
                _serverAddress.WriteTo(bW);

            if (string.IsNullOrEmpty(_serverHostName))
                bW.Write((byte)0);
            else
                s.WriteShortString(_serverHostName);

            if (string.IsNullOrEmpty(_bootFileName))
                bW.Write((byte)0);
            else
                s.WriteShortString(_bootFileName);

            if (_routerAddress is null)
                IPAddress.Any.WriteTo(bW);
            else
                _routerAddress.WriteTo(bW);

            if (_useThisDnsServer)
            {
                bW.Write((byte)255);
            }
            else if (_dnsServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_dnsServers.Count));

                foreach (IPAddress dnsServer in _dnsServers)
                    dnsServer.WriteTo(bW);
            }

            if (_winsServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_winsServers.Count));

                foreach (IPAddress winsServer in _winsServers)
                    winsServer.WriteTo(bW);
            }

            if (_ntpServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_ntpServers.Count));

                foreach (IPAddress ntpServer in _ntpServers)
                    ntpServer.WriteTo(bW);
            }

            if (_ntpServerDomainNames is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_ntpServerDomainNames.Count));

                foreach (string ntpServerDomainName in _ntpServerDomainNames)
                    s.WriteShortString(ntpServerDomainName);
            }

            if (_staticRoutes is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_staticRoutes.Count));

                foreach (ClasslessStaticRouteOption.Route route in _staticRoutes)
                    route.WriteTo(bW.BaseStream);
            }

            if (_vendorInfo is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_vendorInfo.Count));

                foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in _vendorInfo)
                {
                    s.WriteShortString(entry.Key);
                    bW.WriteBuffer(entry.Value.Information);
                }
            }

            if (_capwapAcIpAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_capwapAcIpAddresses.Count));

                foreach (IPAddress capwapAcIpAddress in _capwapAcIpAddresses)
                    capwapAcIpAddress.WriteTo(bW);
            }

            if (_tftpServerAddreses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_tftpServerAddreses.Count));

                foreach (IPAddress tftpServerAddress in _tftpServerAddreses)
                    tftpServerAddress.WriteTo(bW);
            }

            if (_genericOptions is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_genericOptions.Count));

                foreach (DhcpOption genericOption in _genericOptions)
                {
                    bW.Write((byte)genericOption.Code);
                    bW.Write(Convert.ToInt16(genericOption.RawValue.Length));
                    bW.Write(genericOption.RawValue);
                }
            }

            if (_exclusions is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_exclusions.Count));

                foreach (Exclusion exclusion in _exclusions)
                {
                    exclusion.StartingAddress.WriteTo(bW);
                    exclusion.EndingAddress.WriteTo(bW);
                }
            }

            var reservations = _reservedLeases.Values.OrderBy(l => l.ClientIdentifier.ToString(), StringComparer.Ordinal).ToArray();
            bW.Write(reservations.Length);
            foreach (var reservedLease in reservations) reservedLease.WriteTo(bW);

            bW.Write(_allowOnlyReservedLeases);
            bW.Write(_blockLocallyAdministeredMacAddresses);
            bW.Write(_ignoreClientIdentifierOption);

            {
                bW.Write(includeLeases ? _leases.Count : 0);

                if (includeLeases) foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
                    lease.Value.WriteTo(bW);
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            return Equals(obj as Scope);
        }

        public bool Equals(Scope other)
        {
            if (other is null)
                return false;

            if (!_startingAddress.Equals(other._startingAddress))
                return false;

            if (!_endingAddress.Equals(other._endingAddress))
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_startingAddress, _endingAddress, _subnetMask);
        }

        public override string ToString()
        {
            return _name;
        }

        public int CompareTo(Scope other)
        {
            return _name.CompareTo(other._name);
        }

        #endregion

        #region properties

        public string Name
        {
            get { return _name; }
            set
            {
                ValidateScopeName(value);
                _name = value;
            }
        }

        public bool Enabled
        { get { return _enabled; } }

        public IPAddress StartingAddress
        { get { return _startingAddress; } }

        public IPAddress EndingAddress
        { get { return _endingAddress; } }

        public IPAddress SubnetMask
        { get { return _subnetMask; } }

        public ushort LeaseTimeDays
        {
            get { return _leaseTimeDays; }
            set
            {
                if (value > 999)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeDays), "Lease time in days must be between 0 to 999.");

                _leaseTimeDays = value;
            }
        }

        public byte LeaseTimeHours
        {
            get { return _leaseTimeHours; }
            set
            {
                if (value > 23)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeHours), "Lease time in hours must be between 0 to 23.");

                _leaseTimeHours = value;
            }
        }

        public byte LeaseTimeMinutes
        {
            get { return _leaseTimeMinutes; }
            set
            {
                if (value > 59)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeMinutes), "Lease time in minutes must be between 0 to 59.");

                _leaseTimeMinutes = value;
            }
        }

        public ushort OfferDelayTime
        {
            get { return _offerDelayTime; }
            set { _offerDelayTime = value; }
        }

        public bool PingCheckEnabled
        {
            get { return _pingCheckEnabled; }
            set { _pingCheckEnabled = value; }
        }

        public ushort PingCheckTimeout
        {
            get { return _pingCheckTimeout; }
            set { _pingCheckTimeout = value; }
        }

        public byte PingCheckRetries
        {
            get { return _pingCheckRetries; }
            set { _pingCheckRetries = value; }
        }

        public string DomainName
        {
            get { return _domainName; }
            set
            {
                if (value != null)
                    DnsClient.IsDomainNameValid(value, true);

                _domainName = value;
            }
        }

        public IReadOnlyCollection<string> DomainSearchList
        {
            get { return _domainSearchList; }
            set
            {
                if (value is not null)
                {
                    foreach (string domainSearchString in value)
                        DnsClient.IsDomainNameValid(domainSearchString, true);
                }

                _domainSearchList = value;
            }
        }

        public bool DnsUpdates
        {
            get { return _dnsUpdates; }
            set { _dnsUpdates = value; }
        }

        public bool DnsOverwriteForDynamicLease
        {
            get { return _dnsOverwriteForDynamicLease; }
            set { _dnsOverwriteForDynamicLease = value; }
        }

        public uint DnsTtl
        {
            get { return _dnsTtl; }
            set { _dnsTtl = value; }
        }

        public IPAddress ServerAddress
        {
            get { return _serverAddress; }
            set
            {
                ValidateIpv4(value, nameof(ServerAddress));
                _serverAddress = value;
            }
        }

        public string ServerHostName
        {
            get { return _serverHostName; }
            set
            {
                if ((value != null) && (value.Length >= 64))
                    throw new ArgumentException("Server host name cannot exceed 63 bytes.");

                _serverHostName = value;
            }
        }

        public string BootFileName
        {
            get { return _bootFileName; }
            set
            {
                if ((value != null) && (value.Length >= 128))
                    throw new ArgumentException("Boot file name cannot exceed 127 bytes.");

                _bootFileName = value;
            }
        }

        public IPAddress RouterAddress
        {
            get { return _routerAddress; }
            set
            {
                ValidateIpv4(value, nameof(RouterAddress));
                _routerAddress = value;
            }
        }

        public bool UseThisDnsServer
        {
            get { return _useThisDnsServer; }
            set
            {
                _useThisDnsServer = value;

                if (_useThisDnsServer)
                    FindThisDnsServerAddress();
            }
        }

        public IReadOnlyCollection<IPAddress> DnsServers
        {
            get { return _dnsServers; }
            set
            {
                ValidateIpv4(value, nameof(DnsServers));
                _dnsServers = value;

                if ((_dnsServers != null) && _dnsServers.Count > 0)
                    _useThisDnsServer = false;
            }
        }

        public IReadOnlyCollection<IPAddress> WinsServers
        {
            get { return _winsServers; }
            set
            {
                ValidateIpv4(value, nameof(WinsServers));
                _winsServers = value;
            }
        }

        public IReadOnlyCollection<IPAddress> NtpServers
        {
            get { return _ntpServers; }
            set
            {
                ValidateIpv4(value, nameof(NtpServers));
                _ntpServers = value;
            }
        }

        public IReadOnlyCollection<string> NtpServerDomainNames
        {
            get { return _ntpServerDomainNames; }
            set
            {
                if (value is not null)
                {
                    foreach (string ntpServerDomainName in value)
                        DnsClient.IsDomainNameValid(ntpServerDomainName, true);
                }

                _ntpServerDomainNames = value;
            }
        }

        public IReadOnlyCollection<ClasslessStaticRouteOption.Route> StaticRoutes
        {
            get { return _staticRoutes; }
            set { _staticRoutes = value; }
        }

        public IReadOnlyDictionary<string, VendorSpecificInformationOption> VendorInfo
        {
            get { return _vendorInfo; }
            set { _vendorInfo = value; }
        }

        public IReadOnlyCollection<IPAddress> CAPWAPAcIpAddresses
        {
            get { return _capwapAcIpAddresses; }
            set
            {
                ValidateIpv4(value, nameof(CAPWAPAcIpAddresses));
                _capwapAcIpAddresses = value;
            }
        }

        public IReadOnlyCollection<IPAddress> TftpServerAddresses
        {
            get { return _tftpServerAddreses; }
            set
            {
                ValidateIpv4(value, nameof(TftpServerAddresses));
                _tftpServerAddreses = value;
            }
        }

        public IReadOnlyCollection<DhcpOption> GenericOptions
        {
            get { return _genericOptions; }
            set { _genericOptions = value; }
        }

        public IReadOnlyCollection<Exclusion> Exclusions
        {
            get { return _exclusions; }
            set
            {
                if (value is null)
                {
                    _exclusions = null;
                }
                else
                {
                    foreach (Exclusion exclusion in value)
                    {
                        if (!IsAddressInRange(exclusion.StartingAddress))
                            throw new ArgumentOutOfRangeException(nameof(Exclusions), "Exclusion starting address must be in scope range.");

                        if (!IsAddressInRange(exclusion.EndingAddress))
                            throw new ArgumentOutOfRangeException(nameof(Exclusions), "Exclusion ending address must be in scope range.");
                    }

                    _exclusions = value;
                }
            }
        }

        public IReadOnlyCollection<Lease> ReservedLeases
        {
            get
            {
                List<Lease> leases = new List<Lease>(_reservedLeases.Count);

                foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _reservedLeases)
                    leases.Add(entry.Value);

                leases.Sort();
                return leases;
            }
            set
            {
            lock (_provisioningReservationSync)
            {
                if ((value is null) || (value.Count == 0))
                {
                    //remove all DNS entries
                    foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _reservedLeases)
                        _dhcpServer.RemoveDnsEntries(this, entry.Value, true);

                    _reservedLeases.Clear();
                }
                else
                {
                    foreach (Lease reservedLease in value)
                    {
                        if (!IsAddressInRange(reservedLease.Address))
                            throw new ArgumentOutOfRangeException(nameof(ReservedLeases), "Reserved address must be in scope range.");
                    }

                    //remove DNS entries for reserved leases being removed or has updated domain name
                    foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _reservedLeases)
                    {
                        Lease existingReservedLease = entry.Value;
                        bool domainNameMatches = false;

                        foreach (Lease reservedLease in value)
                        {
                            if (existingReservedLease.ClientIdentifier.Equals(reservedLease.ClientIdentifier))
                            {
                                domainNameMatches = (existingReservedLease.HostName is null) || existingReservedLease.HostName.Equals(reservedLease.HostName, StringComparison.Ordinal);
                                break;
                            }
                        }

                        if (!domainNameMatches)
                            _dhcpServer.RemoveDnsEntries(this, existingReservedLease, true); //existing reserved lease is being removed or domain name updated; remove DNS entries for it
                    }

                    _reservedLeases.Clear();

                    foreach (Lease reservedLease in value)
                    {
                        if (_reservedLeases.TryAdd(reservedLease.ClientIdentifier, reservedLease))
                            _dhcpServer.AddDnsEntries(this, reservedLease); //add DNS entries for new reserved lease
                    }
                }
            }
        }
        }

        public bool AllowOnlyReservedLeases
        {
            get { return _allowOnlyReservedLeases; }
            set { _allowOnlyReservedLeases = value; }
        }

        public bool BlockLocallyAdministeredMacAddresses
        {
            get { return _blockLocallyAdministeredMacAddresses; }
            set { _blockLocallyAdministeredMacAddresses = value; }
        }

        public bool IgnoreClientIdentifierOption
        {
            get { return _ignoreClientIdentifierOption; }
            set { _ignoreClientIdentifierOption = value; }
        }

        public IReadOnlyDictionary<ClientIdentifierOption, Lease> Leases
        { get { return _leases; } }

        public IPAddress NetworkAddress
        { get { return _networkAddress; } }

        public IPAddress BroadcastAddress
        { get { return _broadcastAddress; } }

        public IPAddress InterfaceAddress
        { get { return _interfaceAddress; } }

        internal int InterfaceIndex
        { get { return _interfaceIndex; } }

        internal DateTime LastModified
        { get { return _lastModified; } }

        #endregion

        class AddressStatus
        {
            public static readonly AddressStatus TRUE = new AddressStatus(true, null);
            public static readonly AddressStatus FALSE = new AddressStatus(false, null);

            public readonly bool IsAddressAvailable;
            public readonly IPAddress NewAddress;

            public AddressStatus(bool isAddressAvailable, IPAddress newAddress)
            {
                IsAddressAvailable = isAddressAvailable;
                NewAddress = newAddress;
            }
        }
    }
}
