// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Ipam
{
    public sealed class IpamDiscoveryLimitException : Exception
    { public IpamDiscoveryLimitException(string message) : base(message) { } }

    // Independent read-only transports. No DNS/DHCP/device/cloud mutation API is used.
    public static class IpamDiscoveryCollector
    {
        public static string[] Targets(IpamDiscoverySource source) => source.Targets.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
        static IpamDiscoveryEvidence Evidence(IpamDiscoverySource s, string address, string objectId, string host, string client, string confidence)
        {
            var now = DateTime.UtcNow;
            return new(address, s.Id, s.Kind, objectId, host, client, confidence, now, now.AddSeconds(s.FreshSeconds));
        }
        public static async Task<IpamDiscoveryEvidence[]> Collect(IpamDiscoverySource source, IpamNetwork network, CancellationToken cancellationToken)
        {
            if (source.Kind == "TcpConnect") return await Tcp(source, cancellationToken);
            string credential = Environment.GetEnvironmentVariable(source.CredentialReference);
            if (string.IsNullOrEmpty(credential) || credential.Length > 4096 || credential.Contains('\r') || credential.Contains('\n')) throw new InvalidOperationException("Discovery credential is unavailable or invalid.");
            if (source.Kind == "SnmpArp") return await Snmp(source, network, credential, cancellationToken);
            if (source.Kind == "AzureNic")
            {
                using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromMilliseconds(source.TimeoutMs), MaxResponseHeadersLength = 16 };
                using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                return await Azure(source, network, credential, http, cancellationToken);
            }
            throw new ArgumentException("Unknown collector.");
        }
        static async Task<IpamDiscoveryEvidence[]> Tcp(IpamDiscoverySource s, CancellationToken token)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<IpamDiscoveryEvidence>();
            await Parallel.ForEachAsync(Targets(s), new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = token }, async (target, ct) =>
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(s.TimeoutMs);
                using var client = new TcpClient(IPAddress.Parse(target).AddressFamily);
                try
                {
                    await client.ConnectAsync(IPAddress.Parse(target), s.Port, deadline.Token);
                    results.Add(Evidence(s, target, target + ":" + s.Port, "", "", "ConnectionConfirmed"));
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused) { /* explicit negative response; no positive evidence */ }
                // A timeout/unreachable target is an incomplete run, never a successful empty scan.
            });
            if (results.Count > s.MaxResults) throw new IpamDiscoveryLimitException("Discovery result limit exceeded.");
            return results.OrderBy(e => e.Address, StringComparer.Ordinal).ToArray();
        }
        const string ArpColumn = "1.3.6.1.2.1.4.22.1.2";
        static async Task<IpamDiscoveryEvidence[]> Snmp(IpamDiscoverySource s, IpamNetwork network, string community, CancellationToken token)
        {
            using var udp = new UdpClient(IPAddress.Parse(Targets(s)[0]).AddressFamily);
            udp.Connect(IPAddress.Parse(Targets(s)[0]), s.Port);
            async Task<(string Oid, byte Tag, byte[] Value)> Query(string oid, bool next)
            {
                int id = RandomNumberGenerator.GetInt32(1, int.MaxValue);
                var packet = SnmpRequest(id, community, oid, next);
                using var requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                requestDeadline.CancelAfter(s.TimeoutMs);
                await udp.SendAsync(packet, requestDeadline.Token);
                var reply = await udp.ReceiveAsync(requestDeadline.Token);
                if (reply.Buffer.Length > 8192) throw new IpamDiscoveryLimitException("SNMP response is too large.");
                return SnmpResponse(reply.Buffer, id, community);
            }
            var name = await Query("1.3.6.1.2.1.1.5.0", false);
            if (name.Oid != "1.3.6.1.2.1.1.5.0" || name.Tag != 4 || name.Value.Length > 255) throw new InvalidDataException("Invalid SNMP device name response.");
            string host = Encoding.UTF8.GetString(name.Value);
            List<IpamDiscoveryEvidence> result = [];
            var target = Targets(s)[0];
            if (network.Contains(IPAddress.Parse(target))) result.Add(Evidence(s, target, "sysName@" + target, host, "", "DeviceReported"));
            string oid = ArpColumn;
            // Bounds cover every queried row, including rows outside the selected inventory subnet.
            for (int count = 0; count <= s.MaxResults; count++)
            {
                var row = await Query(oid, true);
                if (row.Tag == 0x82) return result.ToArray();
                if (CompareOid(row.Oid, oid) <= 0) throw new InvalidDataException("SNMP walk did not advance.");
                if (!row.Oid.StartsWith(ArpColumn + ".", StringComparison.Ordinal)) return result.ToArray();
                if (count == s.MaxResults) throw new IpamDiscoveryLimitException("SNMP table exceeds the configured row limit; no complete snapshot.");
                string[] suffix = row.Oid[(ArpColumn.Length + 1)..].Split('.');
                if (suffix.Length != 5 || !uint.TryParse(suffix[0], out _) || row.Tag != 4 || row.Value.Length < 1 || row.Value.Length > 32 || suffix.Skip(1).Any(x => !byte.TryParse(x, out _))) throw new InvalidDataException("Invalid SNMP ARP row.");
                string address = string.Join('.', suffix.Skip(1));
                if (network.Contains(IPAddress.Parse(address))) result.Add(Evidence(s, address, row.Oid + "@" + target, "", Convert.ToHexString(row.Value), "DeviceReported"));
                if (result.Count > s.MaxResults) throw new IpamDiscoveryLimitException("SNMP result limit exceeded.");
                oid = row.Oid;
            }
            throw new InvalidDataException("Incomplete SNMP walk.");
        }
        static int CompareOid(string a, string b)
        {
            var x = a.Split('.').Select(ulong.Parse).ToArray(); var y = b.Split('.').Select(ulong.Parse).ToArray();
            for (int i = 0; i < Math.Min(x.Length, y.Length); i++) if (x[i] != y[i]) return x[i].CompareTo(y[i]);
            return x.Length.CompareTo(y.Length);
        }
        public static byte[] SnmpRequest(int id, string community, string oid, bool next)
        {
            var w = new AsnWriter(AsnEncodingRules.BER);
            w.PushSequence(); w.WriteInteger(1); w.WriteOctetString(Encoding.UTF8.GetBytes(community));
            var tag = new Asn1Tag(TagClass.ContextSpecific, next ? 1 : 0, true);
            w.PushSequence(tag); w.WriteInteger(id); w.WriteInteger(0); w.WriteInteger(0);
            w.PushSequence(); w.PushSequence(); w.WriteObjectIdentifier(oid); w.WriteNull(); w.PopSequence(); w.PopSequence(); w.PopSequence(tag); w.PopSequence();
            return w.Encode();
        }
        static (string Oid, byte Tag, byte[] Value) SnmpResponse(byte[] data, int id, string community)
        {
            var root = new AsnReader(data, AsnEncodingRules.BER);
            var message = root.ReadSequence(); root.ThrowIfNotEmpty();
            if (message.ReadInteger() != 1 || !message.ReadOctetString().SequenceEqual(Encoding.UTF8.GetBytes(community))) throw new InvalidDataException("SNMP version or community mismatch.");
            var pdu = message.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)); message.ThrowIfNotEmpty();
            if (pdu.ReadInteger() != id || pdu.ReadInteger() != 0 || pdu.ReadInteger() != 0) throw new InvalidDataException("SNMP request mismatch or agent error.");
            var bindings = pdu.ReadSequence(); pdu.ThrowIfNotEmpty();
            var binding = bindings.ReadSequence(); bindings.ThrowIfNotEmpty();
            string oid = binding.ReadObjectIdentifier();
            var tag = binding.PeekTag();
            byte[] value;
            byte code;
            if (tag == Asn1Tag.PrimitiveOctetString) { code = 4; value = binding.ReadOctetString(); }
            else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2 && !tag.IsConstructed) { code = 0x82; binding.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 2)); value = []; }
            // A GETNEXT beyond this column may return another MIB type (for example IpAddress).
            // Consume its bounded BER value; the caller checks OID scope before requiring ARP octets.
            else { code = 0xff; value = binding.ReadEncodedValue().ToArray(); }
            binding.ThrowIfNotEmpty();
            return (oid, code, value);
        }
        public static string AzurePath(IpamDiscoverySource s) => "/subscriptions/" + s.Subscription + "/resourceGroups/" + Uri.EscapeDataString(s.ResourceGroup) + "/providers/Microsoft.Network/networkInterfaces";
        // HttpClient injection is for controlled native fixture transports; production origin is fixed below.
        public static async Task<IpamDiscoveryEvidence[]> Azure(IpamDiscoverySource s, IpamNetwork network, string bearer, HttpClient http, CancellationToken token)
        {
            string path = AzurePath(s);
            Uri next = new("https://management.azure.com" + path + "?api-version=2024-07-01");
            HashSet<string> visited = [];
            HashSet<string> objects = [];
            List<IpamDiscoveryEvidence> result = [];
            int totalObjects = 0, totalBytes = 0;
            for (int page = 0; next is not null; page++)
            {
                if (page >= 10) throw new IpamDiscoveryLimitException("Azure page limit exceeded.");
                if (!visited.Add(next.AbsoluteUri) || next.Scheme != "https" || next.Host != "management.azure.com" || next.Port != 443 || next.UserInfo.Length != 0 || next.Fragment.Length != 0 || !next.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Azure pagination escaped scope or exceeded bounds.");
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(s.TimeoutMs);
                using var request = new HttpRequestMessage(HttpMethod.Get, next);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                if (!response.IsSuccessStatusCode) throw new HttpRequestException("Azure read failed.");
                if (response.Content.Headers.ContentLength > 1024 * 1024) throw new IpamDiscoveryLimitException("Azure page exceeds byte limit.");
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                using var body = new MemoryStream();
                byte[] buffer = new byte[8192]; int read;
                while ((read = await stream.ReadAsync(buffer, deadline.Token)) > 0)
                {
                    totalBytes += read;
                    if (body.Length + read > 1024 * 1024 || totalBytes > 4 * 1024 * 1024) throw new IpamDiscoveryLimitException("Azure response exceeds byte limit.");
                    body.Write(buffer, 0, read);
                }
                using var doc = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
                if (!doc.RootElement.TryGetProperty("value", out var values) || values.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Azure inventory array is missing.");
                foreach (var nic in values.EnumerateArray())
                {
                    if (++totalObjects > s.MaxResults) throw new IpamDiscoveryLimitException("Azure inventory exceeds object limit.");
                    string id = nic.GetProperty("id").GetString();
                    if (id is null || id.Length > 1900 || !id.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase) || id[(path.Length + 1)..].Contains('/') || !objects.Add(id.ToLowerInvariant())) throw new InvalidDataException("Duplicate or outside-scope Azure NIC.");
                    var properties = nic.GetProperty("properties");
                    if (!properties.TryGetProperty("ipConfigurations", out var ips) || ips.ValueKind != JsonValueKind.Array || ips.GetArrayLength() > s.MaxResults) throw new InvalidDataException("Azure IP configurations are missing or exceed bounds.");
                    foreach (var config in ips.EnumerateArray())
                    {
                        var ipConfig = config.GetProperty("properties");
                        if (!ipConfig.TryGetProperty("privateIPAddress", out var addressValue)) continue; // an unallocated NIC is valid inventory
                        if (!IPAddress.TryParse(addressValue.GetString(), out var address) || address.IsIPv4MappedToIPv6 || address.ScopeIdSafe() != 0) throw new InvalidDataException("Azure returned an invalid private address.");
                        string configId = config.GetProperty("name").GetString();
                        if (string.IsNullOrEmpty(configId) || configId.Length > 80) throw new InvalidDataException("Azure IP configuration identity is invalid.");
                        if (network.Contains(address)) result.Add(Evidence(s, address.ToString(), id + "/" + configId, "", "", "ProviderReported"));
                        if (result.Count > s.MaxResults) throw new IpamDiscoveryLimitException("Azure address limit exceeded.");
                    }
                }
                next = doc.RootElement.TryGetProperty("nextLink", out var link) && link.ValueKind != JsonValueKind.Null && !string.IsNullOrEmpty(link.GetString()) ? new Uri(link.GetString(), UriKind.Absolute) : null;
            }
            return result.ToArray();
        }
    }
}
