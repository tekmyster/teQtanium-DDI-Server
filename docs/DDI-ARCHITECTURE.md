# Security focused DDI architecture

Build a unified DNS, DHCP, and IP address management platform on Technitium, with security policy enforcement and investigations grounded in device and network history. Preserve the existing resolver and its upgrade path while adding the inventory, policy, and operational workflows needed for DDI.

## Product scope

The GPL-covered application retains its GPL permissions; commercial policy applies only to separately licensable private components/services under [license boundaries](LICENSE-BOUNDARIES.md). Optional third-party services have their own terms. The components and milestones below describe target architecture unless explicitly identified as implemented in the [feature matrix](FEATURE-MATRIX.md). Measure improvement through capability acceptance tests, reliability and recovery results, performance, accessibility, operational effort, and interoperability; do not claim superiority without evidence.

The target deployment is a self hosted management service and a cluster supporting three or more DNS and DHCP service nodes. DHCP synchronization must support a configurable node count and must not be restricted to a two server failover pair. Organization size and the first security milestone remain product decisions. Existing DNS behavior should remain compatible unless an administrator explicitly enables a new policy.

Infoblox provides a useful capability reference: unified DNS, DHCP, and IPAM management; asset discovery; DHCP fingerprinting; identity mapping; and security investigation using network context. Its DNS firewall combines policy and threat intelligence with DHCP and IPAM context. These are capability goals, rather than a claim of compatibility with Infoblox APIs, feeds, or proprietary detection systems.

Sources: [Infoblox DDI](https://www.infoblox.com/products/ddi/), [Infoblox DNS Firewall](https://www.infoblox.com/glossary/dns-firewall/), and [Infoblox Threat Defense](https://www.infoblox.com/products/threat-defense/).

## Existing foundation

The reviewed upstream baseline is commit `8d30bab46eea70f6d4f6772f25113a929bd97f14`, with DNS Server version 15.6.1 and .NET 10 projects. The initial build uses TechnitiumLibrary commit `6715bf04c0a39938792cfee4d2654c5f368a1034` in a sibling checkout. Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-ddi.ps1` to build the dependencies, application, and Advanced Blocking app in Release mode. Existing library references expect Release output in the sibling library's `bin` directory.

| Area | Existing implementation | DDI extension |
| --- | --- | --- |
| DNS | Authoritative and recursive resolution, conditional forwarding, caching, DNSSEC, encrypted transports | Versioned security policies, feed provenance, policy simulation, investigation |
| Filtering | Built in block and allow zones, Advanced Blocking app, CNAME target checks | Explicit policy precedence, exceptions with expiry, decision evidence |
| DHCP | IPv4 scopes, reservations, leases, DHCP options, DNS integration | Historical lease events, fingerprints, inventory reconciliation, availability design |
| Inventory | DNS records and DHCP leases contain useful observations | Authoritative IPv4 and IPv6 IPAM, sites, networks, ownership, utilization, address conflicts |
| Administration | Users, groups, permissions, API sessions, SSO, LDAP, operational audit logs | Scoped DDI permissions, structured change history, change validation and rollback |
| Cluster | Primary and secondary management infrastructure; DHCP scopes excluded from configuration transfer | Synchronize DHCP configuration and lease state alongside DNS; coordinate allocation and takeover |
| Telemetry | Query logger interfaces, response classifications, statistics, logging apps | Bounded event ingestion, device enrichment, retention, SIEM export |

Relevant extension points are `IDnsRequestBlockingHandler`, `IDnsRequestController`, and `IDnsQueryLogger` in `DnsServerCore.ApplicationCommon`. DHCP integration lives in `DnsServerCore/Dhcp` and `WebServiceDhcpApi.cs`. Existing cluster management must not be treated as proof of replicated DHCP lease state or safe DHCP failover.

## Proposed components

**Service nodes** retain the Technitium DNS and DHCP engines. DNS policy evaluates a local immutable snapshot. A query must not need a controller request, a remote database lookup, or a threat feed download to resolve. Nodes retain their last valid policy across controller outages and restarts.

**The DDI controller** owns desired inventory and policy configuration, validates changes, distributes revisions, and records which revision each node has applied. It exposes a versioned management API and a unified interface for inventory, DNS, DHCP, and security investigations. Existing Technitium APIs remain available during migration.

**The inventory store** distinguishes intended address assignments from observed leases and DNS records. Each address belongs to a network view so overlapping private networks at different sites remain distinct. Store historical leases as intervals, allowing an event to be attributed to the device using that IP at the event time. An IP address alone does not establish device or user identity.

**The security pipeline** normalizes feed indicators with source, confidence, category, expiry, and revision. Publish validated snapshots atomically and preserve the previous revision for rollback. Query and DHCP observations enter bounded queues with explicit overflow counters; event delivery failure must not stall DNS resolution or DHCP lease handling.

**The investigation store** retains security decisions and selected observations with configurable retention. Keep query analytics separate from transactional inventory so high event volume cannot exhaust address allocation resources. Record node, site, client, query, action, rule, feed provenance, policy revision, and time where available.

## Policy behavior

Define deterministic precedence between built in blocking, app policies, explicit allows, threat feeds, and CNAME target decisions before introducing another handler. The upstream app interface permits allow decisions to bypass configured blocking, so adding independent handlers without a unified precedence model would make exceptions difficult to reason about.

Support allow, block, sinkhole, and monitor actions with network and device group scope. Exceptions need an owner, reason, and optional expiry. Policy simulation should explain the matched rule without changing enforcement. Response policy zone support is a separate interoperability feature requiring supported trigger and action semantics to be specified and tested.

Start behavioral detections in monitor mode. DNS tunneling and domain generation signals require multiple observations and a baseline; entropy alone is insufficient. Evaluate label length, unique subdomains, query rate, response patterns, and device context against representative benign and malicious traffic before enabling automatic blocking.

DNSSEC validation and policy response rewriting need explicit tests. Include cached answers, CNAME chains, negative answers, encrypted transports, IPv6 clients, forwarding groups, and upstream failures in policy coverage.

## IPAM and DHCP behavior

The persisted IPAM implementation and its limits are described in [IPAM source of truth and implementation](IPAM.md). The first NetBox connector publishes DDI-owned prefixes and addresses with explicit VRF mappings, provenance, preview and conditional updates. Security shares threat snapshots and expiring device signals across DNS, DHCP and IPAM, with coordinator ingestion, configuration distribution and bounded investigation workflows. Distributed DHCP now has immutable interleaved allocation sequences (legacy plans retain their original mapping), durable lease snapshots and history, acknowledged overflow and direct HTTPS replication across enrolled nodes. Consensus ownership changes, fenced failover, full provisioning and production qualification remain pending; see the [delivery matrix](FEATURE-MATRIX.md), [DHCP implementation](DHCP-SYNCHRONIZATION.md) and [security implementation](DDI-SECURITY.md).

Model network views, sites, subnets, pools, address assignments, reservations, devices, and lease observations as distinct entities. Enforce address uniqueness within a network view and reject invalid or conflicting allocation requests atomically. Maintain desired configuration separately from node observations so reconciliation does not silently overwrite an operator's intent.

Use lease timestamps to correlate DNS activity with MAC and client identifiers. DHCP fingerprints are evidence with a confidence level, rather than authoritative operating system identity. User identity requires an explicit integration and validity interval.

IPv6 IPAM can precede DHCPv6 service. Full DHCPv6 and DHCP high availability require protocol and state replication work; neither should be advertised based solely on existing IPv6 DNS support or DNS clustering.

The remainder of this paragraph specifies target coordination requirements; a three/five-voter consensus implementation is not delivered. DHCP synchronization across three or more servers is a core requirement for the first functional milestone. Synchronize scope configuration, reservations, and lease state while retaining node specific interface and listener settings. Organize nodes into local HA groups with primary and secondary preference and regional recovery targets. Automatically divide each eligible dynamic pool as evenly as possible among its assigned allocation owners; partition sizes differ by at most one address. An isolated owner continues allocating only within its persisted exclusive partition, journaling mutations locally and replicating them when communication returns. Configuration and ownership changes use coordination through three or five voting nodes with additional nonvoting replicas as needed. Repartitioning requires safe handoff, fencing where necessary, and protection of outstanding leases. A failed heartbeat never triggers independent repartitioning. The cluster configuration transfer currently passes `scopes: false` on export and restore; changing these flags alone would not implement safe DHCP synchronization. See [DHCP synchronization design](DHCP-SYNCHRONIZATION.md) for replication, allocation ownership, and acceptance requirements. Historical Hyper-V takeover tests and current VMware unused-capacity recovery are separate paths. Working production recovery remains incomplete and Disabled; see [dated status](DEPLOYMENT-STATUS.md).

## Security and operational requirements

Dynamic DHCP allocation uses stable sorted-owner interleaved eligible ranks for new plans, with the legacy affine mapping preserved for existing plans. Each server exhausts its own sequence before entering overflow. Borrowing an address from another sequence requires a durable coordinated claim with the original owner; all nodes receive the resulting lease and grant updates. Previously granted addresses remain protected during outages. New borrowing cannot proceed from stale replicated state alone. This preserves independent local service without allowing simultaneous conflicting allocations.

Scope administrative permissions to relevant sites, network views, and operations. Protect node enrollment and policy distribution with authenticated identities and replay protection. Feed fetchers need explicit limits on size, parsing time, redirects, and destination access. Do not log authentication tokens or integration secrets.

Record actor, source, operation, affected object, before and after values, outcome, and correlation identifier for management changes. Export audit records to an independently controlled destination when stronger retention or tamper resistance is required.

ACL, management access firewall, and credential changes must retain the original administrative session until a separate fresh session verifies authentication, intended privileges, and the source address seen by the target. Validate the intended configuration outcome separately. If fresh access fails, repair or roll back before disconnecting; explicitly report untested authorized paths.

Benchmark cache hits, cache misses, blocked queries, policy exceptions, CNAME processing, telemetry enabled, and feed reload under load. Report throughput, latency percentiles, memory, event loss, and resource saturation on stated hardware. Establish targets from the intended deployment rather than inheriting marketing benchmarks.

## Target implementation milestones (not a completion checklist)

1. **Development baseline.** Fork upstream, preserve license and attribution, build the existing application, record dependency revisions, and provide a repeatable build entry point. Keep runtime behavior unchanged at this stage.
2. **DHCP synchronization and inventory.** Implement replicated scope configuration, reservations, and durable lease events with explicit allocation ownership, consensus, membership changes, and replica recovery across three or more nodes. Add network views, subnets, address assignments, lease history ingestion, conflict handling, and read APIs. Demonstrate correct historical attribution when an IP is reused by another device and safe behavior during three and five node partitions.
3. **Protective DNS.** Implement a versioned policy model, feed ingestion, local enforcement, explicit exceptions, decision events, and policy simulation. Demonstrate unchanged enforcement when the controller is unavailable and atomic rollback of a bad revision.
4. **Unified operations.** Add inventory and security views, reservation and DNS workflows, scoped permissions, structured audit records, node reconciliation, and SIEM export. Test partial deployment and failed rollback cases.
5. **Advanced detection and availability.** Add monitor mode tunneling and DGA analytics with measured false positives, DHCPv6, DHCP failover, controller availability, recovery exercises, and compatibility migrations.

DHCP synchronization remains part of the initial functional scope even if protective DNS receives the first user interface. DNS event correlation requires lease history before reliable device attribution.

## First demonstrable workflow

A device obtains a DHCP lease. The platform associates the lease with a site and network view. The device queries a domain matched by a configured threat feed; the node applies its local policy and emits a decision with the rule and feed source. An operator opens the event and sees the device holding that address at the event time, creates an expiring exception, previews its effect, and publishes a new policy revision. The change and each node's applied revision appear in the audit history. Resolution continues during a controller outage.

Completion requires this workflow to run in an isolated lab with integration tests and measured query overhead. The architecture and successful upstream build alone do not constitute an implemented DDI product.
