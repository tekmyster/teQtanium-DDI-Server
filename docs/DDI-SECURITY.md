# DDI security module requirements

Provide protective DNS, threat intelligence enrichment, behavioral analytics and device attribution in the GPL-covered application; [edition policy](../LICENSE.md) does not convert existing GPL features into proprietary gates. Threat intelligence integrations are optional, and the resolver must remain usable without a commercial feed or reachable enrichment service. The first implementation now provides threat matching, a background MISP connector, heuristic scoring, shared DNS/DHCP device signals, IPAM threat findings, authenticated APIs, and a Security console. Advanced detections and regional deployment validation remain work in progress.

## Implemented first slice

Security is disabled by default, with Monitor as its initial mode. Explicit local indicators support exact domains, domain suffixes, IPv4/IPv6 addresses and networks, source confidence, client network scope, and expiry. Queries and reachable CNAME/A/AAAA answers are inspected; unrelated additional-section glue is ignored. URL values are retained as evidence without blocking a host based on an unseen URL path. Block responses use REFUSED, clear the AD bit, and preserve the client's checking-disabled flag. Locally authoritative answers are excluded unless the operator enables inspection.

The Security tab exposes policy settings, bulk indicator entry, exceptions, simulation, recent events, source health, and shared device evidence. IPAM inspection also reports threat intelligence matches against intended and observed addresses. Policy writes require an expected revision and existing Settings modify permission. MISP source and credential-reference changes additionally require Administration modify permission. Credential references are restricted to `DDI_MISP_*_API_KEY` environment variables, including the default `DDI_MISP_API_KEY`; keys are never saved in a policy or returned through the console.

The MISP worker makes bounded, authenticated HTTPS `attributes/restSearch` requests with pagination. It imports permitted domain, hostname, destination IP, domain/IP composite, and URL attributes, preserving attribute UUID, event ID, tags, timestamp, and `to_ids` metadata. Deleted attributes are excluded, successful full refresh replaces the cache to apply retractions, and failed refresh retains the previous complete cache. Enrichment is always Monitor evidence and is bound to its configured source URL. Cache lifetime is configurable; indicator age, sightings, decay scoring, warninglists, and additional sharing-tag policy interpretation are not yet implemented. MISP API visibility is governed by its service token. No DNS query is sent to MISP for live enrichment, and no sightings are submitted.

The heuristic scorer groups by an observed device identity when unambiguous current local or synchronized DHCP evidence is available, otherwise by client IP. Public Suffix List boundaries determine registered domains. The current `heuristic-v2` analyzer uses rolling five-minute and one-hour windows for corroborated tunneling suspicion, cross-domain DGA-pattern suspicion and low-priority periodicity. Scores remain uncalibrated; synthetic regression examples do not establish production precision or recall. Bounded historical lease lookup is available through the DHCP module, while event backfill remains unimplemented. [API-only advisory model mechanics](PREDICTIVE-MODELS.md) support supplied-data centroid training and frozen baselines; empirical effectiveness remains unqualified.

## Extended behavioral analysis and optional models

The current local build adds rolling five-minute/hour windows, corroborated tunneling suspicion, cross-domain DGA-pattern suspicion, low-priority periodicity and visible sample coverage. See [the security roadmap](SECURITY-ROADMAP.md) for the exact boundaries. Local supplied-data baseline/classifier mechanics are described in [the advisory workflow](PREDICTIVE-MODELS.md); authorized representative evaluation remains pending.

[Optional model assistance](SECURITY-LLM.md) provides an administrator-requested, advisory explanation through a local or explicitly authorized HTTPS Chat Completions-compatible endpoint. It is disabled by default, omits identity/raw query data and cannot modify protection. `/api/security/events/analyze` is a POST requiring Settings view and Administration modify. Connection changes and rollback require Administration modify. Run `--security-analytics` for detector and mocked connector checks.

## Shared DNS and DHCP awareness

DNS, DHCP, and IPAM use the same local security manager. A DNS indicator match or qualifying behavioral alert creates an expiring device signal when current lease identity is known. MISP matches can create lower-priority shared context without triggering automatic enforcement. DHCP reads those signals before offering a new lease and records its related evidence. A simple per-identity DHCP offer-request-rate anomaly can also publish a signal that DNS sees. MAC addresses and DHCP client identifiers are observations, not authenticated identity.

Device responses default to Monitor for DNS and Observe for DHCP. In Block mode, operators may enable device DNS blocking and withholding new DHCP leases above a configured threshold. New binding risk is checked both at OFFER and before ACK, including evidence arriving between those messages. Existing active lease renewals are preserved by this initial response mode. An explicitly allowed query does not create new device risk from the rules it overrides. Signals expire after ten minutes. Indicator-derived signals carry evidence fingerprints, so changing, removing, expiring, or retracting the underlying indicator prevents obsolete evidence from driving restrictions. This mechanism does not transfer address ownership or modify ACLs, credentials, or management firewall rules.

Nodes checkpoint local signals every ten seconds and on orderly shutdown, and retry publication after a failed link. A sudden crash can lose observations since the last checkpoint. Secondary nodes submit batches over HTTPS through the existing cluster API session to a coordinator endpoint that requires a direct cluster API token and registered source nodes; ordinary proxied user sessions cannot ingest evidence. The coordinator deduplicates by stable signal ID and timestamp, stores the received signal, and requests distribution through existing cluster configuration synchronization. Policy, MISP cache, and active signals participate in configuration backup/restore and transfer. Receipt by the coordinator does not prove every replica has converged; the console describes asynchronous distribution. Signals received before their matching indicator snapshot cannot drive indicator-based restrictions until that evidence becomes valid locally.

The stores are bounded to 4096 signals, 4096 behavioral windows, a 2048-event delivery queue, and 1000 recent in-memory events. Evidence samples contain at most 32 matching indicators, prioritizing enforcement rules and confidence; decisions and events expose the number of omitted matches. Enforcement still evaluates the complete rule match set. Local JSONL delivery is capped at 10 MiB per UTC day with seven-day retention. Source and delivery health, retry errors, and dropped event delivery counts are visible. Queue limits and retention need workload testing before enterprise rollout. The existing cluster token model trusts cluster members; per-node signed evidence and finer security roles remain future work.

## Investigation and rollback

The console and APIs search recent and persisted events by UTC interval, client/MAC identity and query substring. Searches accept a maximum seven-day interval and 1000 results, scan at most 20 MiB or 20000 journal lines, and expose truncation and unreadable-line counts. JSON export contains the selected search result and coverage metadata for collector or analyst use. It is not a streaming SIEM integration or an externally immutable audit store.

Operators can record Investigating, Confirmed, FalsePositive and Resolved dispositions with notes, actor and timestamp; the last 5000 dispositions are retained locally. These annotations do not alter enforcement. Policy history retains up to 25 snapshots. Rollback republishes previous content under a new revision and preserves revision checks; a rollback changing MISP settings still requires Administration modify permission. History and dispositions are node-local in this implementation and are not included in the general configuration backup. The latest active policy and active device signals remain part of backup and synchronization.

The distributed DHCP module provides local and replicated live lease context through an immutable in-memory index. A client DECLINE creates an unverified address-conflict observation and shared risk priority 80, while the allocation manager quarantines the address for ten minutes. This is not rogue-DHCP discovery or proof of malicious activity.

## API contract

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/security/policy/get` | GET or POST | Policy, MISP health, distribution health, dropped deliveries, active signals |
| `/api/security/policy/set` | POST | Form fields `revision` and serialized `policy`; validate and publish a local snapshot |
| `/api/security/events/list` | GET or POST | Recent node-local DNS/DHCP events and shared active signals |
| `/api/security/simulate` | GET or POST | `query`, optional `client`, comma-separated `cnames` and `addresses`; no enforcement or event mutation |
| `/api/security/signals/ingest` | POST | Coordinator-only authenticated cluster ingestion of a bounded serialized `signals` batch |
| `/api/security/policy/history` | GET or POST | Retained revision summaries |
| `/api/security/policy/rollback` | POST | `revision` and `targetRevision`; republish retained content as a new revision |
| `/api/security/events/search` | GET or POST | UTC `from`/`to`, optional `client`, `query`, `limit`; bounded search with coverage metadata |
| `/api/security/dispositions/list` | GET or POST | Local analyst annotations |
| `/api/security/dispositions/set` | POST | `eventId`, `status`, `notes`; record actor and update time |

## Validation scopes and remaining requirements

Run `dotnet run --project tests/Ipam.Tests/Ipam.Tests.csproj -c Release -- --security` for matching, scoring, three independent stores, mocked MISP and bad-link retries; use `--security-ops` for persisted timelines, dispositions, bounded evidence and rollback. `--api` covers authenticated APIs, live loopback DNS packets, the DHCP offer hook, IPAM findings, permissions, backup format and fresh-session privileges. `--transport` exercises three native local servers through pinned HTTPS allocation endpoints with fixture membership. These fixtures do not establish live regional failover, production enrollment/DANE, a production DHCP relay deployment, an encrypted-DNS transport matrix or detection calibration. Separate Monitor consumption activation is recorded in [dated status](DEPLOYMENT-STATUS.md); that outcome must not be inferred from synthetic checks. Event backfill, general external feed/RPZ support beyond the bounded [typed-feed candidate](THREAT-FEED-MANAGEMENT.md), SVCB/HTTPS hints, sinkholes, advanced analytics, SIEM streaming and enterprise investigation storage remain pending.

## Threat intelligence and enforcement

Normalize domain, hostname, URL, IPv4, IPv6, and CIDR indicators with source, confidence, category, expiry, and provenance. DNS matching operates on hostnames and returned addresses. Preserve a URL's full value for enrichment, but extracting its host does not automatically justify blocking the whole domain. DNS cannot inspect an HTTPS URL path or prove that a client connected to the resolved destination.

Check query names, CNAME targets, and relevant A/AAAA answers, including cached responses. Define supported SVCB/HTTPS address hint handling. Avoid treating unrelated additional-section glue as a client destination. Support exact and explicit suffix matches, allow exceptions with expiry, monitor, block, and sinkhole actions, and policies by network view, site, subnet, and client group. Shared hosting and CDN addresses require careful IP policy scope to avoid blocking unrelated services.

Feed updates need bounded downloads and parsing, atomic activation, retractions, expiry, freshness status, and rollback. Keep the last valid policy locally on every service node. Enrichment HTTP calls and feed refresh must never execute synchronously inside the DNS response path. A feed or MISP outage does not interrupt resolution.

Existing Technitium built in blocking and Advanced Blocking require a unified precedence contract. The DNS Block List app serves DNSBL queries; its presence does not by itself enforce resolved IP reputation on recursive replies. Existing rebinding protection, DNSSEC, and query rate limits are useful foundations to integrate into the security interface.

## MISP enrichment

Use authenticated, paginated background MISP searches for configured indicator types and permitted events. Retain event and attribute UUIDs, tags, threat context, sightings, timestamps, and available indicator decay information. Respect sharing restrictions, deleted attributes, revocations, and `to_ids` semantics. An enrichment match is evidence rather than an unconditional block instruction.

Warninglists and explicit operator exceptions inform false-positive review; they are not universal proof that an indicator is harmless. Maintain source freshness and confidence separately from behavioral risk. Return optional sightings to MISP only when the operator enables that integration, with controls over disclosed client information. Avoid sending full internal DNS telemetry to external enrichment services by default.

Sources: [MISP API specification](https://misp.software/openapi/), [MISP indicator decay](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/), and [MISP tools](https://www.misp-project.org/tools/).

## Explainable exfiltration scoring

Aggregate observations by network context, client identity where known, and registrable domain across short and long windows. Use a maintained public suffix dataset so public suffixes and hosted-domain boundaries are handled deliberately. Resolve device identity from lease history at event time; a reused client IP must not transfer another device's history.

Candidate features include label lengths, character entropy, encoding-like structure, unique subdomain count and ratio, query rate, repeated query payload patterns, query type distribution, response sizes, NXDOMAIN patterns, destination novelty, and changes relative to the client's normal behavior. Track sustained low-rate activity as well as bursts. TXT queries or high entropy alone must not establish exfiltration; legitimate services frequently use machine-generated labels.

Produce a configurable 0 to 100 risk score with feature contributions, evidence window, baseline status, model version, and confidence. The score is a heuristic priority until calibrated against representative labeled traffic; it is not the probability of data theft. DNS label volume is an observable encoding-capacity signal rather than verified bytes stolen. Separate indicator reputation from behavioral exfiltration score in investigations.

Start in monitor mode, require corroborating evidence for escalation, and measure false positives across legitimate CDNs, endpoint telemetry, DNS verification, mail security, and approved tunnels. Blocking thresholds require evaluated data and operator policy. Use decaying windows, bounded per-client state, sampling visibility, and explicit event loss counters.

## Additional security capabilities

| Capability | Intended behavior |
| --- | --- |
| DGA detection | Correlate lexical patterns, query failures, destination novelty, and client behavior across time |
| Command and control signals | Detect repeated beacon-like timing and unusual persistent destinations; label the result as suspicion |
| Lookalike domains | Compare approved organization domains against typos, homographs, and suspicious IDN forms |
| Newly observed domains | Track first-seen locally; distinguish this from externally verified registration age |
| Fast flux signals | Monitor abnormal IP/ASN churn and TTL patterns with exceptions for legitimate infrastructure |
| DNS rebinding | Protect private and link-local destinations while preserving explicitly configured internal services |
| Resolver integrity | Surface DNSSEC failures, suspicious response anomalies, and upstream behavior; retain existing protocol validation |
| Infrastructure abuse | Recursion access controls, query and response rate controls, random-subdomain flood detection, and amplification reduction |
| Zone protection | Restrict transfers and dynamic updates, use TSIG where appropriate, and audit authoritative changes |
| Device correlation | Attach site, view, VLAN, lease-time MAC/client evidence, intended owner, and NetBox references when available |
| DHCP anomalies | Detect pool exhaustion patterns, suspicious lease churn, conflicting identities, and possible rogue DHCP through an appropriate network sensor |
| IPAM drift | Identify observed addresses outside approved intent and changes to DNS or DHCP that bypass the provisioning workflow |
| SOC workflow | Searchable timelines, evidence, SIEM export, webhooks, deduplication, analyst disposition, and optional response integrations |
| Policy operations | Simulation, exception expiry, revision rollout, rollback, and per-node enforcement health |

DNS query logs cannot establish that a client bypassed the resolver through a third-party DoH service or direct IP traffic. Those controls need network or endpoint integrations. Rogue DHCP visibility likewise requires a suitable observation point; a resolver log alone is insufficient.

Capability references: [Infoblox Threat Defense](https://www.infoblox.com/products/threat-defense/), [EfficientIP DNS Guardian](https://efficientip.com/products/dns-guardian/), [BlueCat network security](https://bluecatnetworks.com/products/network-security/), and [Technitium DNS Server](https://technitium.com/dns/). These references establish product categories rather than detection accuracy for this implementation.

## Delivery order

1. Normalize feeds and decision evidence, match domain/CNAME and resolved IP indicators, and publish local policy snapshots with exceptions and rollback.
2. Add asynchronous MISP enrichment, cached evidence, expiry, and source health.
3. Implement monitor-only exfiltration and DGA analytics with replay tests and representative benign baselines.
4. Add device and historical lease correlation, investigations, and SIEM export.
5. Evaluate behavioral enforcement, rate controls, and integration-driven containment with deployment-specific access checks.

No stage automatically changes administrative ACLs, management firewall rules, or credentials without retaining the original session and completing a successful fresh-session check from the affected authorized source. Response automation must have explicit policy authority, reversible actions, and recorded outcomes.
