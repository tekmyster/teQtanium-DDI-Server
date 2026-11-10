<!-- Modified by Tekmyster Industries, LLC — remains GPL-3.0. -->
# Security lists and DNS query settings

Open **Security → Manage local lists** to paste manually maintained indicators. Select exact domain, domain and subdomains, IP address/network, or HTTP(S) URL evidence. DNS names accept case, a trailing dot and IDN names, then save in canonical form. Wildcards, regular expressions, ports and URL syntax are not DNS names. Network values use the existing IP/CIDR parser. URL evidence does not inspect web requests or match DNS queries.

Blank lines and `#` comments are ignored. A paste is atomic: invalid rows reject the entire policy update and retain the form. Errors identify the row in the combined local list. New or changed rows that duplicate the same kind, action, source and client scope are rejected. Existing saved rows retain the predecessor validation contract, including distinct-ID duplicates, during load, settings-only edits, history, restart and restore. Unchanged rows are recognized by normalized content and stable ID at the commit gate; omitting DNS settings does not exempt a new row. Only retained policy history can be rolled back through its dedicated authoritative revision path. Different actions remain distinct; a matching Allow query exception takes precedence within this module. Existing resolver blocking still applies. Expired indicators remain listed but do not match. Expiry entry uses local browser time.

The form accepts at most 1,000 new rows and 256 KiB per paste. The native policy accepts at most 10,000 local rows, 2,048 characters per value and 2 MiB of serialized configuration. The table renders 100 rows per page. Feed ingestion and EDL publication remain separate integrations; list entry enables neither.

Settings view permission exposes the configuration; current Settings modification permission and the cluster primary are required to change it. Connection changes additionally require Administration modification permission. The API checks current session/user authority after form reads and immediately before persisted policy replacement. A stale revision rejects the update. Copy unsaved entries before refreshing a conflicting form.

## DNS tunneling evidence

**Security → DNS query settings** exposes the actual `policy.dnsTunneling` controls below. All bounds are inclusive. Ratios are fractions, not percentages. Unknown keys and null settings are rejected. Legacy policies missing the object or its individual fields use the existing defaults.

| Persistence key | Unit | Default | Bounds |
| --- | --- | ---: | --- |
| shortWindowMinutes | minutes | 5 | 1–15 |
| longWindowMinutes | minutes | 60 | 15–60; greater than short window |
| minimumSamples | sampled queries | 30 | 10–512 |
| longLabelLength | characters | 32 | 8–63 |
| entropyMinimumLength | characters | 20 | 8–63 |
| entropyThreshold | Shannon bits per character | 4.0 | 1–6; finite |
| minimumUniqueSubdomains | distinct fingerprints | 25 | 2–512 |
| noveltyRatio | distinct prefixes / samples | 0.8 | 0.1–1 |
| lexicalRatio | long or high-entropy names / samples | 0.5 | 0.1–1 |
| shortWindowVolume | sampled queries | 60 | minimumSamples–512 |
| longWindowVolume | sampled queries | 120 | minimumSamples–512 |
| txtRatio | TXT queries / samples | 0.5 | 0.1–1 |
| nxDomainRatio | NXDOMAIN responses / samples | 0.5 | 0.1–1 |

The native `BehavioralAnalyzer.Observe` and `Tunneling` methods consume every control. Observation covers completed standard single-question DNS responses while protection is enabled. Transfers, multipart responses and explicit query exceptions are excluded. Authoritative answers require the existing opt-in. Streams group by client identity and registrable domain; the highest finding wins, with short-window precedence on ties.

Fixed contributions remain long labels +20, entropy +20, novelty +25, volume +15, TXT +10 and NXDOMAIN +10. Contributions require the minimum sample count. Lexical evidence requires the configured ratio of either long labels or labels meeting both entropy gates. Novelty requires both the distinct-count and distinct-ratio gates. Without both lexical and novelty corroboration, the score is capped at 49. The existing alert threshold controls event creation separately.

Saved policy revisions carry immutable settings into each evaluation. On the next observation after a settings change, all analyzer windows—including DGA and periodic DNS—restart empty. An older in-flight revision with different settings uses an isolated one-sample window and cannot erase newer state. Restart also clears windows. Unrelated policy edits do not reset them. DGA, periodic-DNS gates and predictive feature definitions remain fixed.

Retention remains one hour, 512 samples per stream and at most 4,096 client streams plus 4,096 client/domain streams. Counts describe retained samples, not total query volume; truncation is marked sample-limited. Stored fingerprints replace possible query payloads. Possible tunneling evidence is uncalibrated, and does not establish confirmed exfiltration or empirical accuracy.

Accepted changes persist atomically before effective-state replacement. Invalid or failed writes preserve the last effective policy. Startup reads at most 2 MiB plus an oversize sentinel; unreadable, malformed, unsupported-version or oversized policy files remain untouched and yield disabled protection with an explicit warning. A later explicit valid save repairs the policy. No default enables blocking, feeds or publication: protection mode and device DNS response remain Monitor, DHCP remains Observe. Recovery configuration is unaffected.
