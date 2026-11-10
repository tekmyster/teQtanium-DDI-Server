<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Modified by Tekmyster Industries, LLC — remains GPL-3.0. -->
# Cooperative DHCP ownership changes

This bounded IPv4 administrative API installs a new immutable allocation epoch for an existing distributed scope. It requires every old and new owner to remain enrolled, unfenced and reachable. Pause the affected native scope on every participant first. Other scopes and DNS can continue serving. There is no console editing flow in this candidate.

The protocol supports same-subnet range expansion/shrink, exclusions, hardware-identity reservations, and adding or removing cooperative owners. The current cluster primary must remain an owner. An unavailable owner prevents preparation. A permanent donor or borrower cannot be removed, and a permanently granted address cannot be removed from eligibility or reserved for another client. Return those grants through a separately qualified authority-return procedure first; this API does not provide one. Native bindings without corresponding current authority are refused for reconciliation.

Each change has a new 32-hex `Epoch`, also used as its operation ID. Ordinary plan installation, replication, backup restoration and stale state cannot replace an epoch. A completed change is not an authority rollback point.

## Review, prepare and commit

All coordinator endpoints use POST under `/api/ddi/dhcp/changes/` and require a direct HTTPS administrator session with DHCP modification and Administration delete privileges on the current primary. Peer endpoints require the direct enrolled-primary cluster session and target-seen primary source. Permissions, source and primary role are checked again after asynchronous boundaries.

1. `preview`: submit `expectedEpoch` and `plan` (JSON `AllocationPlan`). The plan has a fresh epoch, desired owners/range/exclusions/reservations, and the Base64 native paused scope configuration in `configuration`. Its binary configuration must match its eligibility. Use the existing native scope serialization and hardware client identity rules. Caller-supplied authority pins are refused. Native plans/reviews are limited to 2 MiB decoded UTF-8.
2. Preview **durably freezes** each old/new participant before returning its review. This is an administrative state change, not a read-only preview. It drains admitted requests, reconciles the exact later native ACK/offer lifetime only against the same current binding, then freezes the original authoritative owner journal. Responses contain `state` (`AllocationChangeInput`) and `hash`. Review these exact objects before preparation. Concurrent competing changes are refused.
3. `prepare`: submit the returned `change` JSON and `expectedHash`. Every participant independently rebuilds the successor from all original frozen owner journals. It durably installs the prepared successor, strictly saves and rereads its native configuration, and only then records its local preparation receipt. The primary records each matching peer receipt. The scope remains unable to serve while locally pending.
4. `commit`: submit `scope`, `id` and `expectedHash`. Every participant receipt is required. Persisted configuration must still match the exact reviewed native options. Peers commit first, and the primary commits after their replies. Re-enable each native scope only after its ownership commit is acknowledged and the coordinated result is reviewed.
5. `status`: submit `scope`. The returned local record includes phase, ID, hash, original frozen state, prepared payload and receipts. Recover the exact saved payload here after response loss or a coordinator restart. Retry the same prepare/commit; do not invent a new epoch for a pending change. Preview is not the resume endpoint after successor preparation.

Peer-only routes are `freezePeer`, `stage` and `commitPeer`. They do not grant administrator callers peer authority. Receipt names supplied to a peer cannot replace its own durable configuration receipt.

## Protection and failure behavior

Protected current leases and offers keep their client identity, address and exact protected expiry; the later of native and corresponding durable lifetimes is retained before freezing. A successor exclusion, range shrink or reservation collision retains that binding for the existing client. A client-only authority pin prevents another client taking it. After that client releases or the binding expires, the pin cannot create a new allocation. A later reviewed epoch can apply the normal current policy to the freed address.

Permanent donor grants and unused-capacity recovery divisions retain their exact records, IDs and borrower authority. Donor ownership pins keep those records valid when eligible ranks change. Old epochs, original replicas/history, bootstrap evidence, native holds and configuration revisions are archived in each local immutable change payload. Successor replica sequences exceed every frozen original sequence. Historical lookup selects the archived epoch for times preceding the transition.

There is no timeout unfreeze, authority rollback or deletion of permanent grants. A missing owner, rejected review, failed write, permission loss or missing response leaves an explicit frozen/prepared state. A peer may already have committed when its reply is lost; that peer serves only its disjoint successor authority, while uncommitted participants retain their durable serving barrier. Retry the saved operation. A failed allocation-store write withholds service until verified reopen/recovery; a failed native configuration save produces no preparation receipt. Do not close an administrative session when an access change has not passed its separate fresh-session check.

The journal is bounded to 256 transitions per store and 100,000 retained address pins per plan; no compaction/retirement protocol is provided. Native configuration/review size limits can further bound supported pools. DHCPv6, disconnected-owner forced transitions, permanent grant retirement, production relay/client continuity, whole native service process kill/restart, and a user-facing migration UI are not qualified by this candidate.

## Local verification and integration

Reproduce with a .NET 10 SDK and the exact adjacent TechnitiumLibrary DLLs from the private build manifest:

```powershell
dotnet build tests/Ipam.Tests/Ipam.Tests.csproj -c Release --nologo -v minimal
dotnet tests/Ipam.Tests/bin/Release/net10.0/Ipam.Tests.dll --ownership-model
dotnet tests/Ipam.Tests/bin/Release/net10.0/Ipam.Tests.dll --ownership-native
dotnet tests/Ipam.Tests/bin/Release/net10.0/Ipam.Tests.dll --dhcp
dotnet tests/Ipam.Tests/bin/Release/net10.0/Ipam.Tests.dll --transport
```

The native fixture uses disposable loopback nodes, authenticated pinned TLS, parsed native DHCP request handling with actual UDP ACK delivery, real DNS UDP/TCP, owned files, deterministic peer response faults and isolated permissions. Storage fixtures kill actual child processes at durable frozen/prepared/committed boundaries; native API tests separately reopen the allocation manager. These are distinct from killing and restarting the entire native service process. No production credentials, queries, authority changes or deployments are part of these checks.

Source is based on accepted `1740cc0ab1db484e55b54870a683cef42e033402`. Later independently accepted primary static IPAM c1ab/index50350 and Security f45f/indexe743 overlays remain a separate release integration boundary. No `www` assets are edited here. Any future whole-application release must carry those accepted static/session fixes coherently and receive independent review; this local candidate authorizes no deployment, publication or production completion claim.
