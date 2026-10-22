<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Bounded voting coordination

This API-only implementation adds an opt-in, operator-driven replicated voting log. It implements durable Raft-style terms, votes, log matching, current-term commitment and joint voter transitions. It is not a claim of a complete production Raft implementation or automatic failover. There are no election timers, automatic campaigns, automatic primary promotion, automatic ownership transfers or automatic log compaction. Local qualification and independent acceptance are separate.

Voting membership, legacy primary/secondary enrollment, and DHCP allocation ownership are distinct. An isolated owner retains only its existing persisted allocation sequence and legitimate permanent grants. A voting majority does not fence a DHCP server, surrender its grants or establish that its outstanding leases are known. Lease, offer, renewal, release, ordinary donor-coordinated borrowing, grant return/reclaim and existing recovery refusal rules continue to use their allocation/native admission barriers; they do not acquire a quorum dependency merely because voting is enabled. Recovery automation remains Disabled.

## Initial group and learners

Initialize from a direct HTTPS administrator session on the legacy primary using one stable group GUID in 32-hex format, exactly three or five sorted voters, and the remaining enrolled nodes as sorted learners. Every enrolled node must be present exactly once. The primary persists its seed before sending it to peers. Partial initialization is retried with the identical seed; it never resets an existing group. Election requires a majority of the declared voters even if initialization replies were lost. There is no API to erase a seed, replace a group, initialize only a subset, add a new enrolled identity, install an offline snapshot or restore an older log.

An initialized learner receives the complete log and its committed position through explicit synchronization. It cannot campaign or grant a vote, and its acknowledgement never counts toward a majority. Promotion requires an acknowledgement of the complete current log during the leader's current term. This proves voting-log catch-up only; it does not confer a scope assignment, DHCP ownership or a guarantee that every independently replicated lease has arrived.

Enrollment is fixed for this stage. Voter demotion leaves the node enrolled as a learner and preserves its DHCP ownership. Legacy join, leave, delete, identity/source-address changes, primary promotion and cluster-config import are refused after initialization. Normal legacy cluster metadata refresh must retain the exact identities, URLs, roles, sources and fence states. Dynamic enrollment, re-addition, identity/certificate replacement, leader self-removal and primary migration require a separately qualified protocol. Preserve the original node directories, trust configuration and allocation/voting safety files.

## Elections and voter transitions

Each campaign durably increments the candidate's term and records its vote before sending requests. Only distinct eligible voters in the effective configuration count. A voter persists at most one candidate per term and refuses candidates with an older log. A newly elected leader appends a current-term no-op and requires its commitment before returning election success. Higher-term replies revoke leadership, including after an awaited request. Restart always begins as a follower; a saved vote or a saved leader name is not fresh leadership.

Three voters require two acknowledgements; five require three. A joint transition requires both a majority of the old set and a majority of the new set. The joint entry becomes the effective voting rule when it is recorded, including while uncommitted. Finalization requires a committed joint entry and writes the exact new stable configuration. Only one configuration transition can be pending. The leader must remain a voter. Same-ID exact retries reuse one entry; changed content, stale reviewed term or a changed log position for a new ID are refused. Learner promotion, voter demotion and ownership changes never alter enrollment themselves.

`configuration` in status is the latest effective configuration, which may be pending. `committedConfiguration` derives only from the committed prefix. `state.commit` is the durable committed entry count; `state.log.length` includes pending entries. Followers may lag in learning a committed position until the next explicit sync. A successful `sync` of an already committed entry is not a fresh quorum lease or a linearizable status read. A membership or ownership proposal succeeds only when its own entry is committed; a failed or canceled response can leave a pending or committed result and must be resolved by status and an exact retry.

## Native API contract

All paths below are POST under `/api/ddi/voting/`. JSON is sent as the `payload` form value. Coordinator calls require a direct TLS administrator session with DHCP Modify and Administration Delete rights, without `node` proxy selection or `actingUser`. Status permits direct TLS DHCP View. Peer RPCs require a direct TLS cluster-token session, an enrolled unfenced sender, and a target-observed source address matching that sender's enrolled addresses. The production cluster's shared token is a trusted non-Byzantine peer boundary, not an individual cryptographic node credential. Fixture certificate pinning does not qualify production enrollment or DANE.

| Action | Inputs and outcome |
| --- | --- |
| `status` | Returns local durable state, effective/committed configurations and volatile role. Peer status also requires `sender`. |
| `initialize` | `payload`: `{group,voters,learners}`. Legacy primary only; retries all enrolled peers. |
| `initializePeer` | Same seed plus `sender`; enrolled primary source only. |
| `campaign` | Explicit current-voter election and current-term no-op replication. |
| `vote` | Peer `sender` matching `{group,term,candidate,lastIndex,lastTerm}`. Reply success is an actual durable vote, never inferred from HTTP success. |
| `append` | Peer `sender` matching `{group,term,leader,previousIndex,previousTerm,entries,commit}`. Reply success is a durable matching prefix receipt. |
| `sync` | Elected leader explicitly retries full log replication and committed-position publication. |
| `voters` | Stable `id`, `expectedTerm`, `expectedIndex`, and `payload` containing the sorted desired voter array. Starts joint transition. |
| `finalize` | Stable distinct `id`, `expectedTerm`, `expectedIndex`. Commits the pending exact joint successor. |
| `authorizeOwnership` | Stable `id`, `expectedTerm`, `expectedIndex`, and `payload`: `{scope,epoch,successor,hash}` for the legacy primary's exact frozen review. |

`expectedIndex` is the reviewed local log length. An already-recorded ID may be retried at a later index, but its payload must remain exact and `expectedTerm` must identify the current elected term. Request/reply group, term, operation identity and durable log prefix bind decisions to their context. Foreign groups, divergent same-term entries, conflicting committed prefixes, duplicate identities and unsupported commands are refused. Peer RPCs are serialized against local store decisions without holding the voting lock across network requests.

## Ownership application and capacity

Without opt-in, the accepted cooperative all-owner ownership workflow remains available. With voting initialized, the ownership coordinator must also be the elected current-term voting leader. A secondary voting leader can coordinate voting membership, but cannot implicitly take over the legacy primary's ownership workflow.

1. Keep the affected native scopes paused. `/api/ddi/dhcp/changes/preview` first commits a current-term no-op, then uses the existing all-participant freeze and native capture protocol. Missing owners still refuse; a partial freeze remains durably pending.
2. Save the exact returned ownership review and hash. Commit its scope, original epoch, successor ID and hash with `authorizeOwnership`.
3. Prepare using the unchanged review/hash. Each participant verifies the committed authorization and the observed leader term, then uses the existing durable allocation journal, scope admission, native option application, save and independent readback. A committed voting entry alone does not acknowledge native application.
4. Commit only after every original participant acknowledges the original native preparation. Local voting role/term and exact authorization checks share a lock with each final allocation-store mutation; incoming higher terms can revoke future steps. Post-await permission, enrollment and native eligibility checks remain in place. Lost replies resume forward with the original operation.

A previously committed exact authorization remains a durable prerequisite on all participants; quorum loss does not undo it or restore a previous owner map. The original all-owner barriers determine whether application can finish. Voting changes do not remove required ownership participants or shorten existing leases/offers. Permanent grants, original recovery receivers, pending donor request IDs, pending returns and original-donor reclaim tombstones continue through the accepted successor rules. Forced disconnected-owner recovery, alternate receivers, blind unfencing, timeout surrender and stale authority restore remain unsupported/refused.

The log governs only voter transitions and these existing-ownership change APIs. Initial lease-free plan creation and reviewed initial live bootstrap keep their existing all-owner protocols. Direct handoff, capacity lifecycle and externally fenced offline recovery tools retain their original contracts and do not become quorum-authorized confiscation mechanisms. No timer, background callback, service API or import installs a successor ownership map from voting status alone. Backup export/import does not provide a voting-log recovery workflow: preserve the original voting file, barrier and allocation authority separately; cluster-config restore is refused while initialized.

## Durability and qualification limits

`voting-log.json` has an exclusive writer lock, a flushed staged generation and a separate content-hash `.required` barrier. The barrier precedes replacement of the live file; reopening can finish only the exact staged generation bound to that barrier. Missing, truncated, older or conflicting state/barriers withhold coordination. A failed write poisons further coordination mutation until recovery. Independent DNS/DHCP serving uses its separate allocation protections and remains available. Copying an entire old directory including its matching barrier, storage that lies about flush, cloned physical identity and Byzantine enrolled peers are outside this mechanism's guarantees.

The retained journal is bounded to 4,096 entries and 512 KiB of serialized durable state/RPC payload. Encoded form limits can reject a large request earlier. Full-log catch-up is used; there is no pruning or snapshot/compaction API. A size-limit refusal preserves history and requires a separately qualified continuation. Windows file/whole-process failures and native TLS fixtures are locally exercised; Linux directory synchronization follows the existing allocation durability helper but is not new Linux power-loss qualification.

Local tests distinguish persisted voting-store checks, native TLS APIs and allocator entrypoints, parsed-handler actual UDP ACK output, and whole-native-process kill/reopen. Six synthetic identities on one Windows loopback host simulate regions; they do not qualify regional infrastructure, full socket ingress/DORA/relay/OS clients or production failover. The whole-process kill tests stop all six fixture services together; a single-node crash with surviving peers, every disk-write interleaving, long-running churn, new enrollment, compaction, automatic elections and production trust paths remain unqualified. No `www` files are changed, so no desktop/mobile UI acceptance is claimed. No push or deployment is part of this assignment.
