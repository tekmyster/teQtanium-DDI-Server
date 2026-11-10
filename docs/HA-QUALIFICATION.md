<!-- Copyright (c) 2026 Tekmyster Industries, LLC. GPL-3.0; see ../LICENSE. -->
# Local HA evidence qualification

`scripts/ha-review.py` reviews supplied offline evidence and records an ordered,
immutable local review journal. It never connects to VMware, a guest, a controller,
or a teQtanium server. It cannot fence, transfer authority, activate DHCP, rejoin a
service, return capacity, unfence, install a task, or enable recovery. Every receipt
and refusal says `automation: Disabled` and `retainFence: true`.

The existing `recover-unused-dhcp-vmware.ps1` unsupported-provider gate is unchanged.
Its automation must remain Disabled. Neither this tool nor its fixture qualifies
the historical script's unreachable operations.

## Accepted protocol and precise gaps

At base `3b9276c2e29fd59e19455a63f4496c2f87349149`, allocation plans retain fixed
owners/epochs; original stores use exclusive writers and durable authority
watermarks. `RecoverUnusedCapacity` operates on the original offline store,
excludes unexpired bindings, writes permanent grants, and pins the recovery ID and
receiver division. It cannot establish failed-owner live-lease takeover.

Connected-owner `Handoff` atomically replaces selected original authority with
permanent grants carrying client/hardware/hostname and inherited lease/offer/
decline protection. A receiver needs the exact donor grant before serving. Explicit
`RelinquishGrant`/`ReclaimGrant` use durable return and terminal reclaim receipts;
they refuse unexpired protections. A process restart or timeout cannot erase a
grant. Returning unused capacity is distinct from whole-scope failback.

The VMware script has pinned adapter readback logic, but its unconditional
unsupported-provider gate blocks recovery: bounded original-store access and
independently verifiable durable recovery receipts remain absent. Its writer lock
is local. No multi-host controller exclusion, full failed-owner lease capture,
native/client ACK continuity, production fencing, rejoin, or unfence is qualified.
Private DHCP Q is absent from this source bundle and is neither copied nor
modified. Existing fixed-quorum voting and ownership contracts are unchanged.

## Review contract

Use a newly created owned local directory for one transaction. Keep that directory
and its receipts intact for the entire review. All participating local processes
must use the same directory. Missing directories are refused, never recreated.
Choosing another directory or deleting receipts evades this local coordination;
this tool provides no cross-directory or distributed exclusion. Do not use a
network share as a substitute for a qualified distributed coordinator.

The transaction pins a stable ID, scope/epoch, fixed members, donor, all original
receivers, minimum donor sequence, exact plan/configuration/core hashes, VM and
complete adapter inventory, protected-binding digest, and previously permanent
grant bytes. Evidence contains actual parsed allocation snapshots, from which
the tool recomputes plan/configuration and donor replica hashes. It recomputes
binding protection from Lease/Offer/Declined entries and inherited grant protection,
and checks that pinned permanent grant entries remain present. The contract uses
SHA-256 of sorted-key compact ASCII JSON; arrays retain their order.

Each evidence document must include every fixed member's available, matching
authority view. It must assert a successful fence task and complete adapter
readback with connected/start-connected/guest-control all false. Missing, stale,
future, mismatched, conflicting or unavailable authority refuses review. A
60-second supplied observation window is input hygiene; a local clock or supplied
timestamp does not authenticate freshness or rule out renewals during isolation.

The phases are:

1. `FencedReview`: validate pinned identity, asserted fence and current supplied
   original/member authority bytes.
2. `TakeoverReview`: additionally require the exact original durable surrender
   assertion and matching durable receiver assertions with snapshot bytes.
3. `RejoinReview`: additionally require matching restarted original snapshot bytes.

These names identify review stages, never actual operations or serving eligibility.
The original-store/durable/fence assertions are unsigned and untrusted. Matching
bytes cannot prove their origin, physical action, disk persistence, latest native
lease/options state, actual loaded core, provider privileges or client continuity.
This is an offline consistency check, not a production readiness approval.

Example developer invocation (use your own fixture paths):

```powershell
python scripts/ha-review.py C:/owned-review/journal C:/owned-review/transaction.json C:/owned-review/FencedReview.json FencedReview
```

Exit 0 means the local evidence review receipt was stored or exactly retried.
Exit 2 means refusal, with Disabled/retainFence and a reason on stderr. There is
no enable/activate option. An exact retry returns the same immutable receipt;
changed evidence, transaction ID, receivers or phase ordering cannot overwrite it.
Authority cannot regress or conflict at an equal sequence across phases.

The shared JSON loader reads at most 8 MiB plus one byte from the opened binary
stream, then rejects input exceeding 8 MiB before JSON parsing. This applies to
transaction, evidence and saved journal receipts. It does not read to EOF before
checking the bound or rely on a prior file-size check; growth after opening cannot
increase the requested read beyond that cap. Legal JSON exactly at the limit is
permitted. Empty/truncated JSON and ordinary I/O errors retain refusal behavior.

Stored history must use receipt schema 1 with exactly its declared fields and
types. Unsupported versions, unknown fields/states, malformed hashes, invalid
authority sequences, transaction mismatches, filename/phase gaps and incompatible
parent/authority history refuse before current evidence is reviewed. Equal
authority sequences require equal hashes; sequences cannot regress between saved
phases. Exact retries use the already validated receipt. Invalid history is
preserved for explicit reconciliation, with no new phase receipt written. These
are format and consistency checks, not authentication against hostile local writers.

Local processes serialize with an OS exclusive lock, without expiry or lock-file
deletion. Receipts are flushed, then published by an exclusive hard link. Interrupted
pending files, corrupt receipts and I/O failures require explicit reconciliation;
the tool does not discard history or assume an unknown operation never happened.
Only three phase receipts are supported. Windows directory/power-loss durability,
remote filesystems and hostile local writers are unqualified. Retain current
fencing and investigate original outcomes; this tool offers no automatic rollback
or reconciliation that could restore old authority.

## Reproducible owned qualification

Build the native fixture against the exact accepted core/dependencies, without
recompiling or substituting the product core:

```powershell
dotnet build tools/HaQualification/HaQualification.csproj -c Release -p:AcceptedRuntime=C:/owned/accepted-runtime
python scripts/test-ha-review.py C:/owned/new-evidence tools/HaQualification/bin/Release/net10.0/HaQualification.dll
python scripts/test-ha-input-bound.py C:/owned/new-bound-evidence C:/owned/new-evidence
python scripts/test-ha-journal.py C:/owned/new-journal-evidence
```

The destination must not exist. Tests retain synthetic original journals,
watermarks, exports, local review receipts, commands, process IDs, runtime/source
hashes and refusal evidence. Separate native processes exercise live binding
protection, unused recovery, connected handoff, lost-reply retries, import,
restart/stale replay, explicit unused grant return/reclaim, missing watermark and
exclusive-writer refusal. Separate Python processes exercise ordered review,
same-operation races, alternate identity refusal, missing coordination directory,
interrupted journals and malformed/partitioned/stale evidence. Assertions and
native core calls are synthetic; no DNS/DHCP listener or real adapter is launched.
The read-bound regression uses new real files below/at/above the limit, including
controlled growth/truncation after actual open. A clearly labeled real-stream
observer records the size requested by the delivered loader and actual bytes
returned. Transaction/evidence/journal refusals preserve the last safe receipt.
Stored-receipt tests use fresh CLI processes for schema/field/type/state/hash,
filename/chain and authority-history faults; they compare every journal file's
bytes and inventory before and after refusal, and retain valid progression/retry
controls. The pre-repair schema-only reproduction is separate from fixed-code QA.

External prerequisites still block only dependent real activation: authenticated
current physical fence/readback covering every serving path; bounded qualified
original-store access; complete latest native leases/offers/options/renewals;
durable original and receiver receipts; actual client continuity; a qualified
multi-host coordinator; safe native standby/rejoin and separately approved unfence.
Full HA acceptance remains open. Independent review is required for this local work.
