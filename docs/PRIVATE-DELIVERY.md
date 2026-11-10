<!-- Modified by Tekmyster Industries, LLC — remains GPL-3.0 -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Private portable delivery runbook

This alpha workflow installs versioned application payloads in a new explicitly owned root. It does not register a service, change accounts/credentials/ACLs/firewalls/trust/registry or install global dependencies. Use Python 3.12+, .NET 10 for portable payloads, and PowerShell 7 on Windows for detached CMS verification. Native self-contained payloads still need the operating system's native libraries. Run under the existing authorized operator identity. No public binary release or production deployment is authorized by these files.

## Release gates

Every archive contains `delivery.json`, full per-file hashes, exact source/raw/canonical/dependency/package-graph provenance, runtime, version and compatibility policy. These checks prove integrity relative to reviewed inputs; they are not publisher authentication. Detached CMS signs the complete ZIP bytes. Require a legitimate owner-authorized code-signing certificate, pinned thumbprint, trusted chain, current validity and online revocation. No certificate, trust-store change, private-key export or revocation bypass is part of this workflow. There is no timestamp service integration: signatures must validate at verification time; durable archival signature validity is unqualified. The inspected local references supplied no usable signer. Unsigned development results cannot qualify signed delivery.

Production completeness remains blocked: the required newer primary served-static manual IPAM overlay `c1ab5aa345ec4d7f` and security-session overlay `f45fdea720309cb4` are not inputs to the accepted base. The package does not claim to contain them. Obtain Manager-supplied immutable integration inputs, preserve and independently qualify them before any coherent release; never replace the live webroot wholesale with this package.

The supported local data contract is engine 15.6.1 / net10.0, data epoch 1. Package alpha versions distinguish package revisions, not different engine schemas. Upgrade must increase the package version. Only the immediate prior compatible release can be selected for explicit rollback. Other engine/data epochs, historical migrations and arbitrary downgrade are refused or unqualified. Recovery automation stays Disabled; protection/DNS Monitor and DHCP Observe are preserved, not activated by packaging. Licensing never controls DNS/DHCP operation.

## Build and verify

From a clean canonical private source checkout, use the sibling accepted `TechnitiumLibrary/bin` and pinned offline NuGet directory. `scripts/build-private-delivery.py` records complete raw/canonical source and input dependency hashes, restores only that offline directory, publishes into a new immutable output, ships the delivery scripts and this runbook, and creates a deterministic ZIP. Example:

```powershell
python scripts/build-private-delivery.py --output C:/private-build/revision001 --packages C:/private-inputs/offline-packages --runtime portable-net10.0 --version 0.1.0-alpha.1
```

Use `--runtime linux-x64` for a self-contained Linux x64 payload, with pinned .NET/ASP.NET runtime packs 10.0.13 available in the offline directory. Windows-native self-contained builds may use `win-x64`, but require their own actual execution. No macOS/ARM/service-manager qualification follows from this command. Repeating the same clean inputs, toolchain and absolute build paths produces pre-sign identical ZIP bytes (fixed entry timestamps/order/modes); reproduce and compare SHA256. Compiler absolute paths/SDK/Git metadata and restored graphs matter. Cross-path/compiler reproducibility is not claimed. Preserve raw CRLF/LF bytes independently from canonical Git blobs. The opaque accepted Technitium dependency DLLs remain pinned prebuilt inputs, not rebuilt provenance.

On a legitimately provisioned Windows signing host, sign and verify without exporting keys:

```powershell
pwsh -NoProfile -File scripts/private-delivery-signature.ps1 -Mode Sign -Archive C:/private-build/release.zip -Signature C:/private-build/release.zip.p7s -Thumbprint OWNER_PROVIDED_40_HEX_THUMBPRINT
python scripts/private-delivery.py verify C:/private-build/release.zip --signature C:/private-build/release.zip.p7s --thumbprint OWNER_PROVIDED_40_HEX_THUMBPRINT
```

The signature helper accepts `-Store LocalMachine` only when that legitimate identity is already authorized and accessible. Protect the external pinned identity and reviewed tooling. This is not a defense against a local operator able to replace the verifier or its trust policy. The signed workflow currently requires Windows PowerShell 7 verification; Linux CMS trust integration is unqualified. Do not apply `--allow-unsigned-development` to release qualification. That explicit flag exists only for isolated development fixtures and always reports `signed: false`.

## Fresh installation

Choose a new absolute install root on a local filesystem. `init` refuses an existing path; do not use the old root or a production directory. The layout is `releases/<archive-sha256>/` for code/assets, `data/` for live configuration and `current.json` for the atomic version selection. The root also retains exact ZIPs, verification receipts and interruption journals. Reparse/symlink paths are rejected. Budget at least four archive sizes plus 32 MiB staging headroom; decompressed payload limits are 1 GiB, 6,000 entries and 256 MiB per file, with bounded path length/depth. All package entries and manifest entries must correspond exactly. Missing, extra, duplicate, reserved, traversing and case-alias paths are refused.

```powershell
python scripts/private-delivery.py init C:/private-lab/install001
python scripts/private-delivery.py stage C:/private-lab/install001 C:/private-build/release.zip --signature C:/private-build/release.zip.p7s --thumbprint OWNER_PROVIDED_40_HEX_THUMBPRINT
python scripts/private-delivery.py activate C:/private-lab/install001 ARCHIVE_SHA256 --expected-generation 0
```

Preconfigure only the new benign fixture with loopback high DNS/web ports before native launch. Use an existing approved credential mechanism for an actual deployment; the fixture uses a new random process-local `DNS_SERVER_ADMIN_PASSWORD_FILE`, never an existing production credential change. An unconfigured upstream engine may otherwise use default credentials/listeners. The installer does not infer safe network defaults or expose an uninitialized server. Start the exact selected payload through the owned launcher:

```powershell
python scripts/private-delivery.py run C:/private-lab/install001
```

Inspect the actual PID/release/root and exact runtime/core hash. Verify fresh login, required read/modify privileges and current identity/listeners/settings separately from authoritative UDP and TCP NoError+AA answers containing the expected record. Test every required authorized management source path; local loopback tests do not qualify remote paths. For any separately authorized future credential/access change, keep the original session until a separate fresh affected-source session verifies authentication, privileges and target-observed source, then verify the actual intended outcome. No such access change is authorized here.

## Upgrade and rollback

Stage the new verified package while the old owned process runs. Staging does not change selection or touch live data. Keep current data, encrypted backups and independently retained backup keys; retain endpoint trust/spool and authority files in place. Inventory exact hashes plus semantic state before cutover. Packaging fixtures place inert authority sentinels outside native authority filenames; their preservation is not a DHCP authority operation or packet test.

Before activation, ensure lease continuity and a separately qualified DNS continuity design for any real deployment. Stop only the owned application and observe its exit. The launcher holds `run.lock` and records `process.json`; activation refuses a running or unresolved process record. If a launcher dies, retain its record, inspect the owned PID/start identity and verify actual child exit. Never delete the record just to bypass a live/unproven process. External services/processes not launched here are unsupported; do not point this tool at an existing service root.

Activate the new release with the exact observed `current.json` generation. A mismatched generation, same/lower version, changed payload, missing signature, incompatible contract or pending transaction is refused. Kernel file locks serialize stage/cutover and release after process exit. `transition.json` is flushed before pointer cutover; `previous.json` retains rollback selection. No data migration or stale-data restore occurs. The launcher revalidates the complete staged payload against the retained exact package and signature before executing it.

If a command loses its reply or dies, run `reconcile ROOT`, inspect `current.json`, retained reconciled receipt and complete package hashes. A prepared transition with the old pointer means not applied; the new pointer means committed. Reconciliation neither launches a service nor restores data. Repeating discovery does not apply anything twice. Unexpected state fails closed with evidence retained. These are process-interruption checks; directory-fsync, storage-controller behavior, host power-loss and durable filesystem guarantees remain unqualified.

After successful native startup, verify fresh management privilege, actual configuration/DNS records, modes/key-lock state as applicable, authoritative DNS, authority boundary and shipped assets. If it fails, stop the new owned process and select only the immediate previous compatible release:

```powershell
python scripts/private-delivery.py rollback C:/private-lab/install001 PREVIOUS_ARCHIVE_SHA256 --expected-generation CURRENT_GENERATION
```

Restart and verify that prior code reads the current data. Rollback changes application selection only. Never restore an older owner journal, erase permanent grants, create an alternate recovery ID or blindly unfence. An incompatible or uncertain data schema needs separate reviewed recovery; binary rollback alone cannot repair it. An unresolved access check requires retaining the original administrative session and safely correcting/rolling back within its authorized scope.

## Bounded qualification and recovery limits

`scripts/test-private-delivery.py` requires exact old/new archives, a synthetic `dns.config` seed bound to an owned loopback high port, and a new output directory. It records cold startup, live staging/refusal, lock/version failures, ordinary write obstruction, actual installer-process kills before/after pointer cutover, committed lost-reply discovery, fresh native upgrade/rollback processes, data hash preservation, archive/staged tampering and unsafe paths. Finite authoritative DNS and management workloads report offered/correct/error counts, duration, concurrency and latencies. No recursive/external DNS or production load is used. Read the sealed `RESULT.json` for actual platform and outcomes; a build or runbook alone proves none of them.

Target DNS stops during single-process cutover. Before/during/after samples are correctness evidence, not continuous availability or an RTO/SLA. Load is a small local sanity measurement, not enterprise capacity. The code rollback drill retains current configuration, with preimage hashes and retained data evidence; full same-node disaster restoration has not been delivered. Portable encrypted backup support remains bounded standalone restore/startup rollback/fresh retry/historical receipt; persistent key management, forward resume, online quorum/membership replacement, console scheduling, DHCP packet continuity, power-loss and production qualification stay open. Do not run stopped/excluded authority harnesses to fill these gaps.

No automatic uninstall or purge is provided: roots retain configuration, leases/authority, credentials, packages and receipts for review. Stop/verify only the exact owned process; retain private evidence. Do not recursively delete shared/unknown resources or remove live data. Future manifest-owned app removal needs a separately qualified implementation. No cleanup of excluded resources is authorized.
