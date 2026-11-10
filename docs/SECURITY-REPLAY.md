<!-- Copyright (c) 2026 Tekmyster Industries, LLC. GPL-3.0; see ../LICENSE. -->
# Offline behavioral replay

`tools/SecurityReplay` processes inert local observation records through the actual reviewed `BehavioralAnalyzer.Observe` assembly. This command-line tool makes no network requests, launches no server and changes no operational policy, signal, feed, model or DHCP/recovery state. It provides heuristic replay mechanics; representative corpus qualification, empirical effectiveness and production performance remain open. The existing learned evaluator remains `served-advice-v2` at its recorded training-operation time. This tool does not reinterpret learned advice, exercise model management/fallback, evaluate indicator/policy matching or publish EDL output.

## Build and use

Use .NET 10 and an independently reviewed offline runtime directory. The tested runner is **Release**; the referenced accepted006 detector remains its exact original **Debug** assembly. It is deliberately reused, not silently recompiled as Release. The manifest binds its SHA256. No private absolute path is embedded in the project; `DetectorRuntime` is an explicit build property.

```powershell
dotnet build tools/SecurityReplay/SecurityReplay.csproj -c Release -p:DetectorRuntime="C:/owned/reviewed-runtime"
dotnet tools/SecurityReplay/bin/Release/net10.0/SecurityReplay.dll --self-test
dotnet tools/SecurityReplay/bin/Release/net10.0/SecurityReplay.dll --write-synthetic-fixture C:/owned/new-fixture
dotnet tools/SecurityReplay/bin/Release/net10.0/SecurityReplay.dll C:/owned/new-fixture/synthetic-manifest.json C:/owned/new-fixture/synthetic-psl.dat C:/owned/new-report.json
dotnet tools/SecurityReplay/bin/Release/net10.0/SecurityReplay.dll --verify-report C:/owned/new-fixture/synthetic-manifest.json C:/owned/new-report.json
```

There are no NuGet package dependencies; restore uses only the project's local `offline-packages` path and installed SDK/framework packs. The writer requires a new directory and creates invented records, labels and exposure assertions, never customer traffic or quality evidence. Fixture processing rights expire after one day. Generate a new mechanical fixture later rather than rewriting a retained input.

## Version 1 input

`ReplayManifest`, `ReplayRow`, `Exposure` and `Incident` in `Replay.cs` define the exact contract; the synthetic writer provides a complete example. Every constructor field is required, including explicit `synthetic`, booleans and nullable values. Unknown/duplicate fields, null rows and unsupported values fail. Provenance strings are limited to 2048 characters. DNS types are uppercase alphanumeric, 1–16 characters; names pass the detector's own normalization.

Supply owner/source, license, acquisition/processing/derivative/export constraints, collection method/time, privacy/consent/revocation/retention references, selection/exclusions/sampling, label provenance, feature lineage and partition protocol. The protocol freeze precedes the processing-rights check and evaluation `asOf`. Each known query-observation label (`Benign` or `Suspicious`) needs a reference and UTC availability time no later than `asOf`; `Unknown` may have null availability. Labels must be independently justified rather than copied from detector scores. Incident labels require separate case evidence. DNS/query/domain labels alone do not establish compromise or exfiltration.

These are supplied assertions and reference pointers, not authenticated permission, consent, identity or ground truth. The tool fetches no references. Independently review current rights before supplying operational data. Rights must be non-revoked and unexpired at both declared `asOf` and actual processing/publication UTC. Exact input bytes are re-read before persistence, final publication and verification disclosure. Changes/withdrawals fail closed; there is no transactional external revocation service or recall of prior consumption/exports. Existing OS permissions govern local files. No server sessions, credentials or ACL changes are introduced.

Observation, device and independent source/family/capture IDs are lowercase SHA256 assertions. Device/family groups cannot cross Train/Validation/Test; later partitions must strictly follow earlier ones in time. Rows must already be chronological; equal timestamps retain input order. Duplicate IDs and exact normalized `(device,time,query,type,NXDOMAIN)` repeats fail even with new IDs. Legitimate same-instant duplicates may therefore require documented upstream deduplication. Pseudonyms are neither authenticated identity nor anonymity. Correlated domain/source/infrastructure families, sites/views and attribution history still need deliberate grouping; new hashes cannot prove independence. Previous human tuning/final-test reuse cannot be detected by this importer.

Only Test rows enter a fresh analyzer. Train/Validation are validated/hashed but never fit, tune or warm it. The actual implementation supplies normalization, features, selected findings, sparse history, capacity eviction and sample-limit behavior. The clock is each unchanged Test observation's UTC time. Results bind input/partitions, detector/runner, raw PSL and normalized-rule/feature-definition hashes, threshold, process, runtime and clock. No learned model is used.

## Counts, exposure and delay

The unit is one Test observation. Score at or above the frozen threshold is a positive heuristic alert consumed as Monitor. A negative prediction means below-threshold; `Benign` in this binary arithmetic contract is not proof of benign traffic. Policy decisions and learned advice are explicitly Not evaluated. Monitor consumption is not blocking.

Reports reconcile known TP/FP/TN/FN, per-label abstentions, unknown positive/negative/abstained outcomes and known-label coverage. Precision is TP/(TP+FP); conditional recall TP/(TP+FN); full known-positive detection TP/(TP+FN+abstained suspicious). Zero denominators are null. Heuristic scoring never abstains: sparse/sampled flags remain visible without filtering its real decisions. The metric helper's all-abstaining fixture proves arithmetic only.

Exposure consists of independently supported complete-observation half-open UTC intervals `[start,end)`, with stable Test device, coverage label, evidence and positive duration ending by collection. Supplying any exposure requires matching labeled coverage for every Test row. Same-label overlapping/adjacent intervals are unioned per device; contradictory overlaps fail. Gaps remain unobserved. Raw inputs are hashed; normalized unions are retained. Device-days sum unioned device-seconds/86400, never row counts, dates or first/last event span. Missing exposure leaves rates null. Quiet time contributes only with independent coverage evidence.

The FP numerator counts repeated benign per-record alerts, without incident deduplication. Both FP/all observed device-days and FP/benign observed device-days are reported with exact denominators. Unknown/suspicious coverage cannot inflate benign exposure.

Incident delay uses supplied device, normalized registrable domain, onset/end, uncertainty and case-label reference. Null onset is explicit. Matching includes only suspicious Test records for that device/domain within `[onset,end)`. The first qualifying alert determines event-time delay only when complete supplied suspicious coverage spans the whole horizon. Otherwise delay is null. Reports retain horizon, observed follow-up, first observed detection, onset uncertainty, missed/unobserved cases, censoring and pre-onset alert counts. Pre-onset alerts never produce negative delay; no detected-only summary conceals misses.

## Bounds and retained results

Input caps are 16 MiB manifest, 4 MiB PSL, 10000 rows/exposures and 1000 incidents. Stream reads enforce actual growth limits; JSON depth is bounded at 64. The actual analyzer retains 4096 streams and 512 samples. One CLI run is serial with no background queue/spawning. Loop boundaries check cancellation and a 60-second cooperative evaluation budget. Parsing/bounded serialization are not preemptively interrupted. Ctrl+C cancels. There is no global cap across separately launched CLI processes or hard memory/time SLA.

A report is at most 32 MiB, written exclusively to `<output>.pending`, flushed, input/rights rechecked, then renamed without overwriting. Failed replacement preserves the last report; one pending file may remain per requested output. Startup never loads/resumes/publishes it. Operators inspect their exact owned artifacts before choosing a new output or resolving pending work. There is no retention daemon, automatic cleanup, secure erase or rollback promise. The caller controls approved private storage/ACLs/retention. Hashes do not erase retained pseudonymous records.

The version 1 envelope hashes compact .NET JSON serialization of its `payload`. Verification checks envelope/protocol integrity and currently permitted exact input bytes before printing a summary. Reports omit queries and retain hashed domains/devices plus necessary outcomes/coverage. Caller-supplied provenance references must exclude secrets. Integrity is not publisher authenticity.

Content-derived `runId` binds input, runner, detector, PSL and protocol; each process attempt has a distinct `attemptId`. Reuse never becomes a new unseen test. A fresh OS process starts empty and executes only when invoked. Reports persist as files; semantic reproduction excludes actual process/attempt IDs and timings. Expired/withdrawn rights legitimately prevent later new processing.

Throughput measures the actual monotonic analyzer loop plus receipt construction, excluding import/validation/report I/O. Imported/processed/not-replayed/dropped counts, serial concurrency and cold state are explicit; JIT/cache warmness is uncontrolled. Finite offline rows/second does not establish production DNS QPS, tail latency, availability or an SLA. No packet/resolver/provider/model/feed/DHCP/recovery test is included.

No representative authorized labeled replay corpus with measured exposure/onset and current rights evidence was identified in the accepted tracked filename inventory, accepted security/predictive documentation and supplied accepted006 audit report inspected here. This says nothing about uninspected locations. Empirical claims remain suspended pending a specifically authorized corpus and independently reviewed frozen protocol. Synthetic metrics/check counts establish mechanics only.
