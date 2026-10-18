# Reviewed community source publication

Owner authorization dated 2026-10-18 permits this reviewed GPL source publication to community and private GitHub repositories. It supersedes the previous blanket source hold only for this change set. Public binaries and release assets remain on hold. All other pending work remains private.

The source derives from public baseline `e58c1927468d1dfeca6e362396689a3b892b5a53` plus the independently accepted LLM/dashboard v2 patch, SHA256 `ac71bce94cb7c4db1289e65fecd9c8642ab614931477cafffd3f8df241b0838c`. `COMMUNITY-SOURCE.json` records the exact reviewed source files and publication-policy paths. Existing GPL notices and upstream attribution remain in force; newly added server and test files are GPL-3.0, not proprietary.

The change adds the ordinary LLM connector configuration/test path and aggregate node-local operations dashboard: reported token usage, request outcomes, latency percentiles and explicit retention/coverage limits. Saved configuration and historical connection observations remain separate. Dashboard permissions restrict individual sections. It does not establish security enforcement, MISP/EDL qualification, GPU capacity or cluster totals.

Independent QA accepted the frozen source and exercised benign connector, metrics, permission, TLS, packaged asset and desktop/mobile states. This publication does not rerun production activation or claim acceptance of unrelated pending features. Alternate themes, full screen-reader traversal and high-volume soak remain unverified. Local build and benign regression results are recorded with the publication commit.

No private DHCP Q implementation, operational configuration, credential, inventory, capture, deployment evidence or binary is included. `PRIVATE-FILES.txt` remains an exclusion inventory. The source guard rejects inventoried implementations, reserved private paths and private headers. With `-SourceOnly` it additionally verifies reviewed source hashes and allowed changed paths. Default packaging remains blocked by `PUBLICATION-HOLD.txt`; CI for this source branch uploads no artifacts.

Source hashes normalize CRLF to LF for cross-platform checkouts. The unchanged historical LICENSE.md edition-terms document is explicitly hash-pinned as licensing metadata; its text is not an exception for any private implementation or a reclassification of GPL components. THIRD-PARTY-NOTICES.md and LICENSE-BOUNDARIES.md continue to qualify those terms. An edited edition-terms document fails this guard pending provenance review.

Publication validation (2026-10-18): isolated Release application and dependency build passed with 0 warnings/errors; test project build passed; 18 benign connector checks and 36 telemetry checks passed; shared presentation/syntax contract passed. No external model was called in these checks. Private repository Actions are disabled; public source-branch CI runs only the source guard and uploads no artifacts.
