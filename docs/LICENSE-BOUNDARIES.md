# License boundaries

## Publication scope

The Manager has authorized reviewed eligible community GPL source for the PUBLIC community repository, `tekmyster/teQtanium-DDI-Server`. Private commercial publication is authorized only to `tekmyster/teQtanium-DDI-Server-private`, with explicit PRIVATE visibility verification before EACH private push. This supersedes the earlier blanket public hold. `PUBLICATION-HOLD.txt` now records this scope and retains a public binary hold. A task still needs publication authorization; this documentation reconciliation performs no publication. Previously granted licenses are not revoked.

Keeping modifications unpublished is separate from their license: upstream modifications retain GPL-3.0 notices and applicable distribution obligations. Do not replace those notices with proprietary headers. Private development follows the new-file rules below; independent authorship, a private header or a folder alone does not establish an independently licensable work. Private DHCP Q, secrets, deployment inventory, captures, evidence and sensitive third-party archives are excluded from public history, source packages and CI.

The root LICENSE remains GNU GPL-3.0. This policy records the owner's instructions for future private development; it does not change licenses already granted or grant an exception to upstream GPL obligations.

## Upstream and existing GPL files

Every file present in Technitium DNS Server at fork time, and every modification to those files, remains GPL-3.0. Preserve original copyright headers and license notices. Moving, renaming, or wrapping GPL code does not change its license. Do not copy GPL implementation into private files.

Previously published GPL files also retain their existing license. In particular, these existing Windows service files are part of the public GPL application, not newly created private files:

- `Tectanium.WindowsService/Program.cs`
- `Tectanium.WindowsService/Tectanium.WindowsService.csproj`

These files were already present at commit `e59c2ed4ba7d6a483ab3e94d6e4b91c62a912cc3`. This is a specific historical exception to the new-file path rule, not permission to add private code to that project.

## Domain A paths

Preserve GPL notices in existing upstream files and their modifications under `DnsServerCore/**`, `DnsServerCore.ApplicationCommon/**`, `DnsServerCore.HttpApi/**`, `DnsServerApp/**`, `DnsServerWindowsService/**`, `DnsServerSystemTrayApp/**`, `DnsServerWindowsSetup/**`, `DnsServer.sln`, `Dockerfile`, `docker-compose.yml`, and `scripts/**`. Only newly authored independent files in explicitly nested commercial paths can be considered for Domain B; a path alone does not establish independence.

## New private files

New original files created in the following paths are designated private by the owner:

- `Apps/Tectanium.*/**`
- `Tectanium.*/**`
- `Apps/teQtanium.*/**` and `teQtanium.*/**` (new spelling; the same rules apply)
- `DnsServerCore/**/Tectanium/**`
- `docs/tectanium/**`
- `docs/enterprise/**`
- `packaging/tectanium/**`

Files explicitly bearing the owner's All Rights Reserved header are also private, regardless of path. Add this exact notice at the top of each new private file, using comment delimiters required by its format:

```text
// Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.
// teQtanium Private Commercial — Free for Homelabs & Non-Profits under LICENSE.md Domain B
// Enterprise use 250+ IPs / 5k qps requires commercial license.
// Contact: licensing@tekmyster.com | Non-profits: nonprofits@tekmyster.com | https://tekmyster.com
```

Record every new private file by repository-relative path in PRIVATE-FILES.txt and add a corresponding entry to THIRD-PARTY-NOTICES.md. Keep its source and binaries out of public Git history, source archives, containers, installers, and release assets. The path inventory contains no private implementation.

Never gate DNS/DHCP operation on a license result; licensing feedback is a banner only. For uncertain GPL provenance, retain GPL and add `// Modified by Tekmyster Industries, LLC — remains GPL-3.0` in the source comment syntax.

Never add this notice to upstream modifications or previously GPL-distributed files. If provenance is uncertain, preserve/default to GPL-3.0 and ask the owner before creating a private implementation.

## Integration and release checks

Private extensions should be independent services communicating through an API, without copied GPL logic. A folder, header, or interface call alone does not establish a separate licensed work. In-process linking and plugins require review of GPL obligations before distribution. See the [GNU license FAQ on combined programs and aggregation](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation).

`scripts/check-public-license.ps1 -PublicationScope CommunitySource` rejects missing/malformed/duplicate private inventories and any inventoried private file actually present in the candidate, reserved private paths, private notices, compiled/archive material and operational-data paths in the source candidate. It includes ignored working files, so run it on a clean isolated publication snapshot. Public binary packaging must request `PublicBinary`, which is held by policy. The policy file must explicitly authorize the requested scope. The existing GPL Windows wrapper is explicitly allowed. This is a publication guard, not a determination of legal independence or a license-provenance audit of every historical file. Do not bypass it to distribute a private extension; use a separate private repository and release pipeline.

The guard requires PowerShell 7, Git and Python 3.12 or newer. It validates an isolated staged publication snapshot, not the private development tree. Retain normalized relative private inventory entries for files excluded from that snapshot; they are not permission to include those files. PUBLIC-SOURCE-PROVENANCE.json must cover exactly the candidate files with canonical Git byte hashes, declared GPL/third-party/branding/inherited-font classification and an immutable inherited origin or the bounded documentation review origin. Git text CRLF/LF normalization is allowed only with matching canonical staged content and its declared hash; complete raw source hashes must be frozen separately for review. Staged-deleted, untracked, opaque, symlink/reparse and escaping paths are rejected. Existing branded PNG/JPEG/ICO/GIF/BMP assets require explicit classification; they are not executable outputs. Existing bundled font binaries require their exact inherited path, original canonical hash and font-format signature; this does not admit new fonts or modify their third-party licensing notices.

Provenance declarations are reviewed inputs, not authenticated reviewer signatures or proof that a historical file is independently licensable or free of secrets. Inherited origin cannot override private inventory, path or notice gates. Freeze the exact manifest, candidate and independent review before later publication. The guard recognizes opaque/archive/executable formats conservatively; it does not inspect archive contents, arbitrary embedded payloads, remote hosting visibility, all secret formats or legal license independence. It produces no publishable output and performs no upload. PublicBinary always fails closed under the current policy. Private repository visibility must be verified separately, immediately before each private push; the repository name and an old check are insufficient.

Inherited provenance requires the declared immutable base objects in Git. Source CI uses a full-history checkout (`fetch-depth: 0`); a shallow checkout without those objects must fail closed. Fetch the missing history and verify the exact candidate identity before retrying. Neither a manifest edit nor accepting missing blobs is a substitute for that verification.
