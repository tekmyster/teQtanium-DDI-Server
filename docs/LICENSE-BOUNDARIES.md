# License boundaries

## Scoped source publication authorization

Owner authorization on 2026-10-18 permits publication of the reviewed GPL LLM/dashboard v2 source identified in docs/COMMUNITY-PUBLICATION.md and COMMUNITY-SOURCE.json to the community and private repositories. This supersedes the blanket source hold only for that frozen change set and its publication policy. All other pending changes remain private. Public binary packaging and release assets remain on hold; private implementations and operational evidence must never enter public history or artifacts. Preserve GPL notices and run the public source guard.

Keeping modifications unpublished is separate from their license: upstream modifications retain GPL-3.0 notices and applicable distribution obligations. Do not replace those notices with proprietary headers. Independently authored private extensions follow the new-file rules below.

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

`scripts/check-public-license.ps1` rejects private inventory entries, new files in reserved private paths, and private notices in source candidates before public packaging. The existing GPL Windows wrapper is explicitly allowed. This is a publication guard, not a determination of legal independence or a license-provenance audit of every historical file. Do not bypass it to distribute a private extension; use a separate private repository and release pipeline.
