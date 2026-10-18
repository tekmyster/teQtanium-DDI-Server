# Project requirements

## License boundary

Company: Tekmyster Industries, LLC. Product spelling: teQtanium. Keep all existing GPL notices. License failure must never stop DNS/DHCP; banner feedback only. See LICENSE.md for the requested edition terms, subject to the GPL scope in THIRD-PARTY-NOTICES.md.

Owner authorization on 2026-10-18 permits publication of the reviewed GPL LLM/dashboard v2 source identified in docs/COMMUNITY-PUBLICATION.md and COMMUNITY-SOURCE.json to the community and private repositories. This supersedes the blanket source hold only for that frozen change set and its publication policy. All other pending changes remain private. Public binary packaging and release assets remain on hold; private implementations and operational evidence must never enter public history or artifacts. Preserve GPL notices and run the public source guard.

Read [LICENSE-BOUNDARIES.md](docs/LICENSE-BOUNDARIES.md) before creating or moving files. All upstream files and modifications remain GPL-3.0; preserve original copyright headers and license notices. Never relabel previously GPL-distributed files as proprietary.

New original files in `Apps/Tectanium.*`, `Tectanium.*/**`, `DnsServerCore/**/Tectanium/**`, `docs/tectanium/**`, `docs/enterprise/**`, and `packaging/tectanium/**` belong to the owner's private commercial domain. Add the exact private header specified in LICENSE-BOUNDARIES.md and inventory each file in PRIVATE-FILES.txt and THIRD-PARTY-NOTICES.md. Never copy GPL code into private files. For uncertain provenance, retain GPL-3.0 and add `// Modified by Tekmyster Industries, LLC — remains GPL-3.0` using the file comment syntax. Use independent service/API boundaries for private extensions; an in-process interface does not establish a GPL exception.

Do not publish private source or binaries to the public repository or public releases. Run `scripts/check-public-license.ps1` before public packaging. Existing GPL Windows service files listed in LICENSE-BOUNDARIES.md retain their current license despite their directory name.

Apply the [product UX contract](docs/PRODUCT-UX.md) to every user-facing feature, including the existing console, dialogs, integrations, error messages and public DNS setup page. Keep service/API identifiers and behavior separate from presentation. Complete the quality gate in that contract before declaring a UI change complete.

## Administrative access changes

Standing user requirement: "ACL or credential changes will require a successful new-session check before I close the original session."

Keep the original working administrative session open while changing ACLs, management-access firewall rules, or credentials. After the change, establish a separate fresh session from the affected authorized source using the intended credentials, and verify authentication and required administrative privileges before closing the original session. When source restrictions matter, verify the source address seen by the target and test the required authorized access paths; explicitly report any untested paths.

An existing session, an open TCP port, or an SSH banner does not satisfy the new-session check. A successful login alone does not prove that configuration changes or the intended repair succeeded; verify and report those outcomes separately.

If the fresh-session check fails, retain the original session and correct or safely roll back the change before disconnecting. Do not intentionally close the original session while access validation remains unsuccessful.

## Verified change delivery

Standing user requirement: compile changes, update GitHub and update the production teQtanium deployment as changes are made. Deliver each coherent change set after the relevant build and checks pass. Stage verified immutable binaries, back up current configuration and lease authority, maintain DNS availability through a validated DNS-only standby where needed, preserve DNS/DHCP settings, and verify fresh administrative access and service behavior after deployment. Do not run the fresh-install packages over an existing production installation. The administrative-session requirement above continues to apply to any access or credential change.
