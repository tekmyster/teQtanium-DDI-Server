# Build teQtanium DDI Server

Install the .NET 10 SDK, Node.js, PowerShell 7, Git and Python 3.12 or newer. The publication guard uses Python standard-library code and fails closed if that runtime is unavailable. Check out this repository and its pinned library dependency as sibling directories:

```sh
git clone https://github.com/tekmyster/teQtanium-DDI-Server.git
cd teQtanium-DDI-Server
# Replace YOUR_REVIEWED_COMMIT with the accepted immutable revision.
git checkout YOUR_REVIEWED_COMMIT
git clone https://github.com/TechnitiumSoftware/TechnitiumLibrary.git ../TechnitiumLibrary
git -C ../TechnitiumLibrary checkout 6715bf04c0a39938792cfee4d2654c5f368a1034
```

With PowerShell 7:

```powershell
./scripts/build-ddi.ps1
./scripts/test-ddi.ps1
./scripts/check-public-license.ps1 -PublicationScope CommunitySource
# Public binary packaging remains held; do not invoke a release pipeline for source-only authorization.
```

Other package targets are win-x64, linux-x64 and linux-arm64. The Windows service is built from Tectanium.WindowsService. The package scripts describe candidate formats; they do not establish available public releases. Public binary jobs remain disabled by policy. Private validation uses disposable hosts without publishing artifacts. Private source pushes require explicit PRIVATE visibility verification before every push; the community-source guard does not perform that remote check. See [installation](packaging/INSTALL.md).

The library reference and engine assembly identity are compatibility dependencies. Their technical identifiers and required legal notices remain intact while product branding/versioning use teQtanium.

Before a source-scope guard check, prepare a clean isolated candidate and stage only the exact reviewed files plus its reviewed PUBLIC-SOURCE-PROVENANCE.json. Do not generate provenance declarations as a substitute for review. No private implementation, deployment data, build output or archive belongs in that snapshot. The guard compares actual candidate content with declared canonical Git hashes and index content; a PASS is not authorization to publish binaries, merge or deploy.

Keep full Git history available for the guard: inherited provenance is verified against immutable ancestor blobs. The community-source CI checkout uses `fetch-depth: 0`. In an existing shallow clone, fetch the missing history with `git fetch --unshallow --no-tags origin`, verify the intended HEAD is unchanged and rerun the guard. Missing base objects must remain a rejection; do not rewrite provenance to bypass them. Run `python scripts/test-public-source-guard.py --output PRIVATE_NEW_DIRECTORY --ci-checkout-regression` to reproduce the shallow rejection and successful full-history check on a local clone of the exact committed source.
