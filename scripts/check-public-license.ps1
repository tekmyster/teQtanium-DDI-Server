# SPDX-License-Identifier: GPL-3.0-only
# Run only against an isolated exact staged publication candidate; never publishes.
param(
    [string]$RepositoryRoot=(Join-Path $PSScriptRoot '..'),
    [Parameter(Mandatory=$true)][ValidateSet('CommunitySource','PublicBinary')][string]$PublicationScope
)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Publication guard requires PowerShell 7, Git and Python 3.12 or newer; no publication is allowed.' }
$pythonCommand=$null
foreach ($name in @('python','python3')) {
    $candidate=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        & $candidate.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 2)' 2>$null
        if ($LASTEXITCODE -eq 0) { $pythonCommand=$candidate.Source; break }
    }
}
if (!$pythonCommand) { throw 'Publication guard requires Python 3.12 or newer on PATH (python or python3), plus Git. Install the supported runtime before checking a candidate; no publication is allowed.' }
& $pythonCommand (Join-Path $PSScriptRoot 'check_public_source.py') --root $RepositoryRoot --scope $PublicationScope
if ($LASTEXITCODE -ne 0) { throw 'Publication scope/provenance guard rejected this candidate.' }
