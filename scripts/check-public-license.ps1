# SPDX-License-Identifier: GPL-3.0-only
# Public release guard; contains no private implementation.
param([string]$RepositoryRoot=(Join-Path $PSScriptRoot '..'), [switch]$SourceOnly)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $RepositoryRoot).Path
if (-not $SourceOnly -and (Test-Path -LiteralPath (Join-Path $root 'PUBLICATION-HOLD.txt'))) {
    throw 'Public publication is on hold by owner instruction. Private builds may continue; public packaging is blocked.'
}
$inventory=Join-Path $root 'PRIVATE-FILES.txt'
if (-not (Test-Path -LiteralPath $inventory)) { throw 'Private file inventory is missing.' }
$privateEntries=@(Get-Content -LiteralPath $inventory | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })
# Inventory records exclusions; reject any inventoried implementation actually present below.
$files=@(& git -C $root -c core.quotePath=false ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect repository files for public packaging.' }
$presentPrivate=@($files | Where-Object { $_ -cin $privateEntries })
if ($presentPrivate.Count) { throw ('Inventoried private files present: ' + ($presentPrivate -join ', ')) }
if ($SourceOnly) {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $root 'COMMUNITY-SOURCE.json') | ConvertFrom-Json
    foreach ($entry in $manifest.sourceHashes.PSObject.Properties) {
        $content=[IO.File]::ReadAllText((Join-Path $root $entry.Name)).Replace("`r`n","`n")
        $actual=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($content))).ToLowerInvariant()
        if ($actual -cne $entry.Value) { throw ('Reviewed source hash mismatch: ' + $entry.Name) }
    }
    $changed=@(& git -C $root diff --name-only $manifest.baseline --)
    $changed+=@(& git -C $root ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot verify publication scope.' }
    foreach ($path in $changed) {
        if ($path -cnotin $manifest.allowedChanges) { throw ('Unreviewed publication path: ' + $path) }
    }
}
$existingGpl=@('Tectanium.WindowsService/Program.cs','Tectanium.WindowsService/Tectanium.WindowsService.csproj')
$blocked=[System.Collections.Generic.List[string]]::new()
foreach ($relative in $files) {
    $privatePath=$relative -cmatch '^(Apps/(?:Tectanium|teQtanium)\.[^/]+(?:/|$)|(?:Tectanium|teQtanium)\.[^/]+/|DnsServerCore/(?:.*/)?Tectanium/|docs/tectanium/|docs/enterprise/|packaging/tectanium/)'
    if ($privatePath -and $relative -cnotin $existingGpl) { $blocked.Add($relative); continue }
    $path=Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    # The unchanged historical edition-terms document is metadata, not implementation.
    # Pin its exact normalized bytes; an edit must receive a new provenance review.
    if ($relative -ceq 'LICENSE.md') {
        $text=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
        $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))).ToLowerInvariant()
        if ($hash -cne '90ab0d40eef3ad2ce35185a37faaf02fac057b417b788b49049013d871cdac79') { throw 'Edition terms changed; provenance review required.' }
        continue
    }
    $stream=[IO.File]::OpenRead($path)
    try {
        $bytes=[byte[]]::new(2048)
        $length=$stream.Read($bytes,0,$bytes.Length)
        $head=[Text.Encoding]::UTF8.GetString($bytes,0,$length)
        if ($head -match '(?im)^\s*(?://|#|/\*|\*|<!--)?\s*Copyright[^\r\n]*Tekmyster[^\r\n]*All Rights Reserved' -or
            $head -match '(?im)^\s*(?://|#|/\*|\*|<!--)?\s*Proprietary and Confidential') {
            $blocked.Add($relative)
        }
    } finally { $stream.Dispose() }
}
if ($blocked.Count) { throw ('Private or unclassified source cannot enter public packages: ' + (($blocked | Sort-Object -Unique) -join ', ')) }
Write-Output 'Public license guard passed.'
