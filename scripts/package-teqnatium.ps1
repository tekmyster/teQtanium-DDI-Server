param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$')][string]$Version,
      [ValidateSet('portable','win-x64','linux-x64','linux-arm64')][string]$Runtime='portable')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
& (Join-Path $root 'scripts/check-public-license.ps1') -RepositoryRoot $root -PublicationScope PublicBinary
$output=Join-Path $root "artifacts/packages/$Version"
$payload=Join-Path $output $Runtime
if (Test-Path -LiteralPath $payload) { throw 'Use a new output directory for an immutable package.' }
New-Item -ItemType Directory -Path $output -Force | Out-Null
$arguments=@('publish',(Join-Path $root 'DnsServerApp/DnsServerApp.csproj'),'-c','Release','--nologo','-o',$payload)
if ($Runtime -eq 'portable') { $arguments+=@('--self-contained','false','-p:UseAppHost=false') }
else { $arguments+=@('-r',$Runtime,'--self-contained','true') }
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw 'Application publish failed.' }
if ($Runtime -eq 'win-x64') {
    $servicePayload=Join-Path $output 'windows-service'
    & dotnet publish (Join-Path $root 'Tectanium.WindowsService/Tectanium.WindowsService.csproj') -c Release -r win-x64 --self-contained true --nologo -o $servicePayload
    if ($LASTEXITCODE -ne 0) { throw 'Windows service publish failed.' }
    Copy-Item -Path (Join-Path $servicePayload '*') -Destination $payload -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root 'packaging/windows-service.ps1') -Destination $payload
}
# The upstream service/start templates refer to Technitium paths; distribute branded launchers instead.
foreach ($legacy in @('start.sh','start.bat','systemd.service','openrc.service')) {
    $path=Join-Path $payload $legacy
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
Copy-Item -LiteralPath (Join-Path $root 'LICENSE'),(Join-Path $root 'THIRD-PARTY-NOTICES.md'),(Join-Path $root 'packaging/INSTALL.md'),(Join-Path $root 'packaging/check-service.py') -Destination $payload
if ($Runtime -eq 'portable') {
    Copy-Item -LiteralPath (Join-Path $root 'packaging/start.sh'),(Join-Path $root 'packaging/start.cmd') -Destination $payload
}
$extension=if ($Runtime -eq 'win-x64') { 'zip' } else { 'tar.gz' }
$archive=Join-Path $output "teQtanium-$Version-$Runtime.$extension"
& python (Join-Path $root 'packaging/package.py') $payload $archive --version $Version --runtime $Runtime
if ($LASTEXITCODE -ne 0) { throw 'Package validation failed.' }
if ($Runtime -eq 'portable') {
    & python (Join-Path $root 'packaging/package.py') $payload (Join-Path $output "teQtanium-$Version-portable.zip") --version $Version --runtime $Runtime
    if ($LASTEXITCODE -ne 0) { throw 'Portable ZIP failed.' }
}
Write-Output $archive
