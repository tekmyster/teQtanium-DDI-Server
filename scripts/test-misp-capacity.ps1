# Modified by Tekmyster Industries, LLC — remains GPL-3.0
param([switch]$SkipBuild, [string[]]$Profiles = @('observed','boundary','expansion','dense','budget','edl','edl-budget','cancel','duplicate','empty','slow-header','observed-slow','timeout'))
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $sourceRoot 'tests/Ipam.Tests/Ipam.Tests.csproj'
if (-not $SkipBuild) {
    dotnet build $project -c Release --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Capacity fixture build failed.' }
}
foreach ($profile in $Profiles) {
    dotnet run --project $project -c Release --no-build -- --misp-capacity $profile
    if ($LASTEXITCODE -ne 0) { throw "Ordinary capacity profile failed: $profile" }
}
# This entry point deliberately does not invoke the separately gated security-review fixtures.
