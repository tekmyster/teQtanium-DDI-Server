param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$repositoryPath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testProject = Join-Path $repositoryPath 'tests\Ipam.Tests\Ipam.Tests.csproj'
if (-not $SkipBuild) {
    dotnet build (Join-Path $repositoryPath 'DnsServerApp\DnsServerApp.csproj') -c Release --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
    dotnet build $testProject -c Release --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }
}
foreach ($testMode in @('', '--dhcp', '--netbox', '--transport', '--api', '--security', '--misp', '--edl', '--direct-transport', '--misp-edl-repair', '--security-analytics', '--security-ops', '--migration', '--syslog')) {
    if ($testMode) { dotnet run --project $testProject -c Release --no-build -- $testMode }
    else { dotnet run --project $testProject -c Release --no-build }
    if ($LASTEXITCODE -ne 0) { throw "DDI checks failed: $testMode" }
}
node (Join-Path $PSScriptRoot 'test-product-ux.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Product UX presentation checks failed.' }
