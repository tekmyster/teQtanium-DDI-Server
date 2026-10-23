# Modified by Tekmyster Industries, LLC — remains GPL-3.0
# SPDX-License-Identifier: GPL-3.0-or-later
param(
 [Parameter(Mandatory)][ValidateSet('Sign','Verify')][string]$Mode,
 [Parameter(Mandatory)][string]$Archive,
 [Parameter(Mandatory)][string]$Signature,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Thumbprint,
 [ValidateSet('CurrentUser','LocalMachine')][string]$Store='CurrentUser'
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$content=[Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Archive)))
$cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$true)
function Assert-Identity($cert) {
 if ($cert.Thumbprint -ne $Thumbprint) { throw 'Unexpected release signer.' }
 if (@($cert.EnhancedKeyUsageList.ObjectId.Value) -notcontains '1.3.6.1.5.5.7.3.3') { throw 'A code-signing identity is required.' }
 $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
 try {
  $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
  $chain.ChainPolicy.RevocationMode='Online'
  $chain.ChainPolicy.UrlRetrievalTimeout=[TimeSpan]::FromSeconds(15)
  if (-not $chain.Build($cert)) { throw 'Release signer chain, validity or revocation verification failed.' }
 } finally { $chain.Dispose() }
}
if ($Mode -eq 'Sign') {
 if (Test-Path -LiteralPath $Signature) { throw 'Signature output already exists.' }
 $cert=Get-Item -LiteralPath "Cert:/$Store/My/$Thumbprint"
 Assert-Identity $cert
 if (-not $cert.HasPrivateKey) { throw 'Signing identity has no accessible private key.' }
 $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert)
 $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
 $cms.ComputeSignature($signer,$true)
 $stream=[IO.File]::Open($Signature,'CreateNew','Write','None')
 try { $bytes=$cms.Encode();$stream.Write($bytes);$stream.Flush($true) } finally { $stream.Dispose() }
} else {
 $cms.Decode([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Signature)))
 if ($cms.SignerInfos.Count -ne 1) { throw 'Exactly one release signer is required.' }
 if ($cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'SHA256 release signature required.' }
 $cms.CheckSignature($true)
 Assert-Identity $cms.SignerInfos[0].Certificate
}
Write-Output 'PASS detached CMS release signature and pinned trusted code-signing identity.'
