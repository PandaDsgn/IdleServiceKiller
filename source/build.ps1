# Builds the exe and puts the one installation file in ..\installer (a sibling of this folder, outside the git repo):
#   installer\IdleServiceKiller-Setup.exe       double-click it: it is the installer AND the manager window
# Needs Rust (cargo on PATH) and the Visual Studio C++ Build Tools.
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try { cargo build --release; if ($LASTEXITCODE -ne 0) { throw "Build failed" } } finally { Pop-Location }

$out = Join-Path (Split-Path $PSScriptRoot -Parent) 'installer'
New-Item -ItemType Directory -Force $out | Out-Null
$setup = Join-Path $out 'IdleServiceKiller-Setup.exe'
Copy-Item "$PSScriptRoot\target\release\IdleServiceKiller.exe" $setup -Force   # README.txt in there is kept

# Sign with a self-signed certificate named pandadsgn, created once in this user's personal store (private key stays here, not exportable).
# Self-signed: the name shows under Properties > Digital Signatures, but Windows does not trust the publisher on other PCs.
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq 'CN=pandadsgn' -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=pandadsgn' -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5) -KeyExportPolicy NonExportable
}
$sig = Set-AuthenticodeSignature -FilePath $setup -Certificate $cert -HashAlgorithm SHA256
if (-not $sig.SignerCertificate) { throw "Signing failed: $($sig.StatusMessage)" }
Write-Host "Installer is in $out (signed as $($sig.SignerCertificate.Subject))"
