# Builds and signs the MSIX package, on Windows, from a finished release build. The passkey provider
# needs it: Windows only activates a plugin from a package. Not run as part of any build yet, and
# not tested on a real machine (plans/05, History 2026-11-02).
#
#   cargo tauri build --no-bundle
#   apps/desktop/scripts/package-msix.ps1 -Publisher "CN=..." -Certificate octa-pass.pfx -Password $env:PFX_PASSWORD
#
# -Publisher must equal the certificate's subject exactly, or Windows refuses the package. makeappx
# and signtool come from the Windows SDK (10.0.26100.7175 or newer has the plugin headers).
#
# → apps/desktop/target/release/bundle/msix/Octa Pass_<version>_x64.msix
param(
  [Parameter(Mandatory)] [string] $Publisher,
  [Parameter(Mandatory)] [string] $Certificate,
  [string] $Password = ""
)
$ErrorActionPreference = "Stop"

$desktop = Split-Path -Parent $PSScriptRoot
$release = Join-Path $desktop "target\release"
$version = (Get-Content (Join-Path $desktop "src-tauri\tauri.conf.json") -Raw | ConvertFrom-Json).version
$output = Join-Path $release "bundle\msix"
$layout = Join-Path $output "layout"

Remove-Item $layout -Recurse -Force -ErrorAction SilentlyContinue
New-Item (Join-Path $layout "assets") -ItemType Directory -Force | Out-Null

Copy-Item (Join-Path $release "octapass-desktop.exe") $layout
foreach ($icon in "Square150x150Logo.png", "Square44x44Logo.png", "StoreLogo.png") {
  Copy-Item (Join-Path $desktop "windows\assets\$icon") (Join-Path $layout "assets")
}

# Package versions have four parts.
(Get-Content (Join-Path $desktop "windows\AppxManifest.xml") -Raw).
  Replace("__PUBLISHER__", [System.Security.SecurityElement]::Escape($Publisher)).
  Replace("__VERSION__", "$version.0") |
  Set-Content (Join-Path $layout "AppxManifest.xml") -Encoding utf8

$package = Join-Path $output "Octa Pass_${version}_x64.msix"
& makeappx pack /o /d $layout /p $package
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }
& signtool sign /fd SHA256 /a /f $Certificate /p $Password $package
if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
Write-Output $package
