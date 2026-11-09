# Installs the Octa Pass command-line tool on Windows: octapass.exe and its helpers
# (git-credential-octapass, octapass-git-sign, docker-credential-octapass).
#
#   irm __OCTAPASS_SITE__/install.ps1 | iex
#
# It downloads the release archive from GitHub, checks it against the release's SHA256SUMS,
# copies the programs to %LOCALAPPDATA%\Programs\OctaPass\bin (or $env:OCTAPASS_INSTALL_DIR)
# and adds that folder to your user PATH. Nothing runs as administrator.
#
#   $env:OCTAPASS_VERSION = 'v1.2.3'   a release tag instead of the latest release
$ErrorActionPreference = 'Stop'

$repo = if ($env:OCTAPASS_REPO) { $env:OCTAPASS_REPO } else { '__OCTAPASS_REPO__' }
$version = if ($env:OCTAPASS_VERSION) { $env:OCTAPASS_VERSION } else { 'latest' }
$installDir = if ($env:OCTAPASS_INSTALL_DIR) { $env:OCTAPASS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\OctaPass\bin' }

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') { throw "Octa Pass: there's no Windows build for this processor ($arch) yet." }
$target = 'x86_64-pc-windows-msvc'
$archive = "octapass-cli-$target.zip"
$base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("octapass-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "Downloading the Octa Pass CLI for $target..."
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$archive" -OutFile (Join-Path $work $archive)
    } catch {
        throw "Octa Pass: there's no release build for Windows yet. Install Rust (https://rustup.rs), then: cargo install --locked --git https://github.com/$repo octapass-cli"
    }
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $work 'SHA256SUMS')
    $line = Get-Content (Join-Path $work 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($archive))$" } | Select-Object -First 1
    if (-not $line) { throw "Octa Pass: SHA256SUMS doesn't list $archive." }
    $expected = ($line -split ' ')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $work $archive)).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Octa Pass: the download doesn't match SHA256SUMS. Nothing was installed." }

    Expand-Archive -Path (Join-Path $work $archive) -DestinationPath (Join-Path $work 'out')
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Get-ChildItem (Join-Path $work 'out') -Filter '*.exe' | Copy-Item -Destination $installDir -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $installDir)) {
        [Environment]::SetEnvironmentVariable('Path', (($userPath, $installDir) -ne '' -join ';'), 'User')
        Write-Host "Added $installDir to your PATH. Open a new terminal to use it."
    }
    Write-Host "Installed the Octa Pass CLI in $installDir."
    Write-Host ''
    Write-Host 'Next: if the Octa Pass app is on this computer, any octapass command uses its account,'
    Write-Host 'unlocked whenever the app is. Otherwise run: octapass login'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
