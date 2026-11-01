# =====================================================================
#  SOC SHARK - Windows installer
#  ---------------------------------------------------------------------
#  ONE-LINE INSTALL (PowerShell):
#
#    irm https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.ps1 | iex
#
#  Also works as a script (.\install.ps1) or pasted whole into a console.
#  Downloads the ready-made binary from the latest release (checking its
#  SHA-256), installs it into %USERPROFILE%\.socshark\bin and adds it to
#  your PATH. If there is no binary for your machine, or it fails, it
#  builds from source instead (installing Git, the C++ Build Tools and
#  Rust). Run it again any time to update.
#
#  Options (environment variables, all optional):
#    SOCSHARK_VERSION        version to install, e.g. 0.9.0 (default: latest)
#    SOCSHARK_FROM_SOURCE=1  build from source instead of downloading
#    SOCSHARK_DOWNLOAD_URL   another download location (a release mirror, https:// only)
#    SOCSHARK_REPO / SOCSHARK_REF / SOCSHARK_DIR   repo, branch and folder to build
#                            (SOCSHARK_REF defaults to the tag v<version> when
#                            SOCSHARK_VERSION is set, otherwise main)
#    GH_TOKEN                token, only to build from a private repository
#
#  Pure ASCII, no BOM: that is what makes `irm | iex` and Windows
#  PowerShell 5.1 both work. On failure it prints the reason and throws
#  (it never calls `exit`, which would close the console under `irm | iex`).
# =====================================================================

& {
    # --- Settings --------------------------------------------------------
    $Version    = if ($env:SOCSHARK_VERSION) { $env:SOCSHARK_VERSION.TrimStart('v') } else { '' }
    $GhRepo     = if ($env:SOCSHARK_REPO) { $env:SOCSHARK_REPO } else { 'Ruby570bocadito/soc-shark' }
    # A pinned version also pins the source fallback to its tag.
    $GhRef      = if ($env:SOCSHARK_REF)  { $env:SOCSHARK_REF }  elseif ($Version) { "v$Version" } else { 'main' }
    $GhToken    = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
    $RepoDir    = if ($env:SOCSHARK_DIR)  { $env:SOCSHARK_DIR }  else { Join-Path $HOME 'soc-shark' }
    $InstallDir = Join-Path $HOME '.socshark\bin'
    $FromSource = $env:SOCSHARK_FROM_SOURCE -and $env:SOCSHARK_FROM_SOURCE -ne '0'
    $Asset      = 'socshark-x86_64-pc-windows-msvc.zip'
    # No progress bar (it makes downloads crawl in Windows PowerShell 5.1)
    # and TLS 1.2, the minimum GitHub accepts.
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Step([string]$m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor Cyan }
    function Ok([string]$m)   { Write-Host "   [OK] $m" -ForegroundColor Green }
    function Warn([string]$m) { Write-Host "   [!] $m" -ForegroundColor Yellow }
    function Fail([string]$m) { Write-Host ''; Write-Host "[X] $m" -ForegroundColor Red }
    # Prints the reason and stops with an error (non-zero exit when run as
    # a script file; a visible error, not a silent return, under irm | iex).
    function Abort([string]$m, [string[]]$hints = @()) {
        Fail $m
        foreach ($h in $hints) { Write-Host "    $h" -ForegroundColor Red }
        $global:LASTEXITCODE = 1
        throw "SOC SHARK installation failed: $m"
    }
    # True if the ';'-separated list already holds $dir (exact entry match,
    # case-insensitive, ignoring a trailing '\' and expanding %VARS%).
    function PathHas([string]$list, [string]$dir) {
        $want = $dir.TrimEnd('\')
        foreach ($e in ($list -split ';')) {
            if (-not $e) { continue }
            $e2 = [Environment]::ExpandEnvironmentVariables($e).TrimEnd('\')
            if ($e2 -ieq $want -or $e.TrimEnd('\') -ieq $want) { return $true }
        }
        return $false
    }
    function AddSessionPath([string]$p) {
        if (-not (PathHas $env:Path $p)) { $env:Path = "$p;$env:Path" }
    }

    # Block-letter banner. Each ASCII symbol becomes its Unicode box
    # character when printed, so the file itself stays pure ASCII.
    $art = @(
        '#######7 ######7  ######7    #######7##7  ##7 #####7 ######7 ##7  ##7',
        '##F====J##F===##7##F====J    ##F====J##|  ##|##F==##7##F==##7##| ##FJ',
        '#######7##|   ##|##|         #######7#######|#######|######FJ#####FJ',
        'L====##|##|   ##|##|         L====##|##F==##|##F==##|##F==##7##F=##7',
        '#######|L######FJL######7    #######|##|  ##|##|  ##|##|  ##|##|  ##7',
        'L======J L=====J  L=====J    L======JL=J  L=JL=J  L=JL=J  L=JL=J  L=J'
    )
    $glyph = @{ [char]'#' = 0x2588; [char]'7' = 0x2557; [char]'F' = 0x2554; [char]'=' = 0x2550
                [char]'J' = 0x255D; [char]'L' = 0x255A; [char]'|' = 0x2551 }
    Clear-Host
    Write-Host ''
    $row = 0
    foreach ($line in $art) {
        $text = -join ($line.ToCharArray() | ForEach-Object { if ($glyph.ContainsKey($_)) { [char]$glyph[$_] } else { $_ } })
        Write-Host "  $text" -ForegroundColor $(if ($row -lt 3) { 'Cyan' } else { 'DarkCyan' })
        $row++
    }
    Write-Host '  Your network, explained in plain language | Windows installer' -ForegroundColor Gray

    # --- System ----------------------------------------------------------
    if ($env:OS -ne 'Windows_NT') {
        Abort 'This installer is for Windows. On Linux or macOS use install.sh (see the README).'
    }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Abort 'PowerShell 5.1 or newer is required.'
    }
    # A mirror must be HTTPS: the SHA-256 check is only as trustworthy as
    # the channel that delivers SHA256SUMS.
    if ($env:SOCSHARK_DOWNLOAD_URL -and $env:SOCSHARK_DOWNLOAD_URL -notmatch '^https://') {
        Abort "SOCSHARK_DOWNLOAD_URL must start with https:// (got: $env:SOCSHARK_DOWNLOAD_URL)."
    }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }

    # --- Ready-made binary from the release ------------------------------
    $exe = $null
    $tmp = $null
    $why = $null
    if ($FromSource) {
        $why = 'SOCSHARK_FROM_SOURCE is set'
    } elseif ($arch -ne 'x86_64') {
        $why = "there is no ready-made binary for $arch"
    } else {
        Step $(if ($Version) { "Downloading SOC SHARK v$Version" } else { 'Downloading SOC SHARK' })
        $base = if ($env:SOCSHARK_DOWNLOAD_URL) { $env:SOCSHARK_DOWNLOAD_URL.TrimEnd('/') }
                elseif ($Version) { "https://github.com/$GhRepo/releases/download/v$Version" }
                else { "https://github.com/$GhRepo/releases/latest/download" }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('socshark-install-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            $zip  = Join-Path $tmp $Asset
            $sums = Join-Path $tmp 'SHA256SUMS'
            Invoke-WebRequest -Uri "$base/$Asset" -OutFile $zip -UseBasicParsing
            Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
            $want = $null
            foreach ($line in Get-Content $sums) {
                if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$' -and $Matches[2].Trim() -eq $Asset) { $want = $Matches[1]; break }
            }
            $got = (Get-FileHash -Algorithm SHA256 $zip).Hash
            if (-not $want -or $want.ToLower() -ne $got.ToLower()) { throw 'its SHA-256 does not match' }
            Expand-Archive -Path $zip -DestinationPath $tmp -Force
            $candidate = Join-Path $tmp 'socshark.exe'
            $ver = & $candidate --version
            if ($LASTEXITCODE -ne 0) { throw 'it does not start on this machine' }
            Ok "$ver (SHA-256 verified)"
            $exe = $candidate
        } catch {
            $why = "the download failed: $($_.Exception.Message)"
        }
    }

    # --- Build from source (only without a usable binary) ----------------
    if (-not $exe) {
        Step 'Building from source'
        Warn "Building because $why."

        $gitExe = $null
        foreach ($cand in @((Get-Command git -ErrorAction SilentlyContinue).Source,
                            "$env:ProgramFiles\Git\cmd\git.exe",
                            "${env:ProgramFiles(x86)}\Git\cmd\git.exe",
                            "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe")) {
            if ($cand -and (Test-Path $cand)) { $gitExe = $cand; break }
        }
        if (-not $gitExe -and (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host '   Installing Git with winget (accept the UAC prompt if it appears)...'
            winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements | Out-Null
            if (Test-Path "$env:ProgramFiles\Git\cmd\git.exe") {
                $gitExe = "$env:ProgramFiles\Git\cmd\git.exe"
                AddSessionPath "$env:ProgramFiles\Git\cmd"
            }
        }
        if (-not $gitExe) {
            Abort 'Git is missing and could not be installed. Get it from https://git-scm.com/download/win and run this installer again.'
        }
        Ok "$(& $gitExe --version)"

        # Rust's MSVC toolchain links with link.exe: without the Visual Studio
        # C++ Build Tools, `cargo build` fails with "linker link.exe not found".
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $vcComp  = if ($arch -eq 'aarch64') { 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' }
                   else                     { 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
        function HasVcTools {
            if (-not (Test-Path $vswhere)) { return $false }
            return [bool](& $vswhere -latest -products * -requires $vcComp -property installationPath)
        }
        if (-not (HasVcTools) -and (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host '   Installing the Visual Studio C++ Build Tools with winget (2-3 GB, several minutes; accept the UAC prompt)...'
            $vsArgs = "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add $vcComp --includeRecommended"
            winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --accept-source-agreements --accept-package-agreements --override $vsArgs | Out-Null
        }
        if (-not (HasVcTools)) {
            Abort 'The Visual Studio C++ Build Tools are missing (Rust needs them to link).' @(
                'Get them from https://visualstudio.microsoft.com/visual-cpp-build-tools/',
                'tick "Desktop development with C++" and run this installer again.')
        }
        Ok 'C++ Build Tools'

        $cargoExe = $null
        foreach ($cand in @((Get-Command cargo -ErrorAction SilentlyContinue).Source,
                            "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
            if ($cand -and (Test-Path $cand)) { $cargoExe = $cand; break }
        }
        if (-not $cargoExe) {
            Write-Host '   Installing Rust with rustup...'
            $rustupInit = Join-Path $env:TEMP 'rustup-init.exe'
            try {
                Invoke-WebRequest -Uri "https://win.rustup.rs/$arch" -OutFile $rustupInit -UseBasicParsing
            } catch {
                Abort "Could not download rustup-init: $($_.Exception.Message)"
            }
            & $rustupInit -y -q --default-toolchain stable --profile minimal | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Abort 'The Rust installation (rustup) failed.'
            }
            AddSessionPath "$env:USERPROFILE\.cargo\bin"
            $cargoExe = "$env:USERPROFILE\.cargo\bin\cargo.exe"
        }
        Ok "$(& $cargoExe --version)"

        # With a token (private repository) it travels in a header for this
        # command only, passed through GIT_CONFIG_* environment variables:
        # never saved in .git\config, in the remote URL or on the command
        # line (where any process listing would show it).
        function GitAuth {
            $env:GIT_TERMINAL_PROMPT = '0'
            if ($GhToken) {
                $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$GhToken"))
                $env:GIT_CONFIG_COUNT   = '1'
                $env:GIT_CONFIG_KEY_0   = 'http.https://github.com/.extraheader'
                $env:GIT_CONFIG_VALUE_0 = "Authorization: Basic $b64"
            }
            try {
                & $gitExe @args
            } finally {
                foreach ($n in 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_TERMINAL_PROMPT') {
                    Remove-Item -Path "Env:$n" -ErrorAction SilentlyContinue
                }
            }
        }
        if (Test-Path (Join-Path $RepoDir '.git')) {
            GitAuth -C $RepoDir fetch --quiet origin $GhRef
            if ($LASTEXITCODE -eq 0) { & $gitExe -C $RepoDir checkout --quiet FETCH_HEAD }
            if ($LASTEXITCODE -ne 0) { Warn 'Could not update the source; building the local copy.' }
        } else {
            GitAuth clone --quiet --depth 1 --branch $GhRef "https://github.com/$GhRepo.git" $RepoDir
            if ($LASTEXITCODE -ne 0) {
                Abort "Could not clone https://github.com/$GhRepo ($GhRef). Check your connection." @(
                    "If the folder was left half-done, delete it and try again: Remove-Item -Recurse -Force `"$RepoDir`"")
            }
        }
        Ok "Source: $RepoDir ($GhRef)"

        Write-Host '   Compiling (a few minutes the first time)...'
        Push-Location $RepoDir
        try {
            & $cargoExe build --release --locked --quiet -p socshark-cli
            if ($LASTEXITCODE -ne 0) {
                Abort 'The build failed (see the errors above).'
            }
        } finally {
            Pop-Location
        }
        $exe = Join-Path $RepoDir 'target\release\socshark.exe'
        if (-not (Test-Path $exe)) {
            Abort "The build finished but $exe is missing."
        }
        Ok 'Built'
    }

    # --- Install, PATH and a quick self-test ------------------------------
    Step 'Installing'
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $shark = Join-Path $InstallDir 'socshark.exe'
    try {
        Copy-Item $exe $shark -Force -ErrorAction Stop
    } catch {
        if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
        Abort "Could not replace $shark ($($_.Exception.Message))." @(
            'Is socshark running? Close socshark first (the GUI window, a TUI or a live capture)',
            'and run this installer again.')
    }
    if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
    Ok $shark

    # User PATH: read the raw registry value (REG_EXPAND_SZ, %VARS% kept
    # unexpanded), compare whole entries and write it back as ExpandString,
    # so entries such as %USERPROFILE%\bin are not flattened.
    AddSessionPath $InstallDir
    $newTerminal = $false
    if (-not (Test-Path 'HKCU:\Environment')) { New-Item -Path 'HKCU:\Environment' | Out-Null }
    $envKey  = Get-Item -Path 'HKCU:\Environment'
    $rawPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not (PathHas $rawPath $InstallDir)) {
        $newPath = if ($rawPath.Trim(';')) { $rawPath.TrimEnd(';') + ';' + $InstallDir } else { $InstallDir }
        Set-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -Value $newPath -Type ExpandString
        # Tell Explorer and new terminals the environment changed: setting
        # (and removing) a dummy user variable broadcasts WM_SETTINGCHANGE.
        [Environment]::SetEnvironmentVariable('SOCSHARK_PATH_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('SOCSHARK_PATH_REFRESH', $null, 'User')
        $newTerminal = $true
    }

    $demoPcap = Join-Path $env:TEMP 'socshark-selftest.pcap'
    $null = & $shark dev sample-pcap -o $demoPcap 2>&1
    $selfTest = $LASTEXITCODE -eq 0
    if ($selfTest) {
        $null = & $shark capture -r $demoPcap 2>&1
        $selfTest = $LASTEXITCODE -eq 0
    }
    Remove-Item -Force $demoPcap -ErrorAction SilentlyContinue
    if ($selfTest) {
        Ok 'Self-test passed'
    } else {
        Abort 'socshark is installed but could not analyse a demo capture. Try: socshark capture -r <file.pcap>'
    }

    # Live capture needs Npcap (the driver Wireshark uses), loaded at run time.
    if (Test-Path (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll')) {
        Ok 'Live capture ready (Npcap found)'
    } else {
        Warn 'For live capture install Npcap from https://npcap.com (tick "WinPcap API-compatible Mode").'
    }

    # --- Done -------------------------------------------------------------
    Write-Host ''
    Write-Host '  SOC SHARK is ready.' -ForegroundColor Cyan
    if ($newTerminal) {
        Write-Host '  Open a new terminal (it was added to your PATH) and try:' -ForegroundColor Gray
    } else {
        Write-Host '  Try:' -ForegroundColor Gray
    }
    Write-Host '    socshark gui                   window: watch your network live or open a capture' -ForegroundColor White
    Write-Host '    socshark tui -r capture.pcap   terminal interface' -ForegroundColor White
    Write-Host '    socshark --help                everything else' -ForegroundColor White
    Write-Host ''
}
