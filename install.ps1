# =====================================================================
#  soc-shark — Instalador para Windows (listo para copiar y pegar)
#  ---------------------------------------------------------------------
#  Uso: abre PowerShell, copia TODO este archivo y pegalo en la consola.
#  (Tambien funciona como script: .\install.ps1)
#  Instala Git y Rust si faltan, clona el repo privado, compila en
#  release, instala el binario en %USERPROFILE%\.socshark\bin y lo deja
#  en el PATH. Es seguro volver a ejecutarlo (idempotente).
# =====================================================================

& {
    # --- CONFIGURACION (edita si lo necesitas) ------------------------
    $GhRepo     = 'Ruby570bocadito/soc-shark'  # repositorio a clonar
    $GhToken    = ''                           # PAT de GitHub (si lo dejas vacio y hay que clonar, se pedira por consola)
    $RepoDir    = Join-Path $HOME 'soc-shark'  # carpeta de destino del repositorio
    $InstallDir = Join-Path $HOME '.socshark\bin'

    # --- Ayudas de presentacion --------------------------------------
    function Step([string]$m) { Write-Host '' ; Write-Host "==> $m" -ForegroundColor Cyan }
    function Ok([string]$m)   { Write-Host "   [OK] $m" -ForegroundColor Green }
    function Warn([string]$m) { Write-Host "   [AVISO] $m" -ForegroundColor Yellow }
    function AddSessionPath([string]$p) {
        if ($env:Path -notlike "*$p*") { $env:Path = "$p;$env:Path" }
    }

    $banner = @'
  ____         ____  _   _        _
 / ___|  ___ / ___|| | | |  __ _| |_
 \___ \ / __|\___ \| |_| |/ _` | __|
  ___) | (__  ___) |  _  | (_| | |_
 |____/ \___||____/|_| |_|\__,_|\__|
 Analizador de trafico SOC / Blue Team (Rust)
'@
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan
    Write-Host " Despliegue en Windows | repo: $GhRepo" -ForegroundColor DarkGray
    Write-Host ''

    # --- Paso 0: comprobar plataforma --------------------------------
    Step 'Paso 0/6 - Comprobando plataforma'
    if ($env:OS -ne 'Windows_NT') {
        Write-Host '[X] Este instalador es solo para Windows. En Linux/macOS: git clone + cargo install --path crates/socshark-cli' -ForegroundColor Red
        return
    }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host '[X] Se requiere PowerShell 5.1 o superior.' -ForegroundColor Red
        return
    }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
    Ok "Windows detectado ($arch, PowerShell $($PSVersionTable.PSVersion))"

    # --- Paso 1: Git --------------------------------------------------
    Step 'Paso 1/6 - Comprobando Git'
    $gitExe = $null
    foreach ($cand in @((Get-Command git -ErrorAction SilentlyContinue).Source,
                        "$env:ProgramFiles\Git\cmd\git.exe",
                        "${env:ProgramFiles(x86)}\Git\cmd\git.exe",
                        "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe")) {
        if ($cand -and (Test-Path $cand)) { $gitExe = $cand; break }
    }
    if (-not $gitExe) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host '   Instalando Git con winget (acepta el UAC si aparece)...'
            winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements | Out-Null
            if (Test-Path "$env:ProgramFiles\Git\cmd\git.exe") {
                $gitExe = "$env:ProgramFiles\Git\cmd\git.exe"
                AddSessionPath "$env:ProgramFiles\Git\cmd"
            }
        } else {
            Warn 'winget no esta disponible.'
        }
    }
    if (-not $gitExe) {
        Write-Host '[X] Git no esta instalado y no se pudo instalar automaticamente.' -ForegroundColor Red
        Write-Host '    Descargalo de https://git-scm.com/download/win y vuelve a ejecutar este instalador.' -ForegroundColor Red
        return
    }
    Ok "Git: $(& $gitExe --version)"

    # --- Paso 2: Rust (rustup + toolchain estable) --------------------
    Step 'Paso 2/6 - Comprobando toolchain de Rust'
    $cargoExe = $null
    foreach ($cand in @((Get-Command cargo -ErrorAction SilentlyContinue).Source,
                        "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
        if ($cand -and (Test-Path $cand)) { $cargoExe = $cand; break }
    }
    if (-not $cargoExe) {
        Write-Host '   Instalando Rust via rustup (perfil minimal)...'
        $rustupInit = Join-Path $env:TEMP 'rustup-init.exe'
        $rustupUrl  = "https://win.rustup.rs/$arch"
        try {
            Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupInit -UseBasicParsing
        } catch {
            Write-Host "[X] No se pudo descargar rustup-init ($rustupUrl): $_" -ForegroundColor Red
            return
        }
        & $rustupInit -y --default-toolchain stable --profile minimal
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[X] La instalacion de rustup fallo. Revisa el mensaje anterior.' -ForegroundColor Red
            return
        }
        AddSessionPath "$env:USERPROFILE\.cargo\bin"
        $cargoExe = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    }
    Ok "Cargo: $(& $cargoExe --version)"

    # --- Paso 3: clonar / actualizar repositorio ----------------------
    Step 'Paso 3/6 - Obteniendo el repositorio'
    $isRepo = Test-Path (Join-Path $RepoDir '.git')
    if ($isRepo) {
        Write-Host "   Ya existe: $RepoDir - actualizando (pull --ff-only)..."
        & $gitExe -C $RepoDir pull --ff-only
        if ($LASTEXITCODE -ne 0) {
            Warn "No se pudo actualizar (se continua con la copia local)."
        }
    } else {
        if (-not $GhToken) {
            Write-Host '   El repositorio es privado: se necesita un Personal Access Token (PAT)' -ForegroundColor Yellow
            Write-Host "   con permiso de lectura. Crealo en https://github.com/settings/tokens" -ForegroundColor Yellow
            $GhToken = Read-Host '   Pega tu token (o Enter para omitir e intentar clonar sin credencial)'
        }
        $cloneUrl = if ($GhToken) { "https://x-access-token:$GhToken@github.com/$GhRepo.git" }
                    else          { "https://github.com/$GhRepo.git" }
        & $gitExe clone $cloneUrl $RepoDir
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[X] Fallo el clon. Causas tipicas: token invalido/expirado o sin acceso al repo.' -ForegroundColor Red
            Write-Host '    Borra la carpeta e intentalo de nuevo con un token nuevo:' -ForegroundColor Red
            Write-Host "    Remove-Item -Recurse -Force `"$RepoDir`"" -ForegroundColor Red
            return
        }
    }
    Ok "Repositorio listo en $RepoDir"

    # --- Paso 4: compilar en release ----------------------------------
    Step 'Paso 4/6 - Compilando (cargo build --release)'
    Write-Host '   Esto puede tardar varios minutos la primera vez. Ve a por un cafe...'
    Push-Location $RepoDir
    try {
        & $cargoExe build --release
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[X] La compilacion fallo. Comprueba que el repo esta completo y reintenta.' -ForegroundColor Red
            return
        }
    } finally {
        Pop-Location
    }
    $exe = Join-Path $RepoDir 'target\release\socshark.exe'
    if (-not (Test-Path $exe)) {
        Write-Host "[X] No se encontro el binario esperado: $exe" -ForegroundColor Red
        return
    }
    Ok 'Compilacion completada'

    # --- Paso 5: instalar binario + PATH de usuario -------------------
    Step 'Paso 5/6 - Instalando binario y PATH'
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $exe $InstallDir -Force
    AddSessionPath $InstallDir
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
        Warn "Se anyadio al PATH de usuario: $InstallDir (abre una terminal nueva para que aplique)"
    }
    Ok "Binario instalado en $InstallDir\socshark.exe"

    # --- Paso 6: verificacion E2E con el escenario demo ---------------
    Step 'Paso 6/6 - Verificacion (escenario demo reproducible)'
    $demoPcap = Join-Path $env:TEMP 'socshark-demo.pcap'
    $shark    = Join-Path $InstallDir 'socshark.exe'
    & $shark --version
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[X] El binario no arranca correctamente.' -ForegroundColor Red
        return
    }
    & $shark dev sample-pcap -o $demoPcap
    if ($LASTEXITCODE -ne 0) { Warn 'No se pudo generar el pcap de demostracion (no bloquea el uso normal).' }
    else {
        & $shark capture -r $demoPcap
        if ($LASTEXITCODE -ne 0) { Warn 'La lectura del pcap de demo fallo (no bloquea: revisa el archivo).' }
        else { Ok 'Pipeline completo verificado: generacion -> diseccion -> agregacion -> motor SOC' }
    }

    # --- Npcap (solo necesario para captura en vivo) ------------------
    Step 'Extra: captura en vivo'
    $npcap = @("$env:SystemRoot\System32\Npcap\wpcap.dll", "$env:SystemRoot\System32\wpcap.dll") |
             Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($npcap) {
        Ok "Npcap detectado: $npcap - el comando 'socshark daemon' esta listo"
    } else {
        Warn 'Para captura en vivo en Windows hace falta Npcap (analisis offline funciona sin el).'
        Write-Host  '    Instalalo desde https://npcap.com/ (marca "WinPcap API-compatible Mode").' -ForegroundColor Gray
        Write-Host  '    El daemon necesita consola con privilegios de administrador.' -ForegroundColor Gray
    }

    # --- Resumen final ------------------------------------------------
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' soc-shark instalado. Ejemplos:' -ForegroundColor Cyan
    Write-Host '   socshark capture -r captura.pcap --json -' -ForegroundColor White
    Write-Host '   socshark capture -r captura.pcap -f "flow.risk >= 30"' -ForegroundColor White
    Write-Host '   socshark tui -r captura.pcap          <- interfaz TUI' -ForegroundColor White
    Write-Host '   socshark follow -r captura.pcap <id>  <- seguir stream TCP' -ForegroundColor White
    Write-Host '   socshark daemon --list                <- interfaces para captura en vivo' -ForegroundColor White
    Write-Host '   socshark dev fuzz --iters 50000       <- fuzzing determinista' -ForegroundColor White
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' Documentacion: docs/ dentro del repositorio (docs/tui.md para la TUI).' -ForegroundColor DarkGray
    Write-Host ''
}
