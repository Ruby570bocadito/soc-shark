# =====================================================================
#  SOC SHARK - Instalador para Windows
#  ---------------------------------------------------------------------
#  INSTALACION AUTOMATICA (PowerShell, una sola linea):
#
#    $env:GH_TOKEN = 'ghp_tu_token'   # solo mientras el repo sea privado
#    irm https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.ps1 -Headers @{ Authorization = "token $env:GH_TOKEN" } | iex
#
#  Tambien vale como script (.\install.ps1) o copiando y pegando este
#  archivo entero en la consola.
#  Instala Git, las Build Tools de C++ y Rust si faltan, clona el repo,
#  compila en release, instala el binario en %USERPROFILE%\.socshark\bin
#  y lo deja en el PATH. Se puede volver a ejecutar: actualiza y recompila.
#
#  Archivo en ASCII puro y sin BOM: asi funciona con `irm | iex` y en
#  Windows PowerShell 5.1.
# =====================================================================

& {
    # --- CONFIGURACION (variables de entorno opcionales) --------------
    $GhRepo     = if ($env:SOCSHARK_REPO) { $env:SOCSHARK_REPO } else { 'Ruby570bocadito/soc-shark' }
    $GhRef      = if ($env:SOCSHARK_REF)  { $env:SOCSHARK_REF }  else { 'main' }     # rama o etiqueta
    $GhToken    = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }    # PAT (si falta y hay que clonar, se pide)
    $RepoDir    = if ($env:SOCSHARK_DIR)  { $env:SOCSHARK_DIR }  else { Join-Path $HOME 'soc-shark' }
    $InstallDir = Join-Path $HOME '.socshark\bin'

    # --- Ayudas de presentacion --------------------------------------
    function Step([string]$m) { Write-Host '' ; Write-Host "==> $m" -ForegroundColor Cyan }
    function Ok([string]$m)   { Write-Host "   [OK] $m" -ForegroundColor Green }
    function Warn([string]$m) { Write-Host "   [AVISO] $m" -ForegroundColor Yellow }
    function AddSessionPath([string]$p) {
        if ($env:Path -notlike "*$p*") { $env:Path = "$p;$env:Path" }
    }

    # Banner en letras de bloque. Cada simbolo ASCII se traduce a su
    # caracter Unicode al pintarlo (el archivo se queda en ASCII puro).
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
    Write-Host '  Tu red, explicada en lenguaje claro | instalador para Windows' -ForegroundColor Gray
    Write-Host "  repo: $GhRepo ($GhRef)" -ForegroundColor DarkGray
    Write-Host ''

    # --- Paso 0: comprobar plataforma --------------------------------
    Step 'Paso 0/6 - Comprobando plataforma'
    if ($env:OS -ne 'Windows_NT') {
        Write-Host '[X] Este instalador es solo para Windows. En Linux/macOS usa install.sh (curl ... | bash, ver README).' -ForegroundColor Red
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
    # El toolchain MSVC de Rust enlaza con link.exe: sin las Build Tools de
    # C++ de Visual Studio, `cargo build` falla con "linker link.exe not found".
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vcComp  = if ($arch -eq 'aarch64') { 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' }
               else                     { 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
    function HasVcTools {
        if (-not (Test-Path $vswhere)) { return $false }
        return [bool](& $vswhere -latest -products * -requires $vcComp -property installationPath)
    }
    if (-not (HasVcTools)) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host '   Instalando Visual Studio Build Tools (C++) con winget: ~2-3 GB, varios minutos, acepta el UAC...'
            $vsArgs = "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add $vcComp --includeRecommended"
            winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --accept-source-agreements --accept-package-agreements --override $vsArgs | Out-Null
        } else {
            Warn 'winget no esta disponible.'
        }
    }
    if (-not (HasVcTools)) {
        Write-Host '[X] Faltan las Build Tools de C++ de Visual Studio (Rust las necesita para enlazar).' -ForegroundColor Red
        Write-Host '    Descargalas de https://visualstudio.microsoft.com/visual-cpp-build-tools/' -ForegroundColor Red
        Write-Host '    marca "Desarrollo para el escritorio con C++" y vuelve a ejecutar este instalador.' -ForegroundColor Red
        return
    }
    Ok 'Build Tools de C++ (MSVC) presentes'

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
    # Con token, va en una cabecera solo para este comando: nunca se guarda
    # en .git\config ni en la URL del remoto.
    function GitAuth {
        if ($GhToken) {
            $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$GhToken"))
            & $gitExe -c "http.https://github.com/.extraheader=Authorization: Basic $b64" @args
        } else {
            & $gitExe @args
        }
    }
    $isRepo = Test-Path (Join-Path $RepoDir '.git')
    if ($isRepo) {
        Write-Host "   Ya existe: $RepoDir - actualizando ($GhRef)..."
        GitAuth -C $RepoDir fetch --quiet origin $GhRef
        if ($LASTEXITCODE -eq 0) { & $gitExe -C $RepoDir checkout --quiet FETCH_HEAD }
        if ($LASTEXITCODE -ne 0) {
            Warn "No se pudo actualizar (se continua con la copia local)."
        }
    } else {
        if (-not $GhToken) {
            Write-Host '   Si el repositorio es privado hace falta un token de GitHub (PAT) con' -ForegroundColor Yellow
            Write-Host '   permiso de lectura. Crealo en https://github.com/settings/tokens' -ForegroundColor Yellow
            $GhToken = Read-Host '   Pega tu token (o Enter si el repositorio es publico)'
        }
        GitAuth clone --depth 1 --branch $GhRef "https://github.com/$GhRepo.git" $RepoDir
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
        & $cargoExe build --release --locked -p socshark-cli
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

    # --- Captura en vivo ---------------------------------------------
    # Ver la red en tiempo real necesita Npcap (el mismo driver que usa
    # Wireshark). soc-shark lo carga al vuelo: no hace falta recompilar.
    Step 'Extra: captura en vivo (tiempo real)'
    $npcap = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'
    if (Test-Path $npcap) {
        Ok 'Npcap detectado: puedes ver tu red en vivo (socshark gui -> boton "En vivo").'
        Write-Host  '    Si dice que no hay permiso, abre la consola como administrador.' -ForegroundColor Gray
    } else {
        Warn 'Npcap no esta instalado: sin el no se puede ver la red en tiempo real.'
        Write-Host  '    Instalalo desde https://npcap.com y deja marcado "WinPcap API-compatible Mode".' -ForegroundColor Gray
        Write-Host  '    (Si ya tienes Wireshark, normalmente Npcap ya esta instalado.)' -ForegroundColor Gray
        Write-Host  '    Mientras tanto, abrir capturas .pcap funciona completo.' -ForegroundColor Gray
    }

    # --- Resumen final ------------------------------------------------
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' SOC SHARK instalado. Ejemplos:' -ForegroundColor Cyan
    Write-Host '   socshark capture -r captura.pcap --json -' -ForegroundColor White
    Write-Host '   socshark capture -r captura.pcap -f "flow.risk >= 30"' -ForegroundColor White
    Write-Host '   socshark gui                          <- ventana: ver la red en vivo o abrir capturas' -ForegroundColor White
    Write-Host '   socshark gui -r captura.pcapng        <- ventana con una captura ya abierta (pcap o pcapng)' -ForegroundColor White
    Write-Host '   socshark report -r captura.pcapng     <- informe en lenguaje claro (informe.html)' -ForegroundColor White
    Write-Host '   socshark daemon --list                <- interfaces de red (en vivo, con Npcap)' -ForegroundColor White
    Write-Host '   socshark tui -r captura.pcap          <- interfaz en la consola' -ForegroundColor White
    Write-Host '   socshark follow -r captura.pcap --flow 1.2.3.4:443  <- seguir stream TCP' -ForegroundColor White
    Write-Host '   socshark export -r captura.pcap -F ecs -o ecs.jsonl <- export a SIEM' -ForegroundColor White
    Write-Host '   socshark dev fuzz --iterations 50000  <- fuzzing determinista' -ForegroundColor White
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' Documentacion: docs/ dentro del repositorio (docs/tui.md para la TUI).' -ForegroundColor DarkGray
    Write-Host ''
}
