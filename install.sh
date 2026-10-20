#!/usr/bin/env bash
# =====================================================================
#  SOC SHARK · instalador para Linux (también vale en macOS)
#  ---------------------------------------------------------------------
#  En una línea:
#
#    curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.sh | bash
#
#  Descarga el binario del último release (comprobando su SHA-256), lo
#  instala en ~/.local/bin y le da el permiso de captura (setcap) para ver
#  la red en vivo sin sudo. Si no hay binario para tu sistema, o falla, lo
#  compila desde el código (instalando git, un enlazador de C y Rust).
#  Desde una copia del repositorio (./install.sh) compila esa copia.
#  Se puede volver a ejecutar para actualizar.
#
#  Ajustes (variables de entorno, todas opcionales):
#    SOCSHARK_VERSION         versión a instalar, p. ej. 0.7.0 (por defecto, la última)
#    SOCSHARK_FROM_SOURCE=1   compilar desde el código en vez de descargar
#    SOCSHARK_DOWNLOAD_URL    otra dirección de descarga (réplica) con los
#                             mismos archivos que el release
#    SOCSHARK_BIN             dónde instalar  (por defecto ~/.local/bin)
#    SOCSHARK_NO_SETCAP=1     no dar el permiso de captura
#    SOCSHARK_REPO            dueño/repo      (por defecto Ruby570bocadito/soc-shark)
#    SOCSHARK_REF             rama o etiqueta a compilar (por defecto main)
#    SOCSHARK_DIR             código fuente   (por defecto ~/soc-shark)
#    GH_TOKEN / GITHUB_TOKEN  token, solo si clonas un repositorio privado
# =====================================================================
set -euo pipefail

REPO="${SOCSHARK_REPO:-Ruby570bocadito/soc-shark}"
REF="${SOCSHARK_REF:-main}"
SRC_DIR="${SOCSHARK_DIR:-$HOME/soc-shark}"
BIN_DIR="${SOCSHARK_BIN:-$HOME/.local/bin}"
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
VERSION="${SOCSHARK_VERSION:-}"
VERSION="${VERSION#v}"
MIN_RUST="1.75"

# --- presentación ---------------------------------------------------
if [ -t 1 ]; then
    C=$'\033[36m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' D=$'\033[2m' B=$'\033[1m' N=$'\033[0m'
else
    C='' G='' Y='' R='' D='' B='' N=''
fi
step() { printf '\n%s==> %s%s\n' "$C$B" "$1" "$N"; }
ok()   { printf '   %s[OK]%s %s\n' "$G" "$N" "$1"; }
warn() { printf '   %s[!]%s %s\n' "$Y" "$N" "$1"; }
die()  { printf '\n%s[X] %s%s\n' "$R" "$1" "$N" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '\n'
printf '%s  ███████╗ ██████╗  ██████╗    ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗%s\n' "$C$B" "$N"
printf '%s  ██╔════╝██╔═══██╗██╔════╝    ██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝%s\n' "$C$B" "$N"
printf '%s  ███████╗██║   ██║██║         ███████╗███████║███████║██████╔╝█████╔╝%s\n' "$C$B" "$N"
printf '%s  ╚════██║██║   ██║██║         ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗%s\n' "$C$B" "$N"
printf '%s  ███████║╚██████╔╝╚██████╗    ███████║██║  ██║██║  ██║██║  ██║██║  ██╗%s\n' "$C$B" "$N"
printf '%s  ╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝%s\n' "$C$B" "$N"
printf '%s  Tu red, explicada en lenguaje claro · instalador para Linux y macOS · %s%s\n' "$D" "$REPO" "$N"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/socshark-install.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# --- plataforma -----------------------------------------------------
step "Plataforma"
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS/$ARCH" in
    Linux/x86_64 | Linux/amd64) ASSET="socshark-x86_64-unknown-linux-gnu.tar.gz" ;;
    Linux/aarch64 | Linux/arm64) ASSET="socshark-aarch64-unknown-linux-gnu.tar.gz" ;;
    Darwin/*) ASSET="socshark-universal-apple-darwin.tar.gz" ;;
    Linux/*) ASSET="" ;;
    *) die "Sistema no soportado: $OS. En Windows usa install.ps1." ;;
esac
ok "$OS $ARCH"

# sudo solo cuando hace falta (y si existe).
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif have sudo; then
    SUDO="sudo"
else
    SUDO="none"
fi
as_root() {
    if [ "$SUDO" = "none" ]; then return 1; fi
    ${SUDO:+$SUDO} "$@"
}

# Ejecutado como archivo (./install.sh) dentro del repositorio: se compila
# esa copia. Con `curl | bash` no hay archivo.
here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
in_checkout() { [ -n "$here" ] && [ -f "$here/Cargo.toml" ] && grep -q 'socshark' "$here/Cargo.toml"; }

# --- binario del release ----------------------------------------------
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
# Descarga, comprueba y prueba el binario; deja la ruta en $NEW_BIN.
download_release() {
    local base
    if [ -n "${SOCSHARK_DOWNLOAD_URL:-}" ]; then
        base="${SOCSHARK_DOWNLOAD_URL%/}"
    elif [ -n "$VERSION" ]; then
        base="https://github.com/$REPO/releases/download/v$VERSION"
    else
        base="https://github.com/$REPO/releases/latest/download"
    fi
    have curl || { warn "Falta curl para descargar."; return 1; }
    curl -fsL --retry 3 -o "$TMP/$ASSET" "$base/$ASSET" || { warn "No hay $ASSET en el release${VERSION:+ v$VERSION}."; return 1; }
    curl -fsL --retry 3 -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" || { warn "El release no trae SHA256SUMS."; return 1; }
    local want got
    want="$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print $1}' "$TMP/SHA256SUMS")"
    got="$(sha256_of "$TMP/$ASSET")"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        warn "La suma SHA-256 no coincide: no se instala ese archivo."
        return 1
    fi
    ok "SHA-256 comprobado"
    tar -xzf "$TMP/$ASSET" -C "$TMP" socshark || { warn "No se pudo descomprimir $ASSET."; return 1; }
    # Arranca aquí (glibc, arquitectura): si no, se compila.
    "$TMP/socshark" --version >/dev/null 2>&1 || { warn "El binario no arranca en este sistema."; return 1; }
    NEW_BIN="$TMP/socshark"
}

NEW_BIN=""
if [ -n "${SOCSHARK_FROM_SOURCE:-}" ] && [ "${SOCSHARK_FROM_SOURCE}" != 0 ]; then
    MODE=source
elif in_checkout; then
    MODE=source
elif [ -z "$ASSET" ]; then
    warn "No hay binario ya compilado para $ARCH: se compilará desde el código."
    MODE=source
else
    step "Descargando SOC SHARK${VERSION:+ v$VERSION}"
    if download_release; then
        MODE=binary
        ok "$("$NEW_BIN" --version)"
    else
        warn "Se compilará desde el código."
        MODE=source
    fi
fi

# --- paquetes del sistema ---------------------------------------------
has_libpcap() {
    if [ "$OS" = "Darwin" ]; then return 0; fi # viene con macOS
    { ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null || true; } | grep -q 'libpcap\.so' && return 0
    # Sin ldconfig -p (Alpine/musl): se busca el archivo.
    compgen -G '/usr/lib*/libpcap.so*' >/dev/null || compgen -G '/usr/lib/*/libpcap.so*' >/dev/null \
        || compgen -G '/lib/*/libpcap.so*' >/dev/null
}
find_setcap() {
    for c in "$(command -v setcap 2>/dev/null || true)" /usr/sbin/setcap /sbin/setcap; do
        if [ -n "$c" ] && [ -x "$c" ]; then echo "$c"; return 0; fi
    done
    return 1
}
# Nombre del paquete de cada pieza en cada gestor.
pkg_name() {
    case "$1:$2" in
        apt:cc) echo build-essential ;; apt:libpcap) echo libpcap0.8 ;; apt:setcap) echo libcap2-bin ;;
        dnf:cc | yum:cc | zypper:cc) echo gcc ;; dnf:setcap | yum:setcap) echo libcap ;;
        zypper:libpcap) echo libpcap1 ;; zypper:setcap) echo libcap-progs ;;
        pacman:cc) echo base-devel ;; pacman:setcap) echo libcap ;;
        apk:cc) echo build-base ;; apk:setcap) echo libcap-utils ;;
        *) echo "$2" ;;
    esac
}
install_pkgs() {
    local pm names=()
    if have apt-get; then pm=apt; elif have dnf; then pm=dnf; elif have yum; then pm=yum
    elif have pacman; then pm=pacman; elif have zypper; then pm=zypper; elif have apk; then pm=apk
    else return 1; fi
    for p in "$@"; do names+=("$(pkg_name "$pm" "$p")"); done
    case "$pm" in
        apt) as_root apt-get update -qq && as_root apt-get install -y -qq "${names[@]}" ;;
        dnf | yum) as_root "$pm" install -y -q "${names[@]}" ;;
        pacman) as_root pacman -S --needed --noconfirm "${names[@]}" ;;
        zypper) as_root zypper --non-interactive install "${names[@]}" ;;
        apk) as_root apk add --no-cache "${names[@]}" ;;
    esac
}

if [ "$MODE" = source ]; then
    step "Paquetes del sistema (git, enlazador de C, libpcap)"
else
    step "Paquetes del sistema (libpcap, para ver la red en vivo)"
fi
missing=()
if [ "$MODE" = source ]; then
    have git || missing+=(git)
    have curl || missing+=(curl)
    have cc || missing+=(cc)
fi
has_libpcap || missing+=(libpcap)
if [ "$OS" = "Linux" ] && [ -z "${SOCSHARK_NO_SETCAP:-}" ]; then
    find_setcap >/dev/null || missing+=(setcap)
fi

if [ ${#missing[@]} -eq 0 ]; then
    ok "Ya está todo instalado"
elif [ "$OS" = "Darwin" ]; then
    warn "Instalando las herramientas de línea de comandos de Xcode (git y el enlazador)..."
    xcode-select --install 2>/dev/null || true
    die "Termina la instalación de las herramientas de Xcode y vuelve a ejecutar este instalador."
else
    warn "Falta: ${missing[*]}"
    if [ "$SUDO" != "none" ] && install_pkgs "${missing[@]}"; then
        ok "Paquetes instalados"
    else
        warn "No se pudo instalar todo con el gestor de paquetes (¿sin sudo?)."
    fi
fi
if [ "$MODE" = source ]; then
    have git || die "Falta git: instálalo con tu gestor de paquetes y vuelve a ejecutar este instalador."
    have cc || die "Falta un compilador de C (gcc o clang): Rust lo necesita para enlazar."
fi
if has_libpcap; then
    ok "libpcap presente (captura en vivo)"
else
    warn "No se encontró libpcap: abrir capturas funciona; ver la red en vivo, no."
fi

# --- compilar desde el código -------------------------------------------
if [ "$MODE" = source ]; then
    step "Rust"
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
    rust_ok() { have cargo && version_ge "$(rustc --version 2>/dev/null | awk '{print $2}')" "$MIN_RUST"; }
    if ! rust_ok; then
        if have rustup; then
            warn "Rust es anterior a $MIN_RUST: actualizando..."
            rustup update stable
        else
            warn "Instalando Rust con rustup (perfil mínimo)..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
            # shellcheck disable=SC1091
            . "$HOME/.cargo/env"
        fi
    fi
    rust_ok || die "Hace falta Rust $MIN_RUST o más nuevo."
    ok "$(cargo --version)"

    step "Código fuente"
    # Con token (repositorio privado), va en una cabecera solo para git:
    # nunca acaba en .git/config ni en la línea de comandos.
    git_auth() {
        if [ -n "$TOKEN" ]; then
            GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=1 \
                GIT_CONFIG_KEY_0="http.https://github.com/.extraheader" \
                GIT_CONFIG_VALUE_0="Authorization: Basic $(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')" \
                git "$@"
        else
            GIT_TERMINAL_PROMPT=0 git "$@"
        fi
    }
    if in_checkout; then
        SRC_DIR="$here"
        ok "Usando esta copia: $SRC_DIR"
    elif [ -d "$SRC_DIR/.git" ]; then
        if git_auth -C "$SRC_DIR" fetch --quiet origin "$REF" && git -C "$SRC_DIR" checkout --quiet FETCH_HEAD; then
            ok "Actualizado $SRC_DIR ($REF)"
        else
            warn "No se pudo actualizar (se sigue con la copia local)."
        fi
    elif git_auth clone --quiet --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$SRC_DIR"; then
        ok "Clonado en $SRC_DIR"
    else
        die "No se pudo clonar https://github.com/$REPO ($REF). Comprueba la conexión (y, si el repositorio es privado, exporta GH_TOKEN)."
    fi

    step "Compilando (la primera vez tarda unos minutos)"
    (cd "$SRC_DIR" && cargo build --release --locked -p socshark-cli)
    NEW_BIN="$SRC_DIR/target/release/socshark"
fi

# --- instalar -----------------------------------------------------------
step "Instalando"
mkdir -p "$BIN_DIR"
install -m 755 "$NEW_BIN" "$BIN_DIR/socshark"
ok "Instalado en $BIN_DIR/socshark"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        line="export PATH=\"$BIN_DIR:\$PATH\"  # soc-shark"
        for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$rc" ] && ! grep -qxF "$line" "$rc"; then echo "$line" >>"$rc"; fi
        done
        export PATH="$BIN_DIR:$PATH"
        warn "Añadido $BIN_DIR a tu PATH (abre una terminal nueva para que se aplique)."
        ;;
esac

# Ver la red en vivo sin sudo: el mismo permiso que tiene dumpcap (Wireshark).
if [ "$OS" = "Linux" ] && [ -z "${SOCSHARK_NO_SETCAP:-}" ]; then
    if setcap_bin="$(find_setcap)" && as_root "$setcap_bin" cap_net_raw,cap_net_admin=eip "$BIN_DIR/socshark"; then
        ok "Permiso de captura concedido: la red en vivo funciona sin sudo"
    else
        warn "No se pudo dar el permiso de captura. Para ver la red en vivo, ejecuta una vez:"
        printf '       sudo setcap cap_net_raw,cap_net_admin=eip "%s"\n' "$BIN_DIR/socshark"
    fi
elif [ "$OS" = "Darwin" ]; then
    warn "macOS: ver la red en vivo necesita sudo (o ChmodBPF, el ayudante de Wireshark)."
fi

# --- comprobación de punta a punta -----------------------------------------
step "Comprobación (captura de demostración)"
demo="$TMP/demo.pcap"
ok "$("$BIN_DIR/socshark" --version)"
if "$BIN_DIR/socshark" dev sample-pcap -o "$demo" >/dev/null 2>&1 \
    && "$BIN_DIR/socshark" capture -r "$demo" >/dev/null 2>&1; then
    ok "Lectura → disección → conversaciones → motor SOC: todo funciona"
else
    die "El binario no analiza bien la captura de demostración: prueba «socshark capture -r captura.pcap» y mira el error."
fi

cat <<DONE

${C}${B}============================================================${N}
${B} SOC SHARK está listo.${N} Prueba:

   ${G}socshark gui${N}                      ventana: ver la red en vivo o abrir una captura
   ${G}socshark gui -r captura.pcapng${N}    ventana con una captura ya abierta
   ${G}socshark tui -r captura.pcap${N}      interfaz en la terminal
   ${G}socshark report -r captura.pcap${N}   informe en lenguaje claro (informe.html)
   ${G}socshark daemon --list${N}            interfaces de red para capturar en vivo
   ${G}socshark --help${N}                   todo lo demás
${C}${B}============================================================${N}
${D} Para actualizar, vuelve a ejecutar este instalador.${N}

DONE
