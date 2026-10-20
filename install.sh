#!/usr/bin/env bash
# =====================================================================
#  SOC SHARK · instalador para Linux (también vale en macOS)
#  ---------------------------------------------------------------------
#  En una línea (mientras el repositorio sea privado, exporta antes un
#  token de GitHub con permiso de lectura):
#
#    export GH_TOKEN=ghp_tu_token
#    curl -fsSL -H "Authorization: token $GH_TOKEN" \
#      https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.sh | bash
#
#  O desde una copia del repositorio:  ./install.sh
#
#  Instala lo que falte (git, un enlazador de C, libpcap, Rust), compila en
#  release, copia `socshark` a ~/.local/bin y le da el permiso de captura
#  (setcap) para ver la red en vivo sin sudo. Se puede volver a ejecutar:
#  actualiza y recompila.
#
#  Ajustes (variables de entorno, todas opcionales):
#    GH_TOKEN / GITHUB_TOKEN  token para clonar el repositorio privado
#    SOCSHARK_REPO            dueño/repo      (por defecto Ruby570bocadito/soc-shark)
#    SOCSHARK_REF             rama o etiqueta (por defecto main)
#    SOCSHARK_DIR             código fuente   (por defecto ~/soc-shark)
#    SOCSHARK_BIN             dónde instalar  (por defecto ~/.local/bin)
#    SOCSHARK_NO_SETCAP=1     no dar el permiso de captura
# =====================================================================
set -euo pipefail

REPO="${SOCSHARK_REPO:-Ruby570bocadito/soc-shark}"
REF="${SOCSHARK_REF:-main}"
SRC_DIR="${SOCSHARK_DIR:-$HOME/soc-shark}"
BIN_DIR="${SOCSHARK_BIN:-$HOME/.local/bin}"
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
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
printf '%s  Tu red, explicada en lenguaje claro · instalador para Linux · %s%s\n' "$D" "$REPO" "$N"

# --- paso 1: plataforma -----------------------------------------------
step "1/6 · Plataforma"
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Linux | Darwin) ok "$OS $ARCH" ;;
    *) die "Sistema no soportado: $OS. En Windows usa install.ps1." ;;
esac

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

# --- paso 2: paquetes del sistema ----------------------------------------
step "2/6 · Paquetes del sistema (git, enlazador de C, libpcap)"
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
missing=()
have git || missing+=(git)
have curl || missing+=(curl)
have cc || missing+=(cc)
has_libpcap || missing+=(libpcap)
if [ "$OS" = "Linux" ] && [ -z "${SOCSHARK_NO_SETCAP:-}" ]; then
    find_setcap >/dev/null || missing+=(setcap)
fi

if [ ${#missing[@]} -eq 0 ]; then
    ok "Ya está todo instalado"
elif [ "$OS" = "Darwin" ]; then
    if printf '%s\n' "${missing[@]}" | grep -qx 'cc\|git'; then
        warn "Instalando las herramientas de línea de comandos de Xcode (git y el enlazador)..."
        xcode-select --install 2>/dev/null || true
        die "Termina la instalación de las herramientas de Xcode y vuelve a ejecutar este instalador."
    fi
else
    warn "Falta: ${missing[*]}"
    if [ "$SUDO" = "none" ]; then
        die "Instálalo con tu gestor de paquetes (aquí no hay sudo) y vuelve a ejecutar este instalador."
    fi
    if have apt-get; then
        as_root apt-get update -qq
        as_root apt-get install -y -qq git curl build-essential libpcap0.8 libcap2-bin
    elif have dnf; then
        as_root dnf install -y -q git curl gcc libpcap libcap
    elif have yum; then
        as_root yum install -y -q git curl gcc libpcap libcap
    elif have pacman; then
        as_root pacman -S --needed --noconfirm git curl base-devel libpcap libcap
    elif have zypper; then
        as_root zypper --non-interactive install git curl gcc libpcap1 libcap-progs
    elif have apk; then
        as_root apk add --no-cache git curl build-base libpcap libcap
    else
        die "Gestor de paquetes desconocido. Instala git, curl, un compilador de C (gcc) y libpcap, y vuelve a ejecutarlo."
    fi
    ok "Paquetes instalados"
fi
have git || die "Sigue faltando git."
have cc || die "No hay compilador/enlazador de C (cc): Rust lo necesita para enlazar."
if has_libpcap; then
    ok "libpcap presente (captura en vivo)"
else
    warn "No se encontró libpcap: abrir capturas funciona; ver la red en vivo, no."
fi

# --- paso 3: Rust ---------------------------------------------------
step "3/6 · Rust"
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

# --- paso 4: código fuente --------------------------------------------
step "4/6 · Código fuente"
# El token nunca acaba en .git/config ni en la línea de comandos.
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
# Ejecutado como archivo (./install.sh) dentro del repositorio: se usa esa
# copia. Con `curl | bash` no hay archivo y se clona.
here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [ -n "$here" ] && [ -f "$here/Cargo.toml" ] && grep -q 'socshark' "$here/Cargo.toml"; then
    SRC_DIR="$here"
    ok "Usando esta copia: $SRC_DIR"
elif [ -d "$SRC_DIR/.git" ]; then
    if git_auth -C "$SRC_DIR" fetch --quiet origin "$REF" && git -C "$SRC_DIR" checkout --quiet FETCH_HEAD; then
        ok "Actualizado $SRC_DIR ($REF)"
    else
        warn "No se pudo actualizar (se sigue con la copia local)."
    fi
else
    if ! git_auth clone --quiet --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$SRC_DIR"; then
        printf '%s' "$R" >&2
        cat >&2 <<HELP
[X] No se pudo clonar https://github.com/$REPO ($REF).
    Mientras el repositorio sea privado, exporta un token de GitHub con
    permiso de lectura (https://github.com/settings/tokens) y vuelve a
    ejecutar el instalador:

      export GH_TOKEN=ghp_tu_token
HELP
        printf '%s' "$N" >&2
        exit 1
    fi
    ok "Clonado en $SRC_DIR"
fi

# --- paso 5: compilar e instalar --------------------------------------
step "5/6 · Compilando (la primera vez tarda unos minutos)"
(cd "$SRC_DIR" && cargo build --release --locked -p socshark-cli)
mkdir -p "$BIN_DIR"
install -m 755 "$SRC_DIR/target/release/socshark" "$BIN_DIR/socshark"
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

# --- paso 6: comprobación de punta a punta ---------------------------------------
step "6/6 · Comprobación (captura de demostración)"
demo="$(mktemp -t socshark-demo.XXXXXX)"
trap 'rm -f "$demo"' EXIT
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
${D} Documentación: $SRC_DIR/docs · para actualizar, vuelve a ejecutar este instalador${N}

DONE
