#!/usr/bin/env bash
# =====================================================================
#  SOC SHARK · Linux and macOS installer
#  ---------------------------------------------------------------------
#  One line:
#
#    curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.sh | bash
#
#  Downloads the ready-made binary from the latest release (checking its
#  SHA-256), installs it into ~/.local/bin and grants it the capture
#  permission (setcap) so live capture works without sudo. If there is no
#  binary for your system, or it fails, it builds from source instead
#  (installing git, a C linker and Rust). From a clone (./install.sh) it
#  builds that clone. Run it again any time to update.
#
#  Options (environment variables, all optional):
#    SOCSHARK_VERSION         version to install, e.g. 0.9.0 (default: latest)
#    SOCSHARK_FROM_SOURCE=1   build from source instead of downloading
#    SOCSHARK_DOWNLOAD_URL    another download location (a release mirror, https:// only)
#    SOCSHARK_BIN             install folder (default ~/.local/bin)
#    SOCSHARK_NO_SETCAP=1     do not grant the capture permission
#    SOCSHARK_REPO            owner/repo     (default Ruby570bocadito/soc-shark)
#    SOCSHARK_REF             branch or tag to build (default: the tag
#                             v$SOCSHARK_VERSION when a version is pinned, else main)
#    SOCSHARK_DIR             source folder  (default ~/soc-shark)
#    GH_TOKEN / GITHUB_TOKEN  token, only to build from a private repository
# =====================================================================
set -euo pipefail

REPO="${SOCSHARK_REPO:-Ruby570bocadito/soc-shark}"
SRC_DIR="${SOCSHARK_DIR:-$HOME/soc-shark}"
BIN_DIR="${SOCSHARK_BIN:-$HOME/.local/bin}"
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
VERSION="${SOCSHARK_VERSION:-}"
VERSION="${VERSION#v}"
# A pinned version also pins the source fallback to its tag.
if [ -n "$VERSION" ]; then
    REF="${SOCSHARK_REF:-v$VERSION}"
else
    REF="${SOCSHARK_REF:-main}"
fi
MIN_RUST="1.88"

# --- output ---------------------------------------------------------
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
printf '%s  Your network, explained in plain language · Linux and macOS installer%s\n' "$D" "$N"

# A mirror must be HTTPS: the SHA-256 check is only as trustworthy as the
# channel that delivers SHA256SUMS.
if [ -n "${SOCSHARK_DOWNLOAD_URL:-}" ]; then
    case "$SOCSHARK_DOWNLOAD_URL" in
        https://*) ;;
        *) die "SOCSHARK_DOWNLOAD_URL must start with https:// (got: $SOCSHARK_DOWNLOAD_URL)." ;;
    esac
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/socshark-install.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# --- system ---------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS/$ARCH" in
    Linux/x86_64 | Linux/amd64) ASSET="socshark-x86_64-unknown-linux-gnu.tar.gz" ;;
    Linux/aarch64 | Linux/arm64) ASSET="socshark-aarch64-unknown-linux-gnu.tar.gz" ;;
    Darwin/*) ASSET="socshark-universal-apple-darwin.tar.gz" ;;
    Linux/*) ASSET="" ;;
    *) die "Unsupported system: $OS. On Windows use install.ps1." ;;
esac

# sudo only when needed (and only if there is one).
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

# Run as a file (./install.sh) inside the repository: build that clone.
# With `curl | bash` there is no file.
here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
in_checkout() { [ -n "$here" ] && [ -f "$here/Cargo.toml" ] && grep -q 'socshark' "$here/Cargo.toml"; }

# --- ready-made binary from the release ------------------------------
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
# Downloads, verifies and tries the binary; leaves its path in $NEW_BIN or
# the reason it cannot be used in $WHY.
download_release() {
    local base
    if [ -n "${SOCSHARK_DOWNLOAD_URL:-}" ]; then
        base="${SOCSHARK_DOWNLOAD_URL%/}"
    elif [ -n "$VERSION" ]; then
        base="https://github.com/$REPO/releases/download/v$VERSION"
    else
        base="https://github.com/$REPO/releases/latest/download"
    fi
    have curl || { WHY="curl is missing"; return 1; }
    local https=(--proto '=https' --proto-redir '=https' --tlsv1.2)
    curl -fsL "${https[@]}" --retry 3 -o "$TMP/$ASSET" "$base/$ASSET" || { WHY="the release${VERSION:+ v$VERSION} has no $ASSET"; return 1; }
    curl -fsL "${https[@]}" --retry 3 -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" || { WHY="the release has no SHA256SUMS"; return 1; }
    local want got
    want="$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print $1}' "$TMP/SHA256SUMS")"
    got="$(sha256_of "$TMP/$ASSET")"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        WHY="its SHA-256 does not match"
        return 1
    fi
    tar -xzf "$TMP/$ASSET" -C "$TMP" socshark || { WHY="$ASSET could not be unpacked"; return 1; }
    # It must start here (glibc, architecture); if not, build instead.
    "$TMP/socshark" --version >/dev/null 2>&1 || { WHY="the binary does not start on this system"; return 1; }
    NEW_BIN="$TMP/socshark"
}

NEW_BIN=""
WHY=""
if [ -n "${SOCSHARK_FROM_SOURCE:-}" ] && [ "${SOCSHARK_FROM_SOURCE}" != 0 ]; then
    WHY="SOCSHARK_FROM_SOURCE is set"
elif in_checkout; then
    WHY="you ran it from a clone"
elif [ -z "$ASSET" ]; then
    WHY="there is no ready-made binary for $ARCH"
else
    step "Downloading SOC SHARK${VERSION:+ v$VERSION}"
    if download_release; then
        ok "$("$NEW_BIN" --version) (SHA-256 verified)"
    fi
fi
MODE=binary
[ -n "$NEW_BIN" ] || MODE=source

# --- system packages (only what is missing) ---------------------------
has_libpcap() {
    if [ "$OS" = "Darwin" ]; then return 0; fi # part of macOS
    { ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null || true; } | grep -q 'libpcap\.so' && return 0
    # No `ldconfig -p` (Alpine/musl): look for the file.
    compgen -G '/usr/lib*/libpcap.so*' >/dev/null || compgen -G '/usr/lib/*/libpcap.so*' >/dev/null \
        || compgen -G '/lib/*/libpcap.so*' >/dev/null
}
find_setcap() {
    for c in "$(command -v setcap 2>/dev/null || true)" /usr/sbin/setcap /sbin/setcap; do
        if [ -n "$c" ] && [ -x "$c" ]; then echo "$c"; return 0; fi
    done
    return 1
}
# Package name of each piece in each package manager.
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
        apt) as_root apt-get update -qq >/dev/null && as_root apt-get install -y -qq "${names[@]}" >/dev/null ;;
        dnf | yum) as_root "$pm" install -y -q "${names[@]}" >/dev/null ;;
        pacman) as_root pacman -S --needed --noconfirm "${names[@]}" >/dev/null ;;
        zypper) as_root zypper --non-interactive --quiet install "${names[@]}" >/dev/null ;;
        apk) as_root apk add --no-cache --quiet "${names[@]}" ;;
    esac
}

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
if [ ${#missing[@]} -gt 0 ]; then
    if [ "$OS" = "Darwin" ]; then
        warn "Installing the Xcode command line tools (git and the linker)..."
        xcode-select --install 2>/dev/null || true
        die "Finish the Xcode tools installation and run this installer again."
    fi
    step "Installing system packages: ${missing[*]}"
    if [ "$SUDO" != "none" ] && install_pkgs "${missing[@]}"; then
        ok "Installed"
    else
        warn "Could not install everything with the package manager (no sudo?)."
    fi
fi

# --- build from source (only without a usable binary) -----------------
if [ "$MODE" = source ]; then
    step "Building from source"
    warn "Building because $WHY."
    have git || die "git is missing: install it with your package manager and run this installer again."
    have cc || die "A C compiler (gcc or clang) is missing: Rust needs it to link."

    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
    rust_ok() { have cargo && version_ge "$(rustc --version 2>/dev/null | awk '{print $2}')" "$MIN_RUST"; }
    if ! rust_ok; then
        if have rustup; then
            rustup update stable >/dev/null
        else
            printf '   Installing Rust with rustup...\n'
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain stable >/dev/null
            # shellcheck disable=SC1091
            . "$HOME/.cargo/env"
        fi
    fi
    rust_ok || die "Rust $MIN_RUST or newer is required."
    ok "$(cargo --version)"

    # With a token (private repository) it travels in a header for git
    # only: it never ends up in .git/config nor on the command line.
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
    elif [ -d "$SRC_DIR/.git" ]; then
        if ! { git_auth -C "$SRC_DIR" fetch --quiet origin "$REF" && git -C "$SRC_DIR" checkout --quiet FETCH_HEAD; }; then
            warn "Could not update the source; building the local copy."
        fi
    else
        git_auth clone --quiet --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$SRC_DIR" \
            || die "Could not clone https://github.com/$REPO ($REF). Check your connection."
    fi
    ok "Source: $SRC_DIR"

    printf '   Compiling (a few minutes the first time)...\n'
    (cd "$SRC_DIR" && cargo build --release --locked --quiet -p socshark-cli)
    NEW_BIN="$SRC_DIR/target/release/socshark"
    ok "Built"
fi

# --- install, permission and a quick self-test -------------------------
step "Installing"
mkdir -p "$BIN_DIR"
install -m 755 "$NEW_BIN" "$BIN_DIR/socshark"
ok "$BIN_DIR/socshark"

new_terminal=""
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        line="export PATH=\"$BIN_DIR:\$PATH\"  # soc-shark"
        for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$rc" ] && ! grep -qxF "$line" "$rc"; then echo "$line" >>"$rc"; fi
        done
        export PATH="$BIN_DIR:$PATH"
        new_terminal=1
        ;;
esac

demo="$TMP/selftest.pcap"
if "$BIN_DIR/socshark" dev sample-pcap -o "$demo" >/dev/null 2>&1 \
    && "$BIN_DIR/socshark" capture -r "$demo" >/dev/null 2>&1; then
    ok "Self-test passed"
else
    die "socshark is installed but could not analyse a demo capture. Try: socshark capture -r <file.pcap>"
fi

# Live capture without sudo. The file capabilities apply to the whole
# socshark binary (there is no separate capture helper yet; see
# docs/security.md). CAP_NET_RAW opens the capture socket; CAP_NET_ADMIN is
# only needed for promiscuous/monitor mode on some setups. Effective and
# permitted only, never inheritable: programs it starts do not get them.
if ! has_libpcap; then
    warn "libpcap is missing: opening captures works, live capture does not."
elif [ "$OS" = "Linux" ] && [ -z "${SOCSHARK_NO_SETCAP:-}" ]; then
    if setcap_bin="$(find_setcap)" && as_root "$setcap_bin" cap_net_raw,cap_net_admin=ep "$BIN_DIR/socshark"; then
        ok "Live capture ready (no sudo needed)"
    else
        warn "For live capture, run once: sudo setcap cap_net_raw,cap_net_admin=ep \"$BIN_DIR/socshark\""
    fi
elif [ "$OS" = "Darwin" ]; then
    warn "Live capture on macOS needs sudo (or Wireshark's ChmodBPF helper)."
fi

printf '\n%s  SOC SHARK is ready.%s\n' "$C$B" "$N"
if [ -n "$new_terminal" ]; then
    printf '%s  Open a new terminal (it was added to your PATH) and try:%s\n' "$D" "$N"
else
    printf '%s  Try:%s\n' "$D" "$N"
fi
printf '    %ssocshark gui%s                   window: watch your network live or open a capture\n' "$G" "$N"
printf '    %ssocshark tui -r capture.pcap%s   terminal interface\n' "$G" "$N"
printf '    %ssocshark --help%s                everything else\n\n' "$G" "$N"
