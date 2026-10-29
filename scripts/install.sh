#!/usr/bin/env bash
# =============================================================================
# invpush — instalador (Linux)
#
# Instala o binário da última release em ~/.local/bin (sem sudo), conferindo o
# SHA256SUMS, e agenda a autoatualização diária com um timer systemd do
# usuário (`invpush-update.timer` → `invpush update --quiet`).
#
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/vandinho10/invpush/main/scripts/install.sh | bash
#   ./scripts/install.sh [--no-timer]
#
# Variáveis:
#   INVPUSH_REPO         owner/repo (padrão: vandinho10/invpush)
#   INVPUSH_TAG          tag fixa (ex.: v1.2.0); padrão = última release
#   INVPUSH_INSTALL_DIR  pasta de instalação (padrão: ~/.local/bin)
# =============================================================================
set -euo pipefail

APP="invpush"
REPO="${INVPUSH_REPO:-vandinho10/invpush}"
TAG="${INVPUSH_TAG:-}"
INSTALL_DIR="${INVPUSH_INSTALL_DIR:-$HOME/.local/bin}"
TIMER=1
[[ "${1:-}" == "--no-timer" ]] && TIMER=0

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
info() { printf '  \033[36m→\033[0m     %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m     %s\n' "$*"; }
die()  { printf '  \033[31mERRO\033[0m  %s\n' "$*" >&2; exit 1; }

for c in curl sha256sum uname install; do
  command -v "$c" >/dev/null 2>&1 || die "comando obrigatorio nao encontrado: $c"
done

case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  armv7*|armv6*|arm*) ARCH=arm32 ;;
  *) die "arquitetura nao suportada: $(uname -m)" ;;
esac
ASSET="${APP}-linux-${ARCH}"

if [[ -z "$TAG" ]]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$TAG" ]] || die "nao foi possivel descobrir a ultima release de ${REPO}"
fi
info "Release: ${TAG} (${ASSET})"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/${REPO}/releases/download/${TAG}"
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET" || die "falha ao baixar $ASSET"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || die "release ${TAG} sem SHA256SUMS"
( cd "$TMP" && grep -E "[[:space:]]\*?${ASSET}\$" SHA256SUMS | sha256sum -c --status - ) \
  || die "SHA256 nao confere para $ASSET"
ok "SHA256 conferido"

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/$APP"
[[ -x "$DEST" ]] && cp -p "$DEST" "$DEST.old"
install -m 0755 "$TMP/$ASSET" "$DEST.new"
mv -f "$DEST.new" "$DEST"
"$DEST" --version >/dev/null || die "binario instalado nao responde a --version"
ok "Instalado: $DEST ($("$DEST" --version))"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "$INSTALL_DIR nao esta no PATH" ;;
esac

if [[ "$TIMER" == 1 ]]; then
  if ! systemctl --user show-environment >/dev/null 2>&1; then
    warn "systemd do usuario indisponivel; agende manualmente: $DEST update --quiet"
    exit 0
  fi
  UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/${APP}-update.service" <<EOF
[Unit]
Description=Autoatualizacao do ${APP} (GitHub Releases, SHA256 obrigatorio)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=${DEST} update --quiet
EOF
  cat > "$UNIT_DIR/${APP}-update.timer" <<EOF
[Unit]
Description=Verificacao diaria de nova versao do ${APP}

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now "${APP}-update.timer" >/dev/null
  ok "Timer ativo: ${APP}-update.timer (diario)"
  if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]]; then
    warn "linger desligado: o timer so roda com sessao aberta (sudo loginctl enable-linger $USER)"
  fi
fi
