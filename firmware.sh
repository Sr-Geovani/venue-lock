#!/usr/bin/env bash
# =============================================================================
# VENUE LOCK - compila o firmware na própria VPS e publica a atualização.
# Os ESPs online baixam e instalam sozinhos em até 1 minuto (OTA).
#
#   ./firmware.sh            compila e publica se a versão do código for nova
#   ./firmware.sh --force    recompila e republica mesmo com a versão igual
#
# O secret vem do banco do servidor e a senha do portal fica em data/firmware.conf
# (fora do Git). Nada disso entra no repositório.
# =============================================================================
set -Eeuo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$DIR/data/firmware.conf"
SRC="$DIR/firmware/VENUE_Lock_v2/VENUE_Lock_v2.ino"
ACCOUNT="${VL_ACCOUNT:-venue}"
IMAGE="venuelock-fwbuild"
FORCE="${1:-}"

log()  { printf '\033[1;36m[firmware]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aviso]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[erro]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "rode como root"
[[ -f $SRC ]] || die "código do firmware não encontrado: $SRC"
docker inspect -f '{{.State.Running}}' venuelock 2>/dev/null | grep -q true || die "container venuelock não está rodando (rode ./install.sh)"

VER="$(grep -oP '^#define FW_VERSION\s+"\K[^"]+' "$SRC")" || die "FW_VERSION não encontrado no código"
PUB="$(docker exec venuelock python venuelock.py --db /data/venuelock.db fw-version 2>/dev/null | tail -1 || true)"
if [[ $VER == "$PUB" && $FORCE != "--force" ]]; then
  log "firmware $VER já está publicado. Nada a fazer (use --force para recompilar)."
  exit 0
fi
if [[ $FORCE != "--force" ]] && docker exec venuelock python venuelock.py --db /data/venuelock.db fw-known "$VER" >/dev/null 2>&1; then
  # Versão já compilada antes: não republica sozinho (respeita uma volta de versão feita no app)
  log "firmware $VER já foi compilado antes e a publicada agora é ${PUB:-nenhuma}. Nada a fazer."
  log "Para usar a $VER de novo: app -> Conta -> Firmware -> 'Voltar para esta versão'."
  exit 0
fi

# ----------------------------------------------------------------- senha do portal
if [[ ! -f $CONF ]]; then
  [[ -t 0 ]] || die "defina a senha do portal rodando ./firmware.sh no terminal"
  read -rsp "Senha de administrador do portal do ESP (8+ caracteres, letras/números/!@#\$%&*._-): " P; echo
  [[ $P =~ ^[A-Za-z0-9!@#\$%\&*._-]{8,32}$ ]] || die "senha inválida"
  ( umask 077; printf 'ADMIN_PASSWORD=%s\n' "$P" > "$CONF" )
  unset P
  log "Senha salva em $CONF (só root lê)."
fi
ADMIN_PASSWORD="$(grep -m1 '^ADMIN_PASSWORD=' "$CONF" | cut -d= -f2-)"
[[ $ADMIN_PASSWORD =~ ^[A-Za-z0-9!@#\$%\&*._-]{8,32}$ ]] || die "senha inválida em $CONF"

SECRET="$(docker exec venuelock python -c "import sqlite3,sys;r=sqlite3.connect('/data/venuelock.db').execute('select secret from users where username=?',(sys.argv[1],)).fetchone();print(r[0] if r else '')" "$ACCOUNT")"
[[ -n $SECRET ]] || die "conta '$ACCOUNT' não encontrada no servidor"

# ----------------------------------------------------------------- prepara o código
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
mkdir -p "$BUILD/VENUE_Lock_v2" "$BUILD/out"
SECRET="$SECRET" ADMIN_PASSWORD="$ADMIN_PASSWORD" python3 - "$SRC" "$BUILD/VENUE_Lock_v2/VENUE_Lock_v2.ino" <<'PY'
import os, sys
s = open(sys.argv[1], encoding="utf-8").read()
subs = [('#define VL_ACCOUNT_SECRET "COLE_O_SECRET_AQUI"', '#define VL_ACCOUNT_SECRET "%s"' % os.environ["SECRET"]),
        ('#define VL_ADMIN_PASSWORD "TROQUE_ESTA_SENHA"', '#define VL_ADMIN_PASSWORD "%s"' % os.environ["ADMIN_PASSWORD"])]
for old, new in subs:
    if s.count(old) != 1:
        sys.exit("linha esperada não encontrada no firmware: " + old.split('"')[0])
    s = s.replace(old, new)
open(sys.argv[2], "w", encoding="utf-8").write(s)
PY

# ----------------------------------------------------------------- compila
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Primeira vez: preparando o compilador (baixa ~400 MB, leva alguns minutos)..."
fi
docker build -q -t "$IMAGE" "$DIR/firmware/builder" >/dev/null
log "Compilando firmware $VER..."
docker run --rm -v "$BUILD:/work" "$IMAGE" \
  arduino-cli compile --fqbn esp8266:esp8266:generic:eesz=1M --output-dir /work/out /work/VENUE_Lock_v2 \
  | grep -E "Sketch uses|Global variables|error|Error" || true
BIN="$BUILD/out/VENUE_Lock_v2.ino.bin"
[[ -f $BIN ]] || die "a compilação falhou (veja as mensagens acima)"
SIZE=$(stat -c %s "$BIN")
(( SIZE < 500000 )) || warn "firmware com $SIZE bytes: perto do limite de atualização remota (~500 KB)"

# ----------------------------------------------------------------- publica
install -o 1000 -g 1000 -m 600 "$BIN" "$DIR/data/incoming.bin"
docker exec venuelock python venuelock.py --db /data/venuelock.db publish-fw /data/incoming.bin
rm -f "$DIR/data/incoming.bin"
log "Pronto: $VER publicado ($SIZE bytes). ESPs online com atualização automática instalam em até 1 minuto."
log "Acompanhe no app: Dispositivos -> Log (ota_enviado / ota_ok)."
