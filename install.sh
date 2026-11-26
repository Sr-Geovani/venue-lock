#!/usr/bin/env bash
# =============================================================================
# VENUE LOCK - instalador / atualizador para VPS com Caddy em Docker.
#
#   ./install.sh lock.venuemarket.com.br [usuario_admin]
#
# Idempotente: rodar de novo atualiza o servidor sem perder dados.
# Não altera outros projetos: só acrescenta um bloco ao Caddyfile existente
# (com backup e validação antes do reload) e sobe o container "venuelock".
#
# Variáveis opcionais:
#   CADDY_CONTAINER   container do Caddy (padrão: deploy-caddy-1)
# =============================================================================
set -Eeuo pipefail

DOMAIN="${1:-}"
ADMIN="${2:-venue}"
CADDY_CONTAINER="${CADDY_CONTAINER:-deploy-caddy-1}"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;36m[venue]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aviso]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[erro]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "falhou na linha $LINENO (comando: $BASH_COMMAND)"' ERR

# ----------------------------------------------------------------- validações
[[ $EUID -eq 0 ]] || die "rode como root (sudo ./install.sh ...)"
[[ -n $DOMAIN ]] || die "uso: ./install.sh lock.seudominio.com.br [usuario_admin]"
[[ $DOMAIN =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "domínio inválido: $DOMAIN"
[[ $ADMIN =~ ^[a-z0-9_.-]{3,32}$ ]] || die "usuário admin inválido: $ADMIN (a-z 0-9 _ . -)"
command -v docker >/dev/null || die "docker não encontrado"
docker compose version >/dev/null 2>&1 || die "plugin 'docker compose' não encontrado"
[[ -f $INSTALL_DIR/server/venuelock.py ]] || die "rode o instalador de dentro da pasta do repositório venue-lock"

# ----------------------------------------------------------------- DNS
VPS_IP="$(curl -fs4 --max-time 8 ifconfig.me || true)"
DNS_IP="$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)"
if [[ -z $DNS_IP ]]; then
  warn "DNS de $DOMAIN ainda não resolve. Crie o registro A -> ${VPS_IP:-IP da VPS}. O HTTPS só sai depois disso."
elif [[ -n $VPS_IP && $DNS_IP != "$VPS_IP" ]]; then
  warn "DNS $DOMAIN -> $DNS_IP, mas a VPS é $VPS_IP. Confira o registro A (se usa proxy Cloudflare, ignore)."
else
  log "DNS ok: $DOMAIN -> $DNS_IP"
fi

# ----------------------------------------------------------------- Caddy existente
docker inspect "$CADDY_CONTAINER" >/dev/null 2>&1 \
  || die "container do Caddy '$CADDY_CONTAINER' não encontrado (defina CADDY_CONTAINER=nome)"
NET="$(docker inspect "$CADDY_CONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')"
CADDYFILE="$(docker inspect "$CADDY_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/caddy/Caddyfile"}}{{.Source}}{{end}}{{end}}')"
[[ -n $NET ]] || die "não achei a rede Docker do $CADDY_CONTAINER"
[[ -f $CADDYFILE ]] || die "Caddyfile do $CADDY_CONTAINER não está montado como arquivo"
log "Caddy: $CADDY_CONTAINER | rede: $NET | Caddyfile: $CADDYFILE"

# ----------------------------------------------------------------- servidor VENUE
cd "$INSTALL_DIR"
mkdir -p data
chown 1000:1000 data
printf 'PROXY_NETWORK=%s\n' "$NET" > .env
log "Construindo e subindo o container venuelock..."
docker compose up -d --build

log "Aguardando o servidor responder..."
for i in $(seq 1 40); do
  if docker exec venuelock python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)" >/dev/null 2>&1; then
    log "Servidor no ar."
    break
  fi
  if [[ $i -eq 40 ]]; then
    docker compose logs --tail 40 || true
    die "o servidor não respondeu em 40 s (logs acima)"
  fi
  sleep 1
done

# ----------------------------------------------------------------- bloco no Caddy
if grep -qE "^[[:space:]]*${DOMAIN//./\\.}[[:space:]]*\{" "$CADDYFILE"; then
  log "Caddyfile já tem o bloco de $DOMAIN."
else
  BACKUP="$CADDYFILE.bak-venuelock-$(date +%Y%m%d-%H%M%S)"
  cp -p "$CADDYFILE" "$BACKUP"
  # '>>' mantém o mesmo arquivo (inode) que o container do Caddy está usando
  printf '\n%s {\n\treverse_proxy venuelock:8080\n}\n' "$DOMAIN" >> "$CADDYFILE"
  if ! docker exec "$CADDY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/tmp/venuelock-caddy.log 2>&1; then
    cat "$BACKUP" > "$CADDYFILE"
    die "Caddyfile ficou inválido e foi restaurado. Detalhes: /tmp/venuelock-caddy.log"
  fi
  log "Bloco de $DOMAIN adicionado (backup: $BACKUP)."
fi
docker exec "$CADDY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
  || die "caddy reload falhou; os outros sites seguem com a configuração anterior"
log "Caddy recarregado sem reiniciar (outros sites não caem)."

# ----------------------------------------------------------------- administrador
if docker exec venuelock python -c "import sqlite3,sys;sys.exit(0 if sqlite3.connect('/data/venuelock.db').execute('select count(*) from users').fetchone()[0] else 1)" 2>/dev/null; then
  log "Usuário administrador já existe."
else
  log "Criando o administrador '$ADMIN' (digite a senha duas vezes):"
  TTY_FLAG="-i"; [[ -t 0 ]] && TTY_FLAG="-it"
  docker exec "$TTY_FLAG" venuelock python venuelock.py create-user "$ADMIN" --admin
fi

# ----------------------------------------------------------------- backup diário
cat > /etc/cron.d/venuelock-backup <<'EOF'
# VENUE LOCK: cópia diária do banco (7 dias rotativos em /opt/venue-lock/data)
15 3 * * * root docker exec venuelock python -c "import sqlite3,datetime;sqlite3.connect('/data/venuelock.db').backup(sqlite3.connect('/data/backup-'+str(datetime.date.today().isoweekday())+'.db'))" >/dev/null 2>&1
EOF
log "Backup diário configurado (03:15)."

# ----------------------------------------------------------------- teste final
if curl -fsS --max-time 15 "https://$DOMAIN/health" >/dev/null 2>&1; then
  log "HTTPS ok: https://$DOMAIN"
else
  warn "https://$DOMAIN ainda não respondeu (DNS ou certificado em emissão). Teste em alguns minutos:"
  warn "  curl https://$DOMAIN/health"
fi

cat <<EOF

=====================================================================
 VENUE LOCK instalado.
   App (iPhone: Safari > Compartilhar > Tela de Início): https://$DOMAIN
   Logs:        cd $INSTALL_DIR && docker compose logs -f
   Atualizar:   cd $INSTALL_DIR && git pull && ./install.sh $DOMAIN
   Dispositivos: docker exec venuelock python venuelock.py list
=====================================================================
EOF
