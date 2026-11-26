// =============================================================================
// VENUE LOCK v2 — ESP-01S Relay + fechadura eletroímã (energizado = trancado)
//
// Placa: "Generic ESP8266 Module" | Flash 1MB (FS: none ou 64KB) | Crystal 26MHz
// Bibliotecas: ESP8266 core >= 3.1 | WebSockets (Markus Sattler) >= 2.4.1
//              ArduinoJson >= 7.0
//
// Canais de comando (todos funcionam sem internet, exceto o 1):
//   1) Servidor  : wss persistente, mensagens assinadas HMAC (sem TLS novo a cada comando)
//   2) Rede local: http://<uuid>.local  (PIN, desafio HMAC, anti força-bruta)
//   3) AP próprio: "VENUE-<uuid>" (senha = PIN) quando o roteador cai > 60 s
//   4) Botão GPIO2: toque = libera | segurar 4 s = portal de configuração
// Atualização remota (OTA): o servidor manda a ordem assinada; o ESP baixa o .bin
// pelo HTTPS e confere o MD5 recebido pelo canal autenticado antes de gravar.
// Arduino IDE -> Flash Size: "1MB (FS:none OTA:~502KB)" (obrigatório para OTA).
// =============================================================================
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include <bearssl/bearssl.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <memory>
extern "C" {
#include <user_interface.h>
}

#define FW_VERSION      "2.4.2"     // mude a cada nova versão antes de exportar o .bin

// ============================ CONFIGURAÇÃO FIXA ==============================
// Gravada no firmware: o instalador NÃO vê nem altera. No portal do ESP só
// aparecem Wi-Fi e nome do ponto. Cole o secret (app -> Conta -> Secret do ESP)
// antes de compilar. NUNCA envie este arquivo com o secret para o GitHub.
#define VL_SERVER_HOST    "lock.venuemarket.com.br"
#define VL_SERVER_PORT    443
#define VL_ACCOUNT_USER   "venue"
#define VL_ACCOUNT_SECRET "COLE_O_SECRET_AQUI"
#define VL_ADMIN_PASSWORD "TROQUE_ESTA_SENHA"   // senha para abrir a configuração no ESP (mín. 8)
#define RELAY_ACTIVE_HIGH 1          // padrão de fábrica; ajustável no portal (Configurações avançadas)
static_assert(sizeof(VL_ACCOUNT_SECRET) - 1 >= 20,
              "Cole o secret da conta em VL_ACCOUNT_SECRET (app VENUE -> Conta -> Secret do ESP)");
// =============================================================================
#define RELAY_GPIO      0
#define BUTTON_GPIO     2        // botão para GND (INPUT_PULLUP). Não pressionar no boot.
#define BUTTON_ENABLED  1
#define SERIAL_DEBUG    1

static const uint32_t CFG_MAGIC          = 0x564C4B33;  // "VLK3"
static const uint32_t WIFI_AP_FALLBACK_MS= 60000;       // roteador fora > 60 s abre AP de emergência
static const uint32_t AP_IDLE_CLOSE_MS   = 30000;       // AP fecha 30 s após Wi-Fi voltar e sem clientes
static const uint32_t PORTAL_IDLE_MS     = 300000;      // portal de configuração: 5 min sem uso
static const uint32_t NONCE_TTL_MS       = 30000;
static const uint32_t PORTAL_SESSION_MS  = 600000;      // login do portal vale 10 min sem uso
static const uint8_t  LOCAL_MAX_FAILS    = 5;
static const uint32_t LOCAL_LOCKOUT_MS   = 60000;
static const uint32_t PING_MS            = 60000;
static const uint32_t BTN_LONG_MS        = 4000;
static const uint32_t BTN_DEBOUNCE_MS    = 40;

#if SERIAL_DEBUG
  #define LOGF(...) do { Serial.printf(__VA_ARGS__); Serial.println(); } while (0)
#else
  #define LOGF(...) do {} while (0)
#endif

// Marca lida pelo servidor no upload: identifica o firmware VENUE e a versão.
const char FW_TAG[] = "VLFW:" FW_VERSION ":END";

enum Policy : uint8_t { POLICY_RELEASE = 0, POLICY_HOLD = 1 };

struct Config {
  uint32_t magic;
  char ssid[33], pass[65], host[64];
  uint16_t port;
  char user[33], secret[65], uuid[33], name[33], pin[17];
  uint8_t policy, armed, activeHigh, egress;
  uint16_t graceS, releaseMs;
  uint8_t lcfgDirty;      // ajuste feito no portal local ainda não enviado ao servidor
  uint32_t crc;
} cfg;

struct Ev { uint32_t at; char k[14]; char src[8]; char d[56]; };
static const uint8_t EVQ = 24;
Ev evq[EVQ];
uint8_t evHead = 0, evLen = 0;

// Checagem em tempo de compilação (fica depois dos structs: o Arduino IDE gera os
// protótipos das funções antes da primeira função do arquivo)
constexpr bool cstrEq(const char* a, const char* b) { return *a == *b && (*a == 0 || cstrEq(a + 1, b + 1)); }
static_assert(!cstrEq(VL_ADMIN_PASSWORD, "TROQUE_ESTA_SENHA") && sizeof(VL_ADMIN_PASSWORD) - 1 >= 8,
              "Defina VL_ADMIN_PASSWORD (mínimo 8 caracteres): é a senha do portal de configuração do ESP");

ESP8266WebServer web(80);
DNSServer dns;
WebSocketsClient ws;

uint8_t dkey[32];
char serverNonce[33] = "", clientNonce[33] = "", localNonce[33] = "";
uint32_t localNonceAt = 0, localLockUntil = 0;
uint8_t localFails = 0;
bool wsAuthed = false;
uint32_t lastQ = 0, lastLinkMs = 0, lastPingMs = 0;
bool offlineFree = false, localLockOverride = false;
bool pulseActive = false;
uint32_t pulseStart = 0;
bool relayOn = false;
bool portalMode = false;
uint32_t portalActivity = 0;
bool apFallback = false;
uint32_t wifiDownSince = 0, apIdleSince = 0;
bool mdnsUp = false;
uint32_t restartAt = 0;
enum WifiTest : uint8_t { T_IDLE, T_TEST, T_OK, T_FAIL };
WifiTest tState = T_IDLE;
String tSsid, tPass, tMsg;
uint32_t tStart = 0;
bool firstSetup = false;
uint32_t relayTestUntil = 0;
uint8_t relayTestAh = 1;
char portalSession[33] = "";
uint32_t portalSessionAt = 0, portalLockUntil = 0;
uint8_t portalFails = 0;
bool otaPending = false;
String otaPath, otaMd5, otaVer;

// ------------------------------------------------------------------ utils
uint32_t cfgCrc(const uint8_t* d, size_t n) {
  uint32_t c = 0xFFFFFFFF;
  while (n--) { c ^= *d++; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320 & (0 - (c & 1))); }
  return ~c;
}

void toHex(const uint8_t* in, size_t n, char* out) {
  static const char* h = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) { out[2 * i] = h[in[i] >> 4]; out[2 * i + 1] = h[in[i] & 15]; }
  out[2 * n] = 0;
}

void hmacSha256(const uint8_t* key, size_t klen, const char* msg, size_t mlen, uint8_t out[32]) {
  br_hmac_key_context kc;
  br_hmac_key_init(&kc, &br_sha256_vtable, key, klen);
  br_hmac_context hc;
  br_hmac_init(&hc, &kc, 0);
  br_hmac_update(&hc, msg, mlen);
  br_hmac_out(&hc, out);
}

String hmacHex(const uint8_t* key, size_t klen, const String& msg) {
  uint8_t mac[32]; char hex[65];
  hmacSha256(key, klen, msg.c_str(), msg.length(), mac);
  toHex(mac, 32, hex);
  return String(hex);
}

// Comparação exata em tempo constante (senhas)
bool ctEqualExact(const String& a, const String& b) {
  size_t n = max(a.length(), b.length());
  uint8_t r = a.length() != b.length();
  for (size_t i = 0; i < n; i++) r |= (uint8_t)(i < a.length() ? a[i] : 0) ^ (uint8_t)(i < b.length() ? b[i] : 0);
  return r == 0;
}

bool ctEqual(const String& a, const String& b) {
  if (a.length() != b.length()) return false;
  uint8_t r = 0;
  for (size_t i = 0; i < a.length(); i++) r |= (uint8_t)(a[i] ^ tolower(b[i]));
  return r == 0;
}

void randomHex(char out[33]) {
  uint8_t b[16];
  for (int i = 0; i < 16; i += 4) { uint32_t r = ESP.random(); memcpy(b + i, &r, 4); }
  toHex(b, 16, out);
}

bool validUuid(const char* s) {
  size_t n = strlen(s);
  if (n < 2 || n > 32 || !isalnum(s[0])) return false;
  for (size_t i = 0; i < n; i++) if (!(islower(s[i]) || isdigit(s[i]) || s[i] == '_' || s[i] == '-')) return false;
  return true;
}

String htmlEsc(const char* s) {
  String o;
  for (; *s; s++) {
    if (*s == '&') o += F("&amp;"); else if (*s == '<') o += F("&lt;");
    else if (*s == '>') o += F("&gt;"); else if (*s == '"') o += F("&quot;"); else o += *s;
  }
  return o;
}

String mdnsName() {
  String h = cfg.uuid; h.replace('_', '-');
  return h;
}

bool provisioned() {
  return cfg.ssid[0] && validUuid(cfg.uuid);
}

// ------------------------------------------------------------------ config
void cfgDefaults() {
  memset(&cfg, 0, sizeof(cfg));
  cfg.magic = CFG_MAGIC;
  cfg.port = 443;
  snprintf(cfg.uuid, sizeof(cfg.uuid), "vl-%06x", ESP.getChipId());
  strlcpy(cfg.name, cfg.uuid, sizeof(cfg.name));
  cfg.policy = POLICY_RELEASE;
  cfg.armed = 1;
  cfg.activeHigh = RELAY_ACTIVE_HIGH;
  cfg.graceS = 60;
  cfg.releaseMs = 5000;
}

void cfgSave() {
  cfg.magic = CFG_MAGIC;
  cfg.crc = cfgCrc((const uint8_t*)&cfg, offsetof(Config, crc));
  EEPROM.put(0, cfg);
  if (!EEPROM.commit()) LOGF("[cfg] ERRO ao gravar EEPROM");
}

void cfgLoad() {
  EEPROM.get(0, cfg);
  if (cfg.magic != CFG_MAGIC || cfg.crc != cfgCrc((const uint8_t*)&cfg, offsetof(Config, crc))) {
    LOGF("[cfg] EEPROM vazia/corrompida: padrões de fábrica");
    cfgDefaults();
    cfgSave();
  }
  cfg.ssid[32] = cfg.pass[64] = cfg.host[63] = cfg.user[32] = cfg.secret[64] = 0;
  cfg.uuid[32] = cfg.name[32] = cfg.pin[16] = 0;
  if (cfg.graceS < 10) cfg.graceS = 60;
  if (cfg.releaseMs < 1000 || cfg.releaseMs > 60000) cfg.releaseMs = 5000;
  // Servidor, conta, secret e polaridade vêm sempre do firmware (não editáveis no campo)
  strlcpy(cfg.host, VL_SERVER_HOST, sizeof(cfg.host));
  cfg.port = VL_SERVER_PORT;
  strlcpy(cfg.user, VL_ACCOUNT_USER, sizeof(cfg.user));
  strlcpy(cfg.secret, VL_ACCOUNT_SECRET, sizeof(cfg.secret));
  cfg.activeHigh = cfg.activeHigh ? 1 : 0;
}

void deriveDeviceKey() {
  String m = String("dev:") + cfg.uuid;
  hmacSha256((const uint8_t*)cfg.secret, strlen(cfg.secret), m.c_str(), m.length(), dkey);
}

// ------------------------------------------------------------------ relay
// Energizado = eletroímã segurando = TRANCADO. Qualquer falha do ESP = porta livre.
bool effectivePolicyHold() { return cfg.policy == POLICY_HOLD && cfg.egress; }

void sendState();

void applyRelay() {
  bool on = cfg.armed && !pulseActive && !offlineFree && !portalMode;
  if (on == relayOn) return;
  relayOn = on;
  digitalWrite(RELAY_GPIO, (on == (bool)cfg.activeHigh) ? HIGH : LOW);
  LOGF("[rele] %s (armed=%d pulso=%d queda=%d portal=%d)", on ? "TRANCADO" : "LIVRE",
       cfg.armed, pulseActive, offlineFree, portalMode);
  sendState();
}

// ------------------------------------------------------------------ events
void sendJson(JsonDocument& d) {
  if (!wsAuthed) return;
  String out; serializeJson(d, out); ws.sendTXT(out);
}

void sendEventNow(const Ev& e) {
  JsonDocument d;
  d["t"] = "ev"; d["ago"] = millis() - e.at; d["k"] = e.k; d["src"] = e.src; d["d"] = e.d;
  sendJson(d);
}

void logEvent(const char* k, const char* src, const char* detail = "") {
  Ev e; e.at = millis();
  strlcpy(e.k, k, sizeof(e.k)); strlcpy(e.src, src, sizeof(e.src)); strlcpy(e.d, detail, sizeof(e.d));
  LOGF("[ev] %s via %s %s", k, src, detail);
  if (wsAuthed) { sendEventNow(e); return; }
  if (evLen == EVQ) { evHead = (evHead + 1) % EVQ; evLen--; }
  evq[(evHead + evLen) % EVQ] = e; evLen++;
}

void flushEvents() {
  while (evLen && wsAuthed) { sendEventNow(evq[evHead]); evHead = (evHead + 1) % EVQ; evLen--; }
}

void sendState() {
  JsonDocument d;
  d["t"] = "st"; d["armed"] = (bool)cfg.armed; d["relay"] = relayOn; d["free"] = offlineFree;
  sendJson(d);
}

// ------------------------------------------------------------------ actions
// Retorna "" se ok, ou o motivo da recusa.
String doAction(const String& a, const char* src) {
  if (portalMode) return "portal_ativo";
  if (a == "release") {
    pulseActive = true; pulseStart = millis();
    logEvent("release", src);
  } else if (a == "lock") {
    if (!cfg.armed) { cfg.armed = 1; cfgSave(); }
    if (offlineFree) { offlineFree = false; localLockOverride = true; }
    pulseActive = false;
    logEvent("lock", src);
  } else if (a == "unlock") {
    if (cfg.armed) { cfg.armed = 0; cfgSave(); }
    pulseActive = false;
    logEvent("unlock", src);
  } else if (a == "reboot") {
    logEvent("reboot", src);
    restartAt = millis() + 600;
  } else if (a != "status") {
    return "acao_invalida";
  }
  applyRelay();
  sendState();
  return "";
}

// ------------------------------------------------------------------ websocket (servidor)
void handleSigned(const char* p, const char* s) {
  String expect = hmacHex(dkey, 32, String(clientNonce) + "|" + p);
  if (!ctEqual(expect, String(s))) { LOGF("[ws] assinatura inválida: descartado"); return; }
  JsonDocument d;
  if (deserializeJson(d, p)) return;
  uint32_t q = d["q"] | 0;
  if (q <= lastQ) { LOGF("[ws] replay q=%u descartado", q); return; }
  lastQ = q;
  const char* k = d["k"] | "";
  if (!strcmp(k, "cfg")) {
    bool changed = false;
    const char* name = d["name"] | cfg.name; const char* pin = d["pin"] | cfg.pin;
    const char* pol = d["policy"] | "release";
    uint8_t policy = !strcmp(pol, "hold") ? POLICY_HOLD : POLICY_RELEASE;
    uint32_t grace32 = d["grace"] | (uint32_t)cfg.graceS;
    uint16_t grace = grace32 > 65535 ? 65535 : grace32, rel = d["rel"] | cfg.releaseMs;
    uint8_t egress = (d["egress"] | 0) ? 1 : 0;
    if (strcmp(name, cfg.name)) { strlcpy(cfg.name, name, sizeof(cfg.name)); changed = true; }
    if (strcmp(pin, cfg.pin) && strlen(pin) >= 8) { strlcpy(cfg.pin, pin, sizeof(cfg.pin)); changed = true; }
    if (policy != cfg.policy || grace != cfg.graceS || rel != cfg.releaseMs || egress != cfg.egress) {
      cfg.policy = policy; cfg.graceS = max<uint16_t>(grace, 10);
      cfg.releaseMs = constrain(rel, 1000, 60000); cfg.egress = egress; changed = true;
    }
    if (changed) { cfgSave(); LOGF("[cfg] atualizado pelo servidor: policy=%d grace=%u rel=%u egress=%d",
                               cfg.policy, cfg.graceS, cfg.releaseMs, cfg.egress); }
  } else if (!strcmp(k, "ota")) {
    String path = d["path"] | "", md5 = d["md5"] | "", ver = d["ver"] | "";
    uint32_t size = d["size"] | 0;
    // Confere o espaço ANTES de desconectar: sem espaço, avisa e continua online
    if (size && size > ESP.getFreeSketchSpace()) {
      char e[56];
      snprintf(e, sizeof(e), "%s sem espaco %u/%u: regrave USB FS:none", ver.c_str(), size, ESP.getFreeSketchSpace());
      logEvent("ota_falha", "esp", e);
      return;
    }
    if (path.startsWith("/fw/") && md5.length() == 32 && ver.length() && ver != FW_VERSION) {
      otaPath = path; otaMd5 = md5; otaVer = ver; otaPending = true;
      LOGF("[ota] agendado %s -> %s", FW_VERSION, ver.c_str());
    }
  } else if (!strcmp(k, "cmd")) {
    uint32_t id = d["id"] | 0;
    String a = d["a"] | "";
    String err = (a == "status") ? "acao_invalida" : doAction(a, "app");
    JsonDocument r;
    r["t"] = "ack"; r["id"] = id; r["ok"] = err.length() == 0; r["e"] = err;
    sendJson(r);
  }
}

void wsEvent(WStype_t type, uint8_t* payload, size_t len) {
  switch (type) {
    case WStype_CONNECTED:
      LOGF("[ws] conectado, aguardando desafio");
      wsAuthed = false; lastQ = 0;
      break;
    case WStype_DISCONNECTED:
      if (wsAuthed) { LOGF("[ws] desconectado"); logEvent("srv_off", "esp"); }
      wsAuthed = false;
      break;
    case WStype_TEXT: {
      JsonDocument d;
      if (deserializeJson(d, (const char*)payload, len)) return;
      const char* t = d["t"] | "";
      if (!strcmp(t, "auth")) {
        strlcpy(serverNonce, d["n"] | "", sizeof(serverNonce));
        randomHex(clientNonce);
        JsonDocument h;
        h["t"] = "hello"; h["uuid"] = cfg.uuid; h["cn"] = clientNonce;
        h["m"] = hmacHex(dkey, 32, String("hello|") + serverNonce + "|" + clientNonce);
        h["fw"] = FW_VERSION; h["ip"] = WiFi.localIP().toString(); h["host"] = mdnsName();
        h["rssi"] = WiFi.RSSI(); h["armed"] = (bool)cfg.armed; h["relay"] = relayOn; h["free"] = offlineFree;
        h["boot"] = ESP.getResetInfo(); h["tag"] = FW_TAG;  // inclui exceção/endereço se travou
        h["heap"] = ESP.getFreeHeap();
        if (cfg.lcfgDirty) {
          JsonObject l = h["lcfg"].to<JsonObject>();
          l["policy"] = cfg.policy == POLICY_HOLD ? "hold" : "release";
          l["grace"] = cfg.graceS; l["rel"] = cfg.releaseMs; l["egress"] = cfg.egress;
        }
        String out; serializeJson(h, out); ws.sendTXT(out);
      } else if (!strcmp(t, "ok")) {
        String expect = hmacHex(dkey, 32, String("srv|") + clientNonce + "|" + serverNonce);
        if (!ctEqual(expect, String(d["m"] | ""))) {
          LOGF("[ws] servidor NÃO provou identidade: desconectando");
          ws.disconnect();
          return;
        }
        wsAuthed = true; lastLinkMs = millis();
        if (cfg.lcfgDirty) { cfg.lcfgDirty = 0; cfgSave(); }
        LOGF("[ws] autenticado nos dois sentidos");
        flushEvents();
        sendState();
      } else if (!strcmp(t, "x") && wsAuthed) {
        handleSigned(d["p"] | "", d["s"] | "");
      }
      break;
    }
    case WStype_ERROR:
      LOGF("[ws] erro: %.*s", (int)len, payload ? (const char*)payload : "");
      break;
    default:
      break;
  }
}

void wsStart() {
  String path = String("/ws/esp?u=") + cfg.user;
  bool tls = cfg.port == 443 || cfg.port == 8443;
  if (tls) ws.beginSSL(cfg.host, cfg.port, path.c_str());
  else ws.begin(cfg.host, cfg.port, path.c_str());
  ws.onEvent(wsEvent);
  ws.setReconnectInterval(5000);
  ws.enableHeartbeat(20000, 6000, 2);
  LOGF("[ws] %s://%s:%u%s", tls ? "wss" : "ws", cfg.host, cfg.port, path.c_str());
}

// ------------------------------------------------------------------ página local
static const char LOCAL_HTML[] PROGMEM = R"HTML(<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="apple-mobile-web-app-capable" content="yes">
<title>VENUE Local</title><style>body{margin:0;background:#0b0e13;color:#e9edf3;font:16px -apple-system,system-ui,sans-serif;padding:20px}
.c{background:#151a22;border-radius:18px;padding:18px;margin:12px 0}h1{color:#4fd1b5;margin:6px 0}.m{color:#8b94a5;font-size:14px}
button,input{font:inherit;width:100%;border:0;border-radius:14px;padding:15px;margin-top:10px;background:#1e2430;color:#e9edf3;font-weight:600}
.a{background:#1d3a35;color:#4fd1b5;font-size:20px}.s{font-size:26px;font-weight:700;margin:8px 0}.h{display:none}</style></head><body>
<h1>VENUE Local</h1><div class="m" id="nm">Acesso direto, sem internet</div>
<div class="c" id="lg"><div class="m">PIN do dispositivo</div><input id="pin" type="password" inputmode="numeric" autocomplete="off"><button class="a" onclick="login()">Entrar</button></div>
<div class="c h" id="ap"><div class="m">Estado</div><div class="s" id="st">—</div><div class="m" id="inf"></div>
<button class="a" onclick="act('release')">Liberar porta</button><button onclick="act('lock')">Trancar</button><button onclick="act('unlock')">Destrancar</button>
<button onclick="localStorage.removeItem('vlpin');location.reload()">Sair</button></div><div class="m" id="msg"></div>
<script>%SHA%
const $=i=>document.getElementById(i);let PIN="";try{PIN=localStorage.getItem("vlpin")||""}catch(e){}
async function act(a){try{const n=(await(await fetch("/l/nonce")).json()).n;const b=new URLSearchParams({a,n,m:hmac(PIN,"loc|"+n+"|"+a)});
const r=await fetch("/l/cmd",{method:"POST",body:b});const d=await r.json();if(!r.ok){$("msg").textContent=d.e||"erro";if(r.status==401&&d.e=="pin"){PIN="";show(false)}return false}
show(true);$("nm").textContent=d.name;$("st").textContent=d.free?"LIVRE (queda)":d.relay?"TRANCADO":(d.armed?"LIBERANDO":"DESTRANCADO");
$("inf").textContent=(d.online?"Servidor online":"Servidor offline")+" · liberação "+d.rel/1000+"s";$("msg").textContent=a=="release"?"Liberado":"";
if(a=="release")setTimeout(()=>act("status"),d.rel+400);return true}catch(e){$("msg").textContent="Sem resposta do dispositivo"}}
function show(on){$("lg").className=on?"c h":"c";$("ap").className=on?"c":"c h"}
async function login(){PIN=$("pin").value.trim();if(await act("status")){try{localStorage.setItem("vlpin",PIN)}catch(e){}}}
if(PIN)act("status");</script></body></html>)HTML";

static const char SHA_JS[] PROGMEM = R"JS(function sha256(m){const K=[],H=[];let n=2,c=0;const f=x=>(x-Math.floor(x))*4294967296|0;while(c<64){let p=1;for(let i=2;i*i<=n;i++)if(n%i==0){p=0;break}if(p){if(c<8)H[c]=f(Math.pow(n,.5));K[c++]=f(Math.cbrt(n))}n++}
const l=m.length,b=new Uint8Array(((l+72)>>6)<<6);b.set(m);b[l]=128;const v=new DataView(b.buffer);v.setUint32(b.length-4,l*8);const w=new Int32Array(64);
for(let o=0;o<b.length;o+=64){for(let i=0;i<16;i++)w[i]=v.getInt32(o+i*4);for(let i=16;i<64;i++){const a=w[i-15],d=w[i-2];w[i]=((a>>>7|a<<25)^(a>>>18|a<<14)^(a>>>3))+w[i-7]+((d>>>17|d<<15)^(d>>>19|d<<13)^(d>>>10))+w[i-16]|0}
let[A,B,C,D,E,F,G,I]=H;for(let i=0;i<64;i++){const t=I+((E>>>6|E<<26)^(E>>>11|E<<21)^(E>>>25|E<<7))+(E&F^~E&G)+K[i]+w[i]|0,u=((A>>>2|A<<30)^(A>>>13|A<<19)^(A>>>22|A<<10))+(A&B^A&C^B&C)|0;I=G;G=F;F=E;E=D+t|0;D=C;C=B;B=A;A=t+u|0}
H[0]=H[0]+A|0;H[1]=H[1]+B|0;H[2]=H[2]+C|0;H[3]=H[3]+D|0;H[4]=H[4]+E|0;H[5]=H[5]+F|0;H[6]=H[6]+G|0;H[7]=H[7]+I|0}
const r=new Uint8Array(32),rv=new DataView(r.buffer);H.forEach((h,i)=>rv.setInt32(i*4,h));return r}
function hmac(k,m){const e=new TextEncoder();k=e.encode(k);m=e.encode(m);if(k.length>64)k=sha256(k);const p=new Uint8Array(64);p.set(k);const ip=p.map(x=>x^54),op=p.map(x=>x^92);const a=new Uint8Array(64+m.length);a.set(ip);a.set(m,64);const h=sha256(a),o=new Uint8Array(96);o.set(op);o.set(h,64);return[...sha256(o)].map(x=>x.toString(16).padStart(2,"0")).join("")})JS";

void sendNoCache() { web.sendHeader(F("Cache-Control"), F("no-store")); }

void handleLocalPage() {
  String page = FPSTR(LOCAL_HTML);
  String sha = FPSTR(SHA_JS);
  page.replace("%SHA%", sha);
  sendNoCache();
  web.send(200, F("text/html"), page);
}

void handleNonce() {
  randomHex(localNonce);
  localNonceAt = millis();
  sendNoCache();
  web.send(200, F("application/json"), String("{\"n\":\"") + localNonce + "\"}");
}

void localStatusJson(String& out) {
  JsonDocument d;
  d["name"] = cfg.name; d["armed"] = (bool)cfg.armed; d["relay"] = relayOn; d["free"] = offlineFree;
  d["online"] = wsAuthed; d["rel"] = cfg.releaseMs;
  serializeJson(d, out);
}

void localErr(int code, const char* e) {
  sendNoCache();
  web.send(code, F("application/json"), String("{\"e\":\"") + e + "\"}");
}

void handleLocalCmd() {
  if (localLockUntil && (int32_t)(millis() - localLockUntil) < 0) return localErr(429, "bloqueado_1min");
  localLockUntil = 0;
  if (strlen(cfg.pin) < 8) return localErr(503, "pin_nao_configurado");
  String a = web.arg("a"), n = web.arg("n"), m = web.arg("m");
  bool nonceOk = localNonce[0] && n == localNonce && millis() - localNonceAt < NONCE_TTL_MS;
  localNonce[0] = 0;  // uso único
  if (!nonceOk) return localErr(401, "nonce");
  String expect = hmacHex((const uint8_t*)cfg.pin, strlen(cfg.pin), String("loc|") + n + "|" + a);
  if (!ctEqual(expect, m)) {
    if (++localFails >= LOCAL_MAX_FAILS) { localFails = 0; localLockUntil = millis() + LOCAL_LOCKOUT_MS; logEvent("pin_bloq", "local"); }
    return localErr(401, "pin");
  }
  localFails = 0;
  bool viaAp = web.client().localIP() == WiFi.softAPIP();
  if (a == "reboot") return localErr(400, "acao_invalida");
  String err = doAction(a, viaAp ? "ap" : "local");
  if (err.length()) return localErr(409, err.c_str());
  String out; localStatusJson(out);
  sendNoCache();
  web.send(200, F("application/json"), out);
}

// ------------------------------------------------------------------ portal de configuração
// Nível 1 (sem senha): escolher Wi-Fi da lista, testar a senha antes de salvar e,
// na primeira instalação, o nome do ponto.
// Nível 2 (senha de administrador): polaridade, tempos, política de queda, nome,
// teste do relé, reinício e reset de fábrica.
static const char PORTAL_HTML[] PROGMEM = R"HTML(<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>VENUE Lock</title><style>
body{margin:0;background:#0b0e13;color:#e9edf3;font:16px -apple-system,system-ui,sans-serif;padding:16px}
h1{color:#4fd1b5;margin:4px 0;font-size:24px}.c{background:#151a22;border-radius:16px;padding:14px;margin:12px 0}
.m{color:#8b94a5;font-size:14px}.e{color:#f06a6a}.ok{color:#46d483;font-weight:600}.h{display:none}
button,input,select{font:inherit;width:100%;box-sizing:border-box;border:0;border-radius:12px;padding:13px;margin-top:8px;background:#1e2430;color:#e9edf3}
button{font-weight:600}.a{background:#1d3a35;color:#4fd1b5}.d{background:#3a1f22;color:#f06a6a}
.net{display:flex;justify-content:space-between;text-align:left}.row{display:flex;justify-content:space-between;align-items:center}
.sm{width:auto;padding:8px 12px;margin:0}label{display:block;margin-top:10px;color:#8b94a5;font-size:13px}
.ck{display:flex;gap:8px;align-items:center}.ck input{width:auto;margin:0}</style></head><body>
<h1>VENUE Lock</h1><div class="m" id="sub">carregando…</div>
<div id="vWifi" class="c"><div class="row"><b>Escolha a rede Wi-Fi</b><button class="sm" onclick="scan(1)">Atualizar</button></div>
<div id="nets" class="m">Procurando redes…</div><button onclick="pick('',1,1)">Rede oculta / digitar nome</button>
<div class="m" style="margin-top:8px">Só aparecem redes 2,4 GHz (o ESP não usa 5 GHz).</div></div>
<div id="vPass" class="c h"><b id="pNet"></b><input id="pSsid" class="h" placeholder="Nome da rede" maxlength="32">
<input id="pPass" type="password" placeholder="Senha do Wi-Fi" maxlength="63" autocomplete="off">
<label class="ck"><input type="checkbox" onchange="$('pPass').type=this.checked?'text':'password'">mostrar senha</label>
<button class="a" id="bTest" onclick="test()">Conectar</button><button onclick="show('vWifi')">Voltar</button><div id="tMsg" class="m" style="margin-top:10px"></div></div>
<div id="vSave" class="c h"><div class="ok" id="okMsg"></div><div id="nameBox"><label>Nome do ponto (o mesmo do sistema: a-z, 0-9, _ ou -)</label>
<input id="uuid" autocapitalize="none" maxlength="32"></div><button class="a" onclick="save()">Salvar e reiniciar</button></div>
<div id="vLogin" class="c h"><b>Configurações avançadas</b><label>Senha de administrador</label><input id="lp" type="password" autocomplete="off">
<button class="a" onclick="login()">Entrar</button><button onclick="show('vWifi')">Voltar</button></div>
<div id="vAdv" class="c h"><b>Configurações avançadas</b>
<label>Nome do ponto</label><input id="aUuid" autocapitalize="none" maxlength="32">
<label>Polaridade do relé</label><select id="aAh"><option value="1">Ativo em nível ALTO (padrão ESP-01S Relay)</option><option value="0">Ativo em nível BAIXO</option></select>
<button onclick="relayTest()">Testar relé (1,5 s)</button>
<label>Tempo de liberação (ms)</label><input id="aRel" type="number" min="1000" max="60000">
<label>Na queda de internet</label><select id="aPol"><option value="release">Liberar a porta após o tempo abaixo</option><option value="hold">Manter trancado (exige saída livre)</option></select>
<label>Tempo sem servidor antes de aplicar (s)</label><input id="aGrace" type="number" min="10" max="65535">
<label class="ck"><input id="aEg" type="checkbox">Botão de saída e emergência instalados na alimentação da fechadura</label>
<div class="m" id="aPin" style="margin-top:10px"></div>
<button class="a" onclick="saveAdv()">Salvar avançado</button><button onclick="post('/p/exit',{}).then(()=>bye('Reiniciando…'))">Reiniciar ESP</button>
<button class="d" onclick="factory()">Reset de fábrica</button><button onclick="show('vWifi')">Voltar</button></div>
<div class="c"><button onclick="adv()">Configurações avançadas</button><button onclick="post('/p/exit',{}).then(()=>bye('Saindo sem alterar. O ESP volta ao normal.'))">Sair sem alterar</button></div>
<div id="msg" class="m"></div>
<script>
const $=i=>document.getElementById(i);let INFO={},NETS=[];
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function j(u,o){const r=await fetch(u,o);let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.e||('Erro '+r.status));return d}
function post(u,d){return j(u,{method:'POST',body:new URLSearchParams(d)})}
function show(v){['vWifi','vPass','vSave','vLogin','vAdv'].forEach(x=>$(x).classList.toggle('h',x!==v));msg('')}
function msg(t,bad){$('msg').textContent=t;$('msg').className=bad?'e':'ok'}
function bye(t){document.body.innerHTML='<h1>VENUE Lock</h1><p>'+t+'</p><p class="m">Pode fechar esta página.</p>'}
function bars(r){return r>-60?'▂▄▆█':r>-70?'▂▄▆':r>-80?'▂▄':'▂'}
async function info(){try{INFO=await j('/p/info');$('sub').textContent='fw '+INFO.fw+' · '+INFO.uuid+(INFO.ssid?' · rede atual: '+INFO.ssid:' · primeira instalação');$('uuid').value=INFO.uuid}catch(e){$('sub').textContent='sem resposta do ESP'}}
async function scan(force){$('nets').textContent='Procurando redes…';for(let i=0;i<25;i++){let d={};try{d=await j('/p/scan'+(force&&!i?'?r=1':''))}catch(e){}
 if(d.nets){NETS=d.nets;render();return}await wait(800)}$('nets').textContent='Não foi possível listar as redes. Toque em Atualizar.'}
function render(){const b=$('nets');b.innerHTML='';if(!NETS.length){b.textContent='Nenhuma rede 2,4 GHz encontrada.';return}
 NETS.forEach(n=>{const e=document.createElement('button');e.className='net';const a=document.createElement('span'),c=document.createElement('span');
 a.textContent=n.s;c.textContent=(n.e?'🔒 ':'')+bars(n.r);e.append(a,c);e.onclick=()=>pick(n.s,0,n.e);b.append(e)})}
function pick(s,manual,enc){$('pNet').textContent=manual?'Rede oculta':s;$('pSsid').classList.toggle('h',!manual);$('pSsid').value=s;
 $('pPass').value='';$('pPass').classList.toggle('h',!enc);$('tMsg').textContent='';$('tMsg').className='m';show('vPass');if(enc&&!manual)$('pPass').focus()}
async function test(){const s=$('pSsid').value.trim(),p=$('pPass').value;if(!s){$('tMsg').textContent='Informe o nome da rede';return}
 $('bTest').disabled=true;$('tMsg').className='m';$('tMsg').textContent='Testando a conexão (até 20 s). O celular pode desconectar por alguns segundos: se acontecer, conecte de novo no Wi-Fi VENUE_Lock.';
 try{await post('/p/wifi',{ssid:s,pass:p});for(let i=0;i<45;i++){await wait(1000);let d;try{d=await j('/p/wifi')}catch(e){continue}
  if(d.st==='ok'){$('okMsg').textContent='✓ Conectado em '+s+' (sinal '+d.rssi+' dBm)';$('nameBox').classList.toggle('h',!(INFO.first||INFO.admin));show('vSave');return}
  if(d.st==='fail'){$('tMsg').className='e';$('tMsg').textContent='✗ '+d.msg;return}}
  $('tMsg').className='e';$('tMsg').textContent='Sem resposta do ESP. Conecte de novo no Wi-Fi VENUE_Lock e tente outra vez.'}
 catch(e){$('tMsg').className='e';$('tMsg').textContent=e.message}finally{$('bTest').disabled=false}}
async function save(){try{await post('/p/save',{uuid:$('uuid').value.trim().toLowerCase()});bye('Salvo! O ESP está reiniciando e vai conectar na rede escolhida. Em até 1 minuto ele aparece online no app.')}catch(e){msg(e.message,1)}}
async function adv(){if(INFO.admin)return loadAdv();show('vLogin');$('lp').focus()}
async function login(){try{await post('/p/login',{p:$('lp').value});$('lp').value='';INFO.admin=true;await loadAdv()}catch(e){msg(e.message,1)}}
async function loadAdv(){try{const a=await j('/p/adv');$('aUuid').value=a.uuid;$('aAh').value=a.ah;$('aRel').value=a.rel;$('aPol').value=a.pol;$('aGrace').value=a.grace;$('aEg').checked=!!a.eg;
 $('aPin').textContent='PIN local (Wi-Fi de emergência e acesso .local): '+(a.pin||'ainda não recebido do servidor');show('vAdv')}catch(e){INFO.admin=false;msg(e.message,1);show('vLogin')}}
async function saveAdv(){try{await post('/p/adv',{uuid:$('aUuid').value.trim().toLowerCase(),ah:$('aAh').value,rel:$('aRel').value,pol:$('aPol').value,grace:$('aGrace').value,eg:$('aEg').checked?1:0});
 INFO.uuid=$('aUuid').value.trim().toLowerCase();msg('Salvo. Os ajustes sobem para o servidor quando o ESP reconectar.')}catch(e){msg(e.message,1)}}
async function relayTest(){try{await post('/p/relay',{ah:$('aAh').value});msg('Relé acionado por 1,5 s: a fechadura deve TRAVAR e depois soltar. Se fez o contrário, troque a polaridade.')}catch(e){msg(e.message,1)}}
async function factory(){if(!confirm('Apagar Wi-Fi, nome e ajustes deste ESP?'))return;try{await post('/p/factory',{});bye('Reset de fábrica feito. O ESP reinicia no modo de primeira instalação.')}catch(e){msg(e.message,1)}}
info().then(()=>scan(0));
</script></body></html>)HTML";

bool portalAuthed() {
  if (!portalSession[0] || millis() - portalSessionAt > PORTAL_SESSION_MS) { portalSession[0] = 0; return false; }
  String c = web.header("Cookie");
  int i = c.indexOf("vls=");
  if (i < 0 || !ctEqualExact(c.substring(i + 4, i + 36), String(portalSession))) return false;
  portalSessionAt = millis();
  return true;
}

void jsonReply(int code, JsonDocument& d) {
  String o; serializeJson(d, o);
  sendNoCache();
  web.send(code, F("application/json"), o);
}

void jsonErr(int code, const char* e) {
  JsonDocument d; d["e"] = e;
  jsonReply(code, d);
}

void jsonOk() {
  JsonDocument d; d["ok"] = true;
  jsonReply(200, d);
}

bool requireAdmin() {
  if (portalAuthed()) return true;
  jsonErr(401, "Entre com a senha de administrador");
  return false;
}

void pPage() {
  portalActivity = millis();
  sendNoCache();
  web.send_P(200, PSTR("text/html"), PORTAL_HTML);
}

void pInfo() {
  portalActivity = millis();
  JsonDocument d;
  d["fw"] = FW_VERSION; d["chip"] = String(ESP.getChipId(), HEX); d["uuid"] = cfg.uuid;
  d["ssid"] = cfg.ssid; d["first"] = firstSetup; d["admin"] = portalAuthed();
  jsonReply(200, d);
}

void pScan() {
  portalActivity = millis();
  int n = WiFi.scanComplete();
  if (web.hasArg("r") && n != WIFI_SCAN_RUNNING) { WiFi.scanDelete(); n = WIFI_SCAN_FAILED; }
  if (n == WIFI_SCAN_FAILED) WiFi.scanNetworks(true, false);
  if (n < 0) { JsonDocument d; d["scanning"] = true; return jsonReply(200, d); }
  // ordena por sinal e remove duplicadas (mesma rede em vários roteadores/repetidores)
  int idx[48]; int m = 0;
  for (int i = 0; i < n && m < 48; i++) if (WiFi.SSID(i).length()) idx[m++] = i;
  for (int a = 0; a < m; a++) for (int b = a + 1; b < m; b++) if (WiFi.RSSI(idx[b]) > WiFi.RSSI(idx[a])) { int t = idx[a]; idx[a] = idx[b]; idx[b] = t; }
  JsonDocument d;
  JsonArray arr = d["nets"].to<JsonArray>();
  for (int a = 0; a < m && arr.size() < 25; a++) {
    String ss = WiFi.SSID(idx[a]);
    bool dup = false;
    for (JsonObject o : arr) if (ss == o["s"].as<const char*>()) { dup = true; break; }
    if (dup) continue;
    JsonObject o = arr.add<JsonObject>();
    o["s"] = ss; o["r"] = WiFi.RSSI(idx[a]); o["e"] = WiFi.encryptionType(idx[a]) != ENC_TYPE_NONE;
  }
  jsonReply(200, d);
}

void pWifiStart() {
  portalActivity = millis();
  String ssid = web.arg("ssid"), pass = web.arg("pass");
  ssid.trim();
  if (ssid.isEmpty() || ssid.length() > 32) return jsonErr(400, "Nome da rede invalido");
  if (pass.length() && (pass.length() < 8 || pass.length() > 63)) return jsonErr(400, "A senha do Wi-Fi precisa ter de 8 a 63 caracteres");
  tSsid = ssid; tPass = pass; tMsg = ""; tState = T_TEST; tStart = millis();
  WiFi.scanDelete();
  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(tSsid.c_str(), tPass.c_str());
  LOGF("[portal] testando Wi-Fi \"%s\"", tSsid.c_str());
  jsonOk();
}

void pWifiStatus() {
  portalActivity = millis();
  JsonDocument d;
  d["st"] = tState == T_TEST ? "testing" : tState == T_OK ? "ok" : tState == T_FAIL ? "fail" : "idle";
  d["msg"] = tMsg;
  if (tState == T_OK) d["rssi"] = WiFi.RSSI();
  jsonReply(200, d);
}

void wifiTestTick() {
  if (tState != T_TEST) return;
  wl_status_t st = WiFi.status();
  uint32_t el = millis() - tStart;
  const char* fail = nullptr;
  if (st == WL_CONNECTED) {
    tState = T_OK;
    LOGF("[portal] Wi-Fi OK: %s RSSI %d", WiFi.localIP().toString().c_str(), WiFi.RSSI());
    return;
  }
  if (st == WL_WRONG_PASSWORD) fail = "Senha incorreta. Confira maiusculas/minusculas e tente de novo.";
  else if (st == WL_CONNECT_FAILED && el > 3000) fail = "O roteador recusou a conexao. Confira a senha.";
  else if (st == WL_NO_SSID_AVAIL && el > 8000) fail = "Rede nao encontrada: sinal fraco, nome errado ou rede so 5 GHz.";
  else if (el > 20000) fail = "O roteador nao respondeu em 20 s. Aproxime o ESP do roteador e tente de novo.";
  if (fail) {
    tState = T_FAIL; tMsg = fail;
    WiFi.disconnect(false);  // para de tentar: mantém o AP do portal estável
    LOGF("[portal] Wi-Fi falhou: %s (status %d)", fail, (int)st);
  }
}

void pSave() {
  portalActivity = millis();
  if (tState != T_OK) return jsonErr(409, "Teste a conexao Wi-Fi antes de salvar");
  String uuid = web.arg("uuid"); uuid.trim(); uuid.toLowerCase();
  bool canName = firstSetup || portalAuthed();
  if (canName && uuid.length()) {
    if (!validUuid(uuid.c_str())) return jsonErr(400, "Nome do ponto invalido: use a-z, 0-9, _ ou - (2 a 32)");
    if (strcmp(cfg.uuid, uuid.c_str())) {
      strlcpy(cfg.uuid, uuid.c_str(), sizeof(cfg.uuid));
      strlcpy(cfg.name, cfg.uuid, sizeof(cfg.name));
      cfg.pin[0] = 0;
    }
  }
  strlcpy(cfg.ssid, tSsid.c_str(), sizeof(cfg.ssid));
  strlcpy(cfg.pass, tPass.c_str(), sizeof(cfg.pass));
  cfgSave();
  logEvent("wifi_config", "portal", cfg.ssid);
  LOGF("[portal] salvo: rede \"%s\", ponto %s", cfg.ssid, cfg.uuid);
  jsonOk();
  restartAt = millis() + 1200;
}

void pLogin() {
  portalActivity = millis();
  if (portalLockUntil && (int32_t)(millis() - portalLockUntil) < 0) return jsonErr(429, "Muitas tentativas. Aguarde 1 minuto.");
  portalLockUntil = 0;
  if (!ctEqualExact(web.arg("p"), String(VL_ADMIN_PASSWORD))) {
    if (++portalFails >= LOCAL_MAX_FAILS) { portalFails = 0; portalLockUntil = millis() + LOCAL_LOCKOUT_MS; logEvent("portal_bloq", "local"); }
    LOGF("[portal] senha de admin incorreta");
    return jsonErr(401, "Senha incorreta");
  }
  portalFails = 0;
  randomHex(portalSession);
  portalSessionAt = millis();
  logEvent("portal_login", "local");
  web.sendHeader(F("Set-Cookie"), String("vls=") + portalSession + "; Path=/; HttpOnly; Max-Age=600");
  jsonOk();
}

void pAdvGet() {
  portalActivity = millis();
  if (!requireAdmin()) return;
  JsonDocument d;
  d["uuid"] = cfg.uuid; d["ah"] = cfg.activeHigh; d["rel"] = cfg.releaseMs;
  d["pol"] = cfg.policy == POLICY_HOLD ? "hold" : "release"; d["grace"] = cfg.graceS;
  d["eg"] = cfg.egress; d["pin"] = cfg.pin;
  jsonReply(200, d);
}

void pAdvSave() {
  portalActivity = millis();
  if (!requireAdmin()) return;
  String uuid = web.arg("uuid"); uuid.trim(); uuid.toLowerCase();
  long rel = web.arg("rel").toInt(), grace = web.arg("grace").toInt();
  String pol = web.arg("pol");
  uint8_t eg = web.arg("eg") == "1", ah = web.arg("ah") == "0" ? 0 : 1;
  if (!validUuid(uuid.c_str())) return jsonErr(400, "Nome do ponto invalido: use a-z, 0-9, _ ou - (2 a 32)");
  if (rel < 1000 || rel > 60000) return jsonErr(400, "Tempo de liberacao: 1000 a 60000 ms");
  if (grace < 10 || grace > 65535) return jsonErr(400, "Tempo sem servidor: 10 a 65535 s");
  if (pol != "release" && pol != "hold") return jsonErr(400, "Politica invalida");
  if (pol == "hold" && !eg) return jsonErr(409, "Manter trancado na queda exige saida livre por hardware instalada");
  if (strcmp(cfg.uuid, uuid.c_str())) {
    strlcpy(cfg.uuid, uuid.c_str(), sizeof(cfg.uuid));
    strlcpy(cfg.name, cfg.uuid, sizeof(cfg.name));
    cfg.pin[0] = 0;
  }
  cfg.activeHigh = ah; cfg.releaseMs = rel; cfg.graceS = grace; cfg.egress = eg;
  cfg.policy = pol == "hold" ? POLICY_HOLD : POLICY_RELEASE;
  cfg.lcfgDirty = 1;
  cfgSave();
  logEvent("config_local", "portal");
  LOGF("[portal] avançado salvo: ah=%d rel=%u grace=%u pol=%d eg=%d", ah, cfg.releaseMs, cfg.graceS, cfg.policy, eg);
  jsonOk();
}

void pRelayTest() {
  portalActivity = millis();
  if (!requireAdmin()) return;
  relayTestAh = web.arg("ah") == "0" ? 0 : 1;
  digitalWrite(RELAY_GPIO, relayTestAh ? HIGH : LOW);  // energiza
  relayTestUntil = (millis() + 1500) | 1;
  LOGF("[portal] teste do relé (ativo %s)", relayTestAh ? "ALTO" : "BAIXO");
  jsonOk();
}

void pFactory() {
  portalActivity = millis();
  if (!requireAdmin()) return;
  cfgDefaults(); cfgSave();
  LOGF("[portal] reset de fábrica");
  jsonOk();
  restartAt = millis() + 1200;
}

void pExit() {
  portalActivity = millis();
  jsonOk();
  restartAt = millis() + 800;
}

void startPortal() {
  portalMode = true;
  portalActivity = millis();
  firstSetup = !cfg.ssid[0];
  tState = T_IDLE;
  applyRelay();  // porta livre enquanto alguém configura no local (igual ao firmware antigo)
  ws.disconnect();
  wsAuthed = false;
  WiFi.setAutoReconnect(false);
  WiFi.disconnect(false);  // para tentativas antigas: mantém o AP estável
  WiFi.mode(WIFI_AP_STA);
  char ap[33]; snprintf(ap, sizeof(ap), "VENUE_Lock-%06x", ESP.getChipId());
  WiFi.softAP(ap);  // aberto: só existe na primeira instalação ou com o botão físico
  dns.start(53, "*", WiFi.softAPIP());
  WiFi.scanNetworks(true, false);
  LOGF("[portal] AP %s em http://%s", ap, WiFi.softAPIP().toString().c_str());
  logEvent("portal", "botao");
}

// ------------------------------------------------------------------ roteamento web
void routeRoot() { portalMode ? pPage() : handleLocalPage(); }

void routeNotFound() {
  if (portalMode) {
    web.sendHeader(F("Location"), String("http://") + WiFi.softAPIP().toString() + "/");
    web.send(302, F("text/plain"), "");
  } else {
    web.send(404, F("text/plain"), F("404"));
  }
}

// rotas /p/* só existem com o portal aberto
#define PORTAL_ONLY(fn) []() { if (portalMode) fn(); else web.send(403, F("text/plain"), F("403")); }

void setupWeb() {
  web.on("/", HTTP_GET, routeRoot);
  web.on("/p/info", HTTP_GET, PORTAL_ONLY(pInfo));
  web.on("/p/scan", HTTP_GET, PORTAL_ONLY(pScan));
  web.on("/p/wifi", HTTP_POST, PORTAL_ONLY(pWifiStart));
  web.on("/p/wifi", HTTP_GET, PORTAL_ONLY(pWifiStatus));
  web.on("/p/save", HTTP_POST, PORTAL_ONLY(pSave));
  web.on("/p/login", HTTP_POST, PORTAL_ONLY(pLogin));
  web.on("/p/adv", HTTP_GET, PORTAL_ONLY(pAdvGet));
  web.on("/p/adv", HTTP_POST, PORTAL_ONLY(pAdvSave));
  web.on("/p/relay", HTTP_POST, PORTAL_ONLY(pRelayTest));
  web.on("/p/factory", HTTP_POST, PORTAL_ONLY(pFactory));
  web.on("/p/exit", HTTP_POST, PORTAL_ONLY(pExit));
  web.on("/l/nonce", HTTP_GET, []() { if (portalMode) web.send(403); else handleNonce(); });
  web.on("/l/cmd", HTTP_POST, []() { if (portalMode) web.send(403); else handleLocalCmd(); });
  web.onNotFound(routeNotFound);
  web.collectHeaders("Cookie");  // core ESP8266 3.x: lista variádica
  web.begin();
}

// ------------------------------------------------------------------ Wi-Fi / AP de emergência
const char* wifiReason(wl_status_t st) {
  switch (st) {
    case WL_NO_SSID_AVAIL:   return "rede nao encontrada (nome errado, longe ou so 5 GHz)";
    case WL_CONNECT_FAILED:  return "falha ao conectar (senha errada?)";
    case WL_WRONG_PASSWORD:  return "senha do Wi-Fi errada";
    case WL_DISCONNECTED:    return "tentando conectar";
    case WL_IDLE_STATUS:     return "aguardando";
    case WL_CONNECTION_LOST: return "conexao perdida";
    default:                 return "outro";
  }
}

void wifiTick() {
  uint32_t now = millis();
  wl_status_t st = WiFi.status();
  bool up = st == WL_CONNECTED;
  static wl_status_t lastSt = WL_IDLE_STATUS;
  static uint32_t lastLog = 0;
  static bool wasUp = false;
  if (up && !wasUp) LOGF("[wifi] conectado em \"%s\" IP %s RSSI %d dBm", cfg.ssid, WiFi.localIP().toString().c_str(), WiFi.RSSI());
  if (!up && (st != lastSt || now - lastLog > 10000)) {
    LOGF("[wifi] sem conexao com \"%s\": %s (status %d)", cfg.ssid, wifiReason(st), (int)st);
    lastLog = now;
  }
  lastSt = st; wasUp = up;
  if (up) {
    wifiDownSince = 0;
    if (!mdnsUp) {
      String h = mdnsName();
      mdnsUp = MDNS.begin(h.c_str());
      if (mdnsUp) { MDNS.addService("http", "tcp", 80); LOGF("[wifi] %s  http://%s.local", WiFi.localIP().toString().c_str(), h.c_str()); }
    }
    if (apFallback) {
      if (WiFi.softAPgetStationNum() > 0) apIdleSince = 0;
      else if (!apIdleSince) apIdleSince = now;
      else if (now - apIdleSince > AP_IDLE_CLOSE_MS) {
        WiFi.softAPdisconnect(true); WiFi.mode(WIFI_STA); apFallback = false;
        LOGF("[ap] emergência encerrado (Wi-Fi voltou)");
      }
    }
  } else {
    if (mdnsUp) { MDNS.close(); mdnsUp = false; }
    if (!wifiDownSince) wifiDownSince = now ? now : 1;
    if (!apFallback && now - wifiDownSince > WIFI_AP_FALLBACK_MS && strlen(cfg.pin) >= 8) {
      String ap = String("VENUE-") + cfg.uuid;
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAP(ap.c_str(), cfg.pin);
      apFallback = true; apIdleSince = 0;
      LOGF("[ap] roteador fora: AP de emergência %s em http://%s", ap.c_str(), WiFi.softAPIP().toString().c_str());
      logEvent("ap_emerg", "esp");
    }
  }
}

// ------------------------------------------------------------------ política de queda
void offlineTick() {
  uint32_t now = millis();
  if (wsAuthed) {
    lastLinkMs = now;
    if (offlineFree || localLockOverride) {
      if (offlineFree) logEvent("queda_fim", "esp");
      offlineFree = false; localLockOverride = false;
      applyRelay();
    }
    return;
  }
  if (!offlineFree && !localLockOverride && !effectivePolicyHold() && cfg.armed &&
      now - lastLinkMs >= (uint32_t)cfg.graceS * 1000UL) {
    offlineFree = true;
    char d[24]; snprintf(d, sizeof(d), "%us sem servidor", cfg.graceS);
    logEvent("queda_libera", "esp", d);
    applyRelay();
  }
}

// ------------------------------------------------------------------ botão
void buttonTick() {
#if BUTTON_ENABLED
  static bool stable = false, last = false, longFired = false;
  static uint32_t changedAt = 0, pressedAt = 0;
  bool down = digitalRead(BUTTON_GPIO) == LOW;
  uint32_t now = millis();
  if (down != last) { last = down; changedAt = now; }
  if (now - changedAt < BTN_DEBOUNCE_MS || down == stable) {
    if (stable && !longFired && now - pressedAt >= BTN_LONG_MS) { longFired = true; if (!portalMode) startPortal(); }
    return;
  }
  stable = down;
  if (down) { pressedAt = now; longFired = false; }
  else if (!longFired && now - pressedAt < 1500) { if (!portalMode) doAction("release", "botao"); }
#endif
}

// ------------------------------------------------------------------ OTA
bool doOta(String& err) {
  bool tls = cfg.port == 443 || cfg.port == 8443;
  std::unique_ptr<WiFiClient> client;
  if (tls) {
    BearSSL::WiFiClientSecure* sc = new BearSSL::WiFiClientSecure();
    sc->setInsecure();  // integridade garantida pelo MD5 recebido no canal assinado
    client.reset(sc);
  } else {
    client.reset(new WiFiClient());
  }
  HTTPClient http;
  http.setTimeout(20000);
  // Download autenticado: o servidor só entrega o .bin a um ESP com o secret correto
  String q = otaPath + "?u=" + cfg.user + "&d=" + cfg.uuid + "&t=" + hmacHex(dkey, 32, String("fw|") + otaVer);
  if (!http.begin(*client, String(cfg.host), cfg.port, q, tls)) { err = "begin"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { err = "http " + String(code); http.end(); return false; }
  int len = http.getSize();
  if (len <= 0 || (uint32_t)len > ESP.getFreeSketchSpace()) {
    err = "sem espaco " + String(len) + "/" + String(ESP.getFreeSketchSpace());
    http.end(); return false;
  }
  if (!Update.begin(len)) { err = "update.begin " + String(Update.getError()); http.end(); return false; }
  Update.setMD5(otaMd5.c_str());
  size_t written = Update.writeStream(*http.getStreamPtr());
  http.end();
  if (written != (size_t)len) { Update.end(); err = "incompleto " + String(written) + "/" + String(len); return false; }
  if (!Update.end()) { err = "md5/fim " + String(Update.getError()); return false; }
  return true;
}

void runOta() {
  otaPending = false;
  if (portalMode) return;
  LOGF("[ota] iniciando %s -> %s (heap %u)", FW_VERSION, otaVer.c_str(), ESP.getFreeHeap());
  ws.disconnect();  // libera a sessão TLS do WebSocket para caber a do download
  wsAuthed = false;
  delay(200);
  String err;
  if (ESP.getFreeHeap() < 24000) err = "heap " + String(ESP.getFreeHeap());
  else if (doOta(err)) {
    LOGF("[ota] OK, reiniciando na versão %s", otaVer.c_str());
    delay(200);
    ESP.restart();
  }
  LOGF("[ota] falhou: %s", err.c_str());
  String d = otaVer + " " + err;
  logEvent("ota_falha", "esp", d.c_str());  // sobe quando o WebSocket reconectar
  // A desconexão foi provocada pela atualização: não conta como queda de internet
  lastLinkMs = millis();
}

// ------------------------------------------------------------------ setup / loop
void setup() {
  EEPROM.begin(512);
  cfgLoad();
  // Relé no estado salvo ANTES de qualquer outra coisa: queda de energia não destranca
  // por mais tempo que o boot (~100 ms) e não destranca se estava trancado.
  relayOn = !cfg.armed;  // força applyRelay a escrever o pino
  pinMode(RELAY_GPIO, OUTPUT);
  applyRelay();
#if BUTTON_ENABLED
  pinMode(BUTTON_GPIO, INPUT_PULLUP);
#endif
#if SERIAL_DEBUG
  Serial.begin(115200);
  delay(200);
  Serial.println();
#endif
  LOGF("\n[boot] VENUE Lock fw %s | reset: %s | heap %u", FW_VERSION, ESP.getResetReason().c_str(), ESP.getFreeHeap());
  logEvent("boot", "esp", ESP.getResetReason().c_str());

  WiFi.persistent(false);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  // Brasil: canais 1 a 13 (o padrão do SDK pode limitar a 1-11 e esconder redes nos canais 12/13)
  wifi_country_t country = {"BR", 1, 13, WIFI_COUNTRY_POLICY_MANUAL};
  if (!wifi_set_country(&country)) LOGF("[wifi] aviso: nao foi possivel ajustar canais 1-13");
  setupWeb();
  if (!provisioned()) {
    LOGF("[boot] sem configuração: portal aberto");
    startPortal();
    return;
  }
  deriveDeviceKey();
  WiFi.mode(WIFI_STA);
  WiFi.hostname(mdnsName());
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.ssid, cfg.pass);
  LOGF("[wifi] conectando em \"%s\" (senha com %u caracteres)", cfg.ssid, (unsigned)strlen(cfg.pass));
  wsStart();
  lastLinkMs = millis();  // tolerância de queda conta a partir do boot
}

void loop() {
  uint32_t now = millis();
  web.handleClient();
  buttonTick();

  if (pulseActive && now - pulseStart >= cfg.releaseMs) {
    pulseActive = false;
    applyRelay();
  }
  if (restartAt && (int32_t)(now - restartAt) >= 0) {
    LOGF("[boot] reiniciando");
    delay(50);
    ESP.restart();
  }

  if (portalMode) {
    dns.processNextRequest();
    wifiTestTick();
    if (relayTestUntil && (int32_t)(now - relayTestUntil) >= 0) {
      relayTestUntil = 0;
      digitalWrite(RELAY_GPIO, relayTestAh ? LOW : HIGH);  // desenergiza
      relayOn = false;
    }
    if (provisioned() && now - portalActivity > PORTAL_IDLE_MS) { LOGF("[portal] ocioso: reiniciando"); ESP.restart(); }
    return;
  }

  wifiTick();
  if (mdnsUp) MDNS.update();
  ws.loop();
  offlineTick();

  // OTA só com porta em repouso (sem pulso de liberação em andamento)
  if (otaPending && wsAuthed && !pulseActive) runOta();

  if (wsAuthed && now - lastPingMs >= PING_MS) {
    lastPingMs = now;
    JsonDocument d; d["t"] = "ping"; d["rssi"] = WiFi.RSSI(); d["heap"] = ESP.getFreeHeap();
    sendJson(d);
  }
}
