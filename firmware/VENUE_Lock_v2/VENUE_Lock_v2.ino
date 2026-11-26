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

#define FW_VERSION      "2.3.2"     // mude a cada nova versão antes de exportar o .bin

// ============================ CONFIGURAÇÃO FIXA ==============================
// Gravada no firmware: o instalador NÃO vê nem altera. No portal do ESP só
// aparecem Wi-Fi e nome do ponto. Cole o secret (app -> Conta -> Secret do ESP)
// antes de compilar. NUNCA envie este arquivo com o secret para o GitHub.
#define VL_SERVER_HOST    "lock.venuemarket.com.br"
#define VL_SERVER_PORT    443
#define VL_ACCOUNT_USER   "venue"
#define VL_ACCOUNT_SECRET "COLE_O_SECRET_AQUI"
#define VL_ADMIN_PASSWORD "TROQUE_ESTA_SENHA"   // senha para abrir a configuração no ESP (mín. 8)
#define RELAY_ACTIVE_HIGH 1          // ESP-01S Relay padrão: 1. Só mude se o relé funcionar invertido.
static_assert(sizeof(VL_ACCOUNT_SECRET) - 1 >= 20,
              "Cole o secret da conta em VL_ACCOUNT_SECRET (app VENUE -> Conta -> Secret do ESP)");
// =============================================================================
#define RELAY_GPIO      0
#define BUTTON_GPIO     2        // botão para GND (INPUT_PULLUP). Não pressionar no boot.
#define BUTTON_ENABLED  1
#define SERIAL_DEBUG    1

static const uint32_t CFG_MAGIC          = 0x564C4B32;  // "VLK2"
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
  uint32_t crc;
} cfg;

struct Ev { uint32_t at; char k[14]; char src[8]; char d[24]; };
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
String scanOptions;
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
  cfg.activeHigh = 1;
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
  cfg.activeHigh = RELAY_ACTIVE_HIGH;
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
    uint16_t grace = d["grace"] | cfg.graceS, rel = d["rel"] | cfg.releaseMs;
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
        h["boot"] = ESP.getResetReason(); h["tag"] = FW_TAG;
        String out; serializeJson(h, out); ws.sendTXT(out);
      } else if (!strcmp(t, "ok")) {
        String expect = hmacHex(dkey, 32, String("srv|") + clientNonce + "|" + serverNonce);
        if (!ctEqual(expect, String(d["m"] | ""))) {
          LOGF("[ws] servidor NÃO provou identidade: desconectando");
          ws.disconnect();
          return;
        }
        wsAuthed = true; lastLinkMs = millis();
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
// ------------------------------------------------------------------ login do portal
bool portalAuthed() {
  if (!portalSession[0] || millis() - portalSessionAt > PORTAL_SESSION_MS) { portalSession[0] = 0; return false; }
  String c = web.header("Cookie");
  int i = c.indexOf("vls=");
  if (i < 0 || !ctEqualExact(c.substring(i + 4, i + 36), String(portalSession))) return false;
  portalSessionAt = millis();
  return true;
}

void sendLoginPage(const char* msg) {
  String h = F("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
               "<title>VENUE Lock</title><style>body{background:#0b0e13;color:#e9edf3;font:16px system-ui;padding:16px}"
               "input,button{width:100%;box-sizing:border-box;padding:12px;margin:4px 0 10px;border:0;border-radius:10px;background:#1e2430;color:#e9edf3;font:inherit}"
               "button{background:#1d3a35;color:#4fd1b5;font-weight:700}label{color:#8b94a5;font-size:14px}.e{color:#f06a6a}</style></head><body>"
               "<h2 style='color:#4fd1b5'>VENUE Lock</h2><p style='color:#8b94a5'>Configuração protegida</p>"
               "<form method=post action=/login><label>Senha de administrador</label>"
               "<input name=p type=password autocomplete=current-password required autofocus><button>Entrar</button></form><p class=e>");
  h += msg;
  h += F("</p></body></html>");
  sendNoCache();
  web.send(200, F("text/html"), h);
}

void handleLogin() {
  portalActivity = millis();
  if (portalLockUntil && (int32_t)(millis() - portalLockUntil) < 0) return sendLoginPage("Muitas tentativas. Aguarde 1 minuto.");
  portalLockUntil = 0;
  if (!ctEqualExact(web.arg("p"), String(VL_ADMIN_PASSWORD))) {
    if (++portalFails >= LOCAL_MAX_FAILS) { portalFails = 0; portalLockUntil = millis() + LOCAL_LOCKOUT_MS; logEvent("portal_bloq", "local"); }
    LOGF("[portal] senha incorreta");
    return sendLoginPage("Senha incorreta.");
  }
  portalFails = 0;
  randomHex(portalSession);
  portalSessionAt = millis();
  logEvent("portal_login", "local");
  web.sendHeader(F("Set-Cookie"), String("vls=") + portalSession + "; Path=/; HttpOnly; Max-Age=600");
  web.sendHeader(F("Location"), F("/"));
  web.send(303, F("text/plain"), "");
}

void handlePortal() {
  portalActivity = millis();
  if (!portalAuthed()) return sendLoginPage("");
  String h = F("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
               "<title>VENUE Lock - Configurar</title><style>body{background:#0b0e13;color:#e9edf3;font:16px system-ui;padding:16px}"
               "input,button{width:100%;box-sizing:border-box;padding:12px;margin:4px 0 10px;border:0;border-radius:10px;background:#1e2430;color:#e9edf3;font:inherit}"
               "button{background:#1d3a35;color:#4fd1b5;font-weight:700}label{color:#8b94a5;font-size:14px}.r{display:flex;gap:8px;align-items:center}.r input{width:auto}</style></head><body>"
               "<h2 style='color:#4fd1b5'>VENUE Lock</h2><p style='color:#8b94a5'>fw " FW_VERSION " &middot; chip ");
  h += String(ESP.getChipId(), HEX);
  h += F("</p><form method=post action=/save><datalist id=nets>");
  h += scanOptions;
  h += F("</datalist><label>Wi-Fi (SSID)</label><input name=ssid list=nets maxlength=32 required value=\"");
  h += htmlEsc(cfg.ssid);
  h += F("\"><label>Senha do Wi-Fi (vazio = manter)</label><input name=pass type=password maxlength=64>"
         "<label>Nome do ponto (a-z 0-9 _ -; o mesmo nome do ponto no sistema)</label>"
         "<input name=uuid maxlength=32 autocapitalize=none required value=\"");
  h += htmlEsc(cfg.uuid);
  h += F("\"><div class=r><input type=checkbox name=factory><label>Apagar tudo (reset de fábrica)</label></div>"
         "<button>Salvar e reiniciar</button></form></body></html>");
  sendNoCache();
  web.send(200, F("text/html"), h);
}

void handleSave() {
  portalActivity = millis();
  if (!portalAuthed()) { web.send(403, F("text/plain"), F("Sessao expirada. Volte e entre com a senha.")); return; }
  if (web.hasArg("factory")) {
    cfgDefaults(); cfgSave();
    web.send(200, F("text/plain"), F("Reset de fabrica feito. Reiniciando."));
    restartAt = millis() + 800;
    return;
  }
  String ssid = web.arg("ssid"), pass = web.arg("pass"), uuid = web.arg("uuid");
  ssid.trim(); uuid.trim(); uuid.toLowerCase();
  String err;
  if (ssid.isEmpty() || ssid.length() > 32) err = F("Nome do Wi-Fi invalido");
  else if (!validUuid(uuid.c_str())) err = F("Nome do ponto invalido: use a-z, 0-9, _ ou - (2 a 32)");
  if (err.length()) { web.send(400, F("text/plain"), err); return; }
  bool identityChanged = strcmp(cfg.uuid, uuid.c_str()) != 0;
  bool ssidChanged = strcmp(cfg.ssid, ssid.c_str()) != 0;
  strlcpy(cfg.ssid, ssid.c_str(), sizeof(cfg.ssid));
  // senha vazia mantém a atual; se trocou de rede, aceita vazia (rede aberta)
  if (pass.length() || ssidChanged) strlcpy(cfg.pass, pass.c_str(), sizeof(cfg.pass));
  strlcpy(cfg.uuid, uuid.c_str(), sizeof(cfg.uuid));
  if (identityChanged) { strlcpy(cfg.name, cfg.uuid, sizeof(cfg.name)); cfg.pin[0] = 0; cfg.egress = 0; cfg.policy = POLICY_RELEASE; }
  cfgSave();
  web.send(200, F("text/plain"), F("Salvo. Reiniciando para conectar..."));
  restartAt = millis() + 800;
}

void startPortal() {
  portalMode = true;
  portalActivity = millis();
  applyRelay();  // libera a porta enquanto alguém configura localmente
  ws.disconnect();
  wsAuthed = false;
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  scanOptions = "";
  for (int i = 0; i < n && i < 20; i++) {
    scanOptions += F("<option value=\"");
    scanOptions += htmlEsc(WiFi.SSID(i).c_str());
    scanOptions += F("\">");
  }
  WiFi.scanDelete();
  WiFi.mode(WIFI_AP);
  char ap[33]; snprintf(ap, sizeof(ap), "VENUE_Lock-%06x", ESP.getChipId());
  bool secured = provisioned() && strlen(cfg.pin) >= 8;
  WiFi.softAP(ap, secured ? cfg.pin : nullptr);
  dns.start(53, "*", WiFi.softAPIP());
  LOGF("[portal] AP %s (%s) em %s", ap, secured ? "senha = PIN" : "aberto", WiFi.softAPIP().toString().c_str());
  logEvent("portal", "botao");
}

// ------------------------------------------------------------------ roteamento web
void routeRoot() { portalMode ? handlePortal() : handleLocalPage(); }

void routeNotFound() {
  if (portalMode) {
    web.sendHeader(F("Location"), String("http://") + WiFi.softAPIP().toString() + "/");
    web.send(302, F("text/plain"), "");
  } else {
    web.send(404, F("text/plain"), F("404"));
  }
}

void setupWeb() {
  web.on("/", HTTP_GET, routeRoot);
  web.on("/login", HTTP_POST, []() { if (portalMode) handleLogin(); else web.send(403, F("text/plain"), F("403")); });
  web.on("/save", HTTP_POST, []() { if (portalMode) handleSave(); else web.send(403, F("text/plain"), F("403")); });
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
