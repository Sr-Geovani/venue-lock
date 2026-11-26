# VENUE LOCK

Controle de fechaduras eletroímã com ESP-01S Relay. Substitui o Blynk e o gateway Java antigo.

```
server/      servidor (Python + aiohttp + SQLite) com o app PWA para iPhone
firmware/    firmware do ESP-01S (Arduino IDE)
install.sh   instalador/atualizador para a VPS (Caddy em Docker)
```

## Instalar na VPS

Pré-requisitos: registro DNS `A` do subdomínio apontando para a VPS, Docker, e o Caddy
do outro projeto rodando (`deploy-caddy-1`). O instalador só acrescenta um bloco no
Caddyfile (com backup e validação) e sobe o container `venuelock`.

```bash
cd /opt && git clone https://github.com/Sr-Geovani/venue-lock.git && cd venue-lock && ./install.sh lock.venuemarket.com.br
```

Atualizar depois: `cd /opt/venue-lock && git pull && ./install.sh lock.venuemarket.com.br`

## Gravar o ESP-01S (primeira vez, por USB)

1. Arduino IDE → Preferências → URLs adicionais: `https://arduino.esp8266.com/stable/package_esp8266com_index.json`
2. Gerenciador de placas: **esp8266** ≥ 3.1. Bibliotecas: **WebSockets** (Markus Sattler) ≥ 2.4.1, **ArduinoJson** 7.x.
3. Placa **Generic ESP8266 Module**, Flash Size **1MB (FS:none OTA:~502KB)**, Erase Flash **All Flash Contents**.
4. Abra `firmware/VENUE_Lock_v2/VENUE_Lock_v2.ino` e grave com o adaptador USB do ESP-01 (modo PROG).
5. Ligue no módulo: ele abre o Wi-Fi `VENUE_Lock-xxxxxx`. Preencha Wi-Fi do cliente, servidor
   (`lock.venuemarket.com.br`, porta 443), usuário, secret (app → Conta) e o nome do ponto.
   O ESP aparece sozinho no app.

## Atualizações seguintes (automáticas)

1. Mude `FW_VERSION` no topo do `.ino`.
2. Arduino IDE → Sketch → **Exportar binário compilado**.
3. App → Conta → **Firmware dos ESPs** → Publicar. Os ESPs online baixam, conferem o MD5 e reiniciam.

## Segurança da porta (hardware)

Eletroímã energizado = trancado. Ligue no contato **NA** do relé, com **botão de saída NF** e
**quebra-vidro NF em série** na alimentação do eletroímã: a saída funciona mesmo sem ESP,
internet ou firmware. Só marque "saída livre instalada" no app depois disso.

## Funcionamento sem internet

| Situação | Como comandar |
|---|---|
| Internet ok | App / sistema |
| Sem internet, Wi-Fi ok | `http://<nome>.local` com o PIN |
| Roteador desligado | Wi-Fi `VENUE-<nome>` (senha = PIN) → `http://192.168.4.1` |
| Sempre | Botão GPIO2: toque libera, 4 s abre a configuração |

Na queda de internet a porta é liberada após o tempo configurado, a menos que a saída livre
por hardware esteja confirmada e a política "manter trancado" escolhida.
