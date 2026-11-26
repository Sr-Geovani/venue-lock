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
4. Abra `firmware/VENUE_Lock_v2/VENUE_Lock_v2.ino` e, no bloco **CONFIGURAÇÃO FIXA** do topo,
   troque `COLE_O_SECRET_AQUI` pelo secret do app (Conta → Secret do ESP) e `TROQUE_ESTA_SENHA`
   pela senha de administrador do portal (mínimo 8 caracteres). Servidor, usuário e
   polaridade do relé já vêm preenchidos. Sem essas duas trocas o Arduino IDE não compila. **Nunca envie o `.ino` com o secret para o GitHub.**
5. Grave com o adaptador USB do ESP-01 (modo PROG).
6. Ligue no módulo: ele abre o Wi-Fi aberto `VENUE_Lock-xxxxxx` (também abre segurando o botão 4 s).
   - **Sem senha:** escolha a rede na lista, digite a senha do Wi-Fi e toque em Conectar. O ESP
     testa antes de salvar e avisa "senha incorreta" ou "rede não encontrada". Na primeira
     instalação, informe o nome do ponto (o mesmo do sistema).
   - **Configurações avançadas (senha de administrador):** nome do ponto, polaridade do relé com
     botão de teste, tempo de liberação, política de queda, saída livre, PIN, reinício e reset.
     Esses ajustes sobem para o servidor quando o ESP reconectar.
   - Durante o portal a porta fica livre (igual ao firmware antigo): o botão deve ficar do lado
     de dentro.

O secret fica gravado no firmware: não use "Gerar novo secret" no app sem necessidade,
porque todos os ESPs precisariam ser regravados por USB. O `.bin` publicado para atualização
só é entregue a ESPs que provam conhecer o secret.

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
