# Compilador do firmware VENUE Lock (arduino-cli + core ESP8266), usado por firmware.sh
FROM debian:bookworm-slim
ARG ARDUINO_CLI_VERSION=1.1.1
ARG ESP8266_CORE=3.1.2
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh \
    | BINDIR=/usr/local/bin sh -s "${ARDUINO_CLI_VERSION}"
RUN arduino-cli config init \
 && arduino-cli config add board_manager.additional_urls https://arduino.esp8266.com/stable/package_esp8266com_index.json \
 && arduino-cli core update-index \
 && arduino-cli core install "esp8266:esp8266@${ESP8266_CORE}" \
 && arduino-cli lib install "WebSockets" "ArduinoJson"
WORKDIR /work
