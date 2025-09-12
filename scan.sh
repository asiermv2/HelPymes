#!/bin/bash

# Comprobar argumentos
if [ -z "$1" ]; then
    echo "Uso: $0 <IP o hostname> [archivo_salida]"
    exit 1
fi

TARGET="$1"
OUTPUT="$2"

# Ejecutar Nmap en modo connect scan sin detección de versión
# -Pn para no hacer ping
RESULT=$(nmap -Pn "$TARGET" | awk '
    BEGIN {capturando=0}
    # Comienza a capturar cuando aparece la cabecera de puertos
    /^PORT[[:space:]]+STATE[[:space:]]+SERVICE/ {capturando=1}
    capturando {print}
    # Incluir Service Info si aparece
    /^Service Info:/ {print; exit}
')

# Guardar o imprimir
if [ -n "$OUTPUT" ]; then
    echo "$RESULT" > "$OUTPUT"
    echo "[+] Escaneo completado. Resultados guardados en $OUTPUT"
else
    echo "$RESULT"
fi
