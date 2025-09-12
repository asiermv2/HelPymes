#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Uso: $0 <IP o dominio> <nombre_archivo_salida_sin_txt>"
    echo "Ejemplo: $0 amazon.es EscaneoPrincipal"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

# Regex para IPv4
IP_REGEX="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

# Función para escanear con Nmap
escanearNmap() {
    echo "[*] Escaneando Nmap en $TARGET_IP..."
    nmap -Pn "$TARGET_IP" > "${OUTPUT}_nmap.txt"
    echo "[+] Resultados de Nmap guardados en ${OUTPUT}_nmap.txt"
}

# Función para escanear con Nikto
escanearNikto() {
    echo "[*] Escaneando Nikto en $TARGET_DOMAIN..."
    nikto -h "$TARGET_DOMAIN" -Tuning 1 -output "${OUTPUT}_nikto.txt"

    echo "[+] Resultados de Nikto guardados en ${OUTPUT}_nikto.txt"
}

# Determinar si es IP o dominio
if [[ $INPUT =~ $IP_REGEX ]]; then
    TARGET_IP="$INPUT"
    TARGET_DOMAIN="$INPUT"  # Para Nikto si se pone IP
else
    TARGET_DOMAIN="$INPUT"
    TARGET_IP=$(dig +short "$INPUT" | head -n1)  # Resolver IP para Nmap
    if [ -z "$TARGET_IP" ]; then
        echo "Error: No se pudo resolver la IP de $INPUT"
        exit 1
    fi
fi

# Ejecutar escaneos
escanearNmap
escanearNikto
