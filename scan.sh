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

escanearGobuster() {
    echo "[*] Escaneando Gobuster en $TARGET_DOMAIN..."
    # Wordlist básica (puedes cambiarla por otra más completa)
    curl -s https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt > common.txt
    WORDLIST="common.txt"
    # Extensiones a probar
    EXTENSIONS="php,html,txt"
    # Ejecutar Gobuster
    gobuster dir -u "http://$TARGET_DOMAIN" -w "$WORDLIST" -x "$EXTENSIONS" -t 50 -o "${OUTPUT}_gobuster.txt"
    echo "[+] Resultados de Gobuster guardados en ${OUTPUT}_gobuster.txt"
    grep -E "Status: 200|Status: 301" "${OUTPUT}_gobuster.txt" | awk '{print $1}' > rutas.txt
}

# Función para escanear con Nikto
escanearNikto() {
    echo "[*] Escaneando Nikto en $TARGET_DOMAIN..."
    while read RUTA; do
    	nikto -h http://$TARGET_DOMAIN$RUTA -Tuning 1 -output "${OUTPUT}_nikto_${RUTA//\//_}.txt"
    done < rutas.txt
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
escanearGobuster
escanearNikto
