#!/bin/bash

# Instalador Universal para Kali Tools API Server
# Compatible con: Kali, Ubuntu, Debian, Arch, Fedora, y otras distribuciones

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Instalador Universal - Kali Tools API Server         ║${NC}"
echo -e "${CYAN}║  Compatible con cualquier distribución Linux          ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"

# Detectar distribución
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        DISTRO="unknown"
    fi
    
    echo -e "${BLUE}[INFO] Distribución detectada: ${YELLOW}${DISTRO} ${VERSION}${NC}\n"
}

# Verificar privilegios
check_sudo() {
    if [ "$EUID" -eq 0 ]; then 
        echo -e "${YELLOW}[!] No ejecutes este script como root, usa sudo cuando sea necesario${NC}\n"
        exit 1
    fi
}

# Función para instalar paquetes según la distribución
install_package() {
    local package=$1
    
    case $DISTRO in
        kali|debian|ubuntu|linuxmint|pop)
            sudo apt-get install -y "$package" 2>/dev/null
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm "$package" 2>/dev/null || \
            yay -S --noconfirm "$package" 2>/dev/null
            ;;
        fedora|rhel|centos)
            sudo dnf install -y "$package" 2>/dev/null
            ;;
        *)
            echo -e "${YELLOW}[!] Distribución no soportada automáticamente${NC}"
            echo -e "${YELLOW}    Instala manualmente: $package${NC}"
            return 1
            ;;
    esac
}

# Actualizar repositorios
update_repos() {
    echo -e "${YELLOW}[*] Actualizando repositorios...${NC}"
    
    case $DISTRO in
        kali|debian|ubuntu|linuxmint|pop)
            sudo apt-get update -qq
            ;;
        arch|manjaro)
            sudo pacman -Sy
            ;;
        fedora|rhel|centos)
            sudo dnf check-update -q
            ;;
    esac
    
    echo -e "${GREEN}[✓] Repositorios actualizados${NC}\n"
}

# ==================
# MAIN SCRIPT
# ==================

check_sudo
detect_distro

# 1. Python y pip
echo -e "${BLUE}[1] Instalando Python 3 y pip...${NC}\n"

if ! command -v python3 &> /dev/null; then
    case $DISTRO in
        arch|manjaro)
            install_package python python-pip
            ;;
        *)
            install_package python3
            install_package python3-pip
            ;;
    esac
else
    echo -e "${GREEN}[✓] Python 3 ya instalado: $(python3 --version)${NC}"
fi

if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    case $DISTRO in
        kali|debian|ubuntu)
            sudo apt-get install -y python3-pip
            ;;
    esac
fi

# 2. Librerías Python
echo -e "\n${BLUE}[2] Instalando librerías Python...${NC}\n"

# Crear requirements.txt si no existe
if [ ! -f "requirements.txt" ]; then
    cat > requirements.txt << 'EOF'
flask>=2.3.0
requests>=2.31.0
groq>=0.4.0
EOF
fi

python3 -m pip install -r requirements.txt --break-system-packages 2>/dev/null || \
python3 -m pip install -r requirements.txt --user 2>/dev/null || \
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Librerías Python instaladas${NC}"
else
    echo -e "${RED}[✗] Error instalando librerías Python${NC}"
    exit 1
fi

# 3. Herramientas de pentesting
echo -e "\n${BLUE}[3] Instalando herramientas de pentesting...${NC}\n"

update_repos

# Lista de herramientas con nombres de paquetes alternativos según distro
declare -A tools_map=(
    ["nmap"]="nmap"
    ["gobuster"]="gobuster"
    ["nikto"]="nikto"
    ["sqlmap"]="sqlmap"
    ["hydra"]="hydra"
    ["john"]="john"
    ["dirb"]="dirb"
)

# Herramientas especiales (pueden no estar en repos oficiales)
special_tools=(
    "nuclei"
    "whatweb"
    "wpscan"
    "enum4linux"
    "searchsploit"
)

# Instalar herramientas básicas
for tool in "${!tools_map[@]}"; do
    package="${tools_map[$tool]}"
    
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[✓] $tool ya instalado${NC}"
    else
        echo -e "${YELLOW}[*] Instalando $tool...${NC}"
        
        if install_package "$package"; then
            echo -e "${GREEN}[✓] $tool instalado${NC}"
        else
            echo -e "${YELLOW}[!] No se pudo instalar $tool automáticamente${NC}"
        fi
    fi
done

# Herramientas especiales (requieren instalación manual en algunas distros)
echo -e "\n${YELLOW}[*] Verificando herramientas especiales...${NC}"

for tool in "${special_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[✓] $tool ya instalado${NC}"
    else
        echo -e "${YELLOW}[!] $tool no encontrado${NC}"
        
        case $tool in
            nuclei)
                if [ "$DISTRO" = "kali" ]; then
                    install_package nuclei
                else
                    echo -e "${CYAN}    Instala manualmente desde: https://github.com/projectdiscovery/nuclei${NC}"
                    echo -e "${CYAN}    O ejecuta: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest${NC}"
                fi
                ;;
            whatweb)
                if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "ubuntu" ]; then
                    install_package whatweb
                else
                    echo -e "${CYAN}    Instala manualmente desde: https://github.com/urbanadventurer/WhatWeb${NC}"
                fi
                ;;
            wpscan)
                if [ "$DISTRO" = "kali" ]; then
                    install_package wpscan
                else
                    echo -e "${CYAN}    Instala manualmente: gem install wpscan${NC}"
                fi
                ;;
            enum4linux)
                if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "ubuntu" ]; then
                    install_package enum4linux
                else
                    echo -e "${CYAN}    Instala manualmente desde: https://github.com/CiscoCXSecurity/enum4linux${NC}"
                fi
                ;;
            searchsploit)
                if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "ubuntu" ]; then
                    install_package exploitdb
                else
                    echo -e "${CYAN}    Instala manualmente desde: https://github.com/offensive-security/exploitdb${NC}"
                fi
                ;;
        esac
    fi
done

# 4. Wordlists
echo -e "\n${BLUE}[4] Verificando wordlists...${NC}\n"

if [ "$DISTRO" = "kali" ]; then
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        sudo apt-get install -y wordlists
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi
    echo -e "${GREEN}[✓] Wordlists de Kali disponibles${NC}"
else
    echo -e "${YELLOW}[!] No estás en Kali Linux${NC}"
    echo -e "${CYAN}    Las wordlists pueden descargarse desde:${NC}"
    echo -e "${CYAN}    - SecLists: https://github.com/danielmiessler/SecLists${NC}"
    echo -e "${CYAN}    - RockYou: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt${NC}"
    
    # Crear directorio de wordlists local
    mkdir -p ~/.wordlists
    echo -e "${CYAN}    Directorio creado: ~/.wordlists${NC}"
fi

# 5. GROQ API Key
echo -e "\n${BLUE}[5] Configuración de Groq API...${NC}\n"

if [ -z "$GROQ_API_KEY" ]; then
    echo -e "${YELLOW}[!] GROQ_API_KEY no configurada${NC}"
    echo -e "${CYAN}    Añade esto a tu ~/.bashrc o ~/.zshrc:${NC}"
    echo -e "${GREEN}    export GROQ_API_KEY='tu-api-key-aqui'${NC}"
else
    echo -e "${GREEN}[✓] GROQ_API_KEY configurada${NC}"
fi

# 6. Permisos
echo -e "\n${BLUE}[6] Configurando permisos...${NC}\n"

for script in kali_server.py chat_kali_api.py; do
    if [ -f "$script" ]; then
        chmod +x "$script"
        echo -e "${GREEN}[✓] $script ejecutable${NC}"
    fi
done

# Resumen
echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              INSTALACIÓN COMPLETADA                    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}✓ Python y librerías instaladas${NC}"
echo -e "${GREEN}✓ Herramientas verificadas${NC}"

if [ "$DISTRO" != "kali" ]; then
    echo -e "\n${YELLOW}⚠️  NOTA IMPORTANTE:${NC}"
    echo -e "${YELLOW}No estás usando Kali Linux. Algunas herramientas pueden${NC}"
    echo -e "${YELLOW}requerir instalación manual. Revisa los mensajes arriba.${NC}"
fi

echo -e "\n${CYAN}Para ejecutar:${NC}"
echo -e "${YELLOW}1. Terminal 1: python3 kali_server.py${NC}"
echo -e "${YELLOW}2. Terminal 2: python3 chat_kali_api.py${NC}\n"
