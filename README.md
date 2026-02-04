# HelPymes 🛡️

**Herramienta de Análisis de Ciberseguridad para PYMEs**

Sistema inteligente de pentesting y análisis SAST (Static Application Security Testing) con agentes especializados de IA, diseñado específicamente para pequeñas y medianas empresas.

## 🌟 Características

- **Múltiples Agentes Especializados**: Blue Team, Red Team, SOC Analyst, SAST, Compliance, y más
- **Análisis SAST Completo**: Escaneo de código fuente con Semgrep, Gitleaks, Bandit
- **Herramientas de Pentesting**: Nmap, Nuclei, Gobuster, SQLMap, Hydra, y más
- **Dos Modelos de IA**: Compatible con Groq (Llama 3.3) y Anthropic Claude (Sonnet/Haiku/Opus)
- **Interfaz CLI Intuitiva**: Comandos con colores y feedback claro
- **Análisis de Dependencias**: npm audit, pip-audit
- **Detección de Secretos**: Gitleaks para encontrar credenciales hardcodeadas

## 📋 Requisitos Previos

- **Sistema Operativo**: Kali Linux, Debian, Ubuntu, Fedora, Rocky Linux, Arch Linux
- **Python**: 3.8 o superior
- **Acceso a Internet**: Para instalar dependencias y actualizar herramientas
- **API Keys** (gratuitas):
  - [Groq API Key](https://console.groq.com/keys)
  - [Anthropic API Key](https://console.anthropic.com/settings/keys)

## 🚀 Instalación Rápida
```bash
# 1. Clonar el repositorio
git clone https://github.com/asiermv2/HelPymes.git
cd HelPymes

# 2. Dar permisos de ejecución al instalador
chmod +x install_universal.sh

# 3. Ejecutar el instalador
./install_universal.sh

# 4. Configurar API keys
# Detecta tu shell
echo $SHELL

# Si usas ZSH:
nano ~/.zshrc

# Si usas Bash:
nano ~/.bashrc

# Añade al final:
export GROQ_API_KEY="tu_api_key_de_groq"
export ANTHROPIC_API_KEY="tu_api_key_de_anthropic"

# 5. Recargar configuración
source ~/.zshrc  # o ~/.bashrc
```

## 💻 Uso

### Iniciar el Servidor
```bash
./kali_server.py
```

El servidor se iniciará en `http://localhost:5000`

### Iniciar el Chat

**Con Groq (Llama 3.3 - Rápido y gratuito):**
```bash
./chat_kali_api.py
```

**Con Claude (Haiku - por defecto):**
```bash
./chat_claude.py
```

**Con Claude Sonnet (más potente):**
```bash
CLAUDE_MODEL=sonnet ./chat_claude.py
```

**Con Claude Opus (máxima potencia):**
```bash
CLAUDE_MODEL=opus ./chat_claude.py
```

## 🎯 Comandos Especiales

### Cambiar Agente Especializado
```bash
# Ver agentes disponibles
/agent list

# Seleccionar agente Blue Team (defensa)
/agent select blue_team

# Seleccionar agente Red Team (ataque)
/agent select red_team

# Seleccionar agente SAST (análisis de código)
/agent select sast_analyst

# Ver agente actual
/agent current
```

### Agentes Disponibles

- **default**: Asistente general de ciberseguridad
- **blue_team**: Defensa y detección de amenazas
- **red_team**: Simulación de adversarios
- **soc_analyst**: Respuesta a incidentes
- **vulnerability_analyst**: Evaluación de vulnerabilidades
- **pyme_consultant**: Consultor para PYMEs
- **compliance**: Auditor de cumplimiento (ISO 27001, RGPD)
- **web_security**: Seguridad de aplicaciones web
- **network_security**: Seguridad de redes
- **sast_analyst**: Análisis estático de código

## 📚 Ejemplos de Uso

### Auditoría SAST de un Repositorio
```
🧑 Tú: Audita el repositorio https://github.com/user/vulnerable-app

🤖 El agente ejecutará automáticamente:
1. Clonará el repositorio
2. Analizará la estructura del código
3. Ejecutará Semgrep para encontrar vulnerabilidades
4. Buscará secretos con Gitleaks
5. Analizará dependencias si existen
6. Generará un reporte consolidado
```

### Escaneo de Red
```
🧑 Tú: Escanea puertos de scanme.nmap.org

🤖 Ejecutará: nmap -sCV -T4 -Pn scanme.nmap.org
```

### Búsqueda de CVEs
```
🧑 Tú: Busca CVEs críticos de Apache 2.4.49

🤖 Ejecutará: searchsploit Apache 2.4.49
```

### Detección de Tecnologías Web
```
🧑 Tú: Detecta tecnologías de https://example.com

🤖 Ejecutará: whatweb https://example.com
```

## 🛠️ Herramientas Incluidas

### Escaneo de Red
- **Nmap**: Escaneo de puertos y servicios
- **Gobuster**: Fuzzing de directorios
- **Dirb**: Fuzzing de directorios alternativo

### Análisis Web
- **Nuclei**: Escáner de vulnerabilidades CVE
- **WhatWeb**: Detección de tecnologías
- **Nikto**: Escáner de vulnerabilidades web
- **SQLMap**: Detección de SQL injection
- **WPScan**: Escáner de WordPress

### Análisis de Código (SAST)
- **Semgrep**: Análisis estático multi-lenguaje
- **Gitleaks**: Detección de secretos
- **Bandit**: Análisis de seguridad Python

### Fuerza Bruta
- **Hydra**: Brute force genérico
- **SSH Bruteforce**: Script personalizado para SSH
- **John the Ripper**: Cracking de contraseñas

### Análisis de Dependencias
- **npm audit**: Vulnerabilidades en dependencias npm
- **pip-audit**: Vulnerabilidades en dependencias Python

## 🔧 Estructura del Proyecto
```
HelPymes/
├── chat_kali_api.py        # Cliente con Groq
├── chat_claude.py          # Cliente con Claude
├── kali_server.py          # Servidor API de herramientas
├── install_universal.sh    # Instalador automático
├── requirements.txt        # Dependencias Python
├── README.md              # Este archivo
└── bin/
    └── sshconnect          # Script de SSH bruteforce
```

## 📖 Documentación Adicional

### Configuración Avanzada

**Cambiar puerto del servidor:**
```bash
API_PORT=8000 ./kali_server.py
```

**Modo debug:**
```bash
./kali_server.py --debug
```

### Solución de Problemas

**Error: "No se puede conectar al servidor Kali"**
```bash
# Verifica que el servidor esté corriendo
ps aux | grep kali_server

# Reinicia el servidor
pkill -f kali_server.py
./kali_server.py
```

**Error: "Herramienta no encontrada"**
```bash
# Reinstala herramientas faltantes
./install_universal.sh
```

## 🔒 Consideraciones de Seguridad

⚠️ **IMPORTANTE**: Esta herramienta es para uso educativo y pruebas de seguridad autorizadas.

- **Uso Responsable**: Solo usa esta herramienta en sistemas que tienes permiso explícito para auditar
- **Entornos Controlados**: Diseñada para laboratorios y entornos de prueba
- **No uso malicioso**: El autor no se responsabiliza del mal uso de esta herramienta
- **API Keys**: Nunca compartas tus API keys, usa variables de entorno

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Para cambios importantes:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📧 Contacto

**Asier Martínez** - asiermv2@gmail.com

Proyecto: [https://github.com/asiermv2/HelPymes](https://github.com/asiermv2/HelPymes)

## 📄 Licencia

Este proyecto es para uso educativo. No me hago responsable del uso indebido de la herramienta.

---

**Desarrollado con ❤️ para mejorar la ciberseguridad en PYMEs**
