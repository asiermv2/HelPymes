#!/usr/bin/env python3
import os
import requests
import json
import re
from groq import Groq

# 🎨 COLORES ANSI
class Color:
    # Colores básicos
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

    # Colores de texto
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Colores brillantes
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Colores de fondo
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

def print_color(text, color=Color.WHITE, bold=False, end='\n'):
    """Imprimir texto con color"""
    style = Color.BOLD if bold else ''
    print(f"{style}{color}{text}{Color.RESET}", end=end)

def print_banner():
    """Imprimir banner inicial"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║    💬 Chat con Groq + Kali Linux Tools 🔧 + CVE Scanner 🛡️  ║
╚══════════════════════════════════════════════════════════════╝
    """
    print_color(banner, Color.BRIGHT_CYAN, bold=True)

def print_box(title, content, color=Color.CYAN):
    """Imprimir contenido en una caja"""
    lines = content.split('\n')
    max_len = max(len(line) for line in lines) if lines else 0
    max_len = max(max_len, len(title))

    print_color(f"\n┌─ {title} " + "─" * (max_len - len(title) + 2) + "┐", color)
    for line in lines:
        print_color(f"│ {line.ljust(max_len + 2)} │", color)
    print_color("└" + "─" * (max_len + 5) + "┘", color)

KALI_API = "http://localhost:5000"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Verificar conexión
print_color("\n🔍 Verificando conexión con Kali API Server...", Color.YELLOW)
try:
    health = requests.get(f"{KALI_API}/health", timeout=5).json()
    print_color(f"✅ Servidor Kali API: {health['status']}", Color.GREEN, bold=True)
    print_color(f"   Herramientas disponibles: {'Sí ✓' if health.get('all_essential_tools_available') else 'No ✗'}",
                Color.GREEN if health.get('all_essential_tools_available') else Color.YELLOW)
    print_color(f"   Agente activo: {health.get('current_agent', 'default')}", Color.CYAN)
except Exception as e:
    print_color(f"❌ Error: No se puede conectar al servidor Kali", Color.RED, bold=True)
    print_color(f"   Primero inicia: python3 kali_server.py", Color.YELLOW)
    exit(1)

groq = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT_BASE = """Eres un asistente experto en pentesting y ciberseguridad con acceso a herramientas de Kali Linux.

IMPORTANTE: Tienes múltiples herramientas disponibles. ANALIZA la solicitud del usuario y DECIDE cuáles son las más apropiadas.

HERRAMIENTAS DISPONIBLES:

═══════════════════════════════════════════════════════════
📦 ANÁLISIS DE CÓDIGO Y REPOSITORIOS
═══════════════════════════════════════════════════════════

1. git_clone - Clonar repositorio para auditoría local
   Formato: USE_TOOL:git_clone {"repo_url": "https://github.com/user/repo", "destination": "/tmp/audit_repo"}
   Uso: PRIMER PASO para auditar cualquier repositorio GitHub

2. semgrep - Análisis estático de código (detecta vulnerabilidades en código)
   Formato: USE_TOOL:semgrep {"path": "/tmp/audit_repo", "config": "auto"}
   Configs: "auto", "p/security-audit", "p/owasp-top-ten", "p/javascript", "p/python"
   Uso: Detectar SQL injection, XSS, path traversal, etc. en código fuente

3. gitleaks - Detectar secretos en código y historial git
   Formato: USE_TOOL:gitleaks {"path": "/tmp/audit_repo"}
   Uso: Buscar API keys, passwords, tokens en código y commits

4. bandit - Análisis de seguridad para Python
   Formato: USE_TOOL:bandit {"path": "/tmp/audit_repo"}
   Uso: Detectar vulnerabilidades en código Python

═══════════════════════════════════════════════════════════
🌐 ANÁLISIS DE APLICACIONES WEB EN PRODUCCIÓN
═══════════════════════════════════════════════════════════

5. nuclei - Escaneo de CVEs y vulnerabilidades conocidas EN SERVIDOR
   Formato: USE_TOOL:nuclei {"target": "http://example.com", "severity": "critical,high", "tags": "cve"}
   Uso: Para sitios web DESPLEGADOS, no para código fuente

6. whatweb - Detectar tecnologías web y versiones
   Formato: USE_TOOL:whatweb {"target": "http://example.com"}

7. nikto - Escaneo de vulnerabilidades web
   Formato: USE_TOOL:nikto {"target": "http://example.com"}

8. sqlmap - Detección de SQL injection
   Formato: USE_TOOL:sqlmap {"url": "http://example.com/page?id=1"}

9. wpscan - Scanner de WordPress
    Formato: USE_TOOL:wpscan {"url": "http://wordpress.com"}

10. cve_search - Buscar CVEs por software/versión
    Formato: USE_TOOL:cve_search {"software": "apache", "version": "2.4.49"}

═══════════════════════════════════════════════════════════
🔍 ESCANEO DE RED E INFRAESTRUCTURA
═══════════════════════════════════════════════════════════

11. nmap - Escaneo de puertos y servicios
    Formato: USE_TOOL:nmap {"target": "scanme.nmap.org", "ports": "80,443", "scan_type": "-sV"}

12. gobuster - Fuzzing de directorios
    Formato: USE_TOOL:gobuster {"url": "http://example.com"}

13. dirb - Fuzzing de directorios alternativo
    Formato: USE_TOOL:dirb {"url": "http://example.com"}

═══════════════════════════════════════════════════════════
🔐 AUDITORÍA DE CREDENCIALES
═══════════════════════════════════════════════════════════

14. ssh_bruteforce - HERRAMIENTA PRINCIPAL PARA SSH
    Formato: USE_TOOL:ssh_bruteforce {"target": "example.com", "credentials_file": "/home/asier/prueba.txt", "port": "22"}

15. hydra - Brute force genérico
    Formato: USE_TOOL:hydra {"target": "IP", "service": "ssh", "username": "admin", "password_file": "/path"}

═══════════════════════════════════════════════════════════
💻 SISTEMA
═══════════════════════════════════════════════════════════

16. command - Ejecutar cualquier comando Linux
    Formato: USE_TOOL:command {"command": "ls -la /tmp"}
    Uso: Listar archivos, analizar resultados, preparar auditorías

═══════════════════════════════════════════════════════════
🎯 METODOLOGÍA DE AUDITORÍA SAST (Static Application Security Testing)
═══════════════════════════════════════════════════════════

Cuando el usuario pida "auditar" o "analizar seguridad" de un repositorio, actúa como un SAST profesional:

**FASE 1: RECONOCIMIENTO**
1. git_clone - Clonar repositorio
2. command - Analizar estructura del proyecto:
   - "find /tmp/audit_repo -type f | wc -l" (contar archivos)
   - "find /tmp/audit_repo -type f -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' | wc -l"
   - "find /tmp/audit_repo -type f -name '*.py' | wc -l"
   - "find /tmp/audit_repo -type f -name '*.java' | wc -l"
   - "find /tmp/audit_repo -type f -name '*.php' | wc -l"
   - "find /tmp/audit_repo -type f -name '*.go' | wc -l"
3. command - Identificar frameworks y dependencias:
   - "test -f /tmp/audit_repo/package.json && cat /tmp/audit_repo/package.json"
   - "test -f /tmp/audit_repo/requirements.txt && cat /tmp/audit_repo/requirements.txt"
   - "test -f /tmp/audit_repo/pom.xml && cat /tmp/audit_repo/pom.xml"
   - "test -f /tmp/audit_repo/composer.json && cat /tmp/audit_repo/composer.json"
   - "test -f /tmp/audit_repo/go.mod && cat /tmp/audit_repo/go.mod"

**FASE 2: ANÁLISIS DE VULNERABILIDADES EN CÓDIGO**
4. semgrep - Escaneo SAST completo con múltiples rulesets:
   - Config "p/security-audit" (general)
   - Config "p/owasp-top-ten" (OWASP Top 10)
   - Config específica según lenguaje detectado
5. bandit - Si hay Python (vulnerabilidades específicas de Python)

**FASE 3: ANÁLISIS DE SECRETOS Y CREDENCIALES**
6. gitleaks - Buscar secretos hardcodeados:
   - API keys
   - Contraseñas
   - Tokens de acceso
   - Certificados privados
   - Credenciales de base de datos

**FASE 4: ANÁLISIS DE DEPENDENCIAS (si aplica)**
7. command - Verificar vulnerabilidades en dependencias:
   - "test -f /tmp/audit_repo/package.json && cd /tmp/audit_repo && npm audit --json 2>/dev/null || echo 'npm audit no disponible'"
   - "test -f /tmp/audit_repo/requirements.txt && pip-audit -r /tmp/audit_repo/requirements.txt 2>/dev/null || echo 'pip-audit no disponible'"

**FASE 5: ANÁLISIS DE CONFIGURACIÓN**
8. command - Revisar configuraciones inseguras:
   - "find /tmp/audit_repo -name '.env' -o -name '.env.*' -o -name 'config.json' -o -name 'config.yml'"
   - "find /tmp/audit_repo -name 'Dockerfile' -exec cat {} \;"
   - "test -f /tmp/audit_repo/.gitignore && cat /tmp/audit_repo/.gitignore"

**FASE 6: REPORTE CONSOLIDADO**
Después de ejecutar todas las herramientas, proporciona:
- Resumen ejecutivo de hallazgos
- Vulnerabilidades críticas (CVSS >= 9.0)
- Vulnerabilidades altas (CVSS >= 7.0)
- Secretos expuestos
- Dependencias vulnerables
- Recomendaciones priorizadas

═══════════════════════════════════════════════════════════
📋 EJEMPLO DE AUDITORÍA SAST COMPLETA
═══════════════════════════════════════════════════════════

Usuario: "Audita este repositorio https://github.com/user/webapp"

Respuesta del agente (MÚLTIPLES HERRAMIENTAS EN SECUENCIA):

USE_TOOL:git_clone {"repo_url": "https://github.com/user/webapp", "destination": "/tmp/audit_repo"}
USE_TOOL:command {"command": "echo '=== ESTRUCTURA ===' && find /tmp/audit_repo -type f | head -20 && echo '\n=== LENGUAJES ===' && find /tmp/audit_repo -type f -name '*.js' | wc -l && echo 'archivos JS' && find /tmp/audit_repo -type f -name '*.py' | wc -l && echo 'archivos Python'"}
USE_TOOL:command {"command": "test -f /tmp/audit_repo/package.json && cat /tmp/audit_repo/package.json || echo 'No package.json'"}
USE_TOOL:semgrep {"path": "/tmp/audit_repo", "config": "p/security-audit"}
USE_TOOL:semgrep {"path": "/tmp/audit_repo", "config": "p/owasp-top-ten"}
USE_TOOL:gitleaks {"path": "/tmp/audit_repo"}
USE_TOOL:command {"command": "find /tmp/audit_repo -name '.env*' -o -name 'config.json' 2>/dev/null"}

Luego proporciona un REPORTE CONSOLIDADO en formato:

## 🔴 HALLAZGOS CRÍTICOS
- [CVE/CWE] Descripción del hallazgo
- Ubicación: archivo:línea
- Severidad: CRITICAL
- Recomendación: Acción específica

## 🟠 HALLAZGOS ALTOS
...

## 🟡 HALLAZGOS MEDIOS
...

## 🔑 SECRETOS EXPUESTOS
...

## 📦 DEPENDENCIAS VULNERABLES
...

## ✅ RECOMENDACIONES PRIORIZADAS
1. [URGENTE] ...
2. [ALTA] ...
3. [MEDIA] ...
"""

def ejecutar_herramienta(tool_name, params):
    """Ejecutar herramienta en el servidor Kali"""
    endpoints = {
        "nmap": "/api/tools/nmap",
        "nuclei": "/api/tools/nuclei",
        "whatweb": "/api/tools/whatweb",
        "cve_search": "/api/tools/cve_search",
        "gobuster": "/api/tools/gobuster",
        "nikto": "/api/tools/nikto",
        "sqlmap": "/api/tools/sqlmap",
        "wpscan": "/api/tools/wpscan",
        "hydra": "/api/tools/hydra",
        "john": "/api/tools/john",
        "ssh_bruteforce": "/api/tools/ssh_bruteforce",
        "enum4linux": "/api/tools/enum4linux",
        "dirb": "/api/tools/dirb",
        "metasploit": "/api/tools/metasploit",
        "command": "/api/command",
        "git_clone": "/api/tools/git_clone",
        "semgrep": "/api/tools/semgrep",
        "gitleaks": "/api/tools/gitleaks",
        "bandit": "/api/tools/bandit",
        "npm_audit": "/api/tools/npm_audit",
        "pip_audit": "/api/tools/pip_audit",
        "dependency_check": "/api/tools/dependency_check"
    }

    endpoint = endpoints.get(tool_name)
    if not endpoint:
        return {"error": f"Herramienta desconocida: {tool_name}"}

    try:
        response = requests.post(f"{KALI_API}{endpoint}", json=params, timeout=300)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def format_ai_response(text):
    """Formatear respuesta de la IA con colores"""
    # Resaltar CVEs
    text = re.sub(r'(CVE-\d{4}-\d{4,7})',
                  f'{Color.BRIGHT_RED}\\1{Color.BRIGHT_CYAN}', text)

    # Resaltar severidades
    text = re.sub(r'\b(CRITICAL|critical)\b',
                  f'{Color.BRIGHT_RED}\\1{Color.BRIGHT_CYAN}', text)
    text = re.sub(r'\b(HIGH|high)\b',
                  f'{Color.BRIGHT_YELLOW}\\1{Color.BRIGHT_CYAN}', text)
    text = re.sub(r'\b(MEDIUM|medium)\b',
                  f'{Color.BRIGHT_BLUE}\\1{Color.BRIGHT_CYAN}', text)

    # Resaltar palabras clave de seguridad
    text = re.sub(r'\b(vulnerable|vulnerabilidad|exploit|RCE|XSS|SQLi)\b',
                  f'{Color.BRIGHT_RED}\\1{Color.BRIGHT_CYAN}', text, flags=re.IGNORECASE)
    text = re.sub(r'\b(seguro|protegido|actualizado|patcheado)\b',
                  f'{Color.BRIGHT_GREEN}\\1{Color.BRIGHT_CYAN}', text, flags=re.IGNORECASE)
    text = re.sub(r'\b(puerto|port|service|version)\b',
                  f'{Color.BRIGHT_YELLOW}\\1{Color.BRIGHT_CYAN}', text, flags=re.IGNORECASE)

    return text

def handle_agent_command(user_input, historial):
    """Manejar comandos /agent."""
    parts = user_input.split()
    
    if len(parts) < 2:
        print_color("\n❌ Uso: /agent select <tipo> | /agent list | /agent current", Color.RED)
        return True
    
    command = parts[1].lower()
    
    if command == "list":
        # Listar agentes disponibles
        try:
            response = requests.get(f"{KALI_API}/api/agent/list")
            if response.status_code == 200:
                data = response.json()
                print_color("\n╔══════════════════════════════════════════════════════════════╗", Color.BRIGHT_MAGENTA)
                print_color("║           📋 AGENTES DISPONIBLES PARA PYMES                  ║", Color.BRIGHT_MAGENTA, bold=True)
                print_color("╚══════════════════════════════════════════════════════════════╝", Color.BRIGHT_MAGENTA)
                
                for agent in data["agents"]:
                    current_marker = "👉 " if agent["name"] == data["current"] else "   "
                    print_color(f"\n{current_marker}", Color.BRIGHT_GREEN, end='')
                    print_color(f"{agent['name']}", Color.BRIGHT_YELLOW, bold=True)
                    print_color(f"    {agent['description'][:80]}...", Color.CYAN)
                
                print_color("\n" + "═" * 60, Color.BRIGHT_BLUE)
            else:
                print_color(f"❌ Error al listar agentes: {response.text}", Color.RED)
        except Exception as e:
            print_color(f"❌ Error de conexión: {e}", Color.RED)
    
    elif command == "current":
        # Mostrar agente actual
        try:
            response = requests.get(f"{KALI_API}/api/agent/current")
            if response.status_code == 200:
                data = response.json()
                print_color(f"\n👤 Agente actual: ", Color.BRIGHT_CYAN, bold=True, end='')
                print_color(data['agent'], Color.BRIGHT_YELLOW, bold=True)
                print_box("📝 Comportamiento del agente", data['system_prompt'][:300] + "...", Color.CYAN)
            else:
                print_color(f"❌ Error: {response.text}", Color.RED)
        except Exception as e:
            print_color(f"❌ Error de conexión: {e}", Color.RED)
    
    elif command == "select":
        if len(parts) < 3:
            print_color("❌ Uso: /agent select <tipo>", Color.RED)
            print_color("💡 Usa '/agent list' para ver tipos disponibles", Color.YELLOW)
            return True
        
        agent_type = parts[2]
        try:
            response = requests.post(
                f"{KALI_API}/api/agent/select",
                json={"agent_type": agent_type}
            )
            
            if response.status_code == 200:
                data = response.json()
                print_color(f"\n✅ {data['message']}", Color.BRIGHT_GREEN, bold=True)
                print_box("🎭 Nuevo rol especializado", data['system_prompt'][:250] + "...", Color.BRIGHT_MAGENTA)
                
                # Actualizar el system prompt en el historial
                for msg in historial:
                    if msg["role"] == "system":
                        # Combinar el prompt del agente con las instrucciones de herramientas
                        base_instructions = SYSTEM_PROMPT_BASE.split("HERRAMIENTAS DISPONIBLES:")[1]
                        msg["content"] = data['system_prompt'] + "\n\nHERRAMIENTAS DISPONIBLES:" + base_instructions
                        break
                
                print_color("\n💡 El agente ahora responderá según su nueva especialización", Color.CYAN)
            else:
                error_msg = response.json().get('error', 'Unknown error')
                print_color(f"\n❌ Error: {error_msg}", Color.RED)
        except Exception as e:
            print_color(f"❌ Error de conexión: {e}", Color.RED)
    
    else:
        print_color(f"❌ Comando desconocido: {command}", Color.RED)
        print_color("💡 Comandos disponibles: select, list, current", Color.YELLOW)
    
    return True

def chat():
    print_banner()

    print_color("\n📚 Ejemplos de comandos:", Color.BRIGHT_YELLOW, bold=True)
    ejemplos = [
        ("🛡️", "Audita el repositorio https://github.com/user/repo"),
        ("🔍", "Detecta tecnologías de http://example.com"),
        ("🎯", "Busca CVEs críticos de Apache 2.4.49"),
        ("🌐", "Escanea puertos de scanme.nmap.org"),
        ("📁", "Busca directorios en http://testphp.vulnweb.com"),
        ("💻", "Ejecuta whoami"),
        ("🔓", "Prueba SQL injection en http://testphp.vulnweb.com/artists.php?artist=1")
    ]

    for emoji, ejemplo in ejemplos:
        print_color(f"  {emoji}  {ejemplo}", Color.CYAN)

    print_color("\n🎭 Comandos especiales de agentes:", Color.BRIGHT_YELLOW, bold=True)
    print_color("  /agent list          - Ver agentes especializados disponibles", Color.MAGENTA)
    print_color("  /agent select <tipo> - Cambiar rol del asistente (ej: blue_team, red_team)", Color.MAGENTA)
    print_color("  /agent current       - Ver agente actual y su comportamiento", Color.MAGENTA)

    print_color("\n💡 Escribe 'salir' para terminar", Color.BRIGHT_BLACK)
    print_color("═" * 60, Color.BRIGHT_BLUE)

    # Obtener el prompt del agente actual
    try:
        response = requests.get(f"{KALI_API}/api/agent/current")
        if response.status_code == 200:
            data = response.json()
            # Combinar prompt del agente con instrucciones de herramientas
            base_instructions = SYSTEM_PROMPT_BASE.split("HERRAMIENTAS DISPONIBLES:")[1]
            initial_prompt = data['system_prompt'] + "\n\nHERRAMIENTAS DISPONIBLES:" + base_instructions
            historial = [{"role": "system", "content": initial_prompt}]
        else:
            historial = [{"role": "system", "content": SYSTEM_PROMPT_BASE}]
    except:
        historial = [{"role": "system", "content": SYSTEM_PROMPT_BASE}]

    while True:
        try:
            # Prompt del usuario
            print_color("\n🧑 Tú: ", Color.BRIGHT_GREEN, bold=True, end='')
            mensaje = input()

            if mensaje.lower().strip() in ['salir', 'exit', 'quit', 'q']:
                print_color("\n👋 ¡Adiós! Mantente seguro 🔐", Color.BRIGHT_MAGENTA, bold=True)
                break

            if not mensaje.strip():
                continue

            # Manejar comandos /agent
            if mensaje.startswith("/agent"):
                handle_agent_command(mensaje, historial)
                continue

            historial.append({"role": "user", "content": mensaje})

            # Mostrar "pensando..."
            print_color("\n🤖 Groq está pensando...", Color.BRIGHT_BLACK)

            # Llamar a Groq
            response = groq.chat.completions.create(
                messages=historial,
                model="llama-3.3-70b-versatile",
                temperature=0.5,
                max_tokens=2000
            )

            respuesta = response.choices[0].message.content

            # Buscar TODAS las herramientas en la respuesta
            tool_pattern = r'USE_TOOL:(\w+)\s+({[^}]+})'
            tool_matches = list(re.finditer(tool_pattern, respuesta, re.DOTALL))
            
            if tool_matches:
                # Ejecutar todas las herramientas encontradas
                all_results = []
                
                for i, match in enumerate(tool_matches, 1):
                    tool_name = match.group(1)
                    params_str = match.group(2)

                    try:
                        params = json.loads(params_str)

                        # Mostrar lo que se va a ejecutar
                        print_color(f"\n🔧 Ejecutando herramienta {i}/{len(tool_matches)}: ", Color.BRIGHT_YELLOW, bold=True, end='')
                        print_color(tool_name.upper(), Color.BRIGHT_MAGENTA, bold=True)

                        # Mostrar parámetros en tabla
                        print_color("┌─ Parámetros " + "─" * 45, Color.YELLOW)
                        for key, value in params.items():
                            print_color(f"│ {key}: ", Color.YELLOW, end='')
                            print_color(str(value), Color.WHITE)
                        print_color("└" + "─" * 58, Color.YELLOW)

                        print_color("\n⏳ Ejecutando... (esto puede tardar)", Color.BRIGHT_BLACK)

                        resultado = ejecutar_herramienta(tool_name, params)

                        # Verificar si es un "error" válido (algunos tools retornan exit code != 0 pero tienen output útil)
                        has_useful_output = bool(resultado.get("stdout", "").strip() or resultado.get("stderr", "").strip())
                        
                        if resultado.get("success") or (has_useful_output and tool_name in ["gitleaks", "semgrep"]):
                            output = resultado.get("stdout", "") or resultado.get("stderr", "")

                            if resultado.get("timed_out"):
                                print_color("\n⚠️  TIMEOUT - Resultados parciales:", Color.BRIGHT_YELLOW, bold=True)
                            else:
                                print_color("\n✅ ÉXITO", Color.BRIGHT_GREEN, bold=True)

                            # Resaltar CVEs en el output
                            output_formatted = format_ai_response(output)

                            # Limitar output mostrado
                            max_display = 1500
                            if len(output_formatted) > max_display:
                                output_display = output_formatted[:max_display] + f"\n\n... (truncado, total: {len(output)} caracteres)"
                            else:
                                output_display = output_formatted

                            # Mostrar resultado con colores
                            print_box(f"📊 RESULTADO {i}/{len(tool_matches)} - {tool_name}", output_display, Color.BRIGHT_BLUE)

                            if resultado.get("stderr") and tool_name not in ["gitleaks"]:
                                print_box("⚠️  ADVERTENCIAS", resultado['stderr'][:500], Color.YELLOW)

                            all_results.append(f"[{tool_name}]: {output[:500]}...")
                        else:
                            error = resultado.get("error") or resultado.get("stderr", "Error desconocido")
                            
                            # Si es un error de archivo no encontrado, marcarlo como warning en lugar de error
                            if "No existe el fichero" in error or "No such file" in error:
                                print_color(f"\n⚠️  ADVERTENCIA en {tool_name}", Color.BRIGHT_YELLOW, bold=True)
                                print_box("Archivo no encontrado", error[:500], Color.YELLOW)
                                all_results.append(f"[{tool_name} WARNING]: Archivo no encontrado")
                            else:
                                print_color(f"\n❌ ERROR en {tool_name}", Color.BRIGHT_RED, bold=True)
                                print_box("Detalles del error", error[:500], Color.RED)
                                all_results.append(f"[{tool_name} ERROR]: {error[:200]}...")

                    except json.JSONDecodeError as e:
                        print_color(f"\n❌ Error parseando parámetros de {tool_name}: {e}", Color.RED)
                        all_results.append(f"[{tool_name} PARSE ERROR]: {e}")
                
                # Agregar todos los resultados al historial
                combined_results = "\n\n".join(all_results)
                historial.append({
                    "role": "assistant",
                    "content": f"Ejecuté {len(tool_matches)} herramientas:\n{combined_results}"
                })
                
            else:
                # Respuesta normal sin herramientas
                print_color(f"\n🤖 Groq:\n", Color.BRIGHT_CYAN, bold=True)
                formatted_response = format_ai_response(respuesta)
                print_color(formatted_response, Color.BRIGHT_CYAN)
                historial.append({"role": "assistant", "content": respuesta})

        except KeyboardInterrupt:
            print_color("\n\n👋 ¡Adiós!", Color.BRIGHT_MAGENTA, bold=True)
            break
        except Exception as e:
            print_color(f"\n❌ Error inesperado: {e}", Color.RED, bold=True)

if __name__ == "__main__":
    chat()