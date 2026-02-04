#!/usr/bin/env python3
import os
import requests
import json
import re
from anthropic import Anthropic

# 🎨 COLORES ANSI
class Color:
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

def print_color(text, color=Color.WHITE, bold=False, end='\n'):
    """Imprimir texto con color"""
    style = Color.BOLD if bold else ''
    print(f"{style}{color}{text}{Color.RESET}", end=end)

def print_banner(model_name):
    """Imprimir banner inicial"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║    💬 Chat con Claude + Kali Linux Tools 🔧 + CVE Scanner   ║
║    🤖 Modelo: {model_name.ljust(49)} ║
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
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Configuración de modelos
AVAILABLE_MODELS = {
    "sonnet": "claude-3-5-sonnet-20241022",
    "haiku": "claude-3-5-haiku-20241022",
    "opus": "claude-3-opus-20240229"
}

# Modelo por defecto (puedes cambiarlo aquí o con variable de entorno)
DEFAULT_MODEL = "haiku"
SELECTED_MODEL = os.getenv("CLAUDE_MODEL", DEFAULT_MODEL)

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

client = Anthropic(api_key=ANTHROPIC_API_KEY)

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
   IMPORTANTE: Siempre pasar la ruta RAÍZ del repositorio, no subcarpetas

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
🎯 METODOLOGÍA DE AUDITORÍA SAST (MEJORADA)
═══════════════════════════════════════════════════════════

Para AUDITAR UN REPOSITORIO GITHUB:

**FASE 1: RECONOCIMIENTO (SIEMPRE PRIMERO)**
1. git_clone - Clonar el repositorio
2. command - Verificar estructura COMPLETA:
   "find /tmp/audit_repo -type f \\( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \\) | head -20"
   "find /tmp/audit_repo -type f -name '*.py' | head -20"
   "find /tmp/audit_repo -type f -name '*.php' | head -20"
3. command - Verificar archivos de dependencias:
   "ls -la /tmp/audit_repo/package.json /tmp/audit_repo/package-lock.json /tmp/audit_repo/requirements.txt 2>/dev/null || echo 'Archivos de dependencias no encontrados'"

**FASE 2: ANÁLISIS DE CÓDIGO (SOLO SI HAY ARCHIVOS)**
4. semgrep - SOLO si encontraste archivos de código:
   - Si hay JS/TS: usar config "p/javascript" o "p/typescript"
   - Si hay Python: usar config "p/python"
   - Si es mixto o desconocido: usar config "auto"
   - IMPORTANTE: Pasar la ruta RAÍZ /tmp/audit_repo, NO subcarpetas

**FASE 3: ANÁLISIS DE SECRETOS**
5. gitleaks - SIEMPRE ejecutar (busca en todo el repo)

**FASE 4: ANÁLISIS DE DEPENDENCIAS (CONDICIONAL)**
6. command - npm audit SOLO si existe package-lock.json:
   "test -f /tmp/audit_repo/package-lock.json && cd /tmp/audit_repo && npm audit --json || echo '{\"info\": \"No package-lock.json found, cannot audit npm dependencies\"}'"
7. command - pip-audit SOLO si existe requirements.txt:
   "test -f /tmp/audit_repo/requirements.txt && pip-audit -r /tmp/audit_repo/requirements.txt || echo 'No requirements.txt found'"

**REGLAS CRÍTICAS:**
- ✅ SIEMPRE ejecuta git_clone primero
- ✅ SIEMPRE verifica qué archivos existen antes de escanear
- ✅ USA "test -f" antes de leer archivos
- ✅ Pasa la ruta RAÍZ del repo a semgrep, no subcarpetas
- ✅ Si no hay package-lock.json, NO ejecutes npm audit (usa el comando condicional)
- ❌ NUNCA asumas que existe un archivo sin verificar

**EJEMPLO CORRECTO:**

Usuario: "Audita https://github.com/user/repo"

Respuesta:
USE_TOOL:git_clone {"repo_url": "https://github.com/user/repo", "destination": "/tmp/audit_repo"}
USE_TOOL:command {"command": "echo '=== ARCHIVOS JS ===' && find /tmp/audit_repo -name '*.js' | wc -l && echo '=== ARCHIVOS PY ===' && find /tmp/audit_repo -name '*.py' | wc -l"}
USE_TOOL:command {"command": "ls -la /tmp/audit_repo/package.json /tmp/audit_repo/package-lock.json 2>/dev/null || echo 'No dependency files'"}
USE_TOOL:semgrep {"path": "/tmp/audit_repo", "config": "auto"}
USE_TOOL:gitleaks {"path": "/tmp/audit_repo"}
USE_TOOL:command {"command": "test -f /tmp/audit_repo/package-lock.json && cd /tmp/audit_repo && npm audit --json || echo '{\"warning\": \"No package-lock.json found\"}'"}

Puedes usar VARIAS herramientas en una sola respuesta cuando sea lógico.
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
        "bandit": "/api/tools/bandit"
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

def handle_agent_command(user_input, conversation):
    """Manejar comandos /agent."""
    parts = user_input.split()
    
    if len(parts) < 2:
        print_color("\n❌ Uso: /agent select <tipo> | /agent list | /agent current", Color.RED)
        return True
    
    command = parts[1].lower()
    
    if command == "list":
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
                
                # Actualizar el system prompt global
                global CURRENT_SYSTEM_PROMPT
                base_instructions = SYSTEM_PROMPT_BASE.split("HERRAMIENTAS DISPONIBLES:")[1]
                CURRENT_SYSTEM_PROMPT = data['system_prompt'] + "\n\nHERRAMIENTAS DISPONIBLES:" + base_instructions
                
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

# Variable global para el system prompt actual
CURRENT_SYSTEM_PROMPT = SYSTEM_PROMPT_BASE

def chat():
    global CURRENT_SYSTEM_PROMPT
    
    print_banner(AVAILABLE_MODELS[SELECTED_MODEL])

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
    print_color("  /agent select <tipo> - Cambiar rol del asistente (ej: blue_team, red_team, sast_analyst)", Color.MAGENTA)
    print_color("  /agent current       - Ver agente actual y su comportamiento", Color.MAGENTA)

    print_color("\n💡 Escribe 'salir' para terminar", Color.BRIGHT_BLACK)
    print_color("═" * 60, Color.BRIGHT_BLUE)

    # Obtener el prompt del agente actual
    try:
        response = requests.get(f"{KALI_API}/api/agent/current")
        if response.status_code == 200:
            data = response.json()
            base_instructions = SYSTEM_PROMPT_BASE.split("HERRAMIENTAS DISPONIBLES:")[1]
            CURRENT_SYSTEM_PROMPT = data['system_prompt'] + "\n\nHERRAMIENTAS DISPONIBLES:" + base_instructions
    except:
        pass

    conversation = []

    while True:
        try:
            print_color("\n🧑 Tú: ", Color.BRIGHT_GREEN, bold=True, end='')
            mensaje = input()

            if mensaje.lower().strip() in ['salir', 'exit', 'quit', 'q']:
                print_color("\n👋 ¡Adiós! Mantente seguro 🔐", Color.BRIGHT_MAGENTA, bold=True)
                break

            if not mensaje.strip():
                continue

            # Manejar comandos /agent
            if mensaje.startswith("/agent"):
                handle_agent_command(mensaje, conversation)
                continue

            conversation.append({
                "role": "user",
                "content": mensaje
            })

            print_color("\n🤖 Claude está pensando...", Color.BRIGHT_BLACK)

            # Llamar a Claude
            response = client.messages.create(
                model=AVAILABLE_MODELS[SELECTED_MODEL],
                max_tokens=2000,
                system=CURRENT_SYSTEM_PROMPT,
                messages=conversation
            )

            respuesta = response.content[0].text

            # Buscar TODAS las herramientas en la respuesta
            tool_pattern = r'USE_TOOL:(\w+)\s+({[^}]+})'
            tool_matches = list(re.finditer(tool_pattern, respuesta, re.DOTALL))
            
            if tool_matches:
                all_results = []
                
                for i, match in enumerate(tool_matches, 1):
                    tool_name = match.group(1)
                    params_str = match.group(2)

                    try:
                        params = json.loads(params_str)

                        print_color(f"\n🔧 Ejecutando herramienta {i}/{len(tool_matches)}: ", Color.BRIGHT_YELLOW, bold=True, end='')
                        print_color(tool_name.upper(), Color.BRIGHT_MAGENTA, bold=True)

                        print_color("┌─ Parámetros " + "─" * 45, Color.YELLOW)
                        for key, value in params.items():
                            print_color(f"│ {key}: ", Color.YELLOW, end='')
                            print_color(str(value), Color.WHITE)
                        print_color("└" + "─" * 58, Color.YELLOW)

                        print_color("\n⏳ Ejecutando... (esto puede tardar)", Color.BRIGHT_BLACK)

                        resultado = ejecutar_herramienta(tool_name, params)

                        has_useful_output = bool(resultado.get("stdout", "").strip() or resultado.get("stderr", "").strip())
                        
                        # Casos especiales de "éxito"
                        is_special_success = False
                        if tool_name == "semgrep":
                            # Semgrep puede retornar error pero con resultados válidos en JSON
                            try:
                                output_json = json.loads(resultado.get("stdout", "{}"))
                                if "results" in output_json or "errors" in output_json:
                                    is_special_success = True
                            except:
                                pass
                        
                        if resultado.get("success") or is_special_success or (has_useful_output and tool_name in ["gitleaks", "semgrep"]):
                            output = resultado.get("stdout", "") or resultado.get("stderr", "")

                            if resultado.get("timed_out"):
                                print_color("\n⚠️  TIMEOUT - Resultados parciales:", Color.BRIGHT_YELLOW, bold=True)
                            else:
                                print_color("\n✅ ÉXITO", Color.BRIGHT_GREEN, bold=True)

                            output_formatted = format_ai_response(output)

                            max_display = 1500
                            if len(output_formatted) > max_display:
                                output_display = output_formatted[:max_display] + f"\n\n... (truncado, total: {len(output)} caracteres)"
                            else:
                                output_display = output_formatted

                            print_box(f"📊 RESULTADO {i}/{len(tool_matches)} - {tool_name}", output_display, Color.BRIGHT_BLUE)

                            if resultado.get("stderr") and tool_name not in ["gitleaks"]:
                                print_box("⚠️  ADVERTENCIAS", resultado['stderr'][:500], Color.YELLOW)

                            all_results.append(f"[{tool_name}]: {output[:500]}...")
                        else:
                            error = resultado.get("error") or resultado.get("stderr", "Error desconocido")
                            
                            # Si es un error de archivo no encontrado o npm audit sin lockfile, marcarlo como warning
                            if ("No existe el fichero" in error or "No such file" in error or 
                                "package-lock.json" in error or "ENOLOCK" in error):
                                print_color(f"\n⚠️  ADVERTENCIA en {tool_name}", Color.BRIGHT_YELLOW, bold=True)
                                print_box("Archivo no encontrado o no aplicable", error[:500], Color.YELLOW)
                                all_results.append(f"[{tool_name} WARNING]: {error[:200]}...")
                            else:
                                print_color(f"\n❌ ERROR en {tool_name}", Color.BRIGHT_RED, bold=True)
                                print_box("Detalles del error", error[:500], Color.RED)
                                all_results.append(f"[{tool_name} ERROR]: {error[:200]}...")

                    except json.JSONDecodeError as e:
                        print_color(f"\n❌ Error parseando parámetros de {tool_name}: {e}", Color.RED)
                        all_results.append(f"[{tool_name} PARSE ERROR]: {e}")
                
                # Agregar resultado al conversation
                combined_results = "\n\n".join(all_results)
                conversation.append({
                    "role": "assistant",
                    "content": respuesta
                })
                conversation.append({
                    "role": "user",
                    "content": f"Resultados de las herramientas:\n{combined_results}"
                })
                
            else:
                print_color(f"\n🤖 Claude:\n", Color.BRIGHT_CYAN, bold=True)
                formatted_response = format_ai_response(respuesta)
                print_color(formatted_response, Color.BRIGHT_CYAN)
                
                conversation.append({
                    "role": "assistant",
                    "content": respuesta
                })

        except KeyboardInterrupt:
            print_color("\n\n👋 ¡Adiós!", Color.BRIGHT_MAGENTA, bold=True)
            break
        except Exception as e:
            print_color(f"\n❌ Error inesperado: {e}", Color.RED, bold=True)
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    chat()