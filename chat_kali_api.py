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
except Exception as e:
    print_color(f"❌ Error: No se puede conectar al servidor Kali", Color.RED, bold=True)
    print_color(f"   Primero inicia: python3 kali_server.py", Color.YELLOW)
    exit(1)

groq = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT = """Eres un asistente experto en pentesting y ciberseguridad con acceso a herramientas de Kali Linux.

HERRAMIENTAS DISPONIBLES:

1. nmap - Escaneo de puertos y servicios
   Formato: USE_TOOL:nmap {"target": "scanme.nmap.org", "ports": "80,443", "scan_type": "-sV"}

2. nuclei - Escaneo de CVEs y vulnerabilidades conocidas ⭐ NUEVO
   Formato: USE_TOOL:nuclei {"target": "http://example.com", "severity": "critical,high", "tags": "cve"}
   Severidad: critical, high, medium, low, info
   Tags: cve, oast, panel, xss, sqli, rce, lfi

3. whatweb - Detectar tecnologías web y versiones ⭐ NUEVO
   Formato: USE_TOOL:whatweb {"target": "http://example.com"}

4. cve_search - Buscar CVEs por software/versión ⭐ NUEVO
   Formato: USE_TOOL:cve_search {"software": "apache", "version": "2.4.49"}

5. gobuster - Fuzzing de directorios
   Formato: USE_TOOL:gobuster {"url": "http://example.com"}

6. nikto - Escaneo de vulnerabilidades web
   Formato: USE_TOOL:nikto {"target": "http://example.com"}

7. sqlmap - Detección de SQL injection
   Formato: USE_TOOL:sqlmap {"url": "http://example.com/page?id=1"}

8. wpscan - Scanner de WordPress
   Formato: USE_TOOL:wpscan {"url": "http://wordpress.com"}

9. hydra - Brute force de contraseñas
   Formato: USE_TOOL:hydra {"target": "IP", "service": "ssh", "username": "admin", "password_file": "/usr/share/wordlists/rockyou.txt"}

10. command - Ejecutar cualquier comando Linux
    Formato: USE_TOOL:command {"command": "ls -la /tmp"}

WORKFLOW RECOMENDADO PARA BUSCAR CVEs:
1. Primero usa 'whatweb' para detectar tecnologías
2. Luego usa 'nuclei' para buscar CVEs conocidos
3. También puedes usar 'cve_search' si conoces el software exacto

Cuando el usuario pida:
- "buscar CVEs", "vulnerabilidades", "escanear CVEs" → usa nuclei
- "qué tecnologías usa", "detectar versiones" → usa whatweb
- "CVEs de [software]" → usa cve_search

Responde EXACTAMENTE con: USE_TOOL:nombre_herramienta {"param": "valor"}
Si no necesitas herramientas, responde normalmente."""

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
        "enum4linux": "/api/tools/enum4linux",
        "dirb": "/api/tools/dirb",
        "metasploit": "/api/tools/metasploit",
        "command": "/api/command"
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

def chat():
    print_banner()

    print_color("\n📚 Ejemplos de comandos:", Color.BRIGHT_YELLOW, bold=True)
    ejemplos = [
        ("🛡️", "Busca CVEs en http://testphp.vulnweb.com"),
        ("🔍", "Detecta tecnologías de http://example.com"),
        ("🎯", "Busca CVEs críticos de Apache 2.4.49"),
        ("🌐", "Escanea puertos de scanme.nmap.org"),
        ("📁", "Busca directorios en http://testphp.vulnweb.com"),
        ("💻", "Ejecuta whoami"),
        ("🔓", "Prueba SQL injection en http://testphp.vulnweb.com/artists.php?artist=1")
    ]

    for emoji, ejemplo in ejemplos:
        print_color(f"  {emoji}  {ejemplo}", Color.CYAN)

    print_color("\n💡 Escribe 'salir' para terminar", Color.BRIGHT_BLACK)
    print_color("═" * 60, Color.BRIGHT_BLUE)

    historial = [{"role": "system", "content": SYSTEM_PROMPT}]

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

            # Buscar si quiere usar una herramienta
            if "USE_TOOL:" in respuesta:
                match = re.search(r'USE_TOOL:(\w+)\s+({.*?})', respuesta, re.DOTALL)

                if match:
                    tool_name = match.group(1)
                    params_str = match.group(2)

                    try:
                        params = json.loads(params_str)

                        # Mostrar lo que se va a ejecutar
                        print_color(f"\n🔧 Ejecutando herramienta: ", Color.BRIGHT_YELLOW, bold=True, end='')
                        print_color(tool_name.upper(), Color.BRIGHT_MAGENTA, bold=True)

                        # Mostrar parámetros en tabla
                        print_color("┌─ Parámetros " + "─" * 45, Color.YELLOW)
                        for key, value in params.items():
                            print_color(f"│ {key}: ", Color.YELLOW, end='')
                            print_color(str(value), Color.WHITE)
                        print_color("└" + "─" * 58, Color.YELLOW)

                        print_color("\n⏳ Ejecutando... (esto puede tardar)", Color.BRIGHT_BLACK)

                        resultado = ejecutar_herramienta(tool_name, params)

                        if resultado.get("success"):
                            output = resultado.get("stdout", "")

                            if resultado.get("timed_out"):
                                print_color("\n⚠️  TIMEOUT - Resultados parciales:", Color.BRIGHT_YELLOW, bold=True)
                            else:
                                print_color("\n✅ ÉXITO", Color.BRIGHT_GREEN, bold=True)

                            # Resaltar CVEs en el output
                            output_formatted = format_ai_response(output)

                            # Mostrar resultado con colores
                            print_box("📊 RESULTADO", output_formatted, Color.BRIGHT_BLUE)

                            if resultado.get("stderr"):
                                print_box("⚠️  ADVERTENCIAS", resultado['stderr'], Color.YELLOW)

                            historial.append({
                                "role": "assistant",
                                "content": f"Ejecuté {tool_name}. Resultado:\n{output[:500]}..."
                            })
                        else:
                            error = resultado.get("error") or resultado.get("stderr", "Error desconocido")
                            print_color(f"\n❌ ERROR", Color.BRIGHT_RED, bold=True)
                            print_box("Detalles del error", error, Color.RED)

                            historial.append({
                                "role": "assistant",
                                "content": f"Error ejecutando {tool_name}: {error}"
                            })

                    except json.JSONDecodeError as e:
                        print_color(f"\n❌ Error parseando parámetros: {e}", Color.RED)
                        print_color(f"\n🤖 Respuesta original:\n", Color.BRIGHT_CYAN, bold=True)
                        print_color(respuesta, Color.CYAN)
                        historial.append({"role": "assistant", "content": respuesta})
                else:
                    print_color(f"\n🤖 Groq:\n", Color.BRIGHT_CYAN, bold=True)
                    formatted_response = format_ai_response(respuesta)
                    print_color(formatted_response, Color.BRIGHT_CYAN)
                    historial.append({"role": "assistant", "content": respuesta})
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
