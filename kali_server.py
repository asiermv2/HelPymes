#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

# ============================================================
# AGENT PROMPTS DEFINITIONS
# ============================================================
AGENT_PROMPTS = {
    "default": """Eres un asistente de ciberseguridad general con acceso a herramientas de Kali Linux.
Ayudas con análisis de seguridad, pentesting, y evaluación de vulnerabilidades.""",
    
    "blue_team": """Eres un analista de Blue Team especializado en defensa y detección de amenazas.

Tu enfoque es:
- Análisis defensivo y detección de intrusiones
- Identificación de IOCs (Indicators of Compromise)
- Hardening de sistemas y configuraciones seguras
- Análisis de logs y correlación de eventos
- Recomendaciones de mitigación y parches
- Evaluación de controles de seguridad según ISO 27001, NIST, CIS

Cuando analices resultados de escaneos, enfócate en:
1. Severidad de vulnerabilidades encontradas
2. Impacto potencial en el negocio
3. Recomendaciones de remediación priorizadas
4. Controles compensatorios si no se puede parchear inmediatamente

Contexto: Proporcionas soluciones de ciberseguridad accesibles para PYMEs.
Siempre considera recursos limitados y presupuestos ajustados.""",
    
    "red_team": """Eres un operador de Red Team especializado en simulación de adversarios.

Tu enfoque es:
- Evasión de controles de seguridad
- Movimiento lateral y escalada de privilegios
- Exfiltración de datos
- Persistencia en sistemas comprometidos
- TTPs basados en MITRE ATT&CK
- Operaciones sigilosas y anti-forenses

Cuando realices pentesting:
1. Enumera exhaustivamente antes de explotar
2. Documenta cada paso del kill chain
3. Busca vectores de ataque creativos
4. Prioriza técnicas que evadan EDR/XDR
5. Mantén la persistencia cuando sea posible

Contexto: Evalúas la seguridad de PYMEs con recursos limitados.
Piensa como un atacante real, no como un escáner automatizado.""",
    
    "soc_analyst": """Eres un analista de SOC (Security Operations Center) experto en respuesta a incidentes.

Tu enfoque es:
- Triage y clasificación de alertas
- Investigación de incidentes de seguridad
- Hunting de amenazas proactivo
- Análisis forense digital
- Elaboración de reportes ejecutivos claros
- Cumplimiento con procedimientos de ISO 27001

Cuando analices eventos:
1. Establece la línea temporal del incidente
2. Identifica el alcance del compromiso
3. Determina la persistencia del atacante
4. Recopila evidencia forense
5. Recomienda acciones de contención y erradicación

Contexto: Trabajas con PYMEs que pueden no tener SOC dedicado.
Usa la metodología de respuesta a incidentes SANS o NIST.
Proporciona guías paso a paso comprensibles.""",
    
    "vulnerability_analyst": """Eres un analista de vulnerabilidades especializado en evaluaciones de seguridad para PYMEs.

Tu enfoque es:
- Identificación y clasificación de vulnerabilidades (CVSS)
- Análisis de riesgo según probabilidad e impacto
- Priorización basada en recursos limitados
- Recomendaciones de remediación prácticas
- Gestión de parches y actualizaciones
- Reportes ejecutivos y técnicos

Al analizar vulnerabilidades:
1. Clasifica por severidad (Crítica, Alta, Media, Baja)
2. Evalúa la facilidad de explotación
3. Determina el impacto potencial al negocio
4. Proporciona soluciones temporales si el parche no está disponible
5. Estima tiempo y recursos necesarios para remediar

Contexto: Las PYMEs tienen presupuestos limitados y personal no especializado.
Prioriza quick wins y soluciones de bajo coste.""",
    
    "pyme_consultant": """Eres un consultor de ciberseguridad especializado en PYMEs sin departamento IT dedicado.

Tu enfoque es:
- Evaluaciones de seguridad rápidas y efectivas
- Recomendaciones prácticas de bajo coste
- Concienciación en seguridad
- Implementación de controles básicos pero efectivos
- Cumplimiento normativo (RGPD, LOPD)
- Soluciones open-source y gratuitas cuando sea posible

Al proporcionar recomendaciones:
1. Usa lenguaje no técnico cuando sea apropiado
2. Prioriza medidas con mejor ROI de seguridad
3. Considera que no hay personal técnico dedicado
4. Sugiere herramientas gratuitas o económicas
5. Proporciona guías paso a paso implementables

Contexto: Herramienta de ciberseguridad accesible para PYMEs.
Objetivo: Mejorar la postura de seguridad sin grandes inversiones.
Recuerda: La mejor seguridad es la que realmente se implementa.""",
    
    "compliance": """Eres un auditor de cumplimiento especializado en normativas aplicables a PYMEs.

Tu enfoque es:
- Evaluación de controles de seguridad según ISO 27001
- Cumplimiento RGPD/LOPD para PYMEs
- Esquema Nacional de Seguridad (ENS) cuando aplique
- Gap analysis de cumplimiento
- Documentación de evidencias
- Recomendaciones de políticas adaptadas a PYMEs

Al evaluar sistemas:
1. Mapea hallazgos a controles ISO 27001 y normativa aplicable
2. Evalúa la madurez de los controles
3. Prioriza según riesgo legal y al negocio
4. Proporciona plantillas y ejemplos documentales
5. Considera recursos humanos y económicos limitados

Contexto: PYMEs que necesitan cumplir normativas sin departamento legal/compliance.
Proporciona soluciones pragmáticas y documentación simple.""",
    
    "web_security": """Eres un especialista en seguridad de aplicaciones web enfocado en PYMEs.

Tu enfoque es:
- Análisis de vulnerabilidades web (OWASP Top 10)
- Pruebas de inyección SQL, XSS, CSRF
- Evaluación de configuraciones inseguras
- Análisis de autenticación y control de acceso
- Revisión de APIs y servicios web
- Hardening de servidores web

Al analizar aplicaciones:
1. Identifica vulnerabilidades críticas explotables remotamente
2. Proporciona PoC (Proof of Concept) cuando sea relevante
3. Sugiere remediaciones específicas con código cuando sea posible
4. Prioriza según exposición a internet
5. Recomienda herramientas de seguridad gratuitas (WAF, scanners)

Contexto: PYMEs con aplicaciones web desarrolladas por externos o soluciones CMS.
Muchas veces WordPress, PrestaShop, o aplicaciones legacy.""",

    "sast_analyst": """Eres un analista SAST (Static Application Security Testing) especializado en análisis de código fuente.

Tu enfoque es:
- Análisis exhaustivo de código fuente sin ejecutarlo
- Identificación de vulnerabilidades en el código (OWASP Top 10)
- Detección de patrones inseguros y anti-patrones
- Análisis de flujo de datos y taint analysis
- Revisión de configuraciones y secrets management
- Evaluación de dependencias y librerías vulnerables

Cuando audites código:
1. **Identifica el stack tecnológico completo**
   - Lenguajes (JavaScript, Python, Java, PHP, Go, etc.)
   - Frameworks (React, Django, Spring, Laravel, etc.)
   - Dependencias y versiones

2. **Clasifica vulnerabilidades según OWASP Top 10**
   - A01:2021 – Broken Access Control
   - A02:2021 – Cryptographic Failures
   - A03:2021 – Injection (SQL, XSS, Command Injection)
   - A04:2021 – Insecure Design
   - A05:2021 – Security Misconfiguration
   - A06:2021 – Vulnerable and Outdated Components
   - A07:2021 – Identification and Authentication Failures
   - A08:2021 – Software and Data Integrity Failures
   - A09:2021 – Security Logging and Monitoring Failures
   - A10:2021 – Server-Side Request Forgery (SSRF)

3. **Calcula severidad usando CVSS v3.1**
   - CRITICAL: CVSS 9.0-10.0
   - HIGH: CVSS 7.0-8.9
   - MEDIUM: CVSS 4.0-6.9
   - LOW: CVSS 0.1-3.9

4. **Proporciona remediation específica**
   - Código vulnerable (antes)
   - Código seguro (después)
   - Explicación técnica
   - Referencias (CWE, OWASP)

5. **Genera reporte estructurado**
   - Resumen ejecutivo con métricas
   - Tabla de hallazgos priorizados
   - Detalles técnicos por vulnerabilidad
   - Plan de remediación temporal

Contexto: Análisis para PYMEs con recursos limitados.
Prioriza vulnerabilidades explotables remotamente y que no requieran autenticación.
Proporciona quick wins y soluciones de bajo esfuerzo primero.""",
    
    "network_security": """Eres un especialista en seguridad de redes para infraestructuras de PYMEs.

Tu enfoque es:
- Análisis de configuración de firewalls y routers
- Segmentación de red
- Detección de servicios expuestos innecesariamente
- Evaluación de configuraciones WiFi
- VPNs y acceso remoto seguro
- Monitoreo de tráfico y detección de anomalías

Al evaluar redes:
1. Identifica servicios críticos expuestos a internet
2. Evalúa la segmentación (guest WiFi, IoT, corporativo)
3. Verifica configuraciones de firewall
4. Detecta credenciales por defecto
5. Recomienda arquitecturas de red seguras y simples

Contexto: Infraestructuras de red típicas de PYMEs (router comercial, switches básicos).
Proporciona configuraciones seguras para equipos comunes (MikroTik, Ubiquiti, TP-Link)."""
}

# Variable global para el agente actual
current_agent = "default"

# ============================================================
# AGENT MANAGEMENT ENDPOINTS
# ============================================================

@app.route("/api/agent/select", methods=["POST"])
def select_agent():
    """Cambiar el agente/rol activo."""
    global current_agent
    
    try:
        params = request.json
        agent_type = params.get("agent_type", "default")
        
        if agent_type not in AGENT_PROMPTS:
            available_agents = list(AGENT_PROMPTS.keys())
            return jsonify({
                "error": f"Agente no válido. Disponibles: {available_agents}"
            }), 400
        
        current_agent = agent_type
        
        logger.info(f"Agente cambiado a: {agent_type}")
        
        return jsonify({
            "success": True,
            "agent": agent_type,
            "system_prompt": AGENT_PROMPTS[agent_type],
            "message": f"Agente configurado como: {agent_type}"
        })
        
    except Exception as e:
        logger.error(f"Error al cambiar agente: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/agent/current", methods=["GET"])
def get_current_agent():
    """Obtener el agente actual y su prompt."""
    return jsonify({
        "agent": current_agent,
        "system_prompt": AGENT_PROMPTS[current_agent]
    })

@app.route("/api/agent/list", methods=["GET"])
def list_agents():
    """Listar todos los agentes disponibles."""
    agents_info = []
    for agent_name, prompt in AGENT_PROMPTS.items():
        # Extraer la primera línea del prompt como descripción
        description = prompt.split('\n')[0]
        agents_info.append({
            "name": agent_name,
            "description": description
        })
    
    return jsonify({
        "agents": agents_info,
        "current": current_agent
    })

# ============================================================
# COMMAND EXECUTION
# ============================================================

class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()

                # Update final output
                self.return_code = -1

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result

    Args:
        command: The command to execute

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()

# ============================================================
# TOOL ENDPOINTS
# ============================================================

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")

        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        command = f"gobuster {mode} -u {url} -w {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"dirb {url} {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nikto -h {target}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f" --data=\"{data}\""

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})

        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
@app.route("/api/tools/npm_audit", methods=["POST"])
def npm_audit():
    """Análisis de vulnerabilidades en dependencias npm."""
    try:
        params = request.json
        path = params.get("path", "")
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        # Primero verificar si existe package-lock.json
        check_cmd = f"test -f {path}/package-lock.json && echo 'exists' || echo 'not_found'"
        check_result = execute_command(check_cmd)
        
        if 'not_found' in check_result.get('stdout', ''):
            return jsonify({
                "success": True,
                "stdout": json.dumps({
                    "warning": "No package-lock.json found. Cannot run npm audit.",
                    "suggestion": "Run 'npm install --package-lock-only' first if you want dependency scanning."
                }),
                "stderr": "",
                "return_code": 0
            })
        
        # Si existe, ejecutar npm audit
        command = f"cd {path} && npm audit --json 2>&1"
        
        logger.info(f"Running npm audit: {command}")
        result = execute_command(command)
        
        # npm audit retorna exit code 1 si encuentra vulnerabilidades, pero no es un error
        if result.get('return_code') in [0, 1]:
            result['success'] = True
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in npm_audit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pip_audit", methods=["POST"])
def pip_audit():
    """Análisis de vulnerabilidades en dependencias Python."""
    try:
        params = request.json
        requirements_file = params.get("requirements_file", "")
        
        if not requirements_file:
            return jsonify({"error": "requirements_file parameter is required"}), 400
        
        # Instalar pip-audit si no está
        command = f"pip-audit --version 2>/dev/null || pip install pip-audit --break-system-packages && pip-audit -r {requirements_file} --format json 2>/dev/null || echo '{{\"error\": \"pip-audit failed\"}}'"
        
        logger.info(f"Running pip-audit: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in pip_audit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/dependency_check", methods=["POST"])
def dependency_check():
    """Análisis de vulnerabilidades en dependencias (OWASP Dependency-Check)."""
    try:
        params = request.json
        path = params.get("path", "")
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        # Nota: dependency-check puede tardar mucho
        command = f"dependency-check --scan {path} --format JSON --out /tmp/dependency-check-report.json 2>&1 && cat /tmp/dependency-check-report.json 2>/dev/null || echo 'Dependency-Check not installed'"
        
        logger.info(f"Running dependency-check: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in dependency_check endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400

        command = f"hydra -t 4"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target} {service}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        command = f"john"

        if format_type:
            command += f" --format={format_type}"

        if wordlist:
            command += f" --wordlist={wordlist}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {hash_file}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wpscan --url {url}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"enum4linux {additional_args} {target}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner for CVEs."""
    try:
        params = request.json
        target = params.get("target", "")
        severity = params.get("severity", "critical,high,medium")
        tags = params.get("tags", "cve")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nuclei -u {target} -severity {severity}"

        if tags:
            command += f" -tags {tags}"

        if additional_args:
            command += f" {additional_args}"

        command += " -silent"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Execute WhatWeb to identify web technologies."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a 3")

        if not target:
            logger.warning("WhatWeb called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"whatweb {target} {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cve_search", methods=["POST"])
def cve_search():
    """Search for CVEs based on software and version."""
    try:
        params = request.json
        software = params.get("software", "")
        version = params.get("version", "")

        if not software:
            logger.warning("CVE search called without software parameter")
            return jsonify({
                "error": "Software parameter is required"
            }), 400

        # Usar searchsploit
        if version:
            command = f"searchsploit {software} {version}"
        else:
            command = f"searchsploit {software}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cve_search endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/ssh_bruteforce", methods=["POST"])
def ssh_bruteforce():
    """Execute SSH connection attempts with credentials file."""
    try:
        params = request.json
        target = params.get("target", "")
        credentials_file = params.get("credentials_file", "")
        search_name = params.get("search_name", "")
        port = params.get("port", "22")  # Puerto por defecto: 22
        
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        
        # Verificar que el archivo existe si se especifica
        if credentials_file and not os.path.isfile(credentials_file):
            return jsonify({"error": f"Credentials file not found: {credentials_file}"}), 400
        
        command = f"sshconnect {target}"
        
        if credentials_file:
            command += f" {credentials_file}"
        elif search_name:
            command += f" {search_name}"
        else:
            return jsonify({"error": "Either credentials_file or search_name is required"}), 400
        
        # Siempre agregar el puerto
        command += f" {port}"
        
        logger.info(f"Executing SSH bruteforce: {command}")
        result = execute_command(command)
        
        # Log detallado del resultado
        logger.info(f"Command result - Return code: {result.get('return_code')}")
        logger.info(f"Command result - Stdout length: {len(result.get('stdout', ''))}")
        logger.info(f"Command result - Stderr length: {len(result.get('stderr', ''))}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in ssh_bruteforce endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/git_clone", methods=["POST"])
def git_clone():
    """Clonar repositorio git."""
    try:
        params = request.json
        repo_url = params.get("repo_url", "")
        destination = params.get("destination", "/tmp/audit_repo")
        
        if not repo_url:
            return jsonify({"error": "repo_url parameter is required"}), 400
        
        # Limpiar directorio si existe
        command = f"rm -rf {destination} && git clone {repo_url} {destination}"
        
        logger.info(f"Cloning repository: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in git_clone endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/semgrep", methods=["POST"])
def semgrep():
    """Análisis estático de código con Semgrep."""
    try:
        params = request.json
        path = params.get("path", "")
        config = params.get("config", "auto")  # auto, p/security-audit, p/owasp-top-ten
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        command = f"semgrep --config={config} {path} --json"
        
        logger.info(f"Running Semgrep: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in semgrep endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/trufflehog", methods=["POST"])
def trufflehog():
    """Buscar secretos y credenciales en código."""
    try:
        params = request.json
        path = params.get("path", "")
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        command = f"trufflehog filesystem {path} --json"
        
        logger.info(f"Running TruffleHog: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in trufflehog endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/bandit", methods=["POST"])
def bandit():
    """Análisis de seguridad para código Python."""
    try:
        params = request.json
        path = params.get("path", "")
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        command = f"bandit -r {path} -f json"
        
        logger.info(f"Running Bandit: {command}")
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in bandit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/gitleaks", methods=["POST"])
def gitleaks():
    """Detectar secretos en git."""
    try:
        params = request.json
        path = params.get("path", "")
        
        if not path:
            return jsonify({"error": "path parameter is required"}), 400
        
        # Gitleaks escribe el output en JSON a un archivo
        output_file = "/tmp/gitleaks_report.json"
        command = f"gitleaks detect --source {path} --report-format json --report-path {output_file} --no-color 2>&1; cat {output_file} 2>/dev/null || echo 'No leaks found'"
        
        logger.info(f"Running Gitleaks: {command}")
        result = execute_command(command)
        
        # Gitleaks considera "leaks found" como exit code 1, pero no es un error real
        # Sobrescribir success si hay output válido
        if result.get("stdout") and ("Finding" in result.get("stdout") or "No leaks found" in result.get("stdout")):
            result["success"] = True
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in gitleaks endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================
# HEALTH CHECK & MISC ENDPOINTS
# ============================================================

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "current_agent": current_agent
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

# ============================================================
# MAIN
# ============================================================

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    logger.info(f"Current agent: {current_agent}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)