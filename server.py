#!/usr/bin/env python3
import os
import json
import asyncio
import subprocess
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

class KaliMCPServer:
    def __init__(self):
        self.server = Server("kali-tools-server")
        self.setup_tools()

    def ejecutar_comando(self, comando: str, timeout: int = 30) -> dict:
        """Ejecutar comando en Kali de forma segura"""
        try:
            result = subprocess.run(
                comando,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Comando excedió el timeout de {timeout}s"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def setup_tools(self):
        """Definir las herramientas disponibles"""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                # Herramientas de red
                Tool(
                    name="nmap_scan",
                    description="Escanear puertos con nmap",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "IP o dominio a escanear"
                            },
                            "ports": {
                                "type": "string",
                                "description": "Puertos a escanear (ej: 80,443 o 1-1000)",
                                "default": "1-1000"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="ping",
                    description="Hacer ping a un host",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Host a hacer ping"
                            },
                            "count": {
                                "type": "integer",
                                "description": "Número de pings",
                                "default": 4
                            }
                        },
                        "required": ["host"]
                    }
                ),
                Tool(
                    name="whois",
                    description="Consulta WHOIS de un dominio",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Dominio a consultar"
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                Tool(
                    name="dig",
                    description="Consulta DNS con dig",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Dominio a consultar"
                            },
                            "record_type": {
                                "type": "string",
                                "description": "Tipo de registro (A, MX, NS, TXT, etc)",
                                "default": "A"
                            }
                        },
                        "required": ["domain"]
                    }
                ),

                # Herramientas de sistema
                Tool(
                    name="file_read",
                    description="Leer contenido de un archivo",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Ruta del archivo"
                            }
                        },
                        "required": ["path"]
                    }
                ),
                Tool(
                    name="file_write",
                    description="Escribir en un archivo",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Ruta del archivo"
                            },
                            "content": {
                                "type": "string",
                                "description": "Contenido a escribir"
                            }
                        },
                        "required": ["path", "content"]
                    }
                ),
                Tool(
                    name="list_dir",
                    description="Listar contenido de un directorio",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Ruta del directorio",
                                "default": "."
                            }
                        }
                    }
                ),
                Tool(
                    name="system_info",
                    description="Información del sistema",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),

                # Herramienta genérica (¡úsala con cuidado!)
                Tool(
                    name="execute_command",
                    description="Ejecutar comando arbitrario en Kali",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Comando a ejecutar"
                            }
                        },
                        "required": ["command"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> list[TextContent]:
            try:
                # Herramientas de red
                if name == "nmap_scan":
                    target = arguments["target"]
                    ports = arguments.get("ports", "1-1000")
                    cmd = f"nmap -p {ports} {target}"
                    result = self.ejecutar_comando(cmd, timeout=60)

                    if result["success"]:
                        return [TextContent(
                            type="text",
                            text=f"Resultado de nmap:\n\n{result['stdout']}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                elif name == "ping":
                    host = arguments["host"]
                    count = arguments.get("count", 4)
                    cmd = f"ping -c {count} {host}"
                    result = self.ejecutar_comando(cmd)

                    if result["success"]:
                        return [TextContent(
                            type="text",
                            text=f"Resultado de ping:\n\n{result['stdout']}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                elif name == "whois":
                    domain = arguments["domain"]
                    cmd = f"whois {domain}"
                    result = self.ejecutar_comando(cmd)

                    if result["success"]:
                        return [TextContent(
                            type="text",
                            text=f"Información WHOIS:\n\n{result['stdout']}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                elif name == "dig":
                    domain = arguments["domain"]
                    record_type = arguments.get("record_type", "A")
                    cmd = f"dig {domain} {record_type} +short"
                    result = self.ejecutar_comando(cmd)

                    if result["success"]:
                        return [TextContent(
                            type="text",
                            text=f"Registros DNS ({record_type}):\n\n{result['stdout']}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                # Herramientas de sistema
                elif name == "file_read":
                    path = arguments["path"]
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                        return [TextContent(
                            type="text",
                            text=f"Contenido de {path}:\n\n{content}"
                        )]
                    except Exception as e:
                        return [TextContent(
                            type="text",
                            text=f"Error leyendo archivo: {e}"
                        )]

                elif name == "file_write":
                    path = arguments["path"]
                    content = arguments["content"]
                    try:
                        with open(path, 'w') as f:
                            f.write(content)
                        return [TextContent(
                            type="text",
                            text=f"✅ Archivo escrito: {path}"
                        )]
                    except Exception as e:
                        return [TextContent(
                            type="text",
                            text=f"Error escribiendo archivo: {e}"
                        )]

                elif name == "list_dir":
                    path = arguments.get("path", ".")
                    cmd = f"ls -lah {path}"
                    result = self.ejecutar_comando(cmd)

                    if result["success"]:
                        return [TextContent(
                            type="text",
                            text=f"Contenido de {path}:\n\n{result['stdout']}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                elif name == "system_info":
                    info = []

                    # Hostname
                    hostname = self.ejecutar_comando("hostname")
                    info.append(f"Hostname: {hostname['stdout'].strip()}")

                    # OS
                    os_info = self.ejecutar_comando("cat /etc/os-release | grep PRETTY_NAME")
                    info.append(f"OS: {os_info['stdout'].strip()}")

                    # Kernel
                    kernel = self.ejecutar_comando("uname -r")
                    info.append(f"Kernel: {kernel['stdout'].strip()}")

                    # Uptime
                    uptime = self.ejecutar_comando("uptime -p")
                    info.append(f"Uptime: {uptime['stdout'].strip()}")

                    # CPU
                    cpu = self.ejecutar_comando("lscpu | grep 'Model name'")
                    info.append(f"CPU: {cpu['stdout'].strip()}")

                    # Memoria
                    mem = self.ejecutar_comando("free -h | grep Mem")
                    info.append(f"Memoria: {mem['stdout'].strip()}")

                    return [TextContent(
                        type="text",
                        text="Información del sistema:\n\n" + "\n".join(info)
                    )]

                elif name == "execute_command":
                    command = arguments["command"]
                    result = self.ejecutar_comando(command)

                    if result["success"]:
                        output = result['stdout']
                        if result['stderr']:
                            output += f"\n\nStderr:\n{result['stderr']}"
                        return [TextContent(
                            type="text",
                            text=f"Resultado:\n\n{output}"
                        )]
                    else:
                        return [TextContent(
                            type="text",
                            text=f"Error: {result.get('error', result['stderr'])}"
                        )]

                else:
                    return [TextContent(
                        type="text",
                        text=f"❌ Herramienta desconocida: {name}"
                    )]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Error ejecutando {name}: {str(e)}"
                )]

    async def run(self):
        """Ejecutar el servidor"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )

if __name__ == "__main__":
    print("🔧 Servidor MCP Kali Tools iniciando...", flush=True)
    server = KaliMCPServer()
    asyncio.run(server.run())
