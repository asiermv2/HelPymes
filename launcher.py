import subprocess
import xmltodict

target = "10.6.4.73"
result = subprocess.run(["nmap", "-sV", "-oX", "-", target],
                        capture_output=True, text=True, check=True)

parsed = xmltodict.parse(result.stdout)
ports_info = []

host = parsed["nmaprun"]["host"]
if "ports" in host and "port" in host["ports"]:
    host_ports = host["ports"]["port"]
    if not isinstance(host_ports, list):
        host_ports = [host_ports]
    for port in host_ports:
        ports_info.append({
            "port": int(port["@portid"]),
            "state": port["state"]["@state"],
            "service": port["service"]["@name"],
            "version": port["service"].get("@product", "unknown")
        })

for p in ports_info:
    print(p)
