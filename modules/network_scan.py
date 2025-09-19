import nmap
import json

def run(target, **kwargs):
    """Effectue un scan de réseau avec Nmap."""
    config = kwargs.get("config", {})
    nm = nmap.PortScanner()
    ports = config.get("scan_ports", "1-1000")
    arguments = config.get("scan_arguments", "-sV -O")

    try:
        nm.scan(hosts=target, ports=ports, arguments=arguments)
        results = {
            "target": target,
            "scan_type": "nmap",
            "open_ports": [],
            "os_guess": nm[target].get("osmatch", [{}])[0].get("name", "Inconnu"),
            "hostnames": nm[target].hostnames()
        }

        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                service = nm[target][proto][port]
                results["open_ports"].append({
                    "port": port,
                    "protocol": proto,
                    "service": service["name"],
                    "version": service.get("version", "Inconnu"),
                    "product": service.get("product", "Inconnu")
                })

        return results
    except Exception as e:
        return {"error": f"Erreur lors du scan : {e}"}
