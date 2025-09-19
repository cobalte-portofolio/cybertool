import requests
import json

# Base de données simplifiée de vulnérabilités (à remplacer par une API comme Vulners ou NVD)
VULN_DB = {
    "OpenSSH": {
        "versions": {"7.5": ["CVE-2018-15473"], "7.6": ["CVE-2019-6111"]},
    },
    "Apache": {
        "versions": {"2.4.29": ["CVE-2019-0211"]},
    }
}

def check_vulnerabilities(service, version):
    """Vérifie si une version de service est vulnérable."""
    vulnerabilities = []
    if service in VULN_DB:
        for vuln_version, cves in VULN_DB[service]["versions"].items():
            if version.startswith(vuln_version):
                vulnerabilities.extend(cves)
    return vulnerabilities

def run(target, **kwargs):
    """Analyse les vulnérabilités des services détectés."""
    scan_results = kwargs.get("scan_results", {})
    if not scan_results:
        from .network_scan import run as network_scan
        scan_results = network_scan(target, **kwargs)

    results = {
        "target": target,
        "vulnerabilities": []
    }

    for port_info in scan_results.get("open_ports", []):
        service = port_info["service"]
        version = port_info["version"]
        cves = check_vulnerabilities(service, version)
        if cves:
            results["vulnerabilities"].append({
                "port": port_info["port"],
                "service": service,
                "version": version,
                "cves": cves
            })

    return results
