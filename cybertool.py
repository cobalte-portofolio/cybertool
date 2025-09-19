#!/usr/bin/env python3
"""
Outil de cybersécurité modulaire.
Utilisation : python3 cybertool.py [module] [options]
"""

import argparse
import json
import importlib
from datetime import datetime

# Charger la configuration
with open("config.json", "r") as f:
    CONFIG = json.load(f)

def load_module(module_name, target, **kwargs):
    """Charge et exécute un module."""
    try:
        module = importlib.import_module(f"modules.{module_name}")
        result = module.run(target, **kwargs)
        return result
    except ImportError:
        print(f"[!] Module '{module_name}' introuvable.")
    except Exception as e:
        print(f"[!] Erreur dans le module {module_name} : {e}")
    return None

def generate_report(data, report_type="json"):
    """Génère un rapport."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/report_{timestamp}.{report_type}"

    if report_type == "json":
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    elif report_type == "html":
        with open(filename, "w") as f:
            f.write(f"<h1>Rapport de sécurité - {timestamp}</h1><pre>{json.dumps(data, indent=4)}</pre>")
    else:
        print("[!] Format de rapport non supporté.")
        return

    print(f"[+] Rapport généré : {filename}")

def main():
    parser = argparse.ArgumentParser(description="Outil de cybersécurité modulaire.")
    parser.add_argument("module", choices=["scan", "vuln", "monitor", "logs", "response"], help="Module à exécuter.")
    parser.add_argument("target", help="Cible (IP, domaine, fichier de logs).")
    parser.add_argument("--report", choices=["json", "html"], default="json", help="Format du rapport.")
    parser.add_argument("--config", help="Fichier de configuration alternatif.")
    args = parser.parse_args()

    if args.config:
        global CONFIG
        with open(args.config, "r") as f:
            CONFIG = json.load(f)

    print(f"[*] Exécution du module '{args.module}' sur {args.target}...")
    result = load_module(args.module, args.target, config=CONFIG)

    if result:
        generate_report(result, args.report)

if __name__ == "__main__":
    main()
