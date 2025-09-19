import re
from collections import defaultdict

# Règles pour détecter des motifs suspects dans les logs
LOG_RULES = [
    (r"Failed password", "Tentative de connexion échouée"),
    (r"Port scan detected", "Scan de port détecté"),
    (r"SQL injection", "Tentative d'injection SQL"),
    (r"Directory traversal", "Tentative de traversée de répertoire")
]

def analyze_log_file(log_file):
    """Analyse un fichier de logs à la recherche d'anomalies."""
    alerts = defaultdict(list)
    with open(log_file, "r") as f:
        for line in f:
            for pattern, description in LOG_RULES:
                if re.search(pattern, line, re.IGNORECASE):
                    alerts[description].append(line.strip())
    return alerts

def run(target, **kwargs):
    """Analyse les logs pour détecter des activités suspectes."""
    alerts = analyze_log_file(target)
    results = {
        "log_file": target,
        "alerts": []
    }

    for description, lines in alerts.items():
        results["alerts"].append({
            "type": description,
            "occurrences": len(lines),
            "examples": lines[:3]  # Limiter à 3 exemples
        })

    return results
