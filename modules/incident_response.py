import subprocess
import json
import smtplib
from email.mime.text import MIMEText

def block_ip(ip):
    """Bloque une IP avec iptables (Linux)."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return True, f"IP {ip} bloquée avec succès."
    except subprocess.CalledProcessError as e:
        return False, f"Échec du blocage de {ip} : {e}"

def send_alert(email_config, subject, message):
    """Envoie une alerte par e-mail."""
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = email_config["from"]
        msg['To'] = email_config["to"]

        with smtplib.SMTP(email_config["server"], email_config["port"]) as server:
            server.starttls()
            server.login(email_config["user"], email_config["password"])
            server.send_message(msg)
        return True, "Alerte envoyée."
    except Exception as e:
        return False, f"Échec de l'envoi de l'e-mail : {e}"

def run(target, **kwargs):
    """Répond à un incident (blocage d'IP, notification)."""
    config = kwargs.get("config", {})
    email_config = config.get("email_alerts", {})
    results = {
        "target": target,
        "actions": []
    }

    # Exemple : Bloquer une IP et envoyer une alerte
    if "ip_to_block" in kwargs:
        ip = kwargs["ip_to_block"]
        success, message = block_ip(ip)
        results["actions"].append({
            "action": "block_ip",
            "target": ip,
            "status": "Success" if success else "Failed",
            "message": message
        })

        if success and email_config:
            subject = f"Alerte : IP bloquée - {ip}"
            email_message = f"L'IP {ip} a été bloquée en raison d'une activité suspecte."
            send_alert(email_config, subject, email_message)

    return results
