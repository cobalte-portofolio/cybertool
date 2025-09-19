# cybertool
Outil de Cybersécurité Modulaire

# Comment Utiliser l'Outil ?
## 1. **Installer les dépendances** :   ```pip install python-nmap scapy requests   ```
## 2. **Exécuter un module** :
- Scan de réseau :     ```python3 cybertool.py scan 192.168.1.1 --report html     ```
- Analyse de vulnérabilités :     ```python3 cybertool.py vuln 192.168.1.1     ```
- Surveillance du trafic :     ```python3 cybertool.py monitor eth0     ```
- Analyse de logs :     ```python3 cybertool.py logs /var/log/auth.log     ```
- Réponse à un incident (blocage d'IP) :     ```python3 cybertool.py response "192.168.1.100" --ip_to_block 192.168.1.100     ```
