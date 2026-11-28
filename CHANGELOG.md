## 2026-11-28
- Réseau : carte unique en accès par pont sur hotspot iPhone ; IP VM 172.20.10.4 (peut changer).
- SSH admin : port 22022, clé ed25519, mot de passe désactivé, root interdit, AllowUsers alae, limité à l'IP du PC.
- UFW : entrant et sortant refusés par défaut ; sortant autorisé : DNS, DHCP, NTP, 80, 443.
- Noyau : sysctl durci ; isolation systemd de Cowrie et OpenCanary ; auditd ; logrotate OpenCanary ; mises à jour automatiques.
- Impact : l'IP du hotspot peut changer, il faut alors relancer ufw-lab.sh puis nat-redirect.sh. Le trafic sortant est limité, donc pas de téléchargement par un attaquant depuis le honeypot.
# CHANGELOG


