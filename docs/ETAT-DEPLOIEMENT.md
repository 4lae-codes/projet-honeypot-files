# État du déploiement (Alae)

Mis à jour : 2026-11-28 | IP de la VM honeypot : **172.20.10.4** (hotspot iPhone : l'IP peut changer, voir CHANGELOG)

| Machine | IP |
|---|---|
| PC hôte (Alae) | 172.20.10.2 |
| Kali (Lina) | 172.20.10.5 |
| VM honeypot | 172.20.10.4 |

## Services exposés (cibles pour Lina)
| Port | Service | Honeypot |
|---|---|---|
| 22 (redirigé vers 2222) | SSH | Cowrie |
| 23 (redirigé vers 2223) | Telnet | Cowrie |
| 21 | FTP | OpenCanary |
| 80 | HTTP (faux portail NAS) | OpenCanary |
| 3306 | MySQL | OpenCanary |
| 22022 | SSH d'administration | Réel, filtré (IP de l'admin uniquement) : NE PAS ATTAQUER |

SMB non déployé (limite à citer dans le rapport).

## Où trouver quoi
- logs/raw/ : logs Cowrie (cowrie.json*) et OpenCanary (opencanary.log) pour Ghita
- logs/samples/ : échantillons et fichier capturé (T1105)
- config/ : configurations, services systemd et leurs drop-ins, règles UFW/NAT, sysctl, auditd, logrotate
- scripts/ : ufw-lab.sh puis nat-redirect.sh (dans cet ordre)
- preuves/ : sorties de commandes (durcissement, tests) pour Aya ; Nmap de Lina
- CHANGELOG.md : changements et impacts

## Remise en route si l'IP change
sudo ~/ufw-lab.sh IP_KALI IP_PC puis sudo iptables -t nat -F PREROUTING puis sudo ~/nat-redirect.sh
