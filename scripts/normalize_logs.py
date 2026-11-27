#!/usr/bin/env python3
"""
normalize_logs.py

Normalise les logs du honeypot (Cowrie + OpenCanary) vers le format commun
defini par l'equipe :
    timestamp, ip_source, service, user, password, commande

Usage :
    python3 normalize_logs.py --cowrie cowrie.json --opencanary opencanary.log --csv out.csv --json out.json
    python3 normalize_logs.py --cowrie cowrie.json --csv out.csv
    python3 normalize_logs.py --opencanary opencanary.log --json out.json

On peut fournir --cowrie, --opencanary, ou les deux a la fois (chacun peut
etre repete plusieurs fois, utile pour les logs cowrie.json.YYYY-MM-DD
tournes quotidiennement) ; les enregistrements de toutes les sources sont
fusionnes et tries par timestamp.

--- Format Cowrie (SSH/Telnet) ---
Chaque ligne est un objet JSON independant (JSON Lines) avec un champ
"protocol" direct ("ssh" ou "telnet") et un eventid parmi :
    - cowrie.login.failed   -> tentative de connexion echouee
    - cowrie.login.success  -> connexion reussie
    - cowrie.command.input  -> commande tapee dans le faux shell

--- Format OpenCanary (FTP/HTTP/HTTPS/MySQL/SMB) ---
Chaque ligne est un objet JSON independant avec un "logtype" :
    - 1001 -> message de demarrage du service, ignore (pas de user/password)
    - 2000 -> tentative FTP (logdata.USERNAME / logdata.PASSWORD)
    - 3001 -> tentative HTTP (logdata.USERNAME / logdata.PASSWORD)
    - autres logtypes -> traites au mieux si USERNAME/PASSWORD presents,
      sinon ignores (ce sont des logs de service, pas des tentatives de connexion)
Le service est deduit du dst_port (21=ftp, 80=http, 443=https, 3306=mysql, 445=smb).
"""

import argparse
import csv
import json
import sys
from pathlib import Path


COWRIE_PORT_SERVICE_MAP = {
    22: "ssh",
    23: "telnet",
    2222: "ssh",
    2223: "telnet",
}

OPENCANARY_PORT_SERVICE_MAP = {
    21: "ftp",
    80: "http",
    443: "https",
    3306: "mysql",
    445: "smb",
}


def parse_cowrie(file_path: Path):
    """Parse un fichier cowrie (JSON Lines) -> liste de dicts au format commun."""
    records = []
    session_services = {}
    session_ips = {}
    session_users = {}

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] cowrie ({file_path.name}): ligne {line_number} ignoree (JSON invalide)", file=sys.stderr)
                continue

            eventid = event.get("eventid", "")
            timestamp = event.get("timestamp", "")
            session_id = event.get("session")
            src_ip = event.get("src_ip", "")
            dst_port = event.get("dst_port")

            # Service : priorite au champ "protocol" direct (format reel observe),
            # sinon on retombe sur le mapping de port, sinon la memoire de session.
            if "protocol" in event:
                service = event["protocol"]
                session_services[session_id] = service
            elif dst_port in COWRIE_PORT_SERVICE_MAP:
                service = COWRIE_PORT_SERVICE_MAP[dst_port]
                session_services[session_id] = service
            else:
                service = session_services.get(session_id, "unknown")

            if src_ip:
                session_ips[session_id] = src_ip
            ip_source = session_ips.get(session_id, src_ip)

            if eventid == "cowrie.session.connect":
                continue  # evenement technique, pas une ligne a exporter

            if eventid in ("cowrie.login.failed", "cowrie.login.success"):
                user = event.get("username", "")
                password = event.get("password", "")
                session_users[session_id] = user
                records.append({
                    "timestamp": timestamp,
                    "ip_source": ip_source,
                    "service": service,
                    "user": user,
                    "password": password,
                    "commande": "",
                })

            elif eventid == "cowrie.command.input":
                commande = event.get("input", "")
                user = session_users.get(session_id, "")
                records.append({
                    "timestamp": timestamp,
                    "ip_source": ip_source,
                    "service": service,
                    "user": user,
                    "password": "",
                    "commande": commande,
                })

            # Autres eventid (cowrie.session.closed, cowrie.client.version, etc.)
            # ignores volontairement : hors perimetre du format commun.

    return records


def parse_opencanary(file_path: Path):
    """Parse un fichier opencanary (JSON Lines) -> liste de dicts au format commun."""
    records = []

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] opencanary ({file_path.name}): ligne {line_number} ignoree (JSON invalide)", file=sys.stderr)
                continue

            logdata = event.get("logdata", {})
            username = logdata.get("USERNAME")
            password = logdata.get("PASSWORD")

            # logtype 1001 = message de demarrage du service, pas une tentative
            # d'attaque -> on l'ignore. On ignore aussi toute ligne sans
            # username/password (rien a normaliser dans le format commun).
            if username is None and password is None:
                continue

            dst_port = event.get("dst_port", -1)
            service = OPENCANARY_PORT_SERVICE_MAP.get(dst_port, "unknown")

            # src_host est l'IP source reelle de l'attaquant.
            ip_source = event.get("src_host", "")
            timestamp = event.get("utc_time", event.get("local_time", ""))

            records.append({
                "timestamp": timestamp,
                "ip_source": ip_source,
                "service": service,
                "user": username or "",
                "password": password or "",
                "commande": "",
            })

    return records


def write_csv(records, output_path: Path):
    fieldnames = ["timestamp", "ip_source", "service", "user", "password", "commande"]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    print(f"[OK] CSV ecrit : {output_path} ({len(records)} lignes)")


def write_json(records, output_path: Path):
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"[OK] JSON ecrit : {output_path} ({len(records)} lignes)")


def main():
    parser = argparse.ArgumentParser(
        description="Normalise les logs Cowrie et/ou OpenCanary vers le format commun de l'equipe."
    )
    parser.add_argument("--cowrie", type=Path, action="append", default=[],
                         help="Chemin vers un fichier cowrie.json (repetable pour les logs tournes)")
    parser.add_argument("--opencanary", type=Path, action="append", default=[],
                         help="Chemin vers un fichier opencanary.log (repetable)")
    parser.add_argument("--csv", type=Path, help="Chemin de sortie CSV")
    parser.add_argument("--json", type=Path, help="Chemin de sortie JSON")
    args = parser.parse_args()

    if not args.cowrie and not args.opencanary:
        print("[ERREUR] Precise au moins --cowrie ou --opencanary comme entree.", file=sys.stderr)
        sys.exit(1)

    if not args.csv and not args.json:
        print("[ERREUR] Precise au moins --csv ou --json comme sortie.", file=sys.stderr)
        sys.exit(1)

    records = []
    seen = set()  # pour dedupliquer si le fichier courant (cowrie.json) chevauche une rotation

    for cowrie_path in args.cowrie:
        if not cowrie_path.exists():
            print(f"[ERREUR] Fichier introuvable : {cowrie_path}", file=sys.stderr)
            sys.exit(1)
        cowrie_records = parse_cowrie(cowrie_path)
        print(f"[INFO] {len(cowrie_records)} enregistrements extraits de {cowrie_path}")
        for r in cowrie_records:
            key = (r["timestamp"], r["ip_source"], r["service"], r["user"], r["password"], r["commande"])
            if key not in seen:
                seen.add(key)
                records.append(r)

    for oc_path in args.opencanary:
        if not oc_path.exists():
            print(f"[ERREUR] Fichier introuvable : {oc_path}", file=sys.stderr)
            sys.exit(1)
        oc_records = parse_opencanary(oc_path)
        print(f"[INFO] {len(oc_records)} enregistrements extraits de {oc_path}")
        for r in oc_records:
            key = (r["timestamp"], r["ip_source"], r["service"], r["user"], r["password"], r["commande"])
            if key not in seen:
                seen.add(key)
                records.append(r)

    # Tri chronologique (les timestamps sont en ISO 8601 / format triable lexicalement)
    records.sort(key=lambda r: r["timestamp"])

    if not records:
        print("[WARN] Aucun enregistrement extrait au total.", file=sys.stderr)

    if args.csv:
        write_csv(records, args.csv)
    if args.json:
        write_json(records, args.json)


if __name__ == "__main__":
    main()
