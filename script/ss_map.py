#!/usr/bin/env python3
import subprocess
import json
import os
import time
import ipaddress
import re

MAP_SCRIPT = os.path.dirname(os.path.realpath(__file__)) + "/fail2ban_map.py"
JSON_FILE = os.path.dirname(os.path.realpath(__file__)) + "/../public/places.geojson"
DB_PATH = os.path.dirname(os.path.realpath(__file__)) + "/ss_ip.json"
# Ports considérés comme "entrant" (services sur le serveur)
INCOMING_PORTS = {22, 80, 443}
TTL_SECONDS = 48 * 3600  # 48h

def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # si c'est bizarre, on jette

def get_banned_ips():
    banned = set()
    try:
        out = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except Exception:
        return banned

    # Récupérer la liste des jails
    m = re.search(r"Jail list:\s*(.*)", out)
    if not m:
        return banned
    jails = [j.strip() for j in m.group(1).split(",") if j.strip()]

    for jail in jails:
        try:
            out_j = subprocess.run(
                ["fail2ban-client", "status", jail],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        except Exception:
            continue

        m2 = re.search(r"Banned IP list:\s*(.*)", out_j)
        if not m2:
            continue
        ips_line = m2.group(1).strip()
        if ips_line:
            for ip in ips_line.split():
                banned.add(ip.strip())
    return banned

def load_db():
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_db(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f)
    os.replace(tmp, DB_PATH)

def parse_ss_line(line):
    # On s'attend à un truc du genre :
    # tcp   ESTAB 0 0 192.168.1.107:22 1.2.3.4:54321 ...
    parts = line.split()
    if len(parts) < 5:
        return None

    state = parts[1]
    local = parts[4]
    peer = parts[5]

    # On ne s'intéresse qu'aux connexions établies
    if state not in ("ESTAB", "ESTABLISHED"):
        return None

    # Extraire IP/port (IPv4 ou IPv6)
    def split_host_port(addr):
        # exemple "1.2.3.4:22" ou "[::1]:22"
        if addr.startswith('['):  # IPv6 style [::1]:22
            host, port = addr.rsplit("]:", 1)
            host = host.lstrip("[")
        else:
            host, port = addr.rsplit(":", 1)
        return host, port

    try:
        local_ip, local_port = split_host_port(local)
        peer_ip, peer_port = split_host_port(peer)
    except ValueError:
        return None

    # On ne garde que les IP publiques côté peer
    if is_private_ip(peer_ip):
        return None

    try:
        lp = int(local_port)
    except ValueError:
        return None

    direction = "in" if lp in INCOMING_PORTS else "out"

    return {
        "local_ip": local_ip,
        "local_port": lp,
        "peer_ip": peer_ip,
        "peer_port": int(peer_port),
        "direction": direction,
    }

def get_current_connections():
    # Tu peux adapter les options ss si tu veux aussi l'UDP etc.
    proc = subprocess.run(
        ["ss", "-laputen"],
        capture_output=True,
        text=True,
        check=True,
    )

    lines = proc.stdout.splitlines()
    conns = []
    for line in lines[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        c = parse_ss_line(line)
        if c:
            subprocess.call(["/usr/bin/python3", MAP_SCRIPT, "addconnection", c["peer_ip"], c["direction"], str(c["local_port"])])
            conns.append(c)
            
    return conns

def main():
    now = time.time()
    db = load_db()
    print("Got seen ips...")
    banned_ips = get_banned_ips()
    print("Got banned ips...")
    
    db = {
        k: v for k, v in db.items()
        if v.get("ip") not in banned_ips
    }
    print("Removed banned ips from seen ips...")

    conns = get_current_connections()
    print("Got current connections")

    # Index existant par clé ip+direction
    # (tu peux affiner si tu veux distinguer par service)
    for c in conns:
        ip = c["peer_ip"]
        if ip in banned_ips:
            continue  # on ignore les IP déjà bannies
        direction = c["direction"]
        key = f"{ip}|{direction}"

        entry = db.get(key, {
            "ip": ip,
            "direction": direction,
            "port": c["local_port"] if direction == "in" else c["peer_port"],
            "first_seen": now,
            "last_seen": now,
        })
        entry["last_seen"] = now
        db[key] = entry

    # Purge des entrées trop vieilles
    cutoff = now - TTL_SECONDS
    db = {
        k: v for k, v in db.items()
        if v.get("last_seen", v.get("first_seen", now)) >= cutoff
    }

    save_db(db)

if __name__ == "__main__":
    print("Getting connections...")
    main()
