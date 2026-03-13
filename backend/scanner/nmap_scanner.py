"""
nmap_scanner.py — Person A
Runs Nmap on a target IP range and parses results into asset dicts
that match exactly what the scorer and graph engine expect.
"""

import os
import nmap
import json
from pathlib import Path
from datetime import datetime, timezone

NMAP_PATH = os.getenv("NMAP_PATH", "nmap")

# ── Seed data path ─────────────────────────────────────────────────────────────
SEED_FILE = Path(__file__).parent.parent / "data" / "seed_assets.json"


# ── Software name normaliser ───────────────────────────────────────────────────
NMAP_TO_CPE_NAME = {
    "Apache httpd":   "Apache",
    "nginx":          "nginx",
    "OpenSSH":        "OpenSSH",
    "PostgreSQL DB":  "PostgreSQL",
    "MySQL":          "MySQL",
    "MariaDB":        "MariaDB",
    "MongoDB":        "MongoDB",
    "Redis":          "Redis",
    "Apache Tomcat":  "Tomcat",
    "Microsoft IIS":  "IIS",
    "vsftpd":         "vsftpd",
    "ProFTPD":        "ProFTPD",
    "Samba smbd":     "Samba",
    "Elasticsearch":  "Elasticsearch",
    "Node.js":        "Node.js",
    "PHP":            "PHP",
}


# ── Asset type classifier ──────────────────────────────────────────────────────

def classify_asset(open_ports: list) -> int:
    """Return a criticality score based on open ports.

    Criticality scale (matches risk_engine.py CRITICALITY_WEIGHTS):
        1 = dev/test machine
        2 = internal tooling
        3 = customer-facing service
        4 = production server
        5 = crown jewel (DB, auth, payment)
    """
    port_set = set(int(p) for p in open_ports)

    if port_set & {5432, 3306, 1433, 27017, 6379}:
        return 5

    if port_set & {443}:
        return 3

    if port_set & {80, 8080, 8443}:
        return 2

    if port_set & {22}:
        return 1

    return 1


# ── Software list builder ──────────────────────────────────────────────────────

def build_software_list(tcp_data: dict) -> list:
    """
    Converts Nmap TCP port data into the software_list format
    that cve_fetcher.get_cves_for_asset() expects.

    Returns:
        list of {"name": str, "version": str} dicts
    """
    software = []
    seen = set()

    for port, info in tcp_data.items():
        if info.get("state") != "open":
            continue

        product = info.get("product", "").strip()
        version = info.get("version", "").strip()

        if not product or not version:
            continue

        name = NMAP_TO_CPE_NAME.get(product, product)
        key  = f"{name}:{version}"

        if key not in seen:
            seen.add(key)
            software.append({"name": name, "version": version})

    return software


# ── Single host parser ─────────────────────────────────────────────────────────

def parse_host(scanner: nmap.PortScanner, host: str) -> dict:
    """
    Parses a single scanned host into an asset dict.

    FIXES applied:
    - "ip_address" key (not "ip") to match AssetModel and upsert_asset()
    """
    host_data  = scanner[host]
    tcp_data   = host_data.get("tcp", {})

    open_ports = [
        int(port)
        for port, info in tcp_data.items()
        if info.get("state") == "open"
    ]

    hostnames = host_data.get("hostnames", [])
    hostname  = hostnames[0].get("name", host) if hostnames else host
    if not hostname:
        hostname = host

    os_matches = host_data.get("osmatch", [])
    os_name    = os_matches[0].get("name", "Unknown") if os_matches else "Unknown"

    software_list = build_software_list(tcp_data)
    criticality  = classify_asset(open_ports)

    # Any asset with common externally-exposed ports is considered internet-exposed.
    internet_exposed = bool(set(open_ports) & {22, 80, 443, 3389, 21, 23, 25, 110, 143, 445})

    return {
        "ip_address":      host,
        "hostname":        hostname,
        "os":              os_name,
        "open_ports":      open_ports,
        "software_list":   software_list,
        "criticality":     criticality,
        "internet_exposed": internet_exposed,
        "last_scanned":    datetime.now(timezone.utc),
        "risk_score":      None,
        "severity_label":  None,
        "last_scored":     None,
    }


# ── Main scan function ─────────────────────────────────────────────────────────

def scan_network(ip_range: str, ports: str = "1-1024") -> list:
    """
    Runs Nmap on the given IP range and returns a list of asset dicts.
    """
    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    print(f"[nmap_scanner] Scanning {ip_range} ports {ports}...")

    try:
        scanner.scan(
            hosts     = ip_range,
            ports     = ports,
            arguments = "-sV -O --open --host-timeout 30s"
        )
    except nmap.PortScannerError as e:
        print(f"[nmap_scanner] Nmap error: {e}")
        return []
    except Exception as e:
        print(f"[nmap_scanner] Unexpected scan error: {e}")
        return []

    assets = []
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            asset = parse_host(scanner, host)
            assets.append(asset)
            print(f"[nmap_scanner] Found {host} — {len(asset['open_ports'])} open ports")

    print(f"[nmap_scanner] Scan complete — {len(assets)} assets found")
    return assets


# ── Seed data loader ───────────────────────────────────────────────────────────

def load_seed_assets() -> list:
    """
    Loads demo assets from seed_assets.json for hackathon presentation.
    """
    if not SEED_FILE.exists():
        print(f"[nmap_scanner] Seed file not found at {SEED_FILE}")
        return []

    try:
        with open(SEED_FILE, "r") as f:
            assets = json.load(f)
        print(f"[nmap_scanner] Loaded {len(assets)} seed assets")
        return assets
    except (json.JSONDecodeError, IOError) as e:
        print(f"[nmap_scanner] Failed to load seed assets: {e}")
        return []