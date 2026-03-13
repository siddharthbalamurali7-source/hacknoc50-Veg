"""
nmap_scanner.py — Person A
Runs Nmap on a target IP range and parses results into asset dicts
that match exactly what the scorer and graph engine expect.
"""

import nmap
import json
from pathlib import Path
from datetime import datetime

# ── Seed data path ─────────────────────────────────────────────────────────────
SEED_FILE = Path(__file__).parent.parent / "data" / "seed_assets.json"


# ── Software name normaliser ───────────────────────────────────────────────────
# Maps Nmap product strings to the names CPE_MAP in cve_fetcher.py understands.
# If Nmap returns "OpenSSH", cve_fetcher already knows how to look that up.
NMAP_TO_CPE_NAME = {
    "Apache httpd":        "Apache",
    "nginx":               "nginx",
    "OpenSSH":             "OpenSSH",
    "PostgreSQL DB":       "PostgreSQL",
    "MySQL":               "MySQL",
    "MariaDB":             "MariaDB",
    "MongoDB":             "MongoDB",
    "Redis":               "Redis",
    "Apache Tomcat":       "Tomcat",
    "Microsoft IIS":       "IIS",
    "vsftpd":              "vsftpd",
    "ProFTPD":             "ProFTPD",
    "Samba smbd":          "Samba",
    "Elasticsearch":       "Elasticsearch",
    "Node.js":             "Node.js",
    "PHP":                 "PHP",
}


# ── Asset type classifier ──────────────────────────────────────────────────────
# Assigns a criticality level (1-5) based on what ports are open.
# These match the CRITICALITY_WEIGHTS in risk_engine.py exactly.

def classify_asset(open_ports: list) -> tuple:
    """
    Returns (asset_type: str, criticality: int) based on open ports.

    Criticality scale (matches risk_engine.py CRITICALITY_WEIGHTS):
        1 = dev/test machine
        2 = internal tooling
        3 = customer-facing service
        4 = production server
        5 = crown jewel (DB, auth, payment)
    """
    port_set = set(int(p) for p in open_ports)

    # crown jewels — databases and auth servers
    if port_set & {5432, 3306, 1433, 27017, 6379}:
        return "database", 5

    # production web servers
    if port_set & {443}:
        return "web_server", 3

    # internal services
    if port_set & {80, 8080, 8443}:
        return "web_server", 2

    # SSH-only machines — likely dev or internal
    if port_set & {22}:
        return "internal", 1

    return "unknown", 1


# ── Software list builder ──────────────────────────────────────────────────────

def build_software_list(tcp_data: dict) -> list:
    """
    Converts Nmap TCP port data into the software_list format
    that cve_fetcher.get_cves_for_asset() expects.

    Args:
        tcp_data: dict of {port: {name, product, version, state}} from Nmap

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

        # normalise Nmap product name to CPE-friendly name
        name = NMAP_TO_CPE_NAME.get(product, product)

        # deduplicate — same software might appear on multiple ports
        key = f"{name}:{version}"
        if key not in seen:
            seen.add(key)
            software.append({"name": name, "version": version})

    return software


# ── Single host parser ─────────────────────────────────────────────────────────

def parse_host(scanner: nmap.PortScanner, host: str) -> dict:
    """
    Parses a single scanned host into an asset dict.
    This dict maps directly to AssetModel fields in models.py.

    Returns:
        dict with all fields the scorer, graph engine, and hardening module need
    """
    host_data = scanner[host]

    # open TCP ports only
    tcp_data   = host_data.get("tcp", {})
    open_ports = [
        int(port)
        for port, info in tcp_data.items()
        if info.get("state") == "open"
    ]

    # hostname — use first available or fall back to IP
    hostnames  = host_data.get("hostnames", [])
    hostname   = hostnames[0].get("name", host) if hostnames else host
    if not hostname:
        hostname = host

    # OS detection
    os_matches = host_data.get("osmatch", [])
    os_name    = os_matches[0].get("name", "Unknown") if os_matches else "Unknown"

    # software list for CVE lookup
    software_list = build_software_list(tcp_data)

    # classify asset type and criticality
    asset_type, criticality = classify_asset(open_ports)

    return {
        "ip_address":    host,
        "hostname":      hostname,
        "os":            os_name,
        "open_ports":    open_ports,
        "software_list": software_list,
        "asset_type":    asset_type,
        "criticality":   criticality,   # int 1-5, matches risk_engine.py
        "last_scanned":  datetime.now().isoformat(),
        # these are set by the scorer after scoring — initialise to None
        "risk_score":    None,
        "severity_label": None,
        "last_scored":   None,
    }


# ── Main scan function ─────────────────────────────────────────────────────────

def scan_network(ip_range: str, ports: str = "1-1024") -> list:
    """
    Runs Nmap on the given IP range and returns a list of asset dicts.

    Args:
        ip_range: CIDR range or single IP e.g. "192.168.1.0/24" or "192.168.1.1"
        ports:    port range to scan e.g. "1-1024" or "22,80,443,3306,5432"

    Returns:
        list of asset dicts, one per live host found
    """
    scanner = nmap.PortScanner()

    print(f"[nmap_scanner] Scanning {ip_range} ports {ports}...")

    try:
        # -sV = version detection, -O = OS detection, --open = open ports only
        scanner.scan(
            hosts    = ip_range,
            ports    = ports,
            arguments= "-sV -O --open --host-timeout 30s"
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
    Used when a real network scan is not available or too slow.

    Returns:
        list of asset dicts in the same format as scan_network()
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