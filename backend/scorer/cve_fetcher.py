import os
import json
import time
import requests
from datetime import datetime, timedelta
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE   = Path(__file__).parent.parent / "data" / "cve_cache.json"
CACHE_TTL_HOURS = 6   # how long before a cached result is considered stale


# ── CPE mapping ────────────────────────────────────────────────────────────────
# Maps the software names Nmap returns to the correct NVD vendor/product strings.
# CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
CPE_MAP = {
    "Apache":      ("apache",      "http_server"),
    "nginx":       ("nginx",       "nginx"),
    "Nginx":       ("nginx",       "nginx"),
    "OpenSSH":     ("openbsd",     "openssh"),
    "SSH":         ("openbsd",     "openssh"),
    "PostgreSQL":  ("postgresql",  "postgresql"),
    "MySQL":       ("mysql",       "mysql"),
    "MariaDB":     ("mariadb",     "mariadb"),
    "MongoDB":     ("mongodb",     "mongodb"),
    "Redis":       ("redis",       "redis"),
    "Tomcat":      ("apache",      "tomcat"),
    "IIS":         ("microsoft",   "internet_information_services"),
    "OpenSSL":     ("openssl",     "openssl"),
    "PHP":         ("php",         "php"),
    "Python":      ("python",      "python"),
    "Node.js":     ("nodejs",      "node.js"),
    "Ubuntu":      ("canonical",   "ubuntu_linux"),
    "Debian":      ("debian",      "debian_linux"),
    "CentOS":      ("centos",      "centos"),
    "Windows":     ("microsoft",   "windows_server"),
    "vsftpd":      ("vsftpd_project", "vsftpd"),
    "ProFTPD":     ("proftpd",     "proftpd"),
    "Samba":       ("samba",       "samba"),
    "Elasticsearch": ("elastic",   "elasticsearch"),
}


# ── Cache helpers ──────────────────────────────────────────────────────────────

def load_cache() -> dict:
    """Load the local CVE cache from disk. Returns empty dict if missing or corrupt."""
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        # cache file is corrupted — start fresh
        return {}


def save_cache(cache: dict):
    """Save the CVE cache to disk. Creates the data/ directory if needed."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2, default=str)
    except IOError as e:
        print(f"[cve_fetcher] Warning: could not save cache — {e}")


def is_cache_fresh(entry: dict) -> bool:
    """Check if a cache entry is still within the TTL window."""
    try:
        cached_at = datetime.fromisoformat(entry["cached_at"])
        return datetime.now() - cached_at < timedelta(hours=CACHE_TTL_HOURS)
    except (KeyError, ValueError):
        return False


# ── CPE builder ────────────────────────────────────────────────────────────────

def build_cpe(software: str, version: str) -> str:
    """
    Convert a software name and version into a CPE 2.3 string.
    Falls back to lowercased software name if not in the map.

    Example:
        build_cpe("Apache", "2.4.49")
        → "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    """
    vendor, product = CPE_MAP.get(
        software,
        (software.lower().replace(" ", "_"),
         software.lower().replace(" ", "_"))
    )
    clean_version = str(version).strip() if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"


# ── CVE parser ─────────────────────────────────────────────────────────────────

def parse_cve(raw: dict) -> dict:
    """
    Strip a raw NVD CVE record down to just what the scorer needs.

    Tries CVSS v3.1 first, falls back to v3.0, then v2.0.
    Defaults to 5.0 if no score is available.
    """
    cve = raw.get("cve", {})

    # ── CVSS score ─────────────────────────────────────────────────────────────
    metrics = cve.get("metrics", {})
    cvss    = 5.0  # default to medium if unknown

    if "cvssMetricV31" in metrics:
        try:
            cvss = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        except (KeyError, IndexError, ValueError):
            pass
    elif "cvssMetricV30" in metrics:
        try:
            cvss = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
        except (KeyError, IndexError, ValueError):
            pass
    elif "cvssMetricV2" in metrics:
        try:
            cvss = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
        except (KeyError, IndexError, ValueError):
            pass

    # ── Exploit check ──────────────────────────────────────────────────────────
    # NVD tags references with "Exploit" when working exploit code is publicly available
    references  = cve.get("references", [])
    has_exploit = any(
        "Exploit" in ref.get("tags", [])
        for ref in references
    )

    # ── Description ───────────────────────────────────────────────────────────
    descriptions = cve.get("descriptions", [])
    description  = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available."
    )

    # ── Severity label ────────────────────────────────────────────────────────
    if cvss >= 9.0:   severity = "CRITICAL"
    elif cvss >= 7.0: severity = "HIGH"
    elif cvss >= 4.0: severity = "MEDIUM"
    else:             severity = "LOW"

    return {
        "cve_id":      cve.get("id", "UNKNOWN"),
        "cvss":        cvss,
        "has_exploit": has_exploit,
        "description": description[:500],   # truncate for DB storage
        "severity":    severity,
    }


# ── NVD API caller ─────────────────────────────────────────────────────────────

def fetch_from_nvd(cpe: str) -> list:
    """
    Call the NVD API for a specific CPE string and return parsed CVEs.
    Handles rate limiting — without an API key NVD allows 1 req/6 seconds.

    Returns empty list on any error so the scorer degrades gracefully.
    """
    params = {
        "cpeName":        cpe,
        "resultsPerPage": 100,
    }

    if NVD_API_KEY:
        params["apiKey"] = NVD_API_KEY
    else:
        # rate limit without API key — sleep to avoid 403s
        print(f"[cve_fetcher] No API key — waiting 6s before NVD request")
        time.sleep(6)

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=15,
            headers={"User-Agent": "CyberSentry/1.0"}
        )

        if response.status_code == 403:
            print(f"[cve_fetcher] 403 Forbidden — check your NVD_API_KEY in .env")
            return []

        if response.status_code == 404:
            # no CVEs found for this CPE — that's fine, just return empty
            return []

        response.raise_for_status()
        raw_cves = response.json().get("vulnerabilities", [])
        return [parse_cve(c) for c in raw_cves]

    except requests.exceptions.Timeout:
        print(f"[cve_fetcher] Timeout fetching CVEs for {cpe}")
        return []
    except requests.exceptions.ConnectionError:
        print(f"[cve_fetcher] Connection error — is the internet available?")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[cve_fetcher] Request error for {cpe}: {e}")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[cve_fetcher] Failed to parse NVD response for {cpe}: {e}")
        return []


# ── Public functions ───────────────────────────────────────────────────────────

def get_cves_for_software(software: str, version: str) -> list:
    """
    Main function called by scorer_router.py for each piece of software on an asset.

    Checks the local cache first. Only calls the NVD API if the cache
    entry is missing or older than CACHE_TTL_HOURS.

    Args:
        software: software name as returned by Nmap (e.g. "Apache", "OpenSSH")
        version:  software version string (e.g. "2.4.49", "7.4")

    Returns:
        list of CVE dicts, each with: cve_id, cvss, has_exploit, description, severity
        Returns empty list if software/version is missing or on any error.
    """
    if not software or not version:
        return []

    # normalise inputs
    software = software.strip()
    version  = str(version).strip()

    cache_key = f"{software}:{version}"
    cache     = load_cache()

    # return cached result if fresh
    if cache_key in cache and is_cache_fresh(cache[cache_key]):
        print(f"[cve_fetcher] Cache hit for {cache_key}")
        return cache[cache_key]["cves"]

    print(f"[cve_fetcher] Fetching CVEs for {cache_key} from NVD...")
    cpe  = build_cpe(software, version)
    cves = fetch_from_nvd(cpe)

    # save to cache regardless of whether we found CVEs
    # (caching empty results avoids hammering the API for known-clean software)
    cache[cache_key] = {
        "cves":      cves,
        "cached_at": datetime.now().isoformat(),
        "cpe":       cpe,
    }
    save_cache(cache)

    print(f"[cve_fetcher] Found {len(cves)} CVEs for {cache_key}")
    return cves


def get_cves_for_asset(asset) -> list:
    """
    Convenience function — fetch and deduplicate all CVEs for an entire asset.

    Accepts either an AssetModel ORM object or a plain dict.
    Looks up CVEs for every software entry in asset.software_list.

    Returns a deduplicated list of CVE dicts sorted by CVSS score descending.
    """
    # handle both ORM objects and plain dicts
    if hasattr(asset, "software_list"):
        software_list = asset.software_list or []
    else:
        software_list = asset.get("software_list", [])

    all_cves = []
    for software in software_list:
        name    = software.get("name")
        version = software.get("version")
        if name and version:
            cves = get_cves_for_software(name, version)
            all_cves.extend(cves)

    # deduplicate by CVE ID — keep the entry with the highest CVSS if duplicated
    seen     = {}
    for cve in all_cves:
        cve_id = cve["cve_id"]
        if cve_id not in seen or cve["cvss"] > seen[cve_id]["cvss"]:
            seen[cve_id] = cve

    return sorted(seen.values(), key=lambda x: x["cvss"], reverse=True)


def fetch_recent_cves(hours_back: int = 6) -> list:
    """
    Fetch all CVEs published or modified in the last N hours.
    Called by the scheduler for continuous threat intelligence updates.

    Returns list of parsed CVE dicts.
    """
    since = datetime.now() - timedelta(hours=hours_back)
    now   = datetime.now()

    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage":   2000,
    }
    if NVD_API_KEY:
        params["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=30,
            headers={"User-Agent": "CyberSentry/1.0"}
        )
        response.raise_for_status()
        raw_cves = response.json().get("vulnerabilities", [])
        print(f"[cve_fetcher] Fetched {len(raw_cves)} recent CVEs from NVD")
        return [parse_cve(c) for c in raw_cves]

    except requests.exceptions.RequestException as e:
        print(f"[cve_fetcher] Failed to fetch recent CVEs: {e}")
        return []


def match_cves_to_assets(new_cves: list, assets: list) -> dict:
    """
    Given a list of new CVEs and a list of assets, find which assets
    are affected by the new CVEs.

    Used by the scheduler after fetch_recent_cves() to know which
    assets need their scores recalculated.

    Returns:
        dict mapping asset_id -> list of matching new CVEs
    """
    affected = {}

    for asset in assets:
        # get asset id — handle both ORM objects and dicts
        asset_id      = getattr(asset, "id", None) or asset.get("id")
        software_list = getattr(asset, "software_list", None) or asset.get("software_list", [])

        if not asset_id or not software_list:
            continue

        # build a set of CPE strings for this asset's software
        asset_cpes = set()
        for sw in software_list:
            name    = sw.get("name")
            version = sw.get("version")
            if name and version:
                asset_cpes.add(build_cpe(name, version))

        # check each new CVE against this asset's software
        matching = []
        for cve in new_cves:
            # NVD CVEs contain affected CPE strings — check for overlap
            cve_raw  = cve.get("_raw_configurations", [])
            cve_cpes = set(cve_raw)

            if asset_cpes & cve_cpes:
                matching.append(cve)

        if matching:
            affected[asset_id] = matching

    return affected


def clear_cache():
    """
    Wipe the local CVE cache. Useful when you want to force fresh NVD lookups.
    """
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
        print("[cve_fetcher] Cache cleared")
    else:
        print("[cve_fetcher] No cache file found")