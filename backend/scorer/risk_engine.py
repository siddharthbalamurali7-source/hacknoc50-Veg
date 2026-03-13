from datetime import datetime, timezone

# ── Port weights ───────────────────────────────────────────────────────────────
# Each value represents how dangerous that port being open is.
# Higher = more dangerous. Unknown ports get a default weight of 4.
PORT_WEIGHTS = {
    23:    18,   # Telnet       — unencrypted remote shell, worst case
    512:   17,   # rexec        — legacy remote execution
    513:   17,   # rlogin       — legacy remote login
    22:    15,   # SSH          — direct shell access
    3389:  15,   # RDP          — direct Windows desktop access
    5900:  14,   # VNC          — remote desktop, often weakly protected
    1433:  13,   # MSSQL        — direct database access
    3306:  12,   # MySQL        — direct database access
    5432:  12,   # PostgreSQL   — direct database access
    27017: 12,   # MongoDB      — often left with no authentication
    6379:  11,   # Redis        — often left with no authentication
    8080:   6,   # HTTP alt     — common dev server, often misconfigured
    8443:   5,   # HTTPS alt    — alternative HTTPS port
    80:     3,   # HTTP         — low risk on its own
    443:    2,   # HTTPS        — encrypted, lowest risk
}

# ── Criticality weights ────────────────────────────────────────────────────────
# Manually set by the security team in the database.
# Reflects business importance, not just technical exposure.
CRITICALITY_WEIGHTS = {
    1:  5,    # dev/test machine         — low business impact if compromised
    2:  10,   # internal tooling         — moderate impact
    3:  15,   # customer-facing service  — notable impact
    4:  20,   # production server        — serious impact
    5:  25,   # crown jewel              — DB, auth server, payment system
}


# ── Individual factor functions ────────────────────────────────────────────────

def port_score(open_ports: list) -> float:
    """
    Sum the risk weight of every open port.
    Capped at 35 so ports alone cannot dominate the final score.

    Args:
        open_ports: list of integer port numbers found open on the asset

    Returns:
        float between 0 and 35
    """
    if not open_ports:
        return 0.0
    total = sum(PORT_WEIGHTS.get(int(port), 4) for port in open_ports)
    return min(float(total), 35.0)


def cve_score(cves: list) -> float:
    """
    Convert a list of CVE dicts into a score contribution.

    Base score: average CVSS scaled to 0-35 range.
    Exploit bonus: up to 5 extra points if any CVE has a public exploit.
    Capped at 40 — CVEs are intentionally the most impactful factor.

    Each CVE dict must have:
        cvss        (float)  — CVSS base score 0.0-10.0
        has_exploit (bool)   — whether a public exploit exists

    Returns:
        float between 0 and 40
    """
    if not cves:
        return 0.0

    avg_cvss = sum(float(c.get("cvss", 0)) for c in cves) / len(cves)
    base = (avg_cvss / 10.0) * 35.0

    # exploit bonus — extra weight if working exploit code is publicly available
    exploit_bonus = 0.0
    exploitable = [c for c in cves if c.get("has_exploit", False)]
    if exploitable:
        worst_exploit_cvss = max(float(c.get("cvss", 0)) for c in exploitable)
        exploit_bonus = (worst_exploit_cvss / 10.0) * 5.0

    return min(base + exploit_bonus, 40.0)


def criticality_score(criticality: int) -> float:
    """
    Convert criticality level (1-5) to a point contribution.
    Defaults to 10 (level 2) if criticality is missing or invalid.

    Returns:
        float between 5 and 25
    """
    try:
        level = int(criticality)
    except (TypeError, ValueError):
        level = 2
    return float(CRITICALITY_WEIGHTS.get(level, 10))



def patch_age_score(last_scanned) -> float:
    if last_scanned is None:
        return 20.0

    if isinstance(last_scanned, str):
        try:
            last_scanned = datetime.fromisoformat(last_scanned)
        except ValueError:
            return 20.0

    try:
        # use timezone-aware now() to match TIMESTAMPTZ from PostgreSQL
        now  = datetime.now(timezone.utc)
        # make last_scanned timezone-aware if it isn't already
        if last_scanned.tzinfo is None:
            last_scanned = last_scanned.replace(tzinfo=timezone.utc)
        days = (now - last_scanned).days
    except TypeError:
        return 20.0

    if days < 7:   return 0.0
    if days < 14:  return 3.0
    if days < 30:  return 6.0
    if days < 60:  return 10.0
    if days < 90:  return 15.0
    return 20.0


def score_to_label(score: float) -> str:
    """
    Convert a numeric score to a human-readable severity label.
    Used for UI colour coding and task priority assignment.
    """
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


# ── Main scoring function ──────────────────────────────────────────────────────

def calculate_risk(asset: dict, cves: list) -> dict:
    p = port_score(asset.get("open_ports", []))
    c = cve_score(cves)
    k = criticality_score(asset.get("criticality", 2))
    a = patch_age_score(asset.get("last_scanned"))   # ← now works

    raw   = p + c + k + a
    final = min(round(raw, 1), 100.0)

    sorted_cves = sorted(cves, key=lambda x: float(x.get("cvss", 0)), reverse=True)
    top_cves    = [cv["cve_id"] for cv in sorted_cves[:3]]

    return {
        "score":    final,
        "severity": score_to_label(final),
        "breakdown": {
            "ports":       round(p, 1),
            "cves":        round(c, 1),
            "criticality": round(k, 1),
            "patch_age":   round(a, 1),
        },
        "top_cves": top_cves,
    }

def simulate_fix(asset: dict, cves: list, fix: dict) -> dict:
    """
    Predict the score impact of applying a fix WITHOUT saving anything.
    Used by the Fix Impact Prediction feature.

    Args:
        asset: current asset dict
        cves:  current CVE list
        fix:   dict describing the fix:
            type         (str) — "patch_cve" or "close_port"
            cve_id       (str) — CVE to remove (if type is patch_cve)
            port         (int) — port to close (if type is close_port)

    Returns:
        dict with:
            old_score  (float)
            new_score  (float)
            delta      (float) — negative means improvement
            old_severity (str)
            new_severity (str)
    """
    old_result = calculate_risk(asset, cves)

    # apply the hypothetical fix to a copy — never mutate the originals
    fixed_asset = dict(asset)
    fixed_cves  = list(cves)

    if fix.get("type") == "close_port":
        port = fix.get("port")
        fixed_asset["open_ports"] = [
            p for p in (asset.get("open_ports") or []) if p != port
        ]

    elif fix.get("type") == "patch_cve":
        cve_id = fix.get("cve_id")
        fixed_cves = [c for c in cves if c.get("cve_id") != cve_id]

    new_result = calculate_risk(fixed_asset, fixed_cves)

    return {
        "old_score":    old_result["score"],
        "new_score":    new_result["score"],
        "delta":        round(new_result["score"] - old_result["score"], 1),
        "old_severity": old_result["severity"],
        "new_severity": new_result["severity"],
        "old_breakdown": old_result["breakdown"],
        "new_breakdown": new_result["breakdown"],
    }