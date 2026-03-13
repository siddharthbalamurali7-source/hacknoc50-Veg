"""
test_pipeline.py
=================
End-to-end test of the full scanner → scorer pipeline.
No live Nmap scan needed — uses seed data so it works anywhere.

Run from the backend/ folder:
    cd backend
    python test_pipeline.py

What this tests:
    1. Database connects successfully
    2. Seed assets load from seed_assets.json
    3. Assets save to the DB correctly
    4. CVE fetcher finds vulnerabilities for known software
    5. Scorer calculates a score for every asset
    6. Scores are saved to risk_scores table
    7. Summary (company-wide score) calculates correctly
    8. Fix simulation returns a lower score after closing a port
"""

import os
import sys
from dotenv import load_dotenv
load_dotenv()

# ── make sure imports resolve from backend/ ───────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime


# ── helpers ───────────────────────────────────────────────────────────────────

PASS = "  [PASS]"
FAIL = "  [FAIL]"
INFO = "  [INFO]"

def section(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")

def check(label, condition, detail=""):
    if condition:
        print(f"{PASS}  {label}")
        if detail:
            print(f"        {detail}")
    else:
        print(f"{FAIL}  {label}")
        if detail:
            print(f"        {detail}")
    return condition


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — database connection
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 1 — Database connection")

try:
    from database import engine, SessionLocal, Base
    import models  # registers all models with Base

    # Create tables based on current models.
    # Note: if your database already has the assets table with a different
    # schema (e.g., old columns like `ip` or `asset_type`), you must either
    # point DATABASE_URL at a fresh database or update the schema manually.
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    check("Database connected and tables created", True)
except Exception as e:
    check("Database connected", False, str(e))
    print("\n  Cannot continue without a database. Check your .env DATABASE_URL.")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — load seed assets
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 2 — Load seed assets")

try:
    from scanner.nmap_scanner import load_seed_assets
    seed_assets = load_seed_assets()
    check("seed_assets.json loaded", len(seed_assets) > 0, f"{len(seed_assets)} assets found")
except Exception as e:
    check("seed_assets.json loaded", False, str(e))
    seed_assets = []

# spot check first asset has required fields
if seed_assets:
    first = seed_assets[0]
    check("Assets have 'ip_address' field",    "ip_address" in first,     f"ip_address = {first.get('ip_address')}")
    check("Assets have 'open_ports' field",    "open_ports" in first,    f"ports = {first.get('open_ports')}")
    check("Assets have 'software_list' field", "software_list" in first, f"software count = {len(first.get('software_list', []))}")
    check("Assets have 'criticality' field",   "criticality" in first,   f"criticality = {first.get('criticality')}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — save assets to database
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 3 — Save assets to database")

from sqlalchemy import func
from models import AssetModel

# clear existing assets for a clean test run
try:
    deleted = db.query(AssetModel).delete()
    db.commit()
    print(f"{INFO}  Cleared {deleted} existing assets for clean test")
except Exception as e:
    print(f"{INFO}  Could not clear assets: {e}")

saved_assets = []
for asset_dict in seed_assets:
    try:
        # upsert logic — same as asset_router.py
        existing = db.query(AssetModel).filter(
            AssetModel.ip_address == asset_dict["ip_address"]
        ).first()

        if existing:
            existing.hostname         = asset_dict.get("hostname")
            existing.os               = asset_dict.get("os")
            existing.open_ports       = asset_dict.get("open_ports", [])
            existing.software_list    = asset_dict.get("software_list", [])
            existing.criticality      = asset_dict.get("criticality", 2)
            existing.internet_exposed = asset_dict.get("internet_exposed", False)
            db.commit()
            db.refresh(existing)
            saved_assets.append(existing)
        else:
            new_id = asset_dict.get("id")
            if new_id is None:
                max_id = db.query(func.max(AssetModel.id)).scalar() or 0
                new_id = max_id + 1

            new_asset = AssetModel(
                id              = new_id,
                ip_address      = asset_dict["ip_address"],
                hostname        = asset_dict.get("hostname"),
                os              = asset_dict.get("os"),
                open_ports      = asset_dict.get("open_ports", []),
                software_list   = asset_dict.get("software_list", []),
                criticality     = asset_dict.get("criticality", 2),
                internet_exposed = asset_dict.get("internet_exposed", False),
            )
            db.add(new_asset)
            db.commit()
            db.refresh(new_asset)
            saved_assets.append(new_asset)

    except Exception as e:
        db.rollback()
        print(f"{FAIL}  Failed to save {asset_dict.get('ip_address')}: {e}")
check(
    f"All assets saved to DB",
    len(saved_assets) == len(seed_assets),
    f"{len(saved_assets)}/{len(seed_assets)} saved"
)

# verify they're actually in the DB
db_count = db.query(AssetModel).count()
check("Assets readable from DB", db_count == len(saved_assets), f"{db_count} rows in assets table")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — CVE fetcher
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 4 — CVE fetcher")

try:
    from scorer.cve_fetcher import get_cves_for_software, get_cves_for_asset, build_cpe

    # test CPE string building
    cpe = build_cpe("Apache", "2.4.49")
    check(
        "CPE string builds correctly",
        "apache" in cpe and "2.4.49" in cpe,
        cpe
    )

    # test CVE lookup for a known vulnerable version
    print(f"\n{INFO}  Fetching CVEs for Apache 2.4.49 (known vulnerable — CVE-2021-41773)")
    print(f"{INFO}  This may take a few seconds on first run (hitting NVD API)...")
    cves = get_cves_for_software("Apache", "2.4.49")
    check(
        "CVEs returned for Apache 2.4.49",
        len(cves) > 0,
        f"{len(cves)} CVEs found"
    )

    if cves:
        top = cves[0]
        check("CVE has cve_id field",      "cve_id"      in top, top.get("cve_id"))
        check("CVE has cvss score",        "cvss"        in top, f"CVSS = {top.get('cvss')}")
        check("CVE has has_exploit field", "has_exploit" in top, f"has_exploit = {top.get('has_exploit')}")
        check("CVSS score is valid range", 0 <= top.get("cvss", -1) <= 10)

    # test second call uses cache (should be instant)
    import time
    t0 = time.time()
    cves2 = get_cves_for_software("Apache", "2.4.49")
    cache_time = time.time() - t0
    check(
        "Second call uses cache (< 0.5s)",
        cache_time < 0.5,
        f"took {round(cache_time, 3)}s"
    )

    # test that a full asset CVE fetch works
    test_asset = saved_assets[0] if saved_assets else None
    if test_asset:
        asset_cves = get_cves_for_asset(test_asset)
        check(
            f"get_cves_for_asset() works on {test_asset.hostname}",
            isinstance(asset_cves, list),
            f"{len(asset_cves)} CVEs found for this asset"
        )

except Exception as e:
    check("CVE fetcher works", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — score every asset
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 5 — Score every asset")

from scorer.scorer_router import score_one_asset
from models import RiskScoreModel

scored = []
failed = []

for asset in saved_assets:
    try:
        result = score_one_asset(asset, db)
        scored.append((asset, result))
    except Exception as e:
        failed.append((asset, str(e)))
        print(f"{FAIL}  {asset.hostname or asset.ip_address}: {e}")

check(
    "All assets scored successfully",
    len(failed) == 0,
    f"{len(scored)} scored, {len(failed)} failed"
)

# print score table
if scored:
    print(f"\n  {'Hostname':<22} {'IP':<16} {'Score':>6}  {'Severity':<10} {'Top CVE'}")
    print(f"  {'─'*22} {'─'*16} {'─'*6}  {'─'*10} {'─'*20}")
    for asset, result in sorted(scored, key=lambda x: x[1]["score"], reverse=True):
        top_cve = result["top_cves"][0] if result["top_cves"] else "none"
        print(f"  {(asset.hostname or asset.ip_address):<22} {asset.ip_address:<16} {result['score']:>6.1f}  {result['severity']:<10} {top_cve}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — verify scores saved to risk_scores table
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 6 — Verify scores saved to database")

score_count = db.query(RiskScoreModel).count()
check(
    "Score history rows saved to risk_scores table",
    score_count >= len(scored),
    f"{score_count} rows in risk_scores table"
)

# check a score record has all expected fields
sample = db.query(RiskScoreModel).first()
if sample:
    check("Score record has breakdown JSON",  sample.breakdown is not None,  str(sample.breakdown))
    check("Score record has top_cves JSON",   sample.top_cves  is not None,  str(sample.top_cves))
    check("Score record has calculated_at",   sample.calculated_at is not None)
    check("Score is in valid range (0-100)",  0 <= sample.score <= 100, f"score = {sample.score}")

# check denormalised score updated on asset row
refreshed = db.query(AssetModel).first()
if refreshed:
    db.refresh(refreshed)
    check(
        "Asset row updated with denormalised risk_score",
        refreshed.risk_score is not None,
        f"risk_score = {refreshed.risk_score}"
    )
else:
    check(
        "Asset row updated with denormalised risk_score",
        False,
        "no assets in database"
    )


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — company summary
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 7 — Company-wide score summary")

try:
    all_assets   = db.query(AssetModel).all()
    total_weight = sum(a.criticality or 1 for a in all_assets)
    weighted_sum = sum((a.risk_score or 0.0) * (a.criticality or 1) for a in all_assets)
    company_score = round(weighted_sum / total_weight, 1) if total_weight > 0 else 0.0

    if company_score >= 80:   severity = "CRITICAL"
    elif company_score >= 60: severity = "HIGH"
    elif company_score >= 40: severity = "MEDIUM"
    else:                     severity = "LOW"

    critical = sum(1 for a in all_assets if (a.risk_score or 0) >= 80)
    high     = sum(1 for a in all_assets if 60 <= (a.risk_score or 0) < 80)
    medium   = sum(1 for a in all_assets if 40 <= (a.risk_score or 0) < 60)
    low      = sum(1 for a in all_assets if (a.risk_score or 0) < 40)

    check("Company score calculated",      company_score > 0,  f"Company score = {company_score} ({severity})")
    check("Asset severity counts add up",  critical + high + medium + low == len(all_assets),
          f"CRITICAL={critical}  HIGH={high}  MEDIUM={medium}  LOW={low}")

except Exception as e:
    check("Company summary works", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 — fix simulation
# ══════════════════════════════════════════════════════════════════════════════

section("STEP 8 — Fix impact simulation")

try:
    from scorer.risk_engine import simulate_fix

    # find a high-risk asset to simulate on
    risky = max(saved_assets, key=lambda a: a.risk_score or 0)
    print(f"{INFO}  Simulating fix on highest-risk asset: {risky.hostname} (score={risky.risk_score})")

    asset_dict = {
        "open_ports":  risky.open_ports  or [],
        "criticality": risky.criticality or 2,
    }

    from scorer.cve_fetcher import get_cves_for_asset
    cves = get_cves_for_asset(risky)

    # simulate closing the most dangerous open port
    if risky.open_ports:
        from scorer.risk_engine import PORT_WEIGHTS
        most_dangerous_port = max(
            risky.open_ports,
            key=lambda p: PORT_WEIGHTS.get(p, 4)
        )

        result = simulate_fix(asset_dict, cves, {
            "type": "close_port",
            "port": most_dangerous_port
        })

        check(
            f"Closing port {most_dangerous_port} reduces score",
            result["delta"] <= 0,
            f"Score: {result['old_score']} → {result['new_score']} (delta={result['delta']})"
        )
        check(
            "Original asset not mutated",
            risky.open_ports is not None and most_dangerous_port in risky.open_ports
        )

    # simulate patching the top CVE
    if cves:
        top_cve = cves[0]["cve_id"]
        result2 = simulate_fix(asset_dict, cves, {
            "type":   "patch_cve",
            "cve_id": top_cve
        })
        check(
            f"Patching {top_cve} reduces or maintains score",
            result2["delta"] <= 0,
            f"Score: {result2['old_score']} → {result2['new_score']} (delta={result2['delta']})"
        )

except Exception as e:
    check("Fix simulation works", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

section("PIPELINE TEST COMPLETE")
print(f"""
  If all steps show [PASS], the scanner → scorer pipeline is working.

  Next steps:
    1. Start the server:   uvicorn main:app --reload --port 8000
    2. Load seed data:     POST http://localhost:8000/assets/seed
    3. Score assets:       POST http://localhost:8000/scores/recalculate
    4. View results:       GET  http://localhost:8000/scores/summary
    5. Interactive docs:   http://localhost:8000/docs
""")

db.close()