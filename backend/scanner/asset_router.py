"""
asset_router.py — Person A
FastAPI router for asset discovery and management.
Registers under /assets prefix in main.py.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from database import get_db
from models import AssetModel
from schemas import AssetOut, AssetScanRequest, ScanResult
from scorer.scorer_router import score_one_asset
from scanner.nmap_scanner import scan_network, load_seed_assets

router = APIRouter()


# ── Internal helper ────────────────────────────────────────────────────────────

def upsert_asset(asset_dict: dict, db: Session) -> AssetModel:
    """
    Insert a new asset or update an existing one by IP address.
    Prevents duplicate assets when the same network is scanned twice.

    Returns the saved AssetModel instance.
    """
    existing = db.query(AssetModel).filter(
        AssetModel.ip == asset_dict["ip"]
    ).first()

    if existing:
        # update all fields except id, risk_score, severity_label, last_scored
        # those are owned by the scorer — don't overwrite them
        existing.hostname      = asset_dict["hostname"]
        existing.os            = asset_dict["os"]
        existing.open_ports    = asset_dict["open_ports"]
        existing.software_list = asset_dict["software_list"]
        existing.asset_type    = asset_dict["asset_type"]
        existing.criticality   = asset_dict["criticality"]
        existing.last_scanned  = datetime.now()
        db.commit()
        db.refresh(existing)
        return existing
    else:
        new_asset = AssetModel(
            ip            = asset_dict["ip"],
            hostname      = asset_dict["hostname"],
            os            = asset_dict["os"],
            open_ports    = asset_dict["open_ports"],
            software_list = asset_dict["software_list"],
            asset_type    = asset_dict["asset_type"],
            criticality   = asset_dict["criticality"],
            last_scanned  = datetime.now(),
            # scorer fields — start as None, scorer fills these in
            risk_score    = None,
            severity_label= None,
            last_scored   = None,
        )
        db.add(new_asset)
        db.commit()
        db.refresh(new_asset)
        return new_asset


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=list[AssetOut])
def get_all_assets(
    asset_type: Optional[str] = None,
    min_criticality: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Returns all discovered assets.
    Optionally filter by asset_type or minimum criticality level.

    Used by:
    - Frontend asset list panel
    - Graph builder to construct the attack path graph
    - Scorer to know which assets to score
    """
    query = db.query(AssetModel)

    if asset_type:
        query = query.filter(AssetModel.asset_type == asset_type)

    if min_criticality:
        query = query.filter(AssetModel.criticality >= min_criticality)

    assets = query.order_by(AssetModel.criticality.desc()).all()
    return assets


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """
    Returns a single asset by ID.
    Used by the asset detail panel and scorer for per-asset operations.
    """
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return asset


@router.post("/scan", response_model=ScanResult)
def trigger_scan(
    request: AssetScanRequest,
    db: Session = Depends(get_db)
):
    """
    Triggers a live Nmap scan on the given IP range.
    Saves all discovered assets to the database.

    After saving, triggers scorer recalculation automatically
    so scores are always fresh after a scan.

    Body:
        ip_range  (str)  — CIDR range e.g. "192.168.1.0/24"
        ports     (str)  — port range e.g. "1-1024" (optional)
        use_seed  (bool) — use seed data instead of live scan (for demo)
    """
    # use seed data for demo if requested or if no real network available
    if request.use_seed:
        print("[asset_router] Using seed data for demo")
        raw_assets = load_seed_assets()
    else:
        raw_assets = scan_network(
            ip_range = request.ip_range,
            ports    = request.ports or "1-1024"
        )

    if not raw_assets:
        return ScanResult(
            assets_found  = 0,
            assets_saved  = 0,
            ip_range      = request.ip_range,
            scan_duration = 0,
            timestamp     = datetime.now(),
            message       = "No assets found — check the IP range or use seed data"
        )

    start_time = datetime.now()
    saved      = []

    for asset_dict in raw_assets:
        try:
            saved_asset = upsert_asset(asset_dict, db)
            saved.append(saved_asset)
        except Exception as e:
            print(f"[asset_router] Failed to save asset {asset_dict.get('ip')}: {e}")

    # Automatically recalculate risk scores for new/updated assets.
    # This ensures the scorer folder has up-to-date scores after each scan.
    for asset in saved:
        try:
            score_one_asset(asset, db)
        except Exception as e:
            print(f"[asset_router] Failed to score asset {asset.id}: {e}")

    duration = (datetime.now() - start_time).seconds

    return ScanResult(
        assets_found  = len(raw_assets),
        assets_saved  = len(saved),
        ip_range      = request.ip_range,
        scan_duration = duration,
        timestamp     = datetime.now(),
        message       = f"Scan complete — {len(saved)} assets saved"
    )


@router.post("/seed", response_model=ScanResult)
def load_demo_data(db: Session = Depends(get_db)):
    """
    Loads seed assets from data/seed_assets.json into the database.
    Use this endpoint to populate the DB instantly for a demo
    without running a real Nmap scan.

    Called during hackathon presentation setup.
    """
    raw_assets = load_seed_assets()

    if not raw_assets:
        raise HTTPException(
            status_code = 500,
            detail      = "seed_assets.json not found or empty — check data/ folder"
        )

    saved = []
    for asset_dict in raw_assets:
        try:
            saved_asset = upsert_asset(asset_dict, db)
            saved.append(saved_asset)
        except Exception as e:
            print(f"[asset_router] Failed to seed asset {asset_dict.get('ip')}: {e}")

    # Score the seeded assets so the scorer UI has values immediately.
    for asset in saved:
        try:
            score_one_asset(asset, db)
        except Exception as e:
            print(f"[asset_router] Failed to score seeded asset {asset.id}: {e}")

    return ScanResult(
        assets_found  = len(raw_assets),
        assets_saved  = len(saved),
        ip_range      = "seed data",
        scan_duration = 0,
        timestamp     = datetime.now(),
        message       = f"Seeded {len(saved)} demo assets successfully"
    )


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """
    Deletes an asset and all its associated scores.
    Useful for cleaning up the demo environment between runs.
    """
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    db.delete(asset)
    db.commit()
    return {"message": f"Asset {asset_id} deleted"}


@router.delete("/")
def clear_all_assets(db: Session = Depends(get_db)):
    """
    Wipes all assets from the database.
    Use before loading fresh seed data for a clean demo.
    """
    count = db.query(AssetModel).delete()
    db.commit()
    return {"message": f"Deleted {count} assets"}