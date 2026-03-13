"""
asset_router.py — Person A
FastAPI router for asset discovery and management.
Registers under /assets prefix in main.py.

FIXES applied:
- Removed circular import of score_one_asset from scorer.scorer_router
- Removed score_one_asset() calls from trigger_scan() and load_demo_data()
- Fixed ip_address -> ip key in upsert_asset()
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from database import get_db
from models import AssetModel
from schemas import AssetOut, AssetScanRequest, ScanResult
from scanner.nmap_scanner import scan_network, load_seed_assets

router = APIRouter()


# ── Internal helper ────────────────────────────────────────────────────────────

def upsert_asset(asset_dict: dict, db: Session) -> AssetModel:
    """
    Insert a new asset or update an existing one by IP address.
    Prevents duplicate assets when the same network is scanned twice.

    FIX: queries AssetModel.ip (not ip_address) to match AssetModel column.
    FIX: reads asset_dict["ip"] consistently everywhere.
    """
    existing = db.query(AssetModel).filter(
        AssetModel.ip == asset_dict["ip"]   # FIX: was ip_address
    ).first()

    if existing:
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
            ip             = asset_dict["ip"],   # FIX: was ip_address = asset_dict["ip"]
            hostname       = asset_dict["hostname"],
            os             = asset_dict["os"],
            open_ports     = asset_dict["open_ports"],
            software_list  = asset_dict["software_list"],
            asset_type     = asset_dict["asset_type"],
            criticality    = asset_dict["criticality"],
            last_scanned   = datetime.now(),
            risk_score     = None,
            severity_label = None,
            last_scored    = None,
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
    Triggers a live Nmap scan on the given IP range and saves results to DB.

    FIX: removed score_one_asset() call — scoring is triggered separately
    via POST /scores/recalculate to avoid circular imports.
    """
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

    duration = (datetime.now() - start_time).seconds

    return ScanResult(
        assets_found  = len(raw_assets),
        assets_saved  = len(saved),
        ip_range      = request.ip_range,
        scan_duration = duration,
        timestamp     = datetime.now(),
        message       = f"Scan complete — {len(saved)} assets saved. Call POST /scores/recalculate to score them."
    )


@router.post("/seed", response_model=ScanResult)
def load_demo_data(db: Session = Depends(get_db)):
    """
    Loads seed assets from data/seed_assets.json into the database.
    Use this for demo setup without running a real Nmap scan.

    FIX: removed score_one_asset() call — call POST /scores/recalculate after seeding.
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

    return ScanResult(
        assets_found  = len(raw_assets),
        assets_saved  = len(saved),
        ip_range      = "seed data",
        scan_duration = 0,
        timestamp     = datetime.now(),
        message       = f"Seeded {len(saved)} demo assets. Call POST /scores/recalculate to score them."
    )


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """
    Deletes an asset by ID.
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
    Wipes all assets. Use before reseeding for a clean demo.
    """
    count = db.query(AssetModel).delete()
    db.commit()
    return {"message": f"Deleted {count} assets"}