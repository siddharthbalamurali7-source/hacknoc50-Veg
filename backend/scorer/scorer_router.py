from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

# these imports come from Person 1's files
from database import get_db
from models import AssetModel, RiskScoreModel
from schemas import RiskScore, RiskScoreSummary, RiskScoreHistory, FixSimulationResult

# your own files
from scorer.cve_fetcher import get_cves_for_asset, fetch_recent_cves
from scorer.risk_engine import calculate_risk, simulate_fix

router = APIRouter()


# ── Internal helper ────────────────────────────────────────────────────────────

def score_one_asset(asset: AssetModel, db: Session, skip_cve_search: bool = False) -> dict:
    all_cves = [] if skip_cve_search else get_cves_for_asset(asset)

    asset_dict = {
        "open_ports":   asset.open_ports   or [],
        "criticality":  asset.criticality  or 2,
        "last_scanned": asset.last_scanned,
    }

    result = calculate_risk(asset_dict, all_cves)

    score_record = RiskScoreModel(
        asset_id      = asset.id,
        score         = result["score"],
        severity      = result["severity"],
        breakdown     = result["breakdown"],
        top_cves      = result["top_cves"],
        calculated_at = datetime.now()
    )
    db.add(score_record)

    asset.risk_score     = result["score"]
    asset.severity_label = result["severity"]
    asset.last_scored    = datetime.now()

    db.commit()

    return {
        **result,
        "asset_id": asset.id,
        "hostname": asset.hostname,
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=list[RiskScore])
def get_all_scores(db: Session = Depends(get_db)):
    assets = (
        db.query(AssetModel)
        .order_by(AssetModel.risk_score.desc())
        .all()
    )

    return [
        RiskScore(
            asset_id  = a.id,
            hostname  = a.hostname  or "unknown",
            score     = a.risk_score     or 0.0,
            severity  = a.severity_label or "LOW",
            top_cves  = [],
            breakdown = {},
        )
        for a in assets
    ]


@router.get("/summary", response_model=RiskScoreSummary)
def get_score_summary(db: Session = Depends(get_db)):
    assets = db.query(AssetModel).all()

    if not assets:
        return RiskScoreSummary(
            company_score  = 0.0,
            severity       = "LOW",
            total_assets   = 0,
            critical_count = 0,
            high_count     = 0,
            medium_count   = 0,
            low_count      = 0,
            last_calculated = datetime.now(),
        )

    total_weight = sum(a.criticality or 1 for a in assets)
    weighted_sum = sum(
        (a.risk_score or 0.0) * (a.criticality or 1)
        for a in assets
    )
    company_score = round(weighted_sum / total_weight, 1) if total_weight > 0 else 0.0

    if company_score >= 80:   severity = "CRITICAL"
    elif company_score >= 60: severity = "HIGH"
    elif company_score >= 40: severity = "MEDIUM"
    else:                     severity = "LOW"

    return RiskScoreSummary(
        company_score   = company_score,
        severity        = severity,
        total_assets    = len(assets),
        critical_count  = sum(1 for a in assets if (a.risk_score or 0) >= 80),
        high_count      = sum(1 for a in assets if 60 <= (a.risk_score or 0) < 80),
        medium_count    = sum(1 for a in assets if 40 <= (a.risk_score or 0) < 60),
        low_count       = sum(1 for a in assets if (a.risk_score or 0) < 40),
        last_calculated = datetime.now(),
    )


@router.get("/tasks")
def get_hardening_tasks(db: Session = Depends(get_db)):
    """
    Intelligently generates remediation tasks.
    """
    assets = db.query(AssetModel).all()
    tasks = []

    for asset in assets:
        # 1. Port-based tasks (Risky ports)
        if asset.open_ports:
            from scorer.risk_engine import PORT_WEIGHTS
            for port in asset.open_ports:
                weight = PORT_WEIGHTS.get(int(port), 4)
                if weight >= 10:
                    tasks.append({
                        "id": f"port-{asset.id}-{port}",
                        "asset_id": asset.id,
                        "hostname": asset.hostname or asset.ip_address,
                        "description": f"Close risky port {port} (Risk Weight: {weight})",
                        "priority": "Critical" if weight >= 15 else "High",
                        "type": "close_port",
                        "fix": {"type": "close_port", "port": int(port)}
                    })

        # 2. CVE-based tasks
        latest = db.query(RiskScoreModel).filter(RiskScoreModel.asset_id == asset.id).order_by(RiskScoreModel.calculated_at.desc()).first()
        if latest and latest.top_cves:
            for cve in latest.top_cves:
                tasks.append({
                    "id": f"cve-{asset.id}-{cve}",
                    "asset_id": asset.id,
                    "hostname": asset.hostname or asset.ip_address,
                    "description": f"Patch {cve} vulnerability",
                    "cve_id": cve,
                    "priority": "Critical" if latest.score >= 80 else "High",
                    "type": "patch_cve",
                    "fix": {"type": "patch_cve", "cve_id": cve}
                })

    priority_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    tasks.sort(key=lambda x: priority_map.get(x["priority"], 99))
    return tasks


@router.get("/{asset_id}", response_model=RiskScore)
def get_asset_score(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    latest = (
        db.query(RiskScoreModel)
        .filter(RiskScoreModel.asset_id == asset_id)
        .order_by(RiskScoreModel.calculated_at.desc())
        .first()
    )

    if not latest:
        result = score_one_asset(asset, db)
        return RiskScore(
            asset_id  = asset.id,
            hostname  = asset.hostname or "unknown",
            score     = result["score"],
            severity  = result["severity"],
            top_cves  = result["top_cves"],
            breakdown = result["breakdown"],
        )

    return RiskScore(
        asset_id  = asset.id,
        hostname  = asset.hostname or "unknown",
        score     = latest.score,
        severity  = latest.severity,
        top_cves  = latest.top_cves  or [],
        breakdown = latest.breakdown or {},
    )


@router.get("/{asset_id}/history", response_model=list[RiskScoreHistory])
def get_score_history(asset_id: int, limit: int = 30, db: Session = Depends(get_db)):
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    history = (
        db.query(RiskScoreModel)
        .filter(RiskScoreModel.asset_id == asset_id)
        .order_by(RiskScoreModel.calculated_at.desc())
        .limit(limit)
        .all()
    )

    return [
        RiskScoreHistory(
            asset_id      = record.asset_id,
            score         = record.score,
            severity      = record.severity,
            calculated_at = record.calculated_at,
        )
        for record in reversed(history)
    ]


@router.post("/recalculate")
def recalculate_all(db: Session = Depends(get_db)):
    assets  = db.query(AssetModel).all()
    results = []

    for asset in assets:
        old_score = asset.risk_score or 0.0
        try:
            result = score_one_asset(asset, db, skip_cve_search=True)
            results.append({
                "asset_id":    asset.id,
                "hostname":    asset.hostname,
                "old_score":   old_score,
                "new_score":   result["score"],
                "delta":       round(result["score"] - old_score, 1),
                "severity":    result["severity"],
                "status":      "scored",
            })
        except Exception as e:
            results.append({
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "status":   "error",
                "error":    str(e),
            })

    return {
        "assets_scored":  len(results),
        "results":        results,
        "timestamp":      datetime.now().isoformat(),
    }


@router.post("/recalculate/{asset_id}")
def recalculate_one(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    old_score = asset.risk_score or 0.0
    result    = score_one_asset(asset, db)

    return {
        "asset_id":  asset.id,
        "hostname":  asset.hostname,
        "old_score": old_score,
        "new_score": result["score"],
        "delta":     round(result["score"] - old_score, 1),
        "severity":  result["severity"],
        "breakdown": result["breakdown"],
        "top_cves":  result["top_cves"],
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/simulate-fix/{asset_id}", response_model=FixSimulationResult)
def simulate_fix_impact(asset_id: int, fix: dict, db: Session = Depends(get_db)):
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    all_cves   = get_cves_for_asset(asset)
    asset_dict = {
        "open_ports":   asset.open_ports  or [],
        "criticality":  asset.criticality or 2,
        "last_scanned": asset.last_scanned,
    }

    simulation = simulate_fix(asset_dict, all_cves, fix)

    return FixSimulationResult(
        asset_id     = asset.id,
        hostname     = asset.hostname,
        fix_type     = fix.get("type"),
        fix_detail   = fix.get("cve_id") or str(fix.get("port", "")),
        old_score    = simulation["old_score"],
        new_score    = simulation["new_score"],
        delta        = simulation["delta"],
        old_severity = simulation["old_severity"],
        new_severity = simulation["new_severity"],
    )


@router.post("/sync-cves")
def sync_recent_cves(hours_back: int = 6, db: Session = Depends(get_db)):
    new_cves = fetch_recent_cves(hours_back=hours_back)
    if not new_cves:
        return {"new_cves_found": 0, "timestamp": datetime.now().isoformat()}

    assets = db.query(AssetModel).all()
    for asset in assets:
        score_one_asset(asset, db)

    return {"new_cves_found": len(new_cves), "timestamp": datetime.now().isoformat()}


@router.post("/apply-fix/{asset_id}")
def apply_remediation(asset_id: int, fix: dict, db: Session = Depends(get_db)):
    """
    Permanently applies a fix to an asset and recalculates its score.
    """
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if fix.get("type") == "close_port":
        port_to_close = int(fix.get("port"))
        if asset.open_ports:
            asset.open_ports = [p for p in asset.open_ports if int(p) != port_to_close]
    
    elif fix.get("type") == "patch_cve":
        cve_id = fix.get("cve_id")
        # For simplicity in this demo, patching a CVE means it's gone.
        pass

    db.add(asset)
    db.commit()

    # Instant rescore to show updated impact
    result = score_one_asset(asset, db)
    
    return {
        "status": "success",
        "new_score": result["score"]
    }
