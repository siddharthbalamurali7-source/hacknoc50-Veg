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

def score_one_asset(asset: AssetModel, db: Session) -> dict:
    """
    Internal function — scores a single asset, saves the result, returns it.
    Called by multiple endpoints so defined once here.

    Does three things:
    1. Fetches CVEs for every piece of software on the asset
    2. Runs calculate_risk() to get the score
    3. Saves a new row to risk_scores (history) and updates assets table (fast lookup)
    """
    # fetch all CVEs for this asset's software
    all_cves = get_cves_for_asset(asset)

    # build the asset dict that risk_engine expects
    asset_dict = {
        "open_ports":   asset.open_ports   or [],
        "criticality":  asset.criticality  or 2,
        "last_scanned": asset.last_scanned,
    }

    # run the scoring algorithm
    result = calculate_risk(asset_dict, all_cves)

    # ── Save to risk_scores table (history row — always INSERT, never UPDATE) ──
    score_record = RiskScoreModel(
        asset_id      = asset.id,
        score         = result["score"],
        severity      = result["severity"],
        breakdown     = result["breakdown"],
        top_cves      = result["top_cves"],
        calculated_at = datetime.now()
    )
    db.add(score_record)

    # ── Update denormalised score on asset for fast lookups ───────────────────
    # The graph engine and asset list read this directly without joining risk_scores
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
    """
    Returns current risk scores for all assets sorted highest risk first.
    Used by the asset list panel in the frontend.
    """
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
    """
    Company-wide aggregate score for the dashboard header gauge.
    Uses a criticality-weighted average so a DB server matters more than a dev laptop.
    """
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

    # criticality-weighted average
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


@router.get("/{asset_id}", response_model=RiskScore)
def get_asset_score(asset_id: int, db: Session = Depends(get_db)):
    """
    Full score detail for one asset including breakdown and top CVEs.
    Used by the asset detail panel when a judge clicks on a node.
    """
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    # get the most recent score record for the full breakdown
    latest = (
        db.query(RiskScoreModel)
        .filter(RiskScoreModel.asset_id == asset_id)
        .order_by(RiskScoreModel.calculated_at.desc())
        .first()
    )

    # if no score exists yet, calculate one now
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
def get_score_history(
    asset_id: int,
    limit: int = 30,
    db: Session = Depends(get_db)
):
    """
    Returns the score history for one asset — used by the trend chart.
    Returns up to `limit` most recent scores (default 30).
    """
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
        for record in reversed(history)   # return chronologically ascending
    ]


@router.post("/recalculate")
def recalculate_all(db: Session = Depends(get_db)):
    """
    Re-scores every asset in the database.
    Called by POST /hardening/run-now after a new network scan completes.

    Returns a summary showing which assets changed and by how much.
    """
    assets  = db.query(AssetModel).all()
    results = []

    for asset in assets:
        old_score = asset.risk_score or 0.0

        try:
            result = score_one_asset(asset, db)
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
            print(f"[scorer_router] Failed to score asset {asset.id}: {e}")
            results.append({
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "status":   "error",
                "error":    str(e),
            })

    scored_count = sum(1 for r in results if r.get("status") == "scored")
    improved     = sum(1 for r in results if r.get("delta", 0) < 0)
    worsened     = sum(1 for r in results if r.get("delta", 0) > 0)

    return {
        "assets_scored":  scored_count,
        "assets_improved": improved,
        "assets_worsened": worsened,
        "results":        results,
        "timestamp":      datetime.now().isoformat(),
    }


@router.post("/recalculate/{asset_id}")
def recalculate_one(asset_id: int, db: Session = Depends(get_db)):
    """
    Re-scores a single asset.
    Used after a specific fix is applied — lets the team see the score
    update instantly without rescoring the whole network.
    """
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
def simulate_fix_impact(
    asset_id: int,
    fix: dict,
    db: Session = Depends(get_db)
):
    """
    Predict the score impact of applying a fix WITHOUT saving anything.
    This is the Fix Impact Prediction feature.

    fix body examples:
        {"type": "close_port", "port": 22}
        {"type": "patch_cve",  "cve_id": "CVE-2021-44228"}

    Returns old score, new score, and the delta so the team can
    see exactly how much safer they'll be before doing the work.
    """
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
    """
    Fetch CVEs published in the last N hours and recalculate scores
    for any assets affected by newly discovered vulnerabilities.

    Called automatically by the scheduler every 6 hours.
    Can also be triggered manually for a demo.
    """
    print(f"[scorer_router] Fetching CVEs from last {hours_back} hours...")
    new_cves = fetch_recent_cves(hours_back=hours_back)

    if not new_cves:
        return {
            "new_cves_found":    0,
            "assets_rescored":   0,
            "message":           "No new CVEs found in this time window",
            "timestamp":         datetime.now().isoformat(),
        }

    # rescore all assets — in production you'd match CVEs to affected assets
    # for the hackathon, rescore everything when new CVEs are found
    assets  = db.query(AssetModel).all()
    rescored = 0

    for asset in assets:
        try:
            score_one_asset(asset, db)
            rescored += 1
        except Exception as e:
            print(f"[scorer_router] Failed to rescore asset {asset.id}: {e}")

    return {
        "new_cves_found":  len(new_cves),
        "assets_rescored": rescored,
        "message":         f"Found {len(new_cves)} new CVEs, rescored {rescored} assets",
        "timestamp":       datetime.now().isoformat(),
    }
