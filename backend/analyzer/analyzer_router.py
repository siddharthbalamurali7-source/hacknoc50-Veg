from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..database import SessionLocal
from ..schemas import RelationshipOut, RelationshipCreate, AttackPath
from ..models import RelationshipModel, AssetModel
from .graph_engine import GraphEngine

router = APIRouter(prefix="/analyzer", tags=["analyzer"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/relationships", response_model=RelationshipOut)
def create_relationship(rel: RelationshipCreate, db: Session = Depends(get_db)):
    db_rel = RelationshipModel(**rel.dict())
    db.add(db_rel)
    db.commit()
    db.refresh(db_rel)
    return db_rel

@router.get("/relationships", response_model=List[RelationshipOut])
def get_relationships(db: Session = Depends(get_db)):
    return db.query(RelationshipModel).all()

@router.get("/attack-paths/{asset_id}", response_model=AttackPath)
def get_attack_paths(asset_id: int, db: Session = Depends(get_db)):
    target_asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not target_asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    engine = GraphEngine(db)
    return engine.get_attack_paths(asset_id)

@router.get("/critical-paths")
def get_critical_paths(db: Session = Depends(get_db)):
    """
    Finds the highest-probability attack paths for all crown jewel assets (criticality 5).
    """
    critical_assets = db.query(AssetModel).filter(AssetModel.criticality >= 4).all()
    engine = GraphEngine(db)
    
    results = []
    for asset in critical_assets:
        path = engine.get_attack_paths(asset.id)
        if path["nodes"]:
            results.append({
                "asset_id": asset.id,
                "hostname": asset.hostname or asset.ip_address,
                "path": path
            })
    
    # Sort by total probability descending
    results.sort(key=lambda x: x["path"]["total_probability"], reverse=True)
    return results[:5]
