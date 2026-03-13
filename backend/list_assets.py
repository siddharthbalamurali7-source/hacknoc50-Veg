from database import SessionLocal
import models

def list_assets():
    db = SessionLocal()
    try:
        assets = db.query(models.AssetModel).all()
        for a in assets:
            print(f"ID: {a.id}, IP: {a.ip_address}, Hostname: {a.hostname}, Criticality: {a.criticality}")
    finally:
        db.close()

if __name__ == "__main__":
    list_assets()
