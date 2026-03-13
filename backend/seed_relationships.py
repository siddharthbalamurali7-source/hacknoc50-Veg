from database import SessionLocal
import models

def clear_db(db):
    db.query(models.RelationshipModel).delete()
    db.query(models.AssetModel).delete()
    db.commit()

def seed_standard_enterprise(db):
    print("\n--- Seeding Scenario: Standard Enterprise ---")
    a1 = models.AssetModel(ip_address="10.0.0.1", hostname="corp-gateway", internet_exposed=True, criticality=1)
    a2 = models.AssetModel(ip_address="10.0.1.10", hostname="email-server", internet_exposed=True, criticality=3)
    a3 = models.AssetModel(ip_address="10.0.2.20", hostname="hr-portal", internet_exposed=False, criticality=4)
    a4 = models.AssetModel(ip_address="10.0.3.100", hostname="employee-db", internet_exposed=False, criticality=5)
    
    db.add_all([a1, a2, a3, a4])
    db.commit()
    for a in [a1, a2, a3, a4]: db.refresh(a)

    rels = [
        models.RelationshipModel(source_asset_id=a1.id, target_asset_id=a2.id, type="network_reachable", traversal_probability=0.9),
        models.RelationshipModel(source_asset_id=a2.id, target_asset_id=a3.id, type="phishing_session_reuse", traversal_probability=0.4),
        models.RelationshipModel(source_asset_id=a3.id, target_asset_id=a4.id, type="db_creds_in_config", traversal_probability=0.8)
    ]
    db.add_all(rels)
    db.commit()
    return a4.id

def seed_lateral_movement(db):
    print("\n--- Seeding Scenario: Lateral Movement (Shadow IT) ---")
    # Public facing
    web = models.AssetModel(ip_address="45.5.5.1", hostname="public-web", internet_exposed=True, criticality=3)
    # Background dev machine
    dev = models.AssetModel(ip_address="192.168.50.5", hostname="dev-workstation", internet_exposed=True, criticality=1) 
    # Internal servers
    app = models.AssetModel(ip_address="10.50.1.1", hostname="internal-app", internet_exposed=False, criticality=4)
    vault = models.AssetModel(ip_address="10.50.99.99", hostname="secret-vault", internet_exposed=False, criticality=5)
    
    db.add_all([web, dev, app, vault])
    db.commit()
    for a in [web, dev, app, vault]: db.refresh(a)

    rels = [
        # Normal path: web -> app -> vault (Low prob app -> vault)
        models.RelationshipModel(source_asset_id=web.id, target_asset_id=app.id, type="api_connection", traversal_probability=0.5),
        models.RelationshipModel(source_asset_id=app.id, target_asset_id=vault.id, type="restricted_access", traversal_probability=0.1),
        
        # Shadow path: dev machine has keys to everything
        models.RelationshipModel(source_asset_id=dev.id, target_asset_id=vault.id, type="forgotten_ssh_key", traversal_probability=0.95)
    ]
    db.add_all(rels)
    db.commit()
    return vault.id

def seed_misconfigured_cloud(db):
    print("\n--- Seeding Scenario: Misconfigured Cloud ---")
    lb = models.AssetModel(ip_address="1.1.1.1", hostname="load-balancer", internet_exposed=True, criticality=2)
    s3 = models.AssetModel(ip_address="storage.cloud", hostname="s3-bucket-private", internet_exposed=False, criticality=5)
    
    db.add_all([lb, s3])
    db.commit()
    db.refresh(lb); db.refresh(s3)

    rels = [
        # The "Oops" link: DB is actually reachable from the internet via a bypass
        models.RelationshipModel(source_asset_id=lb.id, target_asset_id=s3.id, type="iam_misconfig", traversal_probability=1.0)
    ]
    db.add_all(rels)
    db.commit()
    return s3.id

if __name__ == "__main__":
    db = SessionLocal()
    # This script is now intended to be called by verify_attack_path.py for demo
    db.close()
