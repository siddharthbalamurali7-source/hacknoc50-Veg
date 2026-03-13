from database import SessionLocal
import models

def clear_db(db):
    db.query(models.RelationshipModel).delete()
    db.query(models.AssetModel).delete()
    db.commit()

def seed_standard_enterprise(db):
    print("\n--- Seeding Scenario: Standard Enterprise ---")
    a1 = models.AssetModel(ip_address="10.0.0.1", hostname="corp-gateway", internet_exposed=True, criticality=1, open_ports=[80, 443])
    a2 = models.AssetModel(ip_address="10.0.1.10", hostname="email-server", internet_exposed=True, criticality=3, open_ports=[25, 110, 143])
    a3 = models.AssetModel(ip_address="10.0.2.20", hostname="hr-portal", internet_exposed=False, criticality=4, open_ports=[80, 8080])
    a4 = models.AssetModel(ip_address="10.0.3.100", hostname="employee-db", internet_exposed=False, criticality=5, open_ports=[3306, 5432])
    
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
    web = models.AssetModel(ip_address="45.5.5.1", hostname="public-web", internet_exposed=True, criticality=3, open_ports=[80, 443])
    # Background dev machine
    dev = models.AssetModel(ip_address="192.168.50.5", hostname="dev-workstation", internet_exposed=True, criticality=1, open_ports=[22, 5900]) 
    # Internal servers
    app = models.AssetModel(ip_address="10.50.1.1", hostname="internal-app", internet_exposed=False, criticality=4, open_ports=[8000, 8443])
    vault = models.AssetModel(ip_address="10.50.99.99", hostname="secret-vault", internet_exposed=False, criticality=5, open_ports=[22, 443])
    
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
        models.RelationshipModel(source_asset_id=lb.id, target_asset_id=s3.id, type="iam_misconfig", traversal_probability=1.0)
    ]
    db.add_all(rels)
    db.commit()
    return s3.id

def seed_supply_chain(db):
    print("\n--- Seeding Scenario: Supply Chain Compromise ---")
    gh = models.AssetModel(ip_address="github.com", hostname="malicious-vcs-dependency", internet_exposed=True, criticality=1)
    ci = models.AssetModel(ip_address="10.100.1.5", hostname="build-pipeline-server", internet_exposed=False, criticality=4)
    prod = models.AssetModel(ip_address="10.200.1.10", hostname="production-app-cluster", internet_exposed=False, criticality=5)
    
    db.add_all([gh, ci, prod])
    db.commit()
    for a in [gh, ci, prod]: db.refresh(a)

    rels = [
        models.RelationshipModel(source_asset_id=gh.id, target_asset_id=ci.id, type="malicious_package_update", traversal_probability=0.7),
        models.RelationshipModel(source_asset_id=ci.id, target_asset_id=prod.id, type="untrusted_binary_deployment", traversal_probability=0.9)
    ]
    db.add_all(rels)
    db.commit()
    return prod.id

def seed_ransomware_network(db):
    print("\n--- Seeding Scenario: Multi-Hop Ransomware ---")
    vpn = models.AssetModel(ip_address="vpn.corp.com", hostname="vpn-concentrator", internet_exposed=True, criticality=3, open_ports=[443, 1194])
    file_srv = models.AssetModel(ip_address="10.0.50.1", hostname="corporate-file-server", internet_exposed=False, criticality=4, open_ports=[445, 139])
    backup = models.AssetModel(ip_address="10.0.99.1", hostname="immutable-backup-vault", internet_exposed=False, criticality=5, open_ports=[22, 5432])
    
    db.add_all([vpn, file_srv, backup])
    db.commit()
    for a in [vpn, file_srv, backup]: db.refresh(a)

    rels = [
        models.RelationshipModel(source_asset_id=vpn.id, target_asset_id=file_srv.id, type="domain_admin_compromise", traversal_probability=0.4),
        models.RelationshipModel(source_asset_id=file_srv.id, target_asset_id=backup.id, type="service_account_hijack", traversal_probability=0.3)
    ]
    db.add_all(rels)
    db.commit()
    return backup.id

def seed_all_extended(db):
    """Utility to seed everything for a massive demo graph."""
    clear_db(db)
    seed_standard_enterprise(db)
    seed_lateral_movement(db)
    seed_misconfigured_cloud(db)
    seed_supply_chain(db)
    seed_ransomware_network(db)
    return {"assets": db.query(models.AssetModel).count(), "relationships": db.query(models.RelationshipModel).count()}

if __name__ == "__main__":
    db = SessionLocal()
    # This script is now intended to be called by verify_attack_path.py for demo
    db.close()
