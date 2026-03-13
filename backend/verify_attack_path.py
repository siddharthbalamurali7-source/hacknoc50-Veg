from database import SessionLocal
from analyzer.graph_engine import GraphEngine
import seed_relationships
import json

def run_scenarios():
    db = SessionLocal()
    try:
        scenarios = [
            ("Standard Enterprise", seed_relationships.seed_standard_enterprise),
            ("Lateral Movement", seed_relationships.seed_lateral_movement),
            ("Misconfigured Cloud", seed_relationships.seed_misconfigured_cloud)
        ]

        for name, seed_func in scenarios:
            seed_relationships.clear_db(db)
            target_id = seed_func(db)
            
            engine = GraphEngine(db)
            path = engine.get_attack_paths(target_id)
            
            print(f"Results for Scenario: {name}")
            print(f"Target ID: {target_id}")
            print(f"Path Count: {len(path['nodes'])}")
            print(f"Total Probability: {path['total_probability']}")
            if path["nodes"]:
                print("Path sequence: " + " -> ".join([n["hostname"] for n in path["nodes"]]))
            print("-" * 40)
            
    finally:
        db.close()

if __name__ == "__main__":
    run_scenarios()
