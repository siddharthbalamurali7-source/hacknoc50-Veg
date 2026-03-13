import heapq
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session

try:
    from ..models import AssetModel, RelationshipModel
except ImportError:
    from models import AssetModel, RelationshipModel

class GraphEngine:
    """
    Handles building the infrastructure graph and finding attack paths.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_attack_paths(self, target_asset_id: int) -> Dict[str, Any]:
        """
        Finds the highest probability attack paths to a target asset.
        Uses a variation of Dijkstra's algorithm to maximize path probability.
        """
        # Load all assets and relationships
        assets = self.db.query(AssetModel).all()
        relationships = self.db.query(RelationshipModel).all()

        # Map asset IDs to their hostnames and risk scores
        asset_map = {a.id: a for a in assets}
        if target_asset_id not in asset_map:
            return {"nodes": [], "edges": [], "total_probability": 0.0}

        # Build adjacency list: target -> list of (source, probability, type)
        adj = {}
        for rel in relationships:
            if rel.source_asset_id not in adj:
                adj[rel.source_asset_id] = []
            adj[rel.source_asset_id].append({
                "target": rel.target_asset_id,
                "probability": rel.traversal_probability,
                "type": rel.type
            })

        # Dijkstra for maximizing product of probabilities
        start_nodes = [a.id for a in assets if a.internet_exposed]
        
        probabilities = {a.id: 0.0 for a in assets}
        predecessors = {a.id: None for a in assets}
        
        pq = []
        for node_id in start_nodes:
            probabilities[node_id] = 1.0
            heapq.heappush(pq, (-1.0, node_id))

        while pq:
            curr_prob_neg, u = heapq.heappop(pq)
            curr_prob = -curr_prob_neg

            if curr_prob < probabilities[u]:
                continue

            if u in adj:
                for edge in adj[u]:
                    v = edge["target"]
                    edge_prob = edge["probability"]
                    new_prob = curr_prob * edge_prob

                    if new_prob > probabilities[v]:
                        probabilities[v] = new_prob
                        predecessors[v] = (u, edge["type"], edge_prob)
                        heapq.heappush(pq, (-new_prob, v))

        # Reconstruct path to target_asset_id
        path_nodes = []
        path_edges = []
        curr = target_asset_id
        
        if probabilities[curr] == 0 and not asset_map[curr].internet_exposed:
             return {"nodes": [], "edges": [], "total_probability": 0.0}

        while curr is not None:
            asset = asset_map[curr]
            path_nodes.append({
                "id": asset.id,
                "hostname": asset.hostname or asset.ip_address,
                "risk_score": asset.risk_score or 0.0,
                "severity": asset.severity_label or "LOW"
            })
            
            pred_info = predecessors[curr]
            if pred_info:
                u, rel_type, prob = pred_info
                path_edges.append({
                    "source": u,
                    "target": curr,
                    "type": rel_type,
                    "weight": prob
                })
                curr = u
            else:
                curr = None

        return {
            "nodes": path_nodes[::-1],
            "edges": path_edges[::-1],
            "total_probability": round(probabilities[target_asset_id], 4)
        }
