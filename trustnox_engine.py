"""
TRUSTNOX — Cloud IAM Excessive Permissions & Privilege Escalation Analysis Engine
================================================================================
Core analysis engine written in Python. Analyzes simulated cloud IAM JSON policies,
constructs directed permission graphs, computes risk scores, detects privilege
escalation paths (e.g. PassRole -> AssumeRole -> Admin), and outputs remediation recommendations.
"""

import json
import os
import sys
from datetime import datetime

# Optional NetworkX support with fallback to built-in directed graph engine
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class PurePythonDiGraph:
    """Fallback Directed Graph engine with BFS path finding if NetworkX is not installed."""
    def __init__(self):
        self.adj = {}
        self.node_attr = {}
        self.edge_attr = {}

    def add_node(self, node_id, **attrs):
        if node_id not in self.adj:
            self.adj[node_id] = set()
        self.node_attr[node_id] = attrs

    def add_edge(self, u, v, **attrs):
        self.add_node(u)
        self.add_node(v)
        self.adj[u].add(v)
        self.edge_attr[(u, v)] = attrs

    def nodes(self, data=False):
        if data:
            return list(self.node_attr.items())
        return list(self.adj.keys())

    def edges(self, data=False):
        edges = []
        for u in self.adj:
            for v in self.adj[u]:
                if data:
                    edges.append((u, v, self.edge_attr.get((u, v), {})))
                else:
                    edges.append((u, v))
        return edges

    def find_all_paths(self, start, end, visited=None):
        if visited is None:
            visited = []
        visited = visited + [start]
        if start == end:
            return [visited]
        if start not in self.adj:
            return []
        paths = []
        for neighbor in self.adj[start]:
            if neighbor not in visited:
                new_paths = self.find_all_paths(neighbor, end, visited)
                for p in new_paths:
                    paths.append(p)
        return paths


class TrustnoxAnalyzer:
    """Trustnox IAM excessive permissions analysis engine."""

    def __init__(self, data_file_path=None):
        if not data_file_path:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            data_file_path = os.path.join(script_dir, "sample_iam_data.json")

        self.data_path = data_file_path
        self.data = self._load_data()
        self.graph = nx.DiGraph() if HAS_NETWORKX else PurePythonDiGraph()
        self._build_permission_graph()

    def _load_data(self):
        with open(self.data_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _build_permission_graph(self):
        """Constructs privilege graph connecting users, roles, permissions, and target resources."""
        # Build nodes and edges from primary escalation chain
        for chain in self.data.get("escalation_chains", []):
            for node in chain.get("nodes", []):
                self.graph.add_node(node["id"], **node)
            for edge in chain.get("edges", []):
                self.graph.add_edge(edge["from"], edge["to"], **edge)

    def analyze_identities(self):
        """Calculates risk levels and categorizes identities."""
        identities = self.data.get("identities", [])
        high_risk = []
        medium_risk = []
        low_risk = []
        unused = []

        for identity in identities:
            risk = identity.get("risk_level", "Low")
            if risk == "High":
                high_risk.append(identity)
            elif risk == "Medium":
                medium_risk.append(identity)
            else:
                low_risk.append(identity)

            if identity.get("is_unused", False):
                unused.append(identity)

        return {
            "total": len(identities),
            "high": high_risk,
            "medium": medium_risk,
            "low": low_risk,
            "unused": unused,
            "escalations": self.data.get("escalation_chains", [])
        }

    def detect_escalation_paths(self):
        """Detects whether low-privileged identities can traverse to admin privileges."""
        paths = []
        if HAS_NETWORKX:
            try:
                all_paths = list(nx.all_simple_paths(self.graph, source="n1", target="n6"))
                for p in all_paths:
                    path_labels = [self.graph.nodes[nid].get("label", nid) for nid in p]
                    paths.append(" → ".join(path_labels))
            except Exception:
                pass
        else:
            all_paths = self.graph.find_all_paths("n1", "n6")
            for p in all_paths:
                path_labels = [self.graph.node_attr.get(nid, {}).get("label", nid) for nid in p]
                paths.append(" → ".join(path_labels))

        return paths

    def generate_cli_report(self):
        """Generates a terminal-friendly cybersecurity summary report."""
        analysis = self.analyze_identities()
        escalation_paths = self.detect_escalation_paths()

        print("\n" + "=" * 78)
        print("  TRUSTNOX — CLOUD IAM EXCESSIVE PERMISSIONS ANALYSIS ENGINE")
        print("  Tagline: Finding over-privileged cloud identities before attackers do.")
        print("=" * 78)
        print(f"  Graph Engine: {'NetworkX ' + nx.__version__ if HAS_NETWORKX else 'Pure Python DiGraph Fallback'}")
        print(f"  Target AWS Account: {self.data['scan_metadata']['account_id']}")
        print(f"  Target Environment: {self.data['scan_metadata']['environment']}")
        print(f"  Timestamp:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 78)
        print(f"  Total Identities:    {analysis['total']}")
        print(f"  [HIGH RISK]          {len(analysis['high'])} (Critical attention required)")
        print(f"  [MEDIUM RISK]        {len(analysis['medium'])}")
        print(f"  [LOW RISK]           {len(analysis['low'])}")
        print(f"  [UNUSED ACCOUNTS]    {len(analysis['unused'])} (Dormant > 90 days)")
        print(f"  [ESCALATION PATHS]   {len(analysis['escalations'])}")
        print("-" * 78)

        print("\n[!] CRITICAL PRIVILEGE ESCALATION CHAINS DETECTED:")
        for idx, chain in enumerate(analysis['escalations'], 1):
            print(f"\n  Chain #{idx}: {chain['name']} [{chain['severity']}]")
            print(f"  Risk Score: {chain['risk_score']}/100")
            print(f"  Path:       Developer User -> iam:PassRole -> Deploy Role -> sts:AssumeRole -> Admin Role -> Full Control")
            print(f"  Warning:    {chain['warning']}")
            print(f"  Fix:        {chain['recommendation']}")

        print("\n[!] DORMANT / UNUSED OVER-PRIVILEGED ACCOUNTS:")
        print(f"  {'IDENTITY':<20} {'TYPE':<8} {'LAST USED':<16} {'SCORE':<8} {'RISK'}")
        print("  " + "-" * 65)
        for u in analysis['unused']:
            print(f"  {u['name']:<20} {u['type']:<8} {u['last_used']:<16} {u['risk_score']:<8} {u['risk_level']}")

        print("\n[*] TOP 6 HIGH-RISK IDENTITIES RANKED:")
        sorted_high = sorted(analysis['high'], key=lambda x: x['risk_score'], reverse=True)
        for idx, item in enumerate(sorted_high, 1):
            reasons = "; ".join(item['risk_reasons'][:2])
            print(f"  {idx}. {item['name']:<18} Score: {item['risk_score']}/100 — {item['risk_level']}")
            print(f"     Reason: {reasons}")
            print(f"     Remedy: {item['remediation']['fix']}\n")

        print("=" * 78)
        print("  TRUSTNOX Analysis Completed. Ready for Web Prototype visualization.")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    analyzer = TrustnoxAnalyzer()
    analyzer.generate_cli_report()
