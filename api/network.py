"""POST /api/network — NetworkAnalyzer (PageRank, Louvain, betweenness)."""
from http.server import BaseHTTPRequestHandler
import json
import math


def _build_and_analyze(edges: list) -> dict:
    import networkx as nx
    from networkx.algorithms.community import louvain_communities

    G = nx.DiGraph()
    for e in edges:
        src, tgt = e["from"], e["to"]
        value = float(e.get("value", 1.0))
        weight = math.log1p(value)
        if G.has_edge(src, tgt):
            G[src][tgt]["weight"] += weight
        else:
            G.add_edge(src, tgt, weight=weight)

    if G.number_of_nodes() == 0:
        return {"nodes": [], "edges": [], "communities": [], "hubs": []}

    pagerank = nx.pagerank(G, alpha=0.85, weight="weight")
    betweenness = nx.betweenness_centrality(G, weight="weight", normalized=True)

    # Louvain on undirected version
    UG = G.to_undirected()
    try:
        communities_raw = louvain_communities(UG, seed=42)
        communities = [list(c) for c in communities_raw]
    except Exception:
        communities = [list(G.nodes())]

    # Build community map
    node_community = {}
    for idx, comm in enumerate(communities):
        for node in comm:
            node_community[node] = idx

    nodes_out = []
    for node in G.nodes():
        pr = pagerank.get(node, 0.0)
        bt = betweenness.get(node, 0.0)
        risk = min(pr * 100 * 0.6 + bt * 0.4, 1.0)
        nodes_out.append({
            "id": node,
            "pagerank": round(pr, 6),
            "betweenness": round(bt, 6),
            "in_degree": G.in_degree(node),
            "out_degree": G.out_degree(node),
            "community": node_community.get(node, 0),
            "risk_score": round(risk, 4),
        })

    nodes_out.sort(key=lambda x: x["pagerank"], reverse=True)
    hubs = nodes_out[:5]

    return {
        "nodes": nodes_out,
        "communities": communities,
        "hubs": hubs,
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
    }


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            edges = body.get("edges", [])
            if not edges:
                raise ValueError("Lista de arestas vazia.")
            result = _build_and_analyze(edges)
            self._respond(result)
        except Exception as exc:
            self._respond({"error": str(exc)}, 400)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _respond(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass
