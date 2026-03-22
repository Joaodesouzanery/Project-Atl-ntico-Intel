"""
NetworkAnalyzer — Análise de rede de entidades financeiras com networkx.

Constrói um DiGraph de relacionamentos entre entidades e calcula:
- PageRank (hubs de lavagem de dinheiro)
- Betweenness centrality (intermediários/"laranjas")
- Detecção de comunidades (Louvain)
- Caminhos suspeitos entre entidades

Não importa oqs — sem crypto direto neste módulo.
"""

from __future__ import annotations

import logging
import math
from typing import Any

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """
    Analisa redes de relacionamentos financeiros.

    Usa networkx.DiGraph internamente. Instância é stateless —
    cada chamada a build_graph() retorna um grafo independente.
    """

    def __init__(self, pagerank_alpha: float = 0.85) -> None:
        self._alpha = pagerank_alpha

    def build_graph(self, relationships: list[Any]) -> "networkx.DiGraph":
        """
        Constrói DiGraph networkx a partir de lista de EntityRelationship.

        Cada objeto deve ter: source_entity_id, target_entity_id,
        relationship_type, strength, total_value_brl.

        Peso da aresta: strength * log1p(total_value_brl)
        """
        import networkx as nx

        G = nx.DiGraph()

        for rel in relationships:
            src = str(rel.source_entity_id)
            tgt = str(rel.target_entity_id)
            weight = float(rel.strength or 1.0) * math.log1p(
                float(rel.total_value_brl or 0)
            )
            if G.has_edge(src, tgt):
                G[src][tgt]["weight"] += weight
                G[src][tgt]["transaction_count"] += int(rel.transaction_count or 1)
            else:
                G.add_edge(
                    src,
                    tgt,
                    weight=max(weight, 0.001),  # Mínimo para PageRank
                    relationship_type=rel.relationship_type,
                    transaction_count=int(rel.transaction_count or 1),
                )

        logger.debug(
            "NetworkAnalyzer: grafo com %d nós e %d arestas.",
            G.number_of_nodes(),
            G.number_of_edges(),
        )
        return G

    def compute_centrality(
        self,
        graph: "networkx.DiGraph",
    ) -> dict[str, dict[str, float]]:
        """
        Calcula PageRank e betweenness centrality.

        Returns:
            dict com keys "pagerank" e "betweenness":
            {entity_id: score}
        """
        import networkx as nx

        if graph.number_of_nodes() == 0:
            return {"pagerank": {}, "betweenness": {}}

        try:
            pagerank = nx.pagerank(graph, alpha=self._alpha, weight="weight")
        except Exception as exc:
            logger.warning("PageRank falhou: %s — usando scores iguais.", exc)
            n = graph.number_of_nodes()
            pagerank = {node: 1.0 / n for node in graph.nodes()}

        try:
            betweenness = nx.betweenness_centrality(graph, weight="weight", normalized=True)
        except Exception as exc:
            logger.warning("Betweenness falhou: %s", exc)
            betweenness = {node: 0.0 for node in graph.nodes()}

        return {"pagerank": pagerank, "betweenness": betweenness}

    def detect_communities(
        self,
        graph: "networkx.DiGraph",
    ) -> list[set[str]]:
        """
        Detecta comunidades usando Louvain (networkx).

        Converte DiGraph para undirected para o algoritmo.

        Returns:
            Lista de sets de entity_ids (cada set = uma comunidade)
        """
        import networkx as nx

        if graph.number_of_nodes() < 2:
            return [set(graph.nodes())] if graph.number_of_nodes() > 0 else []

        try:
            # Louvain requer grafo não-direcionado
            undirected = graph.to_undirected()
            communities = nx.algorithms.community.louvain_communities(
                undirected,
                weight="weight",
                seed=42,
            )
            return [set(c) for c in communities]
        except Exception as exc:
            logger.warning("Louvain falhou: %s — retornando comunidade única.", exc)
            return [set(graph.nodes())]

    def find_suspicious_paths(
        self,
        graph: "networkx.DiGraph",
        source_id: str,
        target_id: str,
        max_hops: int = 4,
    ) -> list[list[str]]:
        """
        Encontra todos os caminhos simples entre source e target com até max_hops.

        Útil para detectar conexões indiretas entre entidades suspeitas e
        órgãos públicos ou mineradoras.
        """
        import networkx as nx

        if source_id not in graph or target_id not in graph:
            return []

        try:
            paths = list(
                nx.all_simple_paths(
                    graph,
                    source=source_id,
                    target=target_id,
                    cutoff=max_hops,
                )
            )
            return paths
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        except Exception as exc:
            logger.warning("find_suspicious_paths erro: %s", exc)
            return []

    def get_hub_entities(
        self,
        graph: "networkx.DiGraph",
        top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Retorna as top_n entidades por PageRank.

        Hubs com alto PageRank são candidatos a nós centrais de lavagem.
        """
        centrality = self.compute_centrality(graph)
        pagerank = centrality["pagerank"]
        betweenness = centrality["betweenness"]

        sorted_entities = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:top_n]

        return [
            {
                "entity_id": entity_id,
                "pagerank": score,
                "betweenness": betweenness.get(entity_id, 0.0),
                "out_degree": graph.out_degree(entity_id),
                "in_degree": graph.in_degree(entity_id),
            }
            for entity_id, score in sorted_entities
        ]
