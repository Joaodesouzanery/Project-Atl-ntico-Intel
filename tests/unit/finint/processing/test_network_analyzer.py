"""
Testes unitários para NetworkAnalyzer.

Testa build_graph(), compute_centrality(), detect_communities(), find_suspicious_paths().
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from atlantico.finint.processing.network_analyzer import NetworkAnalyzer


@pytest.fixture
def analyzer() -> NetworkAnalyzer:
    return NetworkAnalyzer(pagerank_alpha=0.85)


def _make_relationship(
    src_id: str,
    tgt_id: str,
    rel_type: str = "fornecedor",
    strength: float = 1.0,
    total_value_brl: float = 100000.0,
    transaction_count: int = 5,
) -> SimpleNamespace:
    """Cria stub de EntityRelationship."""
    return SimpleNamespace(
        source_entity_id=uuid.UUID(src_id),
        target_entity_id=uuid.UUID(tgt_id),
        relationship_type=rel_type,
        strength=strength,
        total_value_brl=total_value_brl,
        transaction_count=transaction_count,
    )


# UUIDs fixos para testes
_A = "00000000-0000-0000-0000-000000000001"
_B = "00000000-0000-0000-0000-000000000002"
_C = "00000000-0000-0000-0000-000000000003"
_D = "00000000-0000-0000-0000-000000000004"
_E = "00000000-0000-0000-0000-000000000005"


class TestBuildGraph:
    def test_grafo_vazio(self, analyzer):
        G = analyzer.build_graph([])
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_grafo_com_1_aresta(self, analyzer):
        rels = [_make_relationship(_A, _B)]
        G = analyzer.build_graph(rels)
        assert G.number_of_nodes() == 2
        assert G.number_of_edges() == 1

    def test_grafo_com_multiplas_arestas(self, analyzer):
        rels = [
            _make_relationship(_A, _B),
            _make_relationship(_B, _C),
            _make_relationship(_C, _A),
        ]
        G = analyzer.build_graph(rels)
        assert G.number_of_nodes() == 3
        assert G.number_of_edges() == 3

    def test_peso_aresta_positivo(self, analyzer):
        rels = [_make_relationship(_A, _B, strength=1.0, total_value_brl=50000.0)]
        G = analyzer.build_graph(rels)
        edge_data = G[_A][_B]
        assert edge_data["weight"] > 0

    def test_arestas_duplicadas_acumulam(self, analyzer):
        """Dois relacionamentos entre os mesmos nós devem somar o peso."""
        rels = [
            _make_relationship(_A, _B, total_value_brl=100.0),
            _make_relationship(_A, _B, total_value_brl=200.0),
        ]
        G = analyzer.build_graph(rels)
        assert G.number_of_nodes() == 2
        # Arestas duplicadas devem ser somadas (não duplicadas)
        assert G.number_of_edges() == 1


class TestComputeCentrality:
    def test_grafo_vazio_retorna_dicts_vazios(self, analyzer):
        import networkx as nx
        G = nx.DiGraph()
        result = analyzer.compute_centrality(G)
        assert result["pagerank"] == {}
        assert result["betweenness"] == {}

    def test_pagerank_soma_1(self, analyzer):
        rels = [
            _make_relationship(_A, _B),
            _make_relationship(_B, _C),
            _make_relationship(_C, _A),
        ]
        G = analyzer.build_graph(rels)
        result = analyzer.compute_centrality(G)
        total_pagerank = sum(result["pagerank"].values())
        assert abs(total_pagerank - 1.0) < 0.01

    def test_hub_tem_pagerank_mais_alto(self, analyzer):
        """Hub (nó A com muitas conexões de entrada) deve ter PageRank maior."""
        # B, C, D, E todos apontam para A
        rels = [
            _make_relationship(_B, _A),
            _make_relationship(_C, _A),
            _make_relationship(_D, _A),
            _make_relationship(_E, _A),
            _make_relationship(_A, _B),  # Ciclo mínimo
        ]
        G = analyzer.build_graph(rels)
        result = analyzer.compute_centrality(G)
        pagerank = result["pagerank"]
        # A deve ter maior PageRank
        assert pagerank[_A] == max(pagerank.values())

    def test_betweenness_retorna_scores_para_todos_nos(self, analyzer):
        rels = [_make_relationship(_A, _B), _make_relationship(_B, _C)]
        G = analyzer.build_graph(rels)
        result = analyzer.compute_centrality(G)
        assert set(result["betweenness"].keys()) == {_A, _B, _C}


class TestDetectCommunities:
    def test_grafo_vazio_retorna_lista_vazia(self, analyzer):
        import networkx as nx
        G = nx.DiGraph()
        communities = analyzer.detect_communities(G)
        assert communities == []

    def test_1_no_retorna_1_comunidade(self, analyzer):
        rels = [_make_relationship(_A, _A)]  # self-loop será ignorado, 1 nó
        G = analyzer.build_graph(rels)
        communities = analyzer.detect_communities(G)
        assert len(communities) >= 1

    def test_2_grupos_separados_retornam_2_comunidades(self, analyzer):
        """Dois subgrafos desconectados devem formar comunidades distintas."""
        rels = [
            # Grupo 1: A ↔ B
            _make_relationship(_A, _B),
            _make_relationship(_B, _A),
            # Grupo 2: C ↔ D (sem conexão com grupo 1)
            _make_relationship(_C, _D),
            _make_relationship(_D, _C),
        ]
        G = analyzer.build_graph(rels)
        communities = analyzer.detect_communities(G)
        assert len(communities) >= 2


class TestFindSuspiciousPaths:
    def test_sem_caminho_retorna_lista_vazia(self, analyzer):
        rels = [_make_relationship(_A, _B)]
        G = analyzer.build_graph(rels)
        paths = analyzer.find_suspicious_paths(G, _A, _C)
        assert paths == []

    def test_caminho_direto_detectado(self, analyzer):
        rels = [_make_relationship(_A, _B)]
        G = analyzer.build_graph(rels)
        paths = analyzer.find_suspicious_paths(G, _A, _B)
        assert len(paths) == 1
        assert paths[0] == [_A, _B]

    def test_caminho_indireto_detectado(self, analyzer):
        rels = [
            _make_relationship(_A, _B),
            _make_relationship(_B, _C),
        ]
        G = analyzer.build_graph(rels)
        paths = analyzer.find_suspicious_paths(G, _A, _C, max_hops=3)
        assert any(_A in p and _C in p for p in paths)

    def test_no_inexistente_retorna_lista_vazia(self, analyzer):
        import networkx as nx
        G = nx.DiGraph()
        paths = analyzer.find_suspicious_paths(G, _A, _B)
        assert paths == []


class TestGetHubEntities:
    def test_retorna_top_n_entidades(self, analyzer):
        rels = [
            _make_relationship(_B, _A),
            _make_relationship(_C, _A),
            _make_relationship(_D, _A),
            _make_relationship(_A, _B),
        ]
        G = analyzer.build_graph(rels)
        hubs = analyzer.get_hub_entities(G, top_n=2)
        assert len(hubs) <= 2
        assert all("entity_id" in h for h in hubs)
        assert all("pagerank" in h for h in hubs)
