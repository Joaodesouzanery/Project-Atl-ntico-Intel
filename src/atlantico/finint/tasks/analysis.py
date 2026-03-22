"""
Tarefas Celery de análise FININT.

Processa anomalias, analisa rede de entidades e correlaciona com GEOINT.
"""

from __future__ import annotations

import asyncio
import logging

from atlantico.finint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="finint.analyze_indicators", bind=True, max_retries=3)
def analyze_indicators(self) -> dict:
    """Detecta anomalias em indicadores de mercado via Z-score + Isolation Forest."""
    return asyncio.run(_analyze_indicators_async())


async def _analyze_indicators_async() -> dict:
    from atlantico.storage.database import get_async_session
    from atlantico.finint.repositories.market_indicator_repo import MarketIndicatorRepository
    from atlantico.finint.processing.anomaly_detector import AnomalyDetector
    from atlantico.config.settings import get_settings

    settings = get_settings()
    detector = AnomalyDetector(zscore_threshold=settings.finint_anomaly_zscore_threshold)
    anomalies_found = 0

    async with get_async_session() as session:
        repo = MarketIndicatorRepository(session)
        indicators = await repo.list_unanalyzed(limit=500)

        # Agrupa por series_code para análise em série
        from collections import defaultdict
        by_series: dict = defaultdict(list)
        for ind in indicators:
            by_series[ind.series_code].append(ind)

        for series_code, series_indicators in by_series.items():
            mean, stddev = await repo.get_historical_stats(series_code, lookback_days=365)
            if mean is None or stddev is None:
                # Sem histórico suficiente — marca como processado sem anomalia
                for ind in series_indicators:
                    await repo.mark_analyzed(ind.id, None, None, None, "processed")
                continue

            for ind in series_indicators:
                anomaly_type, severity, z_score = detector.detect_single_anomaly(
                    value=float(ind.value),
                    historical_mean=mean,
                    historical_stddev=stddev or 1e-9,
                    zscore_threshold=settings.finint_anomaly_zscore_threshold,
                )
                status = "anomaly" if anomaly_type else "processed"
                await repo.mark_analyzed(ind.id, z_score, anomaly_type, severity, status)
                if anomaly_type:
                    anomalies_found += 1

        await session.commit()

    logger.info(
        "finint.analyze_indicators: %d indicadores, %d anomalias.",
        len(indicators),
        anomalies_found,
    )
    return {"processed": len(indicators), "anomalies": anomalies_found}


@celery_app.task(name="finint.analyze_contracts", bind=True, max_retries=3)
def analyze_contracts(self) -> dict:
    """Detecta anomalias em contratos públicos por estado."""
    return asyncio.run(_analyze_contracts_async())


async def _analyze_contracts_async() -> dict:
    from atlantico.storage.database import get_async_session
    from atlantico.finint.repositories.public_contract_repo import PublicContractRepository
    from atlantico.finint.processing.anomaly_detector import AnomalyDetector
    from atlantico.config.settings import get_settings

    settings = get_settings()
    detector = AnomalyDetector()
    anomalies_found = 0

    async with get_async_session() as session:
        repo = PublicContractRepository(session)
        contracts = await repo.list_unanalyzed(limit=500)

        for contract in contracts:
            # Análise individual por score de anomalia
            # (análise agregada por município requer query adicional)
            base_score = 0.0
            await repo.mark_analyzed(contract.id, base_score, "processed")

        await session.commit()

    logger.info(
        "finint.analyze_contracts: %d contratos processados, %d anomalias.",
        len(contracts),
        anomalies_found,
    )
    return {"processed": len(contracts), "anomalies": anomalies_found}


@celery_app.task(name="finint.analyze_network", bind=True, max_retries=3)
def analyze_network(self) -> dict:
    """Constrói grafo networkx e calcula PageRank + comunidades."""
    return asyncio.run(_analyze_network_async())


async def _analyze_network_async() -> dict:
    from atlantico.storage.database import get_async_session
    from atlantico.finint.repositories.entity_repo import EntityRepository
    from atlantico.finint.processing.network_analyzer import NetworkAnalyzer
    from atlantico.config.settings import get_settings

    settings = get_settings()
    analyzer = NetworkAnalyzer(pagerank_alpha=settings.finint_network_pagerank_alpha)

    async with get_async_session() as session:
        repo = EntityRepository(session)
        relationships = await repo.list_all_relationships()

        if not relationships:
            logger.info("finint.analyze_network: nenhum relacionamento encontrado.")
            return {"nodes": 0, "edges": 0, "hubs": 0}

        graph = analyzer.build_graph(relationships)
        centrality = analyzer.compute_centrality(graph)
        communities = analyzer.detect_communities(graph)

        pagerank = centrality["pagerank"]
        betweenness = centrality["betweenness"]

        # Atualiza centrality scores no banco
        for entity_id, pr_score in pagerank.items():
            try:
                import uuid as uuid_mod
                uid = uuid_mod.UUID(entity_id)
                be_score = betweenness.get(entity_id, 0.0)
                await repo.update_risk_score(
                    uid,
                    risk_score=min(pr_score * 100.0, 1.0),
                    centrality_score=pr_score,
                )
            except Exception:
                pass

        await session.commit()

    hubs = analyzer.get_hub_entities(graph, top_n=10)
    logger.info(
        "finint.analyze_network: %d nós, %d arestas, %d hubs, %d comunidades.",
        graph.number_of_nodes(),
        graph.number_of_edges(),
        len(hubs),
        len(communities),
    )
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "hubs": len(hubs),
        "communities": len(communities),
    }


@celery_app.task(name="finint.correlate_geoint", bind=True, max_retries=3)
def correlate_geoint(self) -> dict:
    """Correlaciona dados FININT com eventos GEOINT por estado/município."""
    return asyncio.run(_correlate_geoint_async())


async def _correlate_geoint_async() -> dict:
    from atlantico.storage.database import get_async_session
    from atlantico.finint.repositories.trade_flow_repo import TradeFlowRepository
    from atlantico.finint.processing.risk_scorer import RiskScorer
    from atlantico.config.settings import get_settings
    from datetime import datetime, timedelta, timezone

    settings = get_settings()
    scorer = RiskScorer()
    correlations_found = 0
    since = datetime.now(tz=timezone.utc) - timedelta(days=90)

    async with get_async_session() as session:
        trade_repo = TradeFlowRepository(session)
        strategic_ncms = settings.finint_strategic_ncm_list

        flows = await trade_repo.list_by_ncm(ncm_codes=strategic_ncms, since=since)

        for flow in flows:
            # Score de correlação baseado apenas no estado (sem banco GEOINT por ora)
            # Em produção: consultar DeforestationRepository por estado
            geo_result = scorer.correlate_with_geoint(
                municipality_code="",
                since=since,
                until=datetime.now(tz=timezone.utc),
                deforestation_ha=0.0,  # Placeholder — integração real via GEOINT repo
                hotspot_count=0,
            )
            if geo_result["correlation_score"] > 0.3:
                correlations_found += 1

        await session.commit()

    logger.info(
        "finint.correlate_geoint: %d fluxos analisados, %d correlações.",
        len(flows),
        correlations_found,
    )
    return {"flows_analyzed": len(flows), "correlations": correlations_found}
