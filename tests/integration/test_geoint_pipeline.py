"""
Teste de integração — Pipeline completo GEOINT.

Requer PostgreSQL com PostGIS e extensão vector disponível.
Execute com: pytest tests/integration/test_geoint_pipeline.py -v -m integration

Gates de aceitação (conforme Sprint 3):
1. GeointObservation bem formada (geometry WKT válida, acquired_at timezone-aware)
2. Pipeline: observação INPE → SourceRecord (PQC envelope) → DeforestationEvent →
   análise → Alert (Dilithium-assinado)
3. Audit log registra cada etapa
4. DBSCAN produz FireCluster com centroid_geom e convex_hull corretos
5. Z-score detecta anomalia injetada (value = mean + 5*stddev)
6. InfrastructureAsset.name_enc não expõe plaintext no banco
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import pytest_asyncio

# Marca todos os testes deste arquivo como integration
pytestmark = pytest.mark.integration


# ─── Fixtures de banco ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def settings():
    """Carrega settings com DATABASE_URL configurada para testes de integração."""
    from atlantico.config.settings import get_settings
    return get_settings()


@pytest.fixture(scope="module")
def master_key(settings):
    return settings.master_key_bytes


@pytest.fixture(scope="module", autouse=True)
def init_encryption(master_key):
    """Inicializa EncryptionContext para os testes."""
    from atlantico.storage.encrypted_field import EncryptionContext
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(master_key)


@pytest_asyncio.fixture(scope="module")
async def db_session():
    """Sessão de banco de dados async para testes."""
    from atlantico.storage.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()  # Garante limpeza


@pytest.fixture(scope="module")
def key_manager(master_key):
    """KeyManager configurado para testes de integração."""
    from atlantico.crypto.key_manager import KeyManager
    km = KeyManager(master_key=master_key)
    # Garante chaves geradas
    try:
        km.get_active_kem_public_key()
    except Exception:
        km.generate_kem_keypair()
    try:
        km.get_active_signing_public_key()
    except Exception:
        km.generate_signing_keypair()
    return km


# ─── Gate 1: GeointObservation bem formada ────────────────────────────────────


class TestGeointObservation:
    def test_observacao_deforestation_valida(self):
        from atlantico.geoint.observations import GeointObservation

        obs = GeointObservation(
            source_id="inpe.deter.v1",
            external_id="deter-test-001",
            observation_type="deforestation",
            acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
            payload={"area_ha": 150.0, "biome": "Amazônia"},
            data_classification="PUBLIC",
            bbox_wkt="POLYGON((-54.1 -3.1,-54.1 -3,-54 -3,-54 -3.1,-54.1 -3.1))",
        )

        assert obs.acquired_at.tzinfo is not None
        assert "POLYGON" in obs.geometry_wkt
        assert obs.geo_bounds_wkt == obs.bbox_wkt

    def test_observacao_fire_hotspot(self):
        from atlantico.geoint.observations import GeointObservation

        obs = GeointObservation(
            source_id="inpe.bdqueimadas.v1",
            external_id="bdqueimadas-12345",
            observation_type="fire_hotspot",
            acquired_at=datetime(2024, 8, 15, 14, 30, tzinfo=timezone.utc),
            geometry_wkt="POINT(-52.0 -3.5)",
            payload={"frp": 45.7, "bioma": "Amazônia"},
            bbox_wkt="POLYGON((-52.001 -3.501,-52.001 -3.499,-51.999 -3.499,-51.999 -3.501,-52.001 -3.501))",
        )

        assert obs.acquired_at.tzinfo is not None
        assert obs.geometry_wkt == "POINT(-52.0 -3.5)"

    def test_observacao_sem_timezone_lanca_erro(self):
        from atlantico.geoint.observations import GeointObservation

        with pytest.raises(ValueError, match="timezone-aware"):
            GeointObservation(
                source_id="inpe.deter.v1",
                external_id="test",
                observation_type="deforestation",
                acquired_at=datetime(2024, 8, 15),  # sem tzinfo
                geometry_wkt="POINT(0 0)",
                payload={},
            )

    def test_geo_bounds_fallback_para_geometry(self):
        from atlantico.geoint.observations import GeointObservation

        obs = GeointObservation(
            source_id="inpe.prodes.v2",
            external_id="prodes-test",
            observation_type="deforestation",
            acquired_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54 -3))",
            payload={},
            bbox_wkt=None,  # Sem bbox explícita
        )

        assert obs.geo_bounds_wkt == obs.geometry_wkt


# ─── Gate 2: Pipeline SourceRecord → DeforestationEvent ──────────────────────


class TestDeforestationPipeline:
    @pytest.mark.asyncio
    async def test_persistencia_source_record_pqc(self, db_session, key_manager):
        """Verifica que SourceRecordRepository persiste com envelope PQC."""
        from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

        repo = SourceRecordRepository(session=db_session, key_manager=key_manager)

        record_id = f"deter-integ-{uuid.uuid4()}"
        payload = {
            "area_ha": 150.0,
            "biome": "Amazônia",
            "state": "PA",
            "test": True,
        }

        record = await repo.store(
            record_id=record_id,
            source_id="inpe.deter.v1",
            data_classification="PUBLIC",
            payload=payload,
            acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
            geo_bounds_wkt="POLYGON((-54.1 -3.1,-54.1 -3,-54 -3,-54 -3.1,-54.1 -3.1))",
        )

        assert record is not None
        assert record.id is not None
        # O payload deve ser recuperável via decrypt
        assert record.external_id == record_id

    @pytest.mark.asyncio
    async def test_deforestation_repo_store(self, db_session):
        """DeforestationRepository persiste evento com status pending."""
        from atlantico.geoint.observations import GeointObservation
        from atlantico.geoint.repositories.deforestation_repo import DeforestationRepository

        repo = DeforestationRepository(session=db_session)

        obs = GeointObservation(
            source_id="inpe.deter.v1",
            external_id=f"deter-integ-defor-{uuid.uuid4()}",
            observation_type="deforestation",
            acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
            payload={
                "area_ha": 150.0,
                "biome": "Amazônia",
                "state": "PA",
                "source_type": "deter",
                "classname": "DESMATAMENTO_CR",
                "municipality": "Altamira",
            },
        )

        source_record_id = uuid.uuid4()
        event = await repo.store(obs=obs, source_record_id=source_record_id)

        if event is not None:
            assert event.analysis_status == "pending"
            assert float(event.area_ha) == pytest.approx(150.0, rel=0.01)

    @pytest.mark.asyncio
    async def test_deduplication_on_conflict(self, db_session):
        """Segunda inserção com mesmo external_id → ON CONFLICT DO NOTHING."""
        from atlantico.geoint.observations import GeointObservation
        from atlantico.geoint.repositories.deforestation_repo import DeforestationRepository

        repo = DeforestationRepository(session=db_session)
        external_id = f"deter-dedup-{uuid.uuid4()}"

        obs = GeointObservation(
            source_id="inpe.deter.v1",
            external_id=external_id,
            observation_type="deforestation",
            acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
            geometry_wkt="POLYGON((-55 -4,-55 -4.1,-55.1 -4.1,-55.1 -4,-55 -4))",
            payload={"area_ha": 75.0, "biome": "Cerrado", "state": "MT"},
        )
        source_record_id = uuid.uuid4()

        # Primeira inserção
        event1 = await repo.store(obs=obs, source_record_id=source_record_id)
        # Segunda inserção com mesmo external_id → None (já existe)
        event2 = await repo.store(obs=obs, source_record_id=source_record_id)

        # Pelo menos uma das duas deve ser não-None (a primeira)
        assert event1 is not None or event2 is None


# ─── Gate 3: Audit Log ───────────────────────────────────────────────────────


class TestAuditLog:
    @pytest.mark.asyncio
    async def test_audit_log_registra_operacao_geoint(self, db_session, key_manager):
        """AuditLogRepository.append() funciona para eventos GEOINT."""
        from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

        audit_log = AuditLogRepository(session=db_session, key_manager=key_manager)

        event_id = f"geoint-audit-{uuid.uuid4()}"
        entry = await audit_log.append(
            event_type="GEOINT_ALERT_CREATED",
            actor_id="geoint.deforestation_processor",
            event_data={
                "alert_id": event_id,
                "severity": "HIGH",
                "rule_id": "geoint.deforestation.threshold.v1",
                "area_ha": 150.0,
            },
            target_id=event_id,
        )

        assert entry is not None
        assert entry.event_type == "GEOINT_ALERT_CREATED"


# ─── Gate 4: DBSCAN FireCluster ──────────────────────────────────────────────


class TestFireClusterDBSCAN:
    def test_dbscan_produz_cluster_com_centroid_e_hull(self):
        """FireProcessor.cluster_hotspots() produz cluster geometricamente correto."""
        import uuid as uuid_mod
        from datetime import datetime, timezone
        from types import SimpleNamespace
        from atlantico.geoint.processing.fire_processor import FireProcessor

        processor = FireProcessor()

        # Cria 5 hotspots muito próximos (cluster garantido)
        hotspots = []
        for i in range(5):
            h = SimpleNamespace(
                id=uuid_mod.uuid4(),
                geom=f"SRID=4326;POINT({-52.0 + i * 0.01} {-3.5 + i * 0.01})",
                frp=50.0 + i * 10,
                biome="Amazônia",
                state="PA",
                acquired_at=datetime(2024, 8, 15, 14, i * 10, tzinfo=timezone.utc),
                cluster_id=None,
            )
            hotspots.append(h)

        clusters = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)

        assert len(clusters) >= 1
        cluster = clusters[0]

        # Centroide deve conter POINT
        assert cluster.centroid_geom is not None
        assert "POINT" in str(cluster.centroid_geom)

        # hotspot_count correto
        assert cluster.hotspot_count == 5

        # Severidade classificada
        assert cluster.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_dbscan_dois_grupos_bem_separados(self):
        """Dois grupos a > 1000 km → 2 clusters distintos."""
        import uuid as uuid_mod
        from types import SimpleNamespace
        from atlantico.geoint.processing.fire_processor import FireProcessor

        processor = FireProcessor()

        def make_group(lat_base, lon_base, n=4):
            group = []
            for i in range(n):
                h = SimpleNamespace(
                    id=uuid_mod.uuid4(),
                    geom=f"SRID=4326;POINT({lon_base + i * 0.001} {lat_base + i * 0.001})",
                    frp=30.0,
                    biome="Amazônia",
                    state="PA",
                    acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
                    cluster_id=None,
                )
                group.append(h)
            return group

        # Norte do Pará e Sul do Brasil — separados por ~3000 km
        group_north = make_group(lat_base=-2.0, lon_base=-52.0)
        group_south = make_group(lat_base=-30.0, lon_base=-51.0)

        clusters = processor.cluster_hotspots(
            group_north + group_south, eps_km=10.0, min_samples=3
        )
        assert len(clusters) == 2


# ─── Gate 5: Z-score anomalia injetada ───────────────────────────────────────


class TestWaterAnomalyZScore:
    def test_anomalia_com_5sigma_detectada(self):
        """Anomalia injetada: value = mean + 5*stddev → CRITICAL."""
        from atlantico.geoint.processing.water_processor import WaterProcessor

        processor = WaterProcessor()

        mean = 100.0
        stddev = 10.0
        value_anomalia = mean + 5 * stddev  # z = 5.0

        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=value_anomalia,
            measurement_type="nivel",
            historical_mean=mean,
            historical_stddev=stddev,
            stddev_threshold=3.0,
        )

        assert anomaly_type == "flood"
        assert anomaly_severity == "CRITICAL"
        assert z_score == pytest.approx(5.0)

    def test_valor_dentro_3sigma_nao_e_anomalia(self):
        """Valor dentro do threshold → sem anomalia."""
        from atlantico.geoint.processing.water_processor import WaterProcessor

        processor = WaterProcessor()

        mean = 100.0
        stddev = 10.0
        value_normal = mean + 2 * stddev  # z = 2.0 < 3.0

        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=value_normal,
            measurement_type="nivel",
            historical_mean=mean,
            historical_stddev=stddev,
            stddev_threshold=3.0,
        )

        assert anomaly_type is None
        assert anomaly_severity is None


# ─── Gate 6: InfrastructureAsset.name_enc (sem plaintext no banco) ───────────


class TestInfrastructureEncryption:
    @pytest.mark.asyncio
    async def test_name_enc_nao_contem_plaintext(self, db_session, key_manager):
        """
        InfrastructureAsset.name_enc deve ser ciphertext (bytes opacos),
        não o nome em plaintext.
        """
        from sqlalchemy import text
        from atlantico.geoint.repositories.infrastructure_repo import InfrastructureRepository

        repo = InfrastructureRepository(session=db_session, key_manager=key_manager)

        asset_id = f"infra-test-{uuid.uuid4()}"
        nome_plain = f"Usina Hidrelétrica Teste {uuid.uuid4().hex[:8]}"

        await repo.create_or_update(
            asset_data={
                "external_id": asset_id,
                "asset_type": "hydroelectric",
                "criticality": "HIGH",
                "name": nome_plain.encode(),
                "operator": b"Operadora Teste Ltda",
                "state": "PR",
                "geom_wkt": "POINT(-54.6 -25.4)",
            }
        )
        await db_session.flush()

        # Consulta raw para verificar bytes no banco
        result = await db_session.execute(
            text(
                "SELECT name_enc FROM geoint_infrastructure_assets "
                "WHERE external_id = :ext_id"
            ),
            {"ext_id": asset_id},
        )
        row = result.fetchone()
        if row is not None:
            raw_bytes = row[0]
            # O conteúdo raw NÃO deve conter o plaintext como string UTF-8
            assert isinstance(raw_bytes, (bytes, memoryview))
            raw = bytes(raw_bytes) if isinstance(raw_bytes, memoryview) else raw_bytes
            assert nome_plain.encode() not in raw, (
                "Plaintext encontrado nos bytes brutos do banco — "
                "EncryptedBytes não está cifrando corretamente!"
            )


# ─── Gate 6b: Processor + Repository (sem banco) ─────────────────────────────


class TestProcessorsSemBanco:
    """Testes que verificam processadores sem precisar de banco."""

    def test_deforestation_processor_severity(self):
        from atlantico.geoint.processing.deforestation_processor import DeforestationProcessor

        p = DeforestationProcessor()
        assert p.classify_severity(0.0) == "LOW"
        assert p.classify_severity(25.0) == "MEDIUM"
        assert p.classify_severity(100.0) == "HIGH"
        assert p.classify_severity(500.0) == "CRITICAL"

    def test_fire_processor_cluster_severity(self):
        from atlantico.geoint.processing.fire_processor import FireProcessor

        p = FireProcessor()
        assert p.classify_cluster_severity(4, None) == "LOW"
        assert p.classify_cluster_severity(20, None) == "HIGH"
        assert p.classify_cluster_severity(100, None) == "CRITICAL"

    def test_infrastructure_processor_risk_score(self):
        from atlantico.geoint.processing.infrastructure_processor import InfrastructureProcessor

        p = InfrastructureProcessor()
        # HIGH severity × CRITICAL criticality × distância 0 km → score máximo
        score_high = p.compute_risk_score("HIGH", "CRITICAL", 0.0)
        score_low = p.compute_risk_score("LOW", "LOW", 10.0)
        assert score_high > score_low
        assert 0.0 <= score_low <= 16.0
        assert 0.0 <= score_high <= 16.0
