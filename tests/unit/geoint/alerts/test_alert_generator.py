"""
Testes unitários para GeointAlertGenerator.

Testa:
- generate_deforestation_alert(): criação de alerta + audit log
- generate_fire_cluster_alert(): seleção de regra near_infrastructure
- generate_water_anomaly_alert(): sem anomaly_type → None
- Idempotência: evento já alertado → retorna None
- Severidade mapeada corretamente pelas AlertRules
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from atlantico.geoint.alerts.generator import GeointAlertGenerator
from atlantico.geoint.alerts.rules import ALERT_RULES


# ─── Helpers para criar stubs de objetos de domínio ───────────────────────────


def _make_deforestation_event(
    area_ha: float = 150.0,
    severity: str = "HIGH",
    analysis_status: str = "processed",
    state: str = "PA",
    biome: str = "Amazônia",
):
    """Stub de DeforestationEvent via SimpleNamespace (sem SQLAlchemy)."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        area_ha=Decimal(str(area_ha)),
        severity=severity,
        analysis_status=analysis_status,
        state=state,
        biome=biome,
        municipality="Altamira",
        source_type="deter",
        classname="DESMATAMENTO_CR",
        acquired_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
        geom="SRID=4326;POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
    )


def _make_fire_cluster(
    hotspot_count: int = 20,
    severity: str = "HIGH",
    near_infrastructure: bool = False,
    analysis_status: str = "pending",
):
    """Stub de FireCluster via SimpleNamespace (sem SQLAlchemy)."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        hotspot_count=hotspot_count,
        severity=severity,
        near_infrastructure=near_infrastructure,
        analysis_status=analysis_status,
        biome="Amazônia",
        state="PA",
        total_frp_mw=Decimal("500.0"),
        max_frp_mw=Decimal("80.0"),
        mean_frp_mw=Decimal("25.0"),
        min_acquired_at=datetime(2024, 8, 15, 6, 0, tzinfo=timezone.utc),
        max_acquired_at=datetime(2024, 8, 15, 18, 0, tzinfo=timezone.utc),
        centroid_geom="SRID=4326;POINT(-52.0 -3.5)",
    )


def _make_water_obs(
    value: float = 20.0,
    anomaly_type: str | None = "flood",
    anomaly_severity: str | None = "HIGH",
    z_score: float | None = 4.5,
    analysis_status: str = "pending",
):
    """Stub de WaterObservation via SimpleNamespace (sem SQLAlchemy)."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        station_code="17050001",
        station_name="Itaipu",
        measurement_type="nivel",
        value=Decimal(str(value)),
        unit="m",
        acquired_at=datetime(2024, 8, 15, 12, 0, tzinfo=timezone.utc),
        anomaly_type=anomaly_type,
        anomaly_severity=anomaly_severity,
        z_score=Decimal(str(z_score)) if z_score is not None else None,
        historical_mean=Decimal("10.0"),
        historical_stddev=Decimal("2.0"),
        analysis_status=analysis_status,
        geom="SRID=4326;POINT(-54.6 -25.4)",
    )


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_alert():
    alert = MagicMock()
    alert.id = "geoint-defor-test-uuid"
    return alert


@pytest.fixture
def alert_repo(mock_alert):
    repo = MagicMock()
    repo.create = AsyncMock(return_value=mock_alert)
    return repo


@pytest.fixture
def audit_log():
    log = MagicMock()
    log.append = AsyncMock(return_value=None)
    return log


@pytest.fixture
def generator(alert_repo, audit_log):
    return GeointAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)


# ─── generate_deforestation_alert ─────────────────────────────────────────────


class TestGenerateDeforestationAlert:
    @pytest.mark.asyncio
    async def test_cria_alerta_para_evento_valido(self, generator, alert_repo):
        event = _make_deforestation_event()
        alert = await generator.generate_deforestation_alert(
            event=event, source_record_ids=["rec-uuid-1"]
        )
        assert alert is not None
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_ja_alertado_retorna_none(self, generator, alert_repo):
        event = _make_deforestation_event(analysis_status="alerted")
        alert = await generator.generate_deforestation_alert(
            event=event, source_record_ids=[]
        )
        assert alert is None
        alert_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_id_usa_event_uuid(self, generator, alert_repo):
        event = _make_deforestation_event()
        await generator.generate_deforestation_alert(event=event, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["alert_id"] == f"geoint-defor-{event.id}"

    @pytest.mark.asyncio
    async def test_severidade_mapeada_corretamente(self, generator, alert_repo):
        event = _make_deforestation_event(severity="HIGH")
        await generator.generate_deforestation_alert(event=event, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        # ALERT_RULES["geoint.deforestation.threshold"].severity_mapping["HIGH"] == "HIGH"
        assert call_kwargs["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_rule_id_correto(self, generator, alert_repo):
        event = _make_deforestation_event()
        await generator.generate_deforestation_alert(event=event, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["rule_id"] == "geoint.deforestation.threshold.v1"

    @pytest.mark.asyncio
    async def test_titulo_contem_area_e_estado(self, generator, alert_repo):
        event = _make_deforestation_event(area_ha=150.0, state="PA")
        await generator.generate_deforestation_alert(event=event, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert "150" in call_kwargs["title"]
        assert "PA" in call_kwargs["title"]

    @pytest.mark.asyncio
    async def test_audit_log_chamado(self, generator, audit_log):
        event = _make_deforestation_event()
        await generator.generate_deforestation_alert(event=event, source_record_ids=[])

        audit_log.append.assert_called_once()
        call_kwargs = audit_log.append.call_args[1]
        assert call_kwargs["event_type"] == "GEOINT_ALERT_CREATED"
        assert call_kwargs["actor_id"] == "geoint.deforestation_processor"

    @pytest.mark.asyncio
    async def test_source_record_ids_passados_corretamente(self, generator, alert_repo):
        event = _make_deforestation_event()
        src_ids = ["rec-a", "rec-b"]
        await generator.generate_deforestation_alert(event=event, source_record_ids=src_ids)

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["source_record_ids"] == src_ids

    @pytest.mark.asyncio
    async def test_regra_near_infrastructure_eleva_severidade(self, generator, alert_repo):
        """LOW evento + near_infrastructure rule → MEDIUM alerta."""
        event = _make_deforestation_event(severity="LOW")
        await generator.generate_deforestation_alert(
            event=event,
            source_record_ids=[],
            rule_key="geoint.deforestation.near_infrastructure",
        )
        call_kwargs = alert_repo.create.call_args[1]
        # severity_mapping: LOW → MEDIUM
        assert call_kwargs["severity"] == "MEDIUM"


# ─── generate_fire_cluster_alert ──────────────────────────────────────────────


class TestGenerateFireClusterAlert:
    @pytest.mark.asyncio
    async def test_cria_alerta_para_cluster(self, generator, alert_repo):
        cluster = _make_fire_cluster()
        alert = await generator.generate_fire_cluster_alert(
            cluster=cluster, source_record_ids=[]
        )
        assert alert is not None
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_ja_alertado_retorna_none(self, generator, alert_repo):
        cluster = _make_fire_cluster(analysis_status="alerted")
        alert = await generator.generate_fire_cluster_alert(
            cluster=cluster, source_record_ids=[]
        )
        assert alert is None
        alert_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_near_infrastructure_usa_regra_correta(self, generator, alert_repo):
        cluster = _make_fire_cluster(near_infrastructure=True)
        await generator.generate_fire_cluster_alert(cluster=cluster, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["rule_id"] == "geoint.fire.near_infrastructure.v1"

    @pytest.mark.asyncio
    async def test_sem_infraestrutura_usa_regra_cluster_large(self, generator, alert_repo):
        cluster = _make_fire_cluster(near_infrastructure=False)
        await generator.generate_fire_cluster_alert(cluster=cluster, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["rule_id"] == "geoint.fire.cluster_large.v1"

    @pytest.mark.asyncio
    async def test_near_infrastructure_eleva_severidade_high_para_critical(
        self, generator, alert_repo
    ):
        """HIGH cluster near_infra → CRITICAL alerta."""
        cluster = _make_fire_cluster(severity="HIGH", near_infrastructure=True)
        await generator.generate_fire_cluster_alert(cluster=cluster, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_alert_id_usa_cluster_uuid(self, generator, alert_repo):
        cluster = _make_fire_cluster()
        await generator.generate_fire_cluster_alert(cluster=cluster, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["alert_id"] == f"geoint-fire-{cluster.id}"

    @pytest.mark.asyncio
    async def test_audit_log_registrado(self, generator, audit_log):
        cluster = _make_fire_cluster()
        await generator.generate_fire_cluster_alert(cluster=cluster, source_record_ids=[])

        audit_log.append.assert_called_once()
        call_kwargs = audit_log.append.call_args[1]
        assert call_kwargs["actor_id"] == "geoint.fire_processor"


# ─── generate_water_anomaly_alert ─────────────────────────────────────────────


class TestGenerateWaterAnomalyAlert:
    @pytest.mark.asyncio
    async def test_cria_alerta_para_anomalia(self, generator, alert_repo):
        obs = _make_water_obs(anomaly_type="flood", anomaly_severity="HIGH")
        alert = await generator.generate_water_anomaly_alert(
            observation=obs, source_record_ids=[]
        )
        assert alert is not None
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_sem_anomaly_type_retorna_none(self, generator, alert_repo):
        obs = _make_water_obs(anomaly_type=None, anomaly_severity=None)
        alert = await generator.generate_water_anomaly_alert(
            observation=obs, source_record_ids=[]
        )
        assert alert is None
        alert_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_ja_alertado_retorna_none(self, generator, alert_repo):
        obs = _make_water_obs(analysis_status="alerted")
        alert = await generator.generate_water_anomaly_alert(
            observation=obs, source_record_ids=[]
        )
        assert alert is None
        alert_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_id_usa_observation_uuid(self, generator, alert_repo):
        obs = _make_water_obs()
        await generator.generate_water_anomaly_alert(observation=obs, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["alert_id"] == f"geoint-water-{obs.id}"

    @pytest.mark.asyncio
    async def test_rule_id_correto(self, generator, alert_repo):
        obs = _make_water_obs()
        await generator.generate_water_anomaly_alert(observation=obs, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert call_kwargs["rule_id"] == "geoint.water.anomaly.v1"

    @pytest.mark.asyncio
    async def test_titulo_contem_anomaly_type_e_estacao(self, generator, alert_repo):
        obs = _make_water_obs(anomaly_type="flood")
        await generator.generate_water_anomaly_alert(observation=obs, source_record_ids=[])

        call_kwargs = alert_repo.create.call_args[1]
        assert "flood" in call_kwargs["title"]
        assert "Itaipu" in call_kwargs["title"] or "17050001" in call_kwargs["title"]

    @pytest.mark.asyncio
    async def test_audit_log_registrado(self, generator, audit_log):
        obs = _make_water_obs()
        await generator.generate_water_anomaly_alert(observation=obs, source_record_ids=[])

        audit_log.append.assert_called_once()
        call_kwargs = audit_log.append.call_args[1]
        assert call_kwargs["actor_id"] == "geoint.water_processor"
        assert call_kwargs["event_data"]["anomaly_type"] == "flood"


# ─── Testes de AlertRule ──────────────────────────────────────────────────────


class TestAlertRule:
    def test_map_severity_direto(self):
        rule = ALERT_RULES["geoint.deforestation.threshold"]
        assert rule.map_severity("HIGH") == "HIGH"
        assert rule.map_severity("CRITICAL") == "CRITICAL"

    def test_map_severity_escalado_near_infrastructure(self):
        rule = ALERT_RULES["geoint.deforestation.near_infrastructure"]
        assert rule.map_severity("LOW") == "MEDIUM"
        assert rule.map_severity("MEDIUM") == "HIGH"
        assert rule.map_severity("HIGH") == "CRITICAL"
        assert rule.map_severity("CRITICAL") == "CRITICAL"

    def test_format_title_com_kwargs(self):
        rule = ALERT_RULES["geoint.deforestation.threshold"]
        title = rule.format_title(
            area_ha=250.5,
            state="MT",
            biome="Cerrado",
        )
        assert "250" in title
        assert "MT" in title

    def test_format_title_chave_faltando_retorna_template(self):
        rule = ALERT_RULES["geoint.deforestation.threshold"]
        # Sem os kwargs necessários — deve retornar template (não lançar KeyError)
        title = rule.format_title()
        assert "{" in title or len(title) > 0  # template retornado sem erro

    def test_format_description_agua(self):
        rule = ALERT_RULES["geoint.water.anomaly"]
        desc = rule.format_description(
            anomaly_type="flood",
            station_code="17050001",
            station_name="Itaipu",
            value=20.5,
            unit="m",
            z_score=4.5,
            threshold=3.0,
            historical_mean=10.0,
            historical_stddev=2.0,
        )
        assert "flood" in desc
        assert "17050001" in desc

    def test_todas_regras_tem_rule_id(self):
        for key, rule in ALERT_RULES.items():
            assert rule.rule_id, f"Regra {key} sem rule_id"
            assert "v1" in rule.rule_id

    def test_todas_regras_tem_severity_mapping(self):
        for key, rule in ALERT_RULES.items():
            assert rule.severity_mapping, f"Regra {key} sem severity_mapping"
