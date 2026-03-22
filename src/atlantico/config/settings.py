"""
Configurações centrais do Projeto Atlântico via Pydantic-Settings.

Toda configuração é lida de variáveis de ambiente ou do arquivo .env.
Suítes de algoritmos criptográficos são definidas aqui e propagadas
para o módulo crypto/ via CryptoAgility — zero hardcoding de algoritmos
em código de negócio.
"""

from __future__ import annotations

import secrets
from enum import Enum
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ATLANTICO_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Ambiente ─────────────────────────────────────────────────────
    env: Environment = Environment.DEVELOPMENT

    # ─── Criptografia Pós-Quântica ────────────────────────────────────
    # Estas strings são validadas contra os valores de AlgorithmSuite e
    # SignatureSuite ao inicializar o CryptoAgility registry.
    kem_suite: str = Field(
        default="hybrid-kyber768-x25519",
        description="Suite KEM ativa. Controla criptografia de novos dados.",
    )
    sig_suite: str = Field(
        default="hybrid-dilithium3-ed25519",
        description="Suite de assinatura ativa. Controla assinaturas de novos dados.",
    )
    allow_classical_fallback: bool = Field(
        default=False,
        description=(
            "Permite ativar a suite clássica (sem PQC). "
            "Requer confirmação explícita para prevenir downgrade acidental."
        ),
    )

    # Chave mestra de criptografia (Key Encryption Key — KEK)
    # Em produção: injete via Docker Secret ou HSM.
    # Formato: hex-encoded de 32 bytes (256 bits = AES-256).
    master_key_hex: str = Field(
        default="",
        description="KEK hex-encoded 32 bytes. NUNCA use o padrão em produção.",
    )

    @field_validator("master_key_hex")
    @classmethod
    def validate_master_key(cls, v: str) -> str:
        if not v:
            # Em development, gera uma chave efêmera com aviso.
            return secrets.token_hex(32)
        if len(v) != 64:  # 32 bytes = 64 hex chars
            msg = "ATLANTICO_MASTER_KEY_HEX deve ter exatamente 64 caracteres hex (32 bytes)."
            raise ValueError(msg)
        try:
            bytes.fromhex(v)
        except ValueError as exc:
            msg = "ATLANTICO_MASTER_KEY_HEX contém caracteres não-hexadecimais."
            raise ValueError(msg) from exc
        return v

    @model_validator(mode="after")
    def validate_classical_fallback_in_production(self) -> "Settings":
        if self.env == Environment.PRODUCTION and self.allow_classical_fallback:
            msg = (
                "allow_classical_fallback=True é proibido em ambiente de produção. "
                "Operação sem PQC viola a política de segurança do Projeto Atlântico."
            )
            raise ValueError(msg)
        return self

    # ─── Banco de Dados ───────────────────────────────────────────────
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "atlantico"
    db_user: str = "atlantico_app"
    db_password: str = Field(default="", repr=False)
    db_pool_size: int = 10
    db_max_overflow: int = 20

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql+psycopg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    # ─── Redis ────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ─── API ──────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4

    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_hours: int = 8

    # ─── Rotação de Chaves ────────────────────────────────────────────
    key_rotation_interval_days: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Intervalo máximo entre rotações obrigatórias de chaves.",
    )
    key_retirement_grace_period_days: int = Field(
        default=30,
        ge=1,
        description="Período de graça antes de desativar chaves rotacionadas.",
    )

    # ─── Credenciais de Fontes OSINT ─────────────────────────────────
    inpe_api_key: str = Field(default="", repr=False)
    esa_client_id: str = Field(default="", repr=False)
    esa_client_secret: str = Field(default="", repr=False)
    transparencia_api_key: str = Field(default="", repr=False)

    # ─── GEOINT — URLs de Fontes ──────────────────────────────────────
    ana_hidroweb_url: str = Field(
        default="https://www.snirh.gov.br/hidroweb/rest/api",
        description="URL base da API REST do ANA HidroWeb.",
    )
    copernicus_catalog_url: str = Field(
        default="https://catalogue.dataspace.copernicus.eu/odata/v1",
        description="URL base do catálogo OData do Copernicus Data Space.",
    )
    copernicus_stac_url: str = Field(
        default="https://catalogue.dataspace.copernicus.eu/stac",
        description="URL base do STAC do Copernicus Data Space.",
    )
    copernicus_token_url: str = Field(
        default="https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token",
        description="URL de token OAuth2 do Copernicus.",
    )
    inpe_terrabrasilis_wfs_url: str = Field(
        default="https://terrabrasilis.dpi.inpe.br/geoserver/wfs",
        description="URL do WFS TerraBrasilis (PRODES e DETER).",
    )
    inpe_bdqueimadas_url: str = Field(
        default="https://queimadas.dgi.inpe.br/api",
        description="URL base da API REST do INPE BDQueimadas.",
    )

    # ─── GEOINT — Limiares de Análise ────────────────────────────────
    geoint_deforestation_alert_ha: float = Field(
        default=10.0,
        ge=0.1,
        description="Área mínima em hectares para disparar alerta de desmatamento.",
    )
    geoint_fire_cluster_eps_km: float = Field(
        default=5.0,
        ge=0.1,
        description="Raio DBSCAN em km para agrupamento de focos de incêndio.",
    )
    geoint_fire_cluster_min_samples: int = Field(
        default=3,
        ge=1,
        description="Mínimo de amostras DBSCAN para formar um cluster de incêndio.",
    )
    geoint_fire_alert_cluster_size: int = Field(
        default=5,
        ge=2,
        description="Tamanho mínimo de cluster de incêndio para disparar alerta.",
    )
    geoint_water_anomaly_stddev: float = Field(
        default=3.0,
        ge=1.0,
        description="Número de desvios-padrão para classificar anomalia hídrica.",
    )
    geoint_infra_buffer_km: float = Field(
        default=10.0,
        ge=0.1,
        description="Raio em km ao redor de ativos de infraestrutura para monitoramento.",
    )

    # ─── GEOINT — Intervalos de Ingestão (segundos) ───────────────────
    geoint_ingest_prodes_interval_s: int = Field(
        default=86400,
        description="Intervalo de ingestão PRODES em segundos (padrão: 24h).",
    )
    geoint_ingest_deter_interval_s: int = Field(
        default=3600,
        description="Intervalo de ingestão DETER em segundos (padrão: 1h).",
    )
    geoint_ingest_bdqueimadas_interval_s: int = Field(
        default=900,
        description="Intervalo de ingestão BDQueimadas em segundos (padrão: 15min).",
    )
    geoint_ingest_sentinel2_interval_s: int = Field(
        default=21600,
        description="Intervalo de ingestão metadados Sentinel-2 em segundos (padrão: 6h).",
    )
    geoint_ingest_hidroweb_interval_s: int = Field(
        default=3600,
        description="Intervalo de ingestão HidroWeb em segundos (padrão: 1h).",
    )

    # ─── GEOINT — Bbox padrão (Brasil) ───────────────────────────────
    geoint_default_bbox: str = Field(
        default="-73.98,-33.75,-28.85,5.27",
        description="Bounding box padrão (min_lon,min_lat,max_lon,max_lat) WGS-84.",
    )

    @property
    def geoint_default_bbox_tuple(self) -> tuple[float, float, float, float]:
        """Retorna geoint_default_bbox como tupla (min_lon, min_lat, max_lon, max_lat)."""
        parts = [float(x) for x in self.geoint_default_bbox.split(",")]
        return (parts[0], parts[1], parts[2], parts[3])

    # ─── FININT — URLs de Fontes ─────────────────────────────────────
    bcb_sgs_url: str = Field(
        default="https://api.bcb.gov.br/dados/serie/dados/serie",
        description="URL base da API SGS do Banco Central.",
    )
    cvm_dados_url: str = Field(
        default="https://dados.cvm.gov.br/dados",
        description="URL base dos dados abertos CVM.",
    )
    transparencia_contratos_url: str = Field(
        default="https://api.portaldatransparencia.gov.br/api-de-dados/contratos",
        description="URL da API de contratos do Portal da Transparência.",
    )
    ibge_sidra_url: str = Field(
        default="https://servicodados.ibge.gov.br/api/v3/agregados",
        description="URL base da API SIDRA do IBGE.",
    )
    comexstat_url: str = Field(
        default="https://comexstat.mdic.gov.br/api/exports",
        description="URL base da API ComexStat do MDIC.",
    )

    # ─── FININT — Limiares de Análise ────────────────────────────────
    finint_anomaly_zscore_threshold: float = Field(
        default=3.0,
        ge=1.0,
        description="Threshold Z-score para anomalias FININT.",
    )
    finint_anomaly_isolation_contamination: float = Field(
        default=0.05,
        ge=0.01,
        le=0.5,
        description="Fração de contaminação do Isolation Forest.",
    )
    finint_network_pagerank_alpha: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Fator de amortecimento do PageRank.",
    )
    finint_contract_concentration_threshold: float = Field(
        default=0.8,
        ge=0.5,
        le=1.0,
        description="Limiar de concentração de fornecedor (1 fornecedor > X% do volume).",
    )
    finint_trade_spike_multiplier: float = Field(
        default=3.0,
        ge=1.0,
        description="Multiplicador de desvio-padrão para detectar spike em exportações.",
    )

    # ─── FININT — NCMs de Minerais Estratégicos ─────────────────────
    finint_strategic_ncm_codes: str = Field(
        default="7108,2616,2617,8001,7101,7102",
        description="NCMs CSV de minerais estratégicos (ouro, prata, estanho, pedras preciosas).",
    )

    # ─── FININT — Intervalos de Ingestão (segundos) ──────────────────
    finint_ingest_bcb_interval_s: int = Field(
        default=3600,
        description="Intervalo de ingestão BCB SGS em segundos (padrão: 1h).",
    )
    finint_ingest_contratos_interval_s: int = Field(
        default=14400,
        description="Intervalo de ingestão contratos Transparência em segundos (padrão: 4h).",
    )
    finint_ingest_trade_interval_s: int = Field(
        default=21600,
        description="Intervalo de ingestão ComexStat em segundos (padrão: 6h).",
    )
    finint_ingest_cvm_interval_s: int = Field(
        default=86400,
        description="Intervalo de ingestão CVM em segundos (padrão: 24h).",
    )
    finint_ingest_ibge_interval_s: int = Field(
        default=86400,
        description="Intervalo de ingestão IBGE SIDRA em segundos (padrão: 24h).",
    )

    @property
    def finint_strategic_ncm_list(self) -> list[str]:
        """Retorna lista de NCMs estratégicos a partir da string CSV."""
        return [code.strip() for code in self.finint_strategic_ncm_codes.split(",") if code.strip()]

    # ─── SIGINT — Credenciais de Fontes ──────────────────────────────
    otx_api_key: str = Field(default="", repr=False, description="Chave de API AlienVault OTX.")
    virustotal_api_key: str = Field(default="", repr=False, description="Chave de API VirusTotal v3.")
    nvd_api_key: str = Field(default="", repr=False, description="Chave de API NVD (opcional, aumenta rate limit).")

    # ─── SIGINT — URLs de Fontes ──────────────────────────────────────
    nvd_cve_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="URL base da API NVD CVE v2.0.",
    )
    certbr_alertas_url: str = Field(
        default="https://www.cert.br/rss/alertas.rdf",
        description="URL do feed RDF de alertas do CERT.br.",
    )
    certbr_avisos_url: str = Field(
        default="https://www.cert.br/rss/avisos.rdf",
        description="URL do feed RDF de avisos do CERT.br.",
    )
    certbr_noticias_url: str = Field(
        default="https://www.cert.br/rss/noticias.rdf",
        description="URL do feed RDF de notícias do CERT.br.",
    )
    otx_pulses_url: str = Field(
        default="https://otx.alienvault.com/api/v1/pulses/subscribed",
        description="URL base da API OTX AlienVault (pulsos subscritos).",
    )
    virustotal_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        description="URL base da API VirusTotal v3.",
    )

    # ─── SIGINT — Limiares de Análise ─────────────────────────────────
    sigint_cvss_threshold: float = Field(
        default=7.0,
        ge=0.0,
        le=10.0,
        description="CVSS mínimo para ingestão de CVEs via NVD.",
    )
    sigint_ioc_confidence_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Confiança mínima para gerar alerta de IOC.",
    )
    sigint_disinfo_score_threshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Score mínimo de desinformação para gerar alerta.",
    )
    sigint_cve_alert_score_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Score contextual mínimo para gerar alerta de CVE.",
    )
    sigint_narrative_cluster_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Similaridade cosseno mínima para agrupar narrativas.",
    )
    sigint_vt_malicious_threshold: int = Field(
        default=3,
        ge=1,
        description="Número mínimo de engines VirusTotal detectando malicioso.",
    )

    # ─── SIGINT — Intervalos de Ingestão (segundos) ───────────────────
    sigint_ingest_nvd_interval_s: int = Field(
        default=3600,
        description="Intervalo de ingestão NVD CVE em segundos (padrão: 1h).",
    )
    sigint_ingest_certbr_interval_s: int = Field(
        default=1800,
        description="Intervalo de ingestão CERT.br em segundos (padrão: 30min).",
    )
    sigint_ingest_otx_interval_s: int = Field(
        default=3600,
        description="Intervalo de ingestão OTX AlienVault em segundos (padrão: 1h).",
    )
    sigint_ingest_news_interval_s: int = Field(
        default=900,
        description="Intervalo de ingestão feeds de notícias em segundos (padrão: 15min).",
    )
    sigint_analyze_threats_interval_s: int = Field(
        default=3600,
        description="Intervalo de análise de ameaças em segundos (padrão: 1h).",
    )
    sigint_analyze_narratives_interval_s: int = Field(
        default=1800,
        description="Intervalo de análise de narrativas em segundos (padrão: 30min).",
    )
    sigint_simulate_incidents_interval_s: int = Field(
        default=7200,
        description="Intervalo de simulação de incidentes em segundos (padrão: 2h).",
    )

    # ─── Observabilidade ──────────────────────────────────────────────
    log_level: LogLevel = LogLevel.INFO
    otel_endpoint: str = "http://localhost:4317"
    metrics_port: int = 9090

    @property
    def master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.master_key_hex)

    @property
    def is_production(self) -> bool:
        return self.env == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.env == Environment.DEVELOPMENT


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Retorna instância singleton das configurações.
    Usar `get_settings()` em todo o código — nunca instanciar Settings() diretamente.
    Cache garante que variáveis de ambiente são lidas apenas uma vez.
    """
    return Settings()
