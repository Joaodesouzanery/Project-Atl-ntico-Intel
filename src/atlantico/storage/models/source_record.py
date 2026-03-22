"""
Modelo SQLAlchemy para dados ingeridos das fontes OSINT.

Cada SourceRecord representa um item de dado bruto capturado de uma das
7 fontes abertas do sistema (INPE, ESA Sentinel, BCB/CVM, IBGE, Portal da
Transparência, CIEVS, CERT.br) ou de fontes adicionais em sprints futuros.

ARQUITETURA DE SEGURANÇA — Nível 2:
    O payload está protegido por envelope PQC completo por registro:
    - KEM Kyber768+X25519: chave de sessão encapsulada para o destinatário
    - AES-256-GCM: criptografia do payload com a chave de sessão
    - Dilithium3+Ed25519: assinatura digital do envelope completo

    Isso garante isolamento por registro: comprometer a chave mestra KEK
    (usada em EncryptedBytes) NÃO compromete os payloads OSINT, que exigem
    a chave KEM privada correspondente para decriptação.

GEOESPACIAL (PostGIS):
    geo_bounds armazena o bounding box geográfico em WGS-84 (EPSG:4326).
    Permite buscas por interseção geoespacial via ST_Intersects.
    Índice GIST para performance em queries geoespaciais.

PROVENANCE:
    provenance_hash = SHA3-256(payload_envelope || source_id || acquired_at_iso)
    Garante integridade e não-repúdio dos dados ingeridos.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from geoalchemy2 import Geometry
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class SourceRecord(UUIDPKMixin, TimestampMixin, Base):
    """
    Dados brutos ingeridos de fontes OSINT, protegidos por envelope PQC.

    O campo payload_envelope contém o binário completo do envelope
    (saída de crypto.envelope.encrypt()). O repositório é responsável
    por chamar envelope.encrypt() ao salvar e envelope.decrypt() ao recuperar.
    """

    __tablename__ = "source_records"

    __table_args__ = (
        CheckConstraint(
            "data_classification IN ('PUBLIC', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')",
            name="ck_source_records_classification",
        ),
        # Busca por fonte + período de tempo (query mais comum)
        Index("idx_source_records_source_time", "source_id", "acquired_at"),
        # Índice geoespacial GIST para ST_Intersects queries
        Index("idx_source_records_geo", "geo_bounds", postgresql_using="gist"),
        {"comment": "Dados OSINT ingeridos das fontes abertas, protegidos por envelope PQC"},
    )

    # ID externo único (ex: "PRODES-2024-0123456", "CERT-BR-2024-INC-789")
    record_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        comment="ID externo único da fonte (ex: PRODES-2024-0123456)",
    )

    # Identificador da fonte (ex: "inpe.prodes.v2", "cert-br.alert.v1")
    source_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Identificador da fonte OSINT (ex: inpe.prodes.v2)",
    )

    # Nível de classificação de dados
    data_classification: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Classificação: PUBLIC | RESTRICTED | CONFIDENTIAL | SECRET",
    )

    # Quando o dado foi adquirido na fonte (pode diferir de ingested_at)
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Timestamp de aquisição na fonte (UTC)",
    )

    # Referência à chave KEM usada para criptografar o envelope
    kem_key_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("key_store.key_id", ondelete="RESTRICT"),
        nullable=False,
        comment="key_id da chave KEM usada no envelope PQC",
    )

    # Referência à chave de assinatura usada no envelope
    sig_key_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("key_store.key_id", ondelete="RESTRICT"),
        nullable=False,
        comment="key_id da chave de assinatura usada no envelope PQC",
    )

    # Envelope PQC completo: wire format do crypto/envelope.py
    # [4B version] [4B kem_suite] [32B kem_key_id] [4B kem_ct_len] [kem_ct]
    # [12B nonce] [4B ct_len] [ciphertext] [16B tag]
    # [32B sig_key_id] [4B sig_suite] [4B sig_len] [signature]
    payload_envelope: Mapped[bytes] = mapped_column(
        nullable=False,
        comment="Envelope PQC binário completo (crypto.envelope.encrypt())",
    )

    # Bounding box geoespacial em WGS-84 (PostGIS)
    # nullable=True: nem todos os registros têm componente geoespacial
    geo_bounds: Mapped[object] = mapped_column(
        Geometry("POLYGON", srid=4326),
        nullable=True,
        comment="Bounding box geoespacial WGS-84 (PostGIS, nullable)",
    )

    # Hash de proveniência para integridade dos metadados
    # SHA3-256(payload_envelope || source_id || acquired_at_iso)
    provenance_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA3-256(envelope || source_id || acquired_at) para integridade",
    )

    # Metadados opcionais da fonte (ex: bounding box original em texto, URL de origem)
    source_metadata: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Metadados extras da fonte (JSON texto, sem dados sensíveis)",
    )

    def __repr__(self) -> str:
        return (
            f"SourceRecord(id={self.id!r}, record_id={self.record_id!r}, "
            f"source_id={self.source_id!r}, classification={self.data_classification!r})"
        )
