"""
Modelo SQLAlchemy para alertas de correlação assinados com Dilithium.

Alertas são gerados pelo motor de correlação quando padrões de interesse
são detectados nos dados ingeridos. Cada alerta:

1. Referencia os SourceRecords que o geraram (correlação)
2. Possui título e descrição criptografados (EncryptedBytes — Nível 1)
3. Está assinado digitalmente com Dilithium3+Ed25519 (não-repúdio)
4. Possui localização geoespacial opcional (PostGIS Point)

CRIPTOGRAFIA:
    title_enc e description_enc usam EncryptedBytes (chave por coluna,
    AES-256-GCM derivada da master_key KEK). Estes campos são de uso
    operacional interno — não precisam do isolamento por registro do envelope
    PQC, mas precisam de proteção em repouso.

    Para alertas de altíssima sensibilidade com payload completo, usar
    SourceRecord + envelope PQC no repositório.

ASSINATURA:
    `signature` é a assinatura Dilithium3+Ed25519 sobre o hash SHA3-256
    de todos os campos estáticos do alerta (alert_id, severity, rule_id,
    title, description, source_record_ids, occurred_at). Isso garante
    não-repúdio: qualquer modificação no alerta invalida a assinatura.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from geoalchemy2 import Geometry
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class Alert(UUIDPKMixin, TimestampMixin, Base):
    """
    Alerta de correlação assinado com Dilithium3+Ed25519.

    Gerado pelo motor de correlação (Sprint 5) ao detectar padrões
    de interesse nos dados OSINT. Imutável após criação (assinatura
    garante integridade).
    """

    __tablename__ = "alerts"

    __table_args__ = (
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_alerts_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'investigating', 'closed', 'false_positive')",
            name="ck_alerts_status",
        ),
        # Busca por severidade e status (dashboard operacional)
        Index("idx_alerts_severity_status", "severity", "status", "created_at"),
        # Índice geoespacial para alertas com localização
        Index("idx_alerts_geo", "geo_location", postgresql_using="gist"),
        {"comment": "Alertas de correlação assinados com Dilithium3+Ed25519"},
    )

    # ID externo único do alerta (gerado pela aplicação, não pelo DB)
    alert_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        comment="ID único do alerta (gerado pela aplicação)",
    )

    # Severidade do alerta
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Severidade: LOW | MEDIUM | HIGH | CRITICAL",
    )

    # Regra de correlação que gerou o alerta
    rule_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="ID da regra de correlação que gerou o alerta",
    )

    # Título criptografado (EncryptedBytes — AES-256-GCM chave por coluna)
    title_enc: Mapped[bytes] = mapped_column(
        EncryptedBytes("alerts.title"),
        nullable=False,
        comment="Título do alerta (criptografado com AES-256-GCM)",
    )

    # Descrição completa criptografada
    description_enc: Mapped[bytes] = mapped_column(
        EncryptedBytes("alerts.description"),
        nullable=False,
        comment="Descrição completa do alerta (criptografada com AES-256-GCM)",
    )

    # IDs dos SourceRecords que originaram este alerta (correlação)
    # JSONB: ["uuid1", "uuid2", ...] — lista de UUIDs
    source_record_ids: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        server_default="[]",
        comment="UUIDs dos SourceRecords correlacionados (JSONB array)",
    )

    # Localização geoespacial central do alerta (PostGIS Point, nullable)
    geo_location: Mapped[object] = mapped_column(
        Geometry("POINT", srid=4326),
        nullable=True,
        comment="Localização geoespacial central do alerta (PostGIS Point, nullable)",
    )

    # Estado operacional do alerta
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="open",
        comment="Estado: open | investigating | closed | false_positive",
    )

    # Assinatura digital Dilithium3+Ed25519 do alerta completo
    # Cobre: alert_id, severity, rule_id, title, description,
    #        source_record_ids, occurred_at (em canonical bytes)
    signature: Mapped[bytes] = mapped_column(
        nullable=False,
        comment="Assinatura Dilithium3+Ed25519 do conteúdo do alerta",
    )

    # Referências às chaves criptográficas usadas
    kem_key_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("key_store.key_id", ondelete="RESTRICT"),
        nullable=False,
        comment="key_id da chave KEM disponível para encriptação de resposta",
    )
    sig_key_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("key_store.key_id", ondelete="RESTRICT"),
        nullable=False,
        comment="key_id da chave que assinou este alerta",
    )

    # Timestamp de quando o evento ocorreu (pode diferir de created_at)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Timestamp do evento que gerou o alerta (UTC)",
    )

    # Analista responsável (preenchido ao investigar/fechar)
    assigned_to: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Analista responsável pela investigação (nullable)",
    )

    # Notas de investigação (texto livre, não criptografado — sem dados sensíveis)
    investigation_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Notas de investigação (sem dados sensíveis)",
    )

    def __repr__(self) -> str:
        return (
            f"Alert(id={self.id!r}, alert_id={self.alert_id!r}, "
            f"severity={self.severity!r}, status={self.status!r})"
        )
