"""
Modelo SQLAlchemy para audit log append-only encadeado criptograficamente.

DESIGN DE SEGURANÇA:

1. ENCADEAMENTO SHA3-256:
   Cada entrada armazena o hash da entrada anterior (prev_hash), formando
   uma corrente criptográfica. Adulteração de qualquer entrada invalida
   todas as subsequentes — detectável por verify_chain().

   entry_n.prev_hash = entry_{n-1}.entry_hash
   entry_n.entry_hash = SHA3-256(
       n.event_id || n.event_type || n.actor_id || n.target_id ||
       n.event_data_canonical || n.occurred_at_iso8601 || n.prev_hash
   )

2. ASSINATURA DILITHIUM3+ED25519:
   entry_signature = sign(entry_hash) com chave de assinatura ativa.
   Garante autenticidade mesmo se o hash SHA3-256 for pré-imagem atacado
   no futuro (camada adicional de proteção PQC).

3. ROW-LEVEL SECURITY (PostgreSQL):
   Política RLS bloqueia UPDATE e DELETE para todos os usuários,
   incluindo o usuário da aplicação. Definida na migration Alembic.
   Apenas INSERT é permitido — verdadeiramente append-only.

4. GENESIS HASH:
   A primeira entrada usa AUDIT_LOG_GENESIS_HASH como prev_hash.
   Valor determinístico derivado de string conhecida — qualquer tentativa
   de forjar "entradas antes da gênese" é detectável.

TIPOS DE EVENTOS (event_type):
    KEY_GENERATED, KEY_DEPRECATED, KEY_RETIRED
    RECORD_INGESTED, RECORD_RETRIEVED
    ALERT_CREATED, ALERT_UPDATED, ALERT_CLOSED
    AUTH_LOGIN, AUTH_LOGOUT, AUTH_FAILED
    SYSTEM_STARTUP, SYSTEM_SHUTDOWN
    ADMIN_ACTION, CONFIG_CHANGED

CANONICAL BYTES para cálculo do entry_hash:
    event_id (UTF-8) + "\\0"
    + event_type (UTF-8) + "\\0"
    + actor_id (UTF-8) + "\\0"
    + (target_id or "") (UTF-8) + "\\0"
    + json.dumps(event_data, sort_keys=True, separators=(',',':')) (UTF-8)
    + "\\0"
    + occurred_at.isoformat() (UTC, com "+00:00") + "\\0"
    + prev_hash (UTF-8)
"""

from __future__ import annotations

import hashlib

from sqlalchemy import BigInteger, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base


# Hash de gênese: primeira entrada usa este valor como prev_hash.
# Derivado de string conhecida e documentada — imutável após o deploy.
AUDIT_LOG_GENESIS_HASH: str = hashlib.sha3_256(
    b"ATLANTICO-AUDIT-GENESIS-v1"
).hexdigest()


class AuditLogEntry(Base):
    """
    Entrada no audit log append-only encadeado criptograficamente.

    IMUTÁVEL após inserção: Row-Level Security bloqueia UPDATE/DELETE.
    ENCADEADA: prev_hash referencia entry_hash da entrada anterior.
    ASSINADA: entry_signature = Dilithium3+Ed25519(entry_hash).

    O repositório AuditLogRepository é responsável por calcular
    prev_hash e entry_hash antes de inserir — o modelo apenas
    persiste os valores calculados.
    """

    __tablename__ = "audit_log"

    __table_args__ = (
        UniqueConstraint("event_id", name="uq_audit_log_event_id"),
        # Índice para buscas por tipo de evento e período
        Index("idx_audit_log_event_type_seq", "event_type", "seq"),
        # Índice para buscas por ator
        Index("idx_audit_log_actor_seq", "actor_id", "seq"),
        {
            "comment": (
                "Audit log append-only encadeado SHA3-256 + assinatura Dilithium. "
                "Row-Level Security bloqueia UPDATE e DELETE."
            )
        },
    )

    # Sequência auto-incrementada pelo PostgreSQL — é a chave primária ordenada
    # BIGSERIAL garante ordem de inserção — não depende de timestamp do cliente
    seq: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
        comment="Número de sequência monotônico (BIGSERIAL, gerado pelo PostgreSQL)",
    )

    # UUID do evento (gerado pela aplicação, não pelo DB)
    # Imutável — identifica o evento de forma única e global
    event_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="UUID único do evento (gerado pela aplicação)",
    )

    # Tipo do evento — categoriza a ação auditada
    event_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Tipo do evento (ex: KEY_GENERATED, RECORD_INGESTED)",
    )

    # Quem executou a ação (user_id, service account, ou "system")
    actor_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Identificador do ator (user_id, service_account, ou system)",
    )

    # Objeto alvo da ação (nullable — alguns eventos não têm alvo específico)
    target_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="ID do objeto alvo (key_id, record_id, etc.) — nullable",
    )

    # Dados contextuais do evento em JSONB
    # NUNCA deve conter dados sensíveis: chaves, payloads, credenciais
    # Deve conter: IDs, timestamps, contagens, estados, operações
    event_data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        server_default="{}",
        comment="Dados contextuais do evento (JSONB, sem dados sensíveis)",
    )

    # Timestamp do evento (gerado pela aplicação — não usar server_default
    # para garantir que o timestamp seja idêntico ao usado no entry_hash)
    occurred_at: Mapped[str] = mapped_column(
        # Armazenado como ISO 8601 string para garantir serialização
        # determinística no cálculo do entry_hash (sem dependência de locale)
        Text,
        nullable=False,
        comment="Timestamp ISO 8601 UTC do evento (ex: 2024-01-15T10:30:00+00:00)",
    )

    # Hash SHA3-256 da entrada anterior (encadeamento)
    # Para a primeira entrada: prev_hash = AUDIT_LOG_GENESIS_HASH
    prev_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA3-256 da entrada anterior (ou GENESIS_HASH para a primeira)",
    )

    # Hash SHA3-256 desta entrada (cobre todos os campos acima)
    # Calculado pelo repositório antes da inserção
    entry_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA3-256 desta entrada (cobre todos os campos + prev_hash)",
    )

    # Assinatura Dilithium3+Ed25519 do entry_hash
    # Garante autenticidade mesmo contra pré-imagem futura do SHA3-256
    entry_signature: Mapped[bytes] = mapped_column(
        nullable=False,
        comment="Assinatura Dilithium3+Ed25519 do entry_hash",
    )

    # Referência à chave de assinatura usada
    signer_key_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="key_id da chave de assinatura que gerou entry_signature",
    )

    def __repr__(self) -> str:
        return (
            f"AuditLogEntry(seq={self.seq!r}, event_type={self.event_type!r}, "
            f"actor_id={self.actor_id!r}, target_id={self.target_id!r})"
        )
