"""
Modelo SQLAlchemy para persistência de KeyRecord do módulo crypto/.

KeyStoreEntry substitui InMemoryKeyStore como backend de armazenamento
para KeyManager. A interface é idêntica — basta passar PostgreSQLKeyStore
em vez de InMemoryKeyStore ao instanciar KeyManager.

SEGURANÇA:
    - private_key_enc: criptografado via EncryptedBytes TypeDecorator
      (AES-256-GCM, chave derivada por HKDF da master_key KEK)
    - public_key: armazenado em texto claro (é public por definição)
    - status: validado por CHECK constraint no PostgreSQL
    - key_type: validado por CHECK constraint no PostgreSQL
    - Índice composto em (key_type, status) para consultas de chaves ativas

MAPEAMENTO COM KeyRecord (crypto/key_manager.py):
    KeyRecord.key_id              → KeyStoreEntry.key_id
    KeyRecord.suite               → KeyStoreEntry.suite
    KeyRecord.key_type            → KeyStoreEntry.key_type
    KeyRecord.public_key_hex      → KeyStoreEntry.public_key (BYTEA)
    KeyRecord.private_key_encrypted_hex → KeyStoreEntry.private_key_enc (BYTEA, criptografado)
    KeyRecord.status              → KeyStoreEntry.status
    KeyRecord.created_at          → KeyStoreEntry.created_at
    KeyRecord.deprecated_at       → KeyStoreEntry.deprecated_at
    KeyRecord.retired_at          → KeyStoreEntry.retired_at
    KeyRecord.rotation_reason     → KeyStoreEntry.rotation_reason
"""

from __future__ import annotations

from sqlalchemy import BigInteger, CheckConstraint, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base


class KeyStoreEntry(Base):
    """
    Persistência de chaves criptográficas do KeyManager.

    Cada entrada representa um par de chaves (pública + privada) em um
    determinado estado do ciclo de vida: active → deprecated → retired.
    """

    __tablename__ = "key_store"

    __table_args__ = (
        CheckConstraint(
            "key_type IN ('kem', 'signing')",
            name="ck_key_store_key_type",
        ),
        CheckConstraint(
            "status IN ('active', 'deprecated', 'retired')",
            name="ck_key_store_status",
        ),
        # Consultas frequentes: "qual a chave KEM ativa?"
        Index("idx_key_store_type_status", "key_type", "status"),
        {"comment": "Armazenamento persistente de chaves criptográficas do KeyManager"},
    )

    # Chave primária: ID gerado pelo KeyManager (32 hex chars de os.urandom(16))
    key_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="ID único da chave (32 hex chars gerados por KeyManager)",
    )

    # Suite criptográfica (AlgorithmSuite.value ou SignatureSuite.value)
    # Imutável após criação — determina como a chave deve ser usada
    suite: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Suite criptográfica (ex: hybrid-kyber768-x25519)",
    )

    # Tipo de uso da chave
    key_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Tipo: 'kem' para encriptação, 'signing' para assinaturas",
    )

    # Chave pública em binário (transmissível, não precisa de proteção em repouso)
    public_key: Mapped[bytes] = mapped_column(
        # LargeBinary sem criptografia — chave pública é, por definição, pública
        # mas usamos BYTEA em vez de hex/base64 para eficiência
        nullable=False,
        comment="Chave pública em bytes (não criptografada)",
    )

    # Chave privada criptografada com AES-256-GCM derivada da master_key KEK
    # O TypeDecorator EncryptedBytes cuida de cifrar/decifrar transparentemente
    private_key_enc: Mapped[bytes] = mapped_column(
        EncryptedBytes("key_store.private_key"),
        nullable=False,
        comment="Chave privada criptografada (AES-256-GCM via EncryptedBytes)",
    )

    # Estado do ciclo de vida da chave
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="active",
        comment="Estado: active | deprecated | retired",
    )

    # Timestamps do ciclo de vida (Unix timestamps — compatível com KeyRecord)
    created_at: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        comment="Timestamp Unix de criação",
    )
    deprecated_at: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment="Timestamp Unix de deprecação (None se ainda ativa)",
    )
    retired_at: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment="Timestamp Unix de aposentadoria (None se não aposentada)",
    )

    # Motivo da rotação (vazio se ainda ativa)
    rotation_reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="",
        comment="Motivo da rotação/deprecação da chave",
    )

    def __repr__(self) -> str:
        return (
            f"KeyStoreEntry(key_id={self.key_id!r}, suite={self.suite!r}, "
            f"key_type={self.key_type!r}, status={self.status!r})"
        )
