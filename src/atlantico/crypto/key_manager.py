"""
Gerenciador de Ciclo de Vida de Chaves Criptográficas.

Responsabilidades:
- Geração de pares de chaves KEM e de assinatura.
- Armazenamento criptografado de chaves privadas (usando a KEK — Key Encryption Key).
- Rotação de chaves sem quebrar decriptação de dados existentes.
- Aposentadoria de chaves após o período de graça.
- Derivação de chaves simétricas por registro (evita reutilização de chave).

MODELO DE SEGURANÇA:
    Chaves privadas são SEMPRE armazenadas criptografadas com AES-256-GCM
    usando a KEK (Master Key). A KEK nunca persiste em código — vem do
    ambiente, Docker Secret ou HSM.

    Hierarquia de chaves:
        KEK (Master Key)
            └── Protege: KEM Private Key, Signing Private Key
                    └── Derivam: chaves simétricas por registro

ESTADOS DE CHAVE:
    ACTIVE    → chave atual, usada para novas operações
    DEPRECATED → chave substituída, ainda usada para decriptação de dados antigos
    RETIRED   → chave aposentada, não aceita mais para decriptação

THREAD SAFETY:
    KeyManager não é thread-safe por si só. Em contextos multi-threaded,
    use um lock externo ou instancie um KeyManager por thread.
    A implementação de produção deve usar Redis distributed lock para
    operações de rotação em ambiente multi-instância.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    KEMKeyPair,
    SignatureSuite,
    SigningKeyPair,
    current_timestamp,
    generate_key_id,
)
from atlantico.crypto.exceptions import (
    KeyNotFoundError,
    KeyRetiredError,
    KeyRotationError,
    MasterKeyError,
)

_AES_NONCE_LEN = 12
_AES_TAG_LEN = 16


class KeyStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


@dataclass
class KeyRecord:
    """
    Registro de uma chave no store.
    A private_key_encrypted contém a chave privada criptografada com a KEK.
    """

    key_id: str
    suite: str                      # AlgorithmSuite.value ou SignatureSuite.value
    key_type: str                   # "kem" ou "signing"
    public_key_hex: str             # Chave pública em hex (transmitível)
    private_key_encrypted_hex: str  # Chave privada criptografada com KEK, em hex
    status: KeyStatus
    created_at: int
    deprecated_at: int | None = None
    retired_at: int | None = None
    rotation_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "KeyRecord":
        d = d.copy()
        d["status"] = KeyStatus(d["status"])
        return cls(**d)


@dataclass
class RotationRecord:
    """Registro de uma operação de rotação de chaves."""

    old_key_id: str
    new_key_id: str
    key_type: str
    suite: str
    rotated_at: int
    reason: str
    retire_at: int  # Timestamp quando a chave antiga deve ser aposentada


class InMemoryKeyStore:
    """
    Store de chaves em memória.

    Para Fase 1 (desenvolvimento/testes). Fase 2 e posteriores usarão
    PostgreSQL via storage.models.key_store com a camada de criptografia
    do SQLAlchemy TypeDecorator.
    """

    def __init__(self) -> None:
        self._records: dict[str, KeyRecord] = {}

    def save(self, record: KeyRecord) -> None:
        self._records[record.key_id] = record

    def get(self, key_id: str) -> KeyRecord | None:
        return self._records.get(key_id)

    def list_active(self, key_type: str) -> list[KeyRecord]:
        return [
            r for r in self._records.values()
            if r.key_type == key_type and r.status == KeyStatus.ACTIVE
        ]

    def list_all(self, key_type: str) -> list[KeyRecord]:
        return [r for r in self._records.values() if r.key_type == key_type]

    def update_status(self, key_id: str, status: KeyStatus, timestamp: int) -> None:
        record = self._records.get(key_id)
        if record is None:
            raise KeyNotFoundError(key_id)
        if status == KeyStatus.DEPRECATED:
            record.status = status
            record.deprecated_at = timestamp
        elif status == KeyStatus.RETIRED:
            record.status = status
            record.retired_at = timestamp


class KeyManager:
    """
    Gerenciador central de ciclo de vida de chaves.

    Uso típico:
        km = KeyManager(master_key=settings.master_key_bytes)
        kem_keypair = km.generate_kem_keypair()
        signing_keypair = km.generate_signing_keypair()

        # Mais tarde, para usar a chave privada:
        private_key = km.get_kem_private_key(key_id)
        # ... usar private_key ...
        private_key.zero_private_key()  # Zerar após uso
    """

    def __init__(
        self,
        master_key: bytes,
        store: InMemoryKeyStore | None = None,
        rotation_interval_days: int = 90,
        retirement_grace_period_days: int = 30,
    ) -> None:
        if len(master_key) != 32:
            raise MasterKeyError(
                f"Master key deve ter 32 bytes (256 bits). Recebido: {len(master_key)} bytes."
            )
        self._master_key = master_key
        self._store = store or InMemoryKeyStore()
        self._rotation_interval_days = rotation_interval_days
        self._retirement_grace_period_days = retirement_grace_period_days

    # ─── Geração de Chaves ────────────────────────────────────────────────────

    def generate_kem_keypair(
        self,
        suite: AlgorithmSuite | None = None,
    ) -> KEMKeyPair:
        """
        Gera e armazena um novo par de chaves KEM.
        A chave privada é criptografada com a KEK antes de armazenar.
        Retorna o KEMKeyPair com a chave privada em bytearray (ainda limpa).
        """
        kem = CryptoAgility.get_kem(suite)
        keypair = kem.generate_keypair()

        # Criptografar chave privada com KEK
        encrypted_priv = self._encrypt_with_kek(bytes(keypair.private_key))

        record = KeyRecord(
            key_id=keypair.key_id,
            suite=keypair.suite.value,
            key_type="kem",
            public_key_hex=keypair.public_key.hex(),
            private_key_encrypted_hex=encrypted_priv.hex(),
            status=KeyStatus.ACTIVE,
            created_at=keypair.created_at,
        )
        self._store.save(record)

        return keypair

    def generate_signing_keypair(
        self,
        suite: SignatureSuite | None = None,
    ) -> SigningKeyPair:
        """
        Gera e armazena um novo par de chaves de assinatura.
        """
        signer = CryptoAgility.get_signer(suite)
        keypair = signer.generate_keypair()

        encrypted_priv = self._encrypt_with_kek(bytes(keypair.private_key))

        record = KeyRecord(
            key_id=keypair.key_id,
            suite=keypair.suite.value,
            key_type="signing",
            public_key_hex=keypair.public_key.hex(),
            private_key_encrypted_hex=encrypted_priv.hex(),
            status=KeyStatus.ACTIVE,
            created_at=keypair.created_at,
        )
        self._store.save(record)

        return keypair

    # ─── Recuperação de Chaves ────────────────────────────────────────────────

    def get_active_kem_public_key(self) -> tuple[str, bytes]:
        """
        Retorna (key_id, public_key) da chave KEM ativa atual.
        Usada por clientes para criptografar dados destinados ao sistema.
        """
        active = self._store.list_active("kem")
        if not active:
            msg = "Nenhuma chave KEM ativa encontrada. Execute bootstrap_keys primeiro."
            raise KeyNotFoundError("active-kem")
        # Retorna a mais recente
        latest = max(active, key=lambda r: r.created_at)
        return latest.key_id, bytes.fromhex(latest.public_key_hex)

    def get_active_signing_public_key(self) -> tuple[str, bytes]:
        """Retorna (key_id, public_key) da chave de assinatura ativa."""
        active = self._store.list_active("signing")
        if not active:
            raise KeyNotFoundError("active-signing")
        latest = max(active, key=lambda r: r.created_at)
        return latest.key_id, bytes.fromhex(latest.public_key_hex)

    def get_kem_private_key(self, key_id: str) -> bytearray:
        """
        Recupera e decriptografa a chave privada KEM.

        RESPONSABILIDADE DO CALLER: chamar .zero_private_key() após uso,
        ou pelo menos sobrescrever os bytes do bytearray retornado.

        Raises:
            KeyNotFoundError: key_id não existe.
            KeyRetiredError: chave aposentada.
        """
        record = self._store.get(key_id)
        if record is None:
            raise KeyNotFoundError(key_id)
        if record.status == KeyStatus.RETIRED:
            raise KeyRetiredError(key_id)

        encrypted = bytes.fromhex(record.private_key_encrypted_hex)
        return bytearray(self._decrypt_with_kek(encrypted))

    def get_signing_private_key(self, key_id: str) -> bytearray:
        """Recupera e decriptografa a chave privada de assinatura."""
        record = self._store.get(key_id)
        if record is None:
            raise KeyNotFoundError(key_id)
        if record.status == KeyStatus.RETIRED:
            raise KeyRetiredError(key_id)

        encrypted = bytes.fromhex(record.private_key_encrypted_hex)
        return bytearray(self._decrypt_with_kek(encrypted))

    def get_signing_public_key(self, key_id: str) -> bytes:
        """Recupera a chave pública de assinatura por key_id."""
        record = self._store.get(key_id)
        if record is None:
            raise KeyNotFoundError(key_id)
        return bytes.fromhex(record.public_key_hex)

    def get_all_signing_public_keys(self) -> dict[str, bytes]:
        """
        Retorna todas as chaves públicas de assinatura não-aposentadas.
        Usado pelo envelope.decrypt() para verificação de assinaturas históricas.
        """
        return {
            r.key_id: bytes.fromhex(r.public_key_hex)
            for r in self._store.list_all("signing")
            if r.status != KeyStatus.RETIRED
        }

    # ─── Rotação de Chaves ────────────────────────────────────────────────────

    def rotate_kem_keys(self, reason: str = "scheduled") -> RotationRecord:
        """
        Rotaciona as chaves KEM:
        1. Gera novo par de chaves.
        2. Depreca a chave anterior (ainda pode decriptografar).
        3. Agenda aposentadoria após o período de graça.

        Retorna RotationRecord para registro no audit log.
        """
        try:
            active = self._store.list_active("kem")
            old_key_ids = [r.key_id for r in active]

            # Gerar nova chave
            new_keypair = self.generate_kem_keypair()
            now = current_timestamp()

            # Deprecar chaves antigas
            for old_key_id in old_key_ids:
                self._store.update_status(old_key_id, KeyStatus.DEPRECATED, now)

            retire_at = now + self._retirement_grace_period_days * 86400

            return RotationRecord(
                old_key_id=old_key_ids[0] if old_key_ids else "none",
                new_key_id=new_keypair.key_id,
                key_type="kem",
                suite=new_keypair.suite.value,
                rotated_at=now,
                reason=reason,
                retire_at=retire_at,
            )
        except Exception as exc:
            raise KeyRotationError(f"Falha na rotação de chaves KEM: {exc}") from exc

    def rotate_signing_keys(self, reason: str = "scheduled") -> RotationRecord:
        """Rotaciona as chaves de assinatura."""
        try:
            active = self._store.list_active("signing")
            old_key_ids = [r.key_id for r in active]

            new_keypair = self.generate_signing_keypair()
            now = current_timestamp()

            for old_key_id in old_key_ids:
                self._store.update_status(old_key_id, KeyStatus.DEPRECATED, now)

            retire_at = now + self._retirement_grace_period_days * 86400

            return RotationRecord(
                old_key_id=old_key_ids[0] if old_key_ids else "none",
                new_key_id=new_keypair.key_id,
                key_type="signing",
                suite=new_keypair.suite.value,
                rotated_at=now,
                reason=reason,
                retire_at=retire_at,
            )
        except Exception as exc:
            raise KeyRotationError(f"Falha na rotação de chaves de assinatura: {exc}") from exc

    def retire_expired_keys(self) -> list[str]:
        """
        Aposenta chaves deprecadas cujo período de graça expirou.
        Deve ser chamado periodicamente (ex: tarefa Celery diária).
        Retorna lista de key_ids aposentados.
        """
        now = current_timestamp()
        grace_seconds = self._retirement_grace_period_days * 86400
        retired: list[str] = []

        for key_type in ("kem", "signing"):
            for record in self._store.list_all(key_type):
                if (
                    record.status == KeyStatus.DEPRECATED
                    and record.deprecated_at is not None
                    and now - record.deprecated_at >= grace_seconds
                ):
                    self._store.update_status(record.key_id, KeyStatus.RETIRED, now)
                    retired.append(record.key_id)

        return retired

    def needs_rotation(self) -> bool:
        """
        Verifica se as chaves ativas ultrapassaram o intervalo de rotação.
        Usado pelo monitoramento para alertas de rotação pendente.
        """
        now = current_timestamp()
        rotation_interval_seconds = self._rotation_interval_days * 86400

        for key_type in ("kem", "signing"):
            active = self._store.list_active(key_type)
            if not active:
                return True
            oldest = min(active, key=lambda r: r.created_at)
            if now - oldest.created_at >= rotation_interval_seconds:
                return True

        return False

    # ─── Derivação de Chave por Registro ─────────────────────────────────────

    def derive_data_key(
        self,
        record_id: str,
        source_id: str,
        timestamp: int,
    ) -> bytes:
        """
        Deriva uma chave simétrica única por registro via HKDF.

        O contexto combina record_id + source_id + timestamp para garantir
        que cada registro receba uma chave diferente, mesmo com a mesma KEK.
        Comprometimento de uma chave de registro não expõe outros registros.
        """
        from atlantico.crypto.hybrid import derive_symmetric_key

        context = f"{record_id}:{source_id}:{timestamp}".encode("utf-8")
        return derive_symmetric_key(
            master_secret=self._master_key,
            context=context,
            suite_label="data-key-derivation-v1",
        )

    # ─── Criptografia Interna (KEK) ───────────────────────────────────────────

    def _encrypt_with_kek(self, plaintext: bytes) -> bytes:
        """
        Criptografa dados com a KEK usando AES-256-GCM.
        Retorna: nonce (12B) || ciphertext || tag (16B)
        """
        nonce = os.urandom(_AES_NONCE_LEN)
        aesgcm = AESGCM(self._master_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext_with_tag

    def _decrypt_with_kek(self, encrypted: bytes) -> bytes:
        """Decriptografa dados criptografados com a KEK."""
        if len(encrypted) < _AES_NONCE_LEN + _AES_TAG_LEN:
            raise MasterKeyError("Dados criptografados com KEK estão corrompidos (muito curtos).")
        nonce = encrypted[:_AES_NONCE_LEN]
        ciphertext_with_tag = encrypted[_AES_NONCE_LEN:]
        aesgcm = AESGCM(self._master_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as exc:
            raise MasterKeyError(
                "Falha ao decriptografar com KEK. Chave mestra incorreta ou dados corrompidos."
            ) from exc
