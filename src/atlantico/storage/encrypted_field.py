"""
Criptografia Transparente por Coluna para SQLAlchemy.

Implementa dois componentes:

1. EncryptionContext — Singleton que detém a master_key após startup da aplicação.
   TypeDecorators leem desta instância, nunca do ambiente diretamente.

2. EncryptedBytes — TypeDecorator que criptografa BYTEA transparentemente.
   Chave derivada por campo via HKDF-SHA3-512(master_key, info=field_label).
   Wire format: [12B nonce] || [ciphertext] || [16B AES-GCM tag]

LIMITAÇÃO INTENCIONAL:
    EncryptedBytes usa chave por coluna (não por linha). Para dados operacionais
    de alta sensibilidade (payloads de registros OSINT, alertas completos), usar
    envelope.encrypt() no repositório, que provê isolamento por registro via KEM PQC.

SEPARAÇÃO DE DOMÍNIO:
    field_label (ex: "key_store.private_key", "alerts.title") é incluído como
    "additional data" no AES-GCM e como contexto no HKDF. Isso garante:
    - Chaves diferentes para colunas diferentes (mesmo com mesma master_key)
    - Falha de autenticação se dados de uma coluna forem movidos para outra
    - Proteção contra ataques de re-uso de ciphertext entre colunas

INICIALIZAÇÃO:
    # No startup da aplicação (main.py ou lifespan FastAPI):
    from atlantico.storage.encrypted_field import EncryptionContext
    EncryptionContext.initialize(settings.master_key_bytes)
"""

from __future__ import annotations

import os
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import LargeBinary
from sqlalchemy.types import TypeDecorator

from atlantico.crypto.hybrid import derive_symmetric_key

_AES_NONCE_LEN = 12
_AES_TAG_LEN = 16
_HKDF_SUITE_LABEL = "storage-field-encryption-v1"


class StorageEncryptionError(Exception):
    """Erro de criptografia na camada de storage."""


class EncryptionContextNotInitializedError(StorageEncryptionError):
    """EncryptionContext não foi inicializado antes do uso."""


class EncryptionContext:
    """
    Singleton thread-safe que detém a master_key após startup.

    Garante que a chave mestra nunca é lida diretamente do ambiente por
    TypeDecorators — sempre passa por este ponto central, que pode ser
    monitorado, testado e substituído por uma implementação HSM no futuro.

    THREAD SAFETY: Usa lock para inicialização, mas get_master_key() é
    lock-free após a inicialização (chave imutável após set).
    """

    _master_key: bytes | None = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def initialize(cls, master_key: bytes) -> None:
        """
        Inicializa o contexto com a master_key.
        Deve ser chamado UMA VEZ no startup, antes de qualquer operação de DB.

        Args:
            master_key: 32 bytes (AES-256). Vem de settings.master_key_bytes.

        Raises:
            ValueError: Se master_key não tiver 32 bytes.
            RuntimeError: Se tentar inicializar com chave diferente (proteção contra
                          re-inicialização acidental em produção).
        """
        if len(master_key) != 32:
            msg = (
                f"master_key deve ter exatamente 32 bytes (256 bits). "
                f"Recebido: {len(master_key)} bytes."
            )
            raise ValueError(msg)

        with cls._lock:
            if cls._master_key is not None and cls._master_key != master_key:
                msg = (
                    "EncryptionContext já inicializado com chave diferente. "
                    "Re-inicialização em produção pode causar corrupção de dados. "
                    "Chame _reset_for_testing() apenas em testes."
                )
                raise RuntimeError(msg)
            cls._master_key = master_key

    @classmethod
    def get_master_key(cls) -> bytes:
        """
        Retorna a master_key. Lock-free após inicialização.

        Raises:
            EncryptionContextNotInitializedError: Se não foi inicializado.
        """
        key = cls._master_key
        if key is None:
            raise EncryptionContextNotInitializedError(
                "EncryptionContext não foi inicializado. "
                "Chame EncryptionContext.initialize(settings.master_key_bytes) "
                "no startup da aplicação."
            )
        return key

    @classmethod
    def is_initialized(cls) -> bool:
        return cls._master_key is not None

    @classmethod
    def _reset_for_testing(cls) -> None:
        """APENAS PARA TESTES. Reseta o estado do contexto."""
        with cls._lock:
            cls._master_key = None


class EncryptedBytes(TypeDecorator):
    """
    TypeDecorator SQLAlchemy para criptografia transparente de colunas BYTEA.

    Criptografa no write (process_bind_param) e decriptografa no read
    (process_result_value). Transparente para o código que usa os modelos ORM.

    Chave por campo: HKDF-SHA3-512(master_key, context=field_label.encode())
    Wire format: [12B: nonce AES-GCM] || [N: ciphertext] || [16B: tag AES-GCM]

    O field_label é incluído como "associated data" no AES-GCM, vinculando
    o ciphertext ao campo específico — mover dados entre colunas causa falha
    de autenticação (proteção contra ataques de transposição).

    Uso:
        class KeyStoreEntry(Base):
            private_key_enc: Mapped[bytes] = mapped_column(
                EncryptedBytes("key_store.private_key")
            )
    """

    impl = LargeBinary
    cache_ok = True  # Seguro para cache do SQLAlchemy (field_label é constante)

    def __init__(self, field_label: str, *args: object, **kwargs: object) -> None:
        """
        Args:
            field_label: Identificador único deste campo (ex: "table.column").
                         Usado para separação de domínio. Nunca alterar após
                         dados serem escritos — ciphertexts existentes tornam-se
                         irrecuperáveis.
        """
        if not field_label or "." not in field_label:
            msg = (
                f"field_label '{field_label}' deve seguir o formato 'tabela.coluna' "
                "para garantir separação de domínio adequada."
            )
            raise ValueError(msg)
        super().__init__(*args, **kwargs)
        self.field_label = field_label

    def _derive_column_key(self) -> bytes:
        """Deriva a chave AES-256 específica para este campo."""
        return derive_symmetric_key(
            master_secret=EncryptionContext.get_master_key(),
            context=self.field_label.encode("utf-8"),
            suite_label=_HKDF_SUITE_LABEL,
            key_length=32,
        )

    def process_bind_param(
        self, value: bytes | None, dialect: object
    ) -> bytes | None:
        """
        Chamado antes de escrever no DB: criptografa o valor.

        Args:
            value: Bytes em texto claro, ou None.
            dialect: Dialeto SQLAlchemy (ignorado).

        Returns:
            Bytes criptografados [nonce || ciphertext || tag], ou None.
        """
        if value is None:
            return None

        key = self._derive_column_key()
        nonce = os.urandom(_AES_NONCE_LEN)
        aesgcm = AESGCM(key)

        # field_label como "associated data" no AES-GCM: vincula o ciphertext ao campo.
        associated_data = self.field_label.encode("utf-8")
        ciphertext_with_tag = aesgcm.encrypt(nonce, value, associated_data)

        return nonce + ciphertext_with_tag

    def process_result_value(
        self, value: bytes | None, dialect: object
    ) -> bytes | None:
        """
        Chamado após ler do DB: decriptografa o valor.

        Args:
            value: Bytes criptografados [nonce || ciphertext || tag], ou None.
            dialect: Dialeto SQLAlchemy (ignorado).

        Returns:
            Bytes em texto claro, ou None.

        Raises:
            StorageEncryptionError: Se a decriptação falhar (dados corrompidos
                                    ou chave incorreta).
        """
        if value is None:
            return None

        if len(value) < _AES_NONCE_LEN + _AES_TAG_LEN:
            msg = (
                f"Campo '{self.field_label}': dados criptografados muito curtos "
                f"({len(value)} bytes). Possível corrupção."
            )
            raise StorageEncryptionError(msg)

        key = self._derive_column_key()
        nonce = value[:_AES_NONCE_LEN]
        ciphertext_with_tag = value[_AES_NONCE_LEN:]
        aesgcm = AESGCM(key)

        associated_data = self.field_label.encode("utf-8")
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except Exception as exc:
            msg = (
                f"Falha ao decriptografar campo '{self.field_label}'. "
                "Possível corrupção de dados, chave incorreta ou adulteração."
            )
            raise StorageEncryptionError(msg) from exc

    def __repr__(self) -> str:
        return f"EncryptedBytes({self.field_label!r})"
