"""
Testes unitários para EncryptionContext e EncryptedBytes TypeDecorator.

Testa sem banco de dados real — simula o SQLAlchemy dialect para
testar process_bind_param e process_result_value diretamente.
"""

from __future__ import annotations

import os

import pytest

from atlantico.storage.encrypted_field import (
    EncryptedBytes,
    EncryptionContext,
    EncryptionContextNotInitializedError,
    StorageEncryptionError,
)

# Dialect simulado (EncryptedBytes ignora o dialect — apenas para assinatura do método)
_MOCK_DIALECT = object()


@pytest.fixture(autouse=True)
def reset_encryption_context():
    """Reseta o EncryptionContext antes e depois de cada teste."""
    EncryptionContext._reset_for_testing()
    yield
    EncryptionContext._reset_for_testing()


@pytest.fixture
def master_key_32() -> bytes:
    """Chave mestra de 32 bytes para testes."""
    return bytes(range(32))  # Bytes 0..31 — determinístico para testes


@pytest.fixture
def initialized_context(master_key_32) -> bytes:
    """EncryptionContext inicializado para testes."""
    EncryptionContext.initialize(master_key_32)
    return master_key_32


# ─── EncryptionContext ────────────────────────────────────────────────────────


class TestEncryptionContext:
    def test_initialize_stores_key(self, master_key_32):
        EncryptionContext.initialize(master_key_32)
        assert EncryptionContext.get_master_key() == master_key_32

    def test_is_initialized_false_before_init(self):
        assert not EncryptionContext.is_initialized()

    def test_is_initialized_true_after_init(self, master_key_32):
        EncryptionContext.initialize(master_key_32)
        assert EncryptionContext.is_initialized()

    def test_get_master_key_raises_if_not_initialized(self):
        with pytest.raises(EncryptionContextNotInitializedError):
            EncryptionContext.get_master_key()

    def test_initialize_rejects_short_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            EncryptionContext.initialize(b"\x00" * 16)

    def test_initialize_rejects_long_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            EncryptionContext.initialize(b"\x00" * 48)

    def test_initialize_twice_same_key_is_idempotent(self, master_key_32):
        EncryptionContext.initialize(master_key_32)
        EncryptionContext.initialize(master_key_32)  # Não deve lançar
        assert EncryptionContext.is_initialized()

    def test_initialize_twice_different_key_raises(self, master_key_32):
        EncryptionContext.initialize(master_key_32)
        different_key = bytes([k ^ 0xFF for k in master_key_32])
        with pytest.raises(RuntimeError, match="já inicializado"):
            EncryptionContext.initialize(different_key)

    def test_reset_for_testing_allows_reinit(self, master_key_32):
        EncryptionContext.initialize(master_key_32)
        EncryptionContext._reset_for_testing()
        assert not EncryptionContext.is_initialized()
        # Reinicialização deve funcionar após reset
        EncryptionContext.initialize(master_key_32)
        assert EncryptionContext.is_initialized()


# ─── EncryptedBytes TypeDecorator ─────────────────────────────────────────────


class TestEncryptedBytesInit:
    def test_valid_field_label(self, initialized_context):
        eb = EncryptedBytes("table.column")
        assert eb.field_label == "table.column"

    def test_field_label_without_dot_raises(self):
        with pytest.raises(ValueError, match="tabela.coluna"):
            EncryptedBytes("invalid_no_dot")

    def test_empty_field_label_raises(self):
        with pytest.raises(ValueError):
            EncryptedBytes("")

    def test_repr(self, initialized_context):
        eb = EncryptedBytes("key_store.private_key")
        assert "key_store.private_key" in repr(eb)


class TestEncryptedBytesRoundtrip:
    def test_roundtrip_basic(self, initialized_context):
        eb = EncryptedBytes("test.column")
        plaintext = b"dado secreto do OSINT"

        encrypted = eb.process_bind_param(plaintext, _MOCK_DIALECT)
        decrypted = eb.process_result_value(encrypted, _MOCK_DIALECT)

        assert decrypted == plaintext

    def test_roundtrip_empty_bytes(self, initialized_context):
        eb = EncryptedBytes("test.column")

        encrypted = eb.process_bind_param(b"", _MOCK_DIALECT)
        decrypted = eb.process_result_value(encrypted, _MOCK_DIALECT)

        assert decrypted == b""

    def test_roundtrip_large_payload(self, initialized_context):
        eb = EncryptedBytes("test.column")
        plaintext = os.urandom(1024 * 64)  # 64KB

        encrypted = eb.process_bind_param(plaintext, _MOCK_DIALECT)
        decrypted = eb.process_result_value(encrypted, _MOCK_DIALECT)

        assert decrypted == plaintext

    def test_none_passthrough_bind(self, initialized_context):
        eb = EncryptedBytes("test.column")
        assert eb.process_bind_param(None, _MOCK_DIALECT) is None

    def test_none_passthrough_result(self, initialized_context):
        eb = EncryptedBytes("test.column")
        assert eb.process_result_value(None, _MOCK_DIALECT) is None

    def test_encrypted_differs_from_plaintext(self, initialized_context):
        eb = EncryptedBytes("test.column")
        plaintext = b"texto secreto"

        encrypted = eb.process_bind_param(plaintext, _MOCK_DIALECT)

        assert encrypted != plaintext
        # Wire format: 12B nonce + ciphertext + 16B tag
        assert len(encrypted) == 12 + len(plaintext) + 16

    def test_two_encryptions_differ_nonce(self, initialized_context):
        """Cada cifração usa nonce diferente (os.urandom)."""
        eb = EncryptedBytes("test.column")
        plaintext = b"mesmo texto"

        enc1 = eb.process_bind_param(plaintext, _MOCK_DIALECT)
        enc2 = eb.process_bind_param(plaintext, _MOCK_DIALECT)

        assert enc1 != enc2  # Nonces diferentes → ciphertexts diferentes


class TestEncryptedBytesDomainSeparation:
    def test_different_labels_produce_different_ciphertexts(self, initialized_context):
        """Separação de domínio: mesma plaintext, colunas diferentes → chaves diferentes."""
        eb1 = EncryptedBytes("table.column_a")
        eb2 = EncryptedBytes("table.column_b")
        plaintext = b"dado compartilhado"

        enc1 = eb1.process_bind_param(plaintext, _MOCK_DIALECT)
        enc2 = eb2.process_bind_param(plaintext, _MOCK_DIALECT)

        # Ciphertexts devem ser diferentes (chaves derivadas são diferentes)
        assert enc1[12:] != enc2[12:]  # Ignora os 12B de nonce

    def test_wrong_label_decryption_fails(self, initialized_context):
        """Mover ciphertext entre colunas causa falha de autenticação AES-GCM."""
        eb_a = EncryptedBytes("alerts.title")
        eb_b = EncryptedBytes("alerts.description")
        plaintext = b"titulo do alerta"

        encrypted_for_a = eb_a.process_bind_param(plaintext, _MOCK_DIALECT)

        # Tentar decriptografar como se fosse a coluna B
        with pytest.raises(StorageEncryptionError, match="Falha ao decriptografar"):
            eb_b.process_result_value(encrypted_for_a, _MOCK_DIALECT)

    def test_decryption_fails_with_wrong_master_key(self, master_key_32):
        """Chave mestra errada causa falha de decriptação."""
        EncryptionContext.initialize(master_key_32)
        eb = EncryptedBytes("test.column")
        encrypted = eb.process_bind_param(b"dados", _MOCK_DIALECT)

        # Reinicializa com chave diferente
        EncryptionContext._reset_for_testing()
        different_key = bytes([k ^ 0xAA for k in master_key_32])
        EncryptionContext.initialize(different_key)

        with pytest.raises(StorageEncryptionError):
            eb.process_result_value(encrypted, _MOCK_DIALECT)


class TestEncryptedBytesSecurity:
    def test_raises_if_context_not_initialized(self):
        """process_bind_param deve falhar se EncryptionContext não foi inicializado."""
        eb = EncryptedBytes("test.column")
        with pytest.raises(EncryptionContextNotInitializedError):
            eb.process_bind_param(b"dados", _MOCK_DIALECT)

    def test_raises_if_context_not_initialized_on_read(self):
        """process_result_value deve falhar se EncryptionContext não foi inicializado."""
        eb = EncryptedBytes("test.column")
        # Cria um ciphertext mínimo falso (28B = 12 nonce + 16 tag)
        fake_encrypted = b"\x00" * 28
        with pytest.raises(EncryptionContextNotInitializedError):
            eb.process_result_value(fake_encrypted, _MOCK_DIALECT)

    def test_short_ciphertext_raises(self, initialized_context):
        """Ciphertexts muito curtos (corrupção) são rejeitados antes de tentar decriptar."""
        eb = EncryptedBytes("test.column")
        with pytest.raises(StorageEncryptionError, match="curtos"):
            eb.process_result_value(b"\x00" * 10, _MOCK_DIALECT)

    def test_tampered_ciphertext_raises(self, initialized_context):
        """Adulteração do ciphertext invalida a tag AES-GCM."""
        eb = EncryptedBytes("test.column")
        encrypted = eb.process_bind_param(b"dados secretos", _MOCK_DIALECT)

        tampered = bytearray(encrypted)
        tampered[len(tampered) // 2] ^= 0xFF

        with pytest.raises(StorageEncryptionError):
            eb.process_result_value(bytes(tampered), _MOCK_DIALECT)

    def test_cache_ok_is_true(self):
        """TypeDecorator é seguro para cache SQLAlchemy (field_label é constante)."""
        eb = EncryptedBytes("table.column")
        assert eb.cache_ok is True
