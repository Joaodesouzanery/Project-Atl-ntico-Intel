"""
Testes do gerenciador de ciclo de vida de chaves.
"""

from __future__ import annotations

import time

import pytest

from atlantico.crypto.exceptions import (
    KeyNotFoundError,
    KeyRetiredError,
    MasterKeyError,
)
from atlantico.crypto.key_manager import KeyManager, KeyStatus


class TestKeyManagerInitialization:
    def test_rejects_short_master_key(self, initialized_crypto):
        with pytest.raises(MasterKeyError, match="32 bytes"):
            KeyManager(master_key=b"curto")

    def test_rejects_long_master_key(self, initialized_crypto):
        with pytest.raises(MasterKeyError):
            KeyManager(master_key=b"x" * 33)

    def test_accepts_32_byte_key(self, initialized_crypto):
        km = KeyManager(master_key=b"\x00" * 32)
        assert km is not None


class TestKEMKeyGeneration:
    def test_generate_kem_keypair_returns_keypair(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        assert keypair.public_key
        assert keypair.private_key
        assert keypair.key_id

    def test_generated_key_is_stored(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        record = key_manager._store.get(keypair.key_id)
        assert record is not None
        assert record.key_id == keypair.key_id
        assert record.status == KeyStatus.ACTIVE

    def test_stored_private_key_is_encrypted(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        record = key_manager._store.get(keypair.key_id)

        # Chave armazenada NÃO deve ser igual à chave em texto claro
        stored_bytes = bytes.fromhex(record.private_key_encrypted_hex)
        original_bytes = bytes(keypair.private_key)
        assert stored_bytes != original_bytes

    def test_retrieve_kem_private_key(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        retrieved = key_manager.get_kem_private_key(keypair.key_id)
        assert bytes(retrieved) == bytes(keypair.private_key)

    def test_get_active_kem_public_key(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        key_id, pub_key = key_manager.get_active_kem_public_key()
        assert key_id == keypair.key_id
        assert pub_key == keypair.public_key

    def test_get_active_kem_public_key_no_keys_raises(self, key_manager):
        with pytest.raises(KeyNotFoundError):
            key_manager.get_active_kem_public_key()


class TestSigningKeyGeneration:
    def test_generate_signing_keypair(self, key_manager):
        keypair = key_manager.generate_signing_keypair()
        assert keypair.public_key
        assert keypair.key_id

    def test_retrieve_signing_public_key(self, key_manager):
        keypair = key_manager.generate_signing_keypair()
        pub = key_manager.get_signing_public_key(keypair.key_id)
        assert pub == keypair.public_key


class TestKeyRotation:
    def test_kem_rotation_creates_new_active_key(self, key_manager):
        old_keypair = key_manager.generate_kem_keypair()
        rotation = key_manager.rotate_kem_keys(reason="scheduled")

        assert rotation.new_key_id != old_keypair.key_id
        new_id, _ = key_manager.get_active_kem_public_key()
        assert new_id == rotation.new_key_id

    def test_kem_rotation_deprecates_old_key(self, key_manager):
        old_keypair = key_manager.generate_kem_keypair()
        key_manager.rotate_kem_keys(reason="test")

        old_record = key_manager._store.get(old_keypair.key_id)
        assert old_record.status == KeyStatus.DEPRECATED

    def test_deprecated_key_still_decryptable(self, key_manager):
        """Chave deprecada ainda permite decriptação de dados antigos."""
        old_keypair = key_manager.generate_kem_keypair()
        key_manager.rotate_kem_keys(reason="test")

        # Chave antiga ainda deve ser recuperável
        priv = key_manager.get_kem_private_key(old_keypair.key_id)
        assert bytes(priv) == bytes(old_keypair.private_key)

    def test_signing_rotation(self, key_manager):
        old = key_manager.generate_signing_keypair()
        rotation = key_manager.rotate_signing_keys(reason="test")
        assert rotation.new_key_id != old.key_id

    def test_rotation_record_contains_reason(self, key_manager):
        key_manager.generate_kem_keypair()
        rotation = key_manager.rotate_kem_keys(reason="compliance-audit")
        assert rotation.reason == "compliance-audit"


class TestKeyRetirement:
    def test_retired_key_raises_on_access(self, key_manager):
        old_keypair = key_manager.generate_kem_keypair()

        # Forçar deprecação e aposentadoria
        key_manager._store.update_status(old_keypair.key_id, KeyStatus.DEPRECATED, int(time.time()))
        key_manager._store.update_status(old_keypair.key_id, KeyStatus.RETIRED, int(time.time()))

        with pytest.raises(KeyRetiredError):
            key_manager.get_kem_private_key(old_keypair.key_id)

    def test_nonexistent_key_raises(self, key_manager):
        with pytest.raises(KeyNotFoundError):
            key_manager.get_kem_private_key("chave-que-nao-existe")

    def test_retire_expired_deprecated_keys(self, key_manager):
        """Chaves deprecadas há mais de grace_period devem ser aposentadas."""
        old_keypair = key_manager.generate_kem_keypair()

        # Simular deprecação no passado (além do período de graça)
        past_time = int(time.time()) - (31 * 86400)  # 31 dias atrás
        record = key_manager._store.get(old_keypair.key_id)
        record.status = KeyStatus.DEPRECATED
        record.deprecated_at = past_time

        # Gerar nova chave (para ter uma ativa)
        key_manager.generate_kem_keypair()

        retired = key_manager.retire_expired_keys()
        assert old_keypair.key_id in retired

        # Verificar que foi marcada como RETIRED
        updated = key_manager._store.get(old_keypair.key_id)
        assert updated.status == KeyStatus.RETIRED


class TestNeedsRotation:
    def test_needs_rotation_false_when_fresh(self, key_manager):
        key_manager.generate_kem_keypair()
        key_manager.generate_signing_keypair()
        assert not key_manager.needs_rotation()

    def test_needs_rotation_true_when_no_keys(self, key_manager):
        assert key_manager.needs_rotation()

    def test_needs_rotation_true_when_old(self, key_manager):
        keypair = key_manager.generate_kem_keypair()
        key_manager.generate_signing_keypair()

        # Forçar a data de criação para o passado
        record = key_manager._store.get(keypair.key_id)
        record.created_at = int(time.time()) - (91 * 86400)  # 91 dias atrás

        # KM tem rotation_interval_days=90, então deve precisar de rotação
        assert key_manager.needs_rotation()


class TestDataKeyDerivation:
    def test_same_context_same_key(self, key_manager):
        k1 = key_manager.derive_data_key("record-1", "inpe", 1700000000)
        k2 = key_manager.derive_data_key("record-1", "inpe", 1700000000)
        assert k1 == k2

    def test_different_record_id_different_key(self, key_manager):
        k1 = key_manager.derive_data_key("record-1", "inpe", 1700000000)
        k2 = key_manager.derive_data_key("record-2", "inpe", 1700000000)
        assert k1 != k2

    def test_different_source_different_key(self, key_manager):
        k1 = key_manager.derive_data_key("record-1", "inpe", 1700000000)
        k2 = key_manager.derive_data_key("record-1", "cert-br", 1700000000)
        assert k1 != k2

    def test_key_length_is_32_bytes(self, key_manager):
        key = key_manager.derive_data_key("record-1", "inpe", 1700000000)
        assert len(key) == 32
