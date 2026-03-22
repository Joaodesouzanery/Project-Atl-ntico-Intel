"""
Testes de Rotação de Chaves — Gate de Segurança Crítico.

Verifica que:
1. Rotação de chaves cria nova chave ativa.
2. Dados cifrados com chave antiga continuam decriptografáveis após rotação.
3. Novos dados usam a nova chave.
4. Chaves aposentadas não permitem mais decriptação.
5. Múltiplas rotações em sequência funcionam corretamente.
6. Rotação de chaves de assinatura não invalida verificação de assinaturas antigas.
"""

from __future__ import annotations

import time

import pytest

from atlantico.crypto.agility import AlgorithmSuite, CryptoAgility, SignatureSuite
from atlantico.crypto.envelope import decrypt, encrypt
from atlantico.crypto.exceptions import KeyRetiredError
from atlantico.crypto.key_manager import KeyManager, KeyStatus


class TestKEMKeyRotation:
    def test_rotation_creates_new_active_key(self, key_manager):
        old = key_manager.generate_kem_keypair()
        rotation = key_manager.rotate_kem_keys(reason="test")

        # Nova chave é diferente da antiga
        assert rotation.new_key_id != old.key_id

        # Nova chave está ativa
        new_id, _ = key_manager.get_active_kem_public_key()
        assert new_id == rotation.new_key_id

    def test_old_data_remains_accessible_after_rotation(self, key_manager):
        """
        CRÍTICO: dados cifrados antes da rotação devem permanecer acessíveis.
        """
        # 1. Gerar chave e cifrar dados
        old_kp = key_manager.generate_kem_keypair()
        sig_kp = key_manager.generate_signing_keypair()

        sig_pub_keys = key_manager.get_all_signing_public_keys()
        plaintext = b"dados historicos cifrados antes da rotacao"

        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=old_kp.public_key,
            signing_private_key=key_manager.get_signing_private_key(sig_kp.key_id),
            signing_key_id=sig_kp.key_id,
            kem_key_id=old_kp.key_id,
        )

        # 2. Rotacionar chaves
        key_manager.rotate_kem_keys(reason="scheduled")
        key_manager.rotate_signing_keys(reason="scheduled")

        # 3. Dados antigos ainda decriptografáveis com chave antiga
        old_private = key_manager.get_kem_private_key(old_kp.key_id)

        # Chaves de assinatura antigas ainda disponíveis para verificação
        all_sig_pub_keys = key_manager.get_all_signing_public_keys()

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=old_private,
            verifier_public_keys=all_sig_pub_keys,
        )
        assert recovered == plaintext

    def test_new_data_uses_new_key_after_rotation(self, key_manager):
        """Após rotação, novos dados usam a nova chave ativa."""
        key_manager.generate_kem_keypair()
        key_manager.generate_signing_keypair()
        rotation = key_manager.rotate_kem_keys(reason="test")

        new_id, new_pub = key_manager.get_active_kem_public_key()
        assert new_id == rotation.new_key_id

    def test_multiple_rotations_preserve_all_data(self, key_manager):
        """Múltiplas rotações em sequência — todos os dados históricos acessíveis."""
        sig_kp = key_manager.generate_signing_keypair()

        envelopes = []
        kp_ids = []

        # Rotacionar 3 vezes, cifrando dados após cada rotação
        for i in range(3):
            kp = key_manager.generate_kem_keypair()
            kp_ids.append(kp.key_id)

            plaintext = f"dados da rotacao {i}".encode()
            envelope_bytes = encrypt(
                plaintext=plaintext,
                recipient_kem_public_key=kp.public_key,
                signing_private_key=key_manager.get_signing_private_key(sig_kp.key_id),
                signing_key_id=sig_kp.key_id,
                kem_key_id=kp.key_id,
            )
            envelopes.append((kp.key_id, plaintext, envelope_bytes))

            if i < 2:  # Rotacionar antes das últimas iterações
                key_manager.rotate_kem_keys(reason="scheduled")

        # Verificar que todos os dados ainda são acessíveis
        all_sig_pub_keys = key_manager.get_all_signing_public_keys()
        for key_id, expected_plaintext, envelope_bytes in envelopes:
            priv = key_manager.get_kem_private_key(key_id)
            recovered = decrypt(
                envelope_bytes=envelope_bytes,
                recipient_kem_private_key=priv,
                verifier_public_keys=all_sig_pub_keys,
            )
            assert recovered == expected_plaintext

    def test_retired_key_prevents_decryption(self, key_manager):
        """Chave aposentada não permite mais decriptação."""
        old_kp = key_manager.generate_kem_keypair()

        # Forçar aposentadoria
        record = key_manager._store.get(old_kp.key_id)
        record.status = KeyStatus.RETIRED
        record.deprecated_at = int(time.time())
        record.retired_at = int(time.time())

        with pytest.raises(KeyRetiredError):
            key_manager.get_kem_private_key(old_kp.key_id)


class TestSigningKeyRotation:
    def test_signatures_with_old_key_still_verifiable(self, key_manager):
        """
        CRÍTICO: assinaturas feitas com chave antiga devem ser verificáveis
        após rotação, desde que a chave não esteja aposentada.
        """
        sig_kp = key_manager.generate_signing_keypair()
        kem_kp = key_manager.generate_kem_keypair()

        # Cifrar com chave de assinatura antiga
        old_sig_priv = key_manager.get_signing_private_key(sig_kp.key_id)
        envelope_bytes = encrypt(
            plaintext=b"dado assinado antes da rotacao",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=old_sig_priv,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        # Rotacionar chave de assinatura
        key_manager.rotate_signing_keys(reason="scheduled")

        # Decriptografar — deve funcionar com chave de assinatura antiga
        all_sig_pub_keys = key_manager.get_all_signing_public_keys()
        assert sig_kp.key_id in all_sig_pub_keys  # Chave antiga ainda disponível

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=key_manager.get_kem_private_key(kem_kp.key_id),
            verifier_public_keys=all_sig_pub_keys,
        )
        assert recovered == b"dado assinado antes da rotacao"

    def test_rotation_record_includes_retire_at(self, key_manager):
        key_manager.generate_signing_keypair()
        rotation = key_manager.rotate_signing_keys(reason="test")

        assert rotation.retire_at > rotation.rotated_at
        # Deve ser aproximadamente 30 dias à frente
        expected_delta = 30 * 86400
        actual_delta = rotation.retire_at - rotation.rotated_at
        assert abs(actual_delta - expected_delta) < 60  # Tolerância de 60 segundos


class TestKeyStatusTransitions:
    """Testa as transições de estado de chave."""

    def test_status_flow_active_to_deprecated_to_retired(self, key_manager):
        kp = key_manager.generate_kem_keypair()
        record = key_manager._store.get(kp.key_id)
        assert record.status == KeyStatus.ACTIVE

        # Deprecar
        now = int(time.time())
        key_manager._store.update_status(kp.key_id, KeyStatus.DEPRECATED, now)
        record = key_manager._store.get(kp.key_id)
        assert record.status == KeyStatus.DEPRECATED
        assert record.deprecated_at == now

        # Aposentar
        key_manager._store.update_status(kp.key_id, KeyStatus.RETIRED, now + 100)
        record = key_manager._store.get(kp.key_id)
        assert record.status == KeyStatus.RETIRED
        assert record.retired_at == now + 100
