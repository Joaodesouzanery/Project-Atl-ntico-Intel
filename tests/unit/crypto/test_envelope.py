"""
Testes do envelope criptográfico.

Usa providers de stub (sem liboqs) para testar toda a lógica de
serialização, criptografia AES-GCM, verificação de assinatura e
detecção de adulteração.
"""

from __future__ import annotations

import pytest

from atlantico.crypto import agility as _agility_module
from atlantico.crypto.envelope import Envelope, decrypt, encrypt
from atlantico.crypto.exceptions import (
    EnvelopeDecryptionError,
    EnvelopeFormatError,
    IntegrityViolationError,
)


@pytest.fixture
def keypairs(initialized_crypto):
    """Gera keypairs KEM e de assinatura usando providers de stub."""
    from atlantico.crypto.agility import CryptoAgility

    kem = CryptoAgility.get_kem()
    signer = CryptoAgility.get_signer()

    kem_keypair = kem.generate_keypair()
    sig_keypair = signer.generate_keypair()

    return kem_keypair, sig_keypair


class TestEnvelopeEncryptDecrypt:
    def test_roundtrip_basic(self, keypairs):
        """Criptografar e decriptografar retorna o plaintext original."""
        kem_kp, sig_kp = keypairs

        plaintext = b"dado de inteligencia secreto"
        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=kem_kp.private_key,
            verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
        )

        assert recovered == plaintext

    def test_roundtrip_with_context(self, keypairs):
        """Contexto deve ser o mesmo na criptografia e decriptografia."""
        kem_kp, sig_kp = keypairs
        context = b"record-uuid-abc123:inpe:1700000000"
        plaintext = b"dados com contexto"

        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
            context=context,
        )

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=kem_kp.private_key,
            verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
            context=context,
        )

        assert recovered == plaintext

    def test_wrong_context_fails_decryption(self, keypairs):
        """Contexto incorreto resulta em falha de decriptação (AES-GCM tag)."""
        kem_kp, sig_kp = keypairs
        plaintext = b"dados com contexto"

        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
            context=b"contexto-correto",
        )

        with pytest.raises((EnvelopeDecryptionError, IntegrityViolationError)):
            decrypt(
                envelope_bytes=envelope_bytes,
                recipient_kem_private_key=kem_kp.private_key,
                verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
                context=b"contexto-errado",
            )

    def test_missing_verifier_key_fails(self, keypairs):
        """Verificação falha se a chave pública de assinatura não estiver disponível."""
        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"dados",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        with pytest.raises(EnvelopeDecryptionError, match="não encontrada"):
            decrypt(
                envelope_bytes=envelope_bytes,
                recipient_kem_private_key=kem_kp.private_key,
                verifier_public_keys={},  # Vazio — chave não disponível
            )

    def test_tampered_ciphertext_fails_integrity(self, keypairs):
        """Adulteração do ciphertext deve ser detectada (AES-GCM ou assinatura)."""
        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"dados originais",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        # Adulterar byte no meio do envelope
        tampered = bytearray(envelope_bytes)
        tampered[len(tampered) // 2] ^= 0xFF

        with pytest.raises((EnvelopeDecryptionError, IntegrityViolationError, EnvelopeFormatError)):
            decrypt(
                envelope_bytes=bytes(tampered),
                recipient_kem_private_key=kem_kp.private_key,
                verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
            )

    def test_empty_plaintext(self, keypairs):
        """Plaintext vazio deve ser tratado corretamente."""
        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=kem_kp.private_key,
            verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
        )

        assert recovered == b""

    def test_large_plaintext(self, keypairs):
        """Plaintext grande (1MB) deve ser tratado corretamente."""
        kem_kp, sig_kp = keypairs
        import os

        plaintext = os.urandom(1024 * 1024)  # 1MB

        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=kem_kp.private_key,
            verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
        )

        assert recovered == plaintext


class TestEnvelopeSerialization:
    def test_serialize_deserialize_roundtrip(self, keypairs):
        """Serialização e desserialização do Envelope é lossless."""
        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"teste de serializacao",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        envelope = Envelope.from_bytes(envelope_bytes)
        re_serialized = envelope.to_bytes()

        assert envelope_bytes == re_serialized

    def test_invalid_envelope_format_raises(self):
        with pytest.raises(EnvelopeFormatError):
            Envelope.from_bytes(b"dados invalidos")

    def test_truncated_envelope_raises(self, keypairs):
        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"dado",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        with pytest.raises(EnvelopeFormatError):
            Envelope.from_bytes(envelope_bytes[:20])  # Truncar drasticamente

    def test_envelope_contains_expected_suite(self, keypairs, initialized_crypto):
        """Suite registrada no envelope deve corresponder à suite padrão do registry."""
        from atlantico.crypto.agility import AlgorithmSuite, CryptoAgility

        kem_kp, sig_kp = keypairs

        envelope_bytes = encrypt(
            plaintext=b"dado",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        envelope = Envelope.from_bytes(envelope_bytes)
        assert envelope.kem_suite == CryptoAgility.get_default_kem_suite()
