"""
Fixtures compartilhadas entre todos os testes.

IMPORTANTE: Testes do módulo crypto usam providers de stub (sem liboqs)
quando a biblioteca não está disponível. Os stubs implementam os mesmos
Protocols, garantindo que a lógica de cripto-agilidade seja testada
independentemente da disponibilidade do liboqs.
"""

from __future__ import annotations

import os
import secrets

import pytest

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    EncapsulatedKey,
    KEMKeyPair,
    KEMProvider,
    SignatureProvider,
    SignatureSuite,
    SigningKeyPair,
    current_timestamp,
    generate_key_id,
)
from atlantico.crypto.key_manager import KeyManager


# ─── Providers de Stub (sem liboqs) ──────────────────────────────────────────
# Usados em todos os testes de unidade que testam a lógica de cripto-agilidade,
# gerenciamento de chaves e envelope, sem depender de liboqs estar instalado.


class StubKEMProvider:
    """
    Provider KEM de stub para testes.
    Usa X25519 puro (via cryptography) simulando a interface híbrida.
    NÃO protege contra quântico — apenas para testes de lógica.
    """

    suite: AlgorithmSuite = AlgorithmSuite.HYBRID_KYBER768_X25519

    def generate_keypair(self) -> KEMKeyPair:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        return KEMKeyPair(
            public_key=pub,
            private_key=bytearray(priv_bytes),
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def encapsulate(self, recipient_public_key: bytes) -> EncapsulatedKey:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()
        rec_pub = X25519PublicKey.from_public_bytes(recipient_public_key)
        shared = eph.exchange(rec_pub)

        return EncapsulatedKey(
            ciphertext=eph_pub,
            shared_secret=shared,
            suite=self.suite,
        )

    def decapsulate(self, ciphertext: bytes, private_key: bytearray) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        priv = X25519PrivateKey.from_private_bytes(bytes(private_key))
        eph_pub = X25519PublicKey.from_public_bytes(ciphertext)
        return priv.exchange(eph_pub)


class StubSignatureProvider:
    """
    Provider de assinatura de stub para testes.
    Usa Ed25519 puro simulando a interface híbrida.
    """

    suite: SignatureSuite = SignatureSuite.HYBRID_DILITHIUM3_ED25519

    def generate_keypair(self) -> SigningKeyPair:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        return SigningKeyPair(
            public_key=pub_bytes,
            private_key=bytearray(priv_bytes),
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def sign(self, payload: bytes, private_key: bytearray) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        return priv.sign(payload)

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, payload)
            return True
        except Exception:
            return False


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_crypto_agility():
    """
    Reseta o CryptoAgility registry antes de cada teste.
    Garante isolamento entre testes.
    """
    CryptoAgility._reset_for_testing()
    yield
    CryptoAgility._reset_for_testing()


@pytest.fixture
def stub_kem_provider() -> StubKEMProvider:
    return StubKEMProvider()


@pytest.fixture
def stub_sig_provider() -> StubSignatureProvider:
    return StubSignatureProvider()


@pytest.fixture
def initialized_crypto(stub_kem_provider, stub_sig_provider):
    """
    Inicializa CryptoAgility com providers de stub.
    Use esta fixture para testar lógica que depende do registry.
    """
    CryptoAgility._kem_providers[AlgorithmSuite.HYBRID_KYBER768_X25519] = stub_kem_provider
    CryptoAgility._sig_providers[SignatureSuite.HYBRID_DILITHIUM3_ED25519] = stub_sig_provider
    CryptoAgility._default_kem_suite = AlgorithmSuite.HYBRID_KYBER768_X25519
    CryptoAgility._default_sig_suite = SignatureSuite.HYBRID_DILITHIUM3_ED25519
    CryptoAgility._initialized = True
    return CryptoAgility


@pytest.fixture
def master_key() -> bytes:
    """Chave mestra AES-256 para testes (32 bytes fixos para reprodutibilidade)."""
    return bytes.fromhex("0" * 64)  # 32 bytes de zeros — APENAS PARA TESTES


@pytest.fixture
def key_manager(master_key, initialized_crypto) -> KeyManager:
    """KeyManager configurado com providers de stub."""
    return KeyManager(
        master_key=master_key,
        rotation_interval_days=90,
        retirement_grace_period_days=30,
    )
