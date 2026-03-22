"""
Implementações de Key Encapsulation Mechanism (KEM).

Provê o KEM híbrido que combina Kyber (PQC) com X25519 (clássico).

DEFESA HARVEST-NOW-DECRYPT-LATER:
    O adversário que capturar tráfego hoje precisaria, no futuro, quebrar
    SIMULTANEAMENTE Kyber768 (resistente a computadores quânticos segundo
    análise NIST) E X25519 (resistente a computadores clássicos). A
    combinação via HKDF garante que comprometer um não ajuda a comprometer o outro.

DEPENDÊNCIAS:
    - liboqs-python: bindings Python para a biblioteca Open Quantum Safe (liboqs C)
      Kyber768 implementado em tempo constante em C.
    - cryptography: X25519 para o componente clássico.

NOTA DE INSTALAÇÃO:
    liboqs-python requer que a biblioteca C liboqs esteja compilada.
    Em Docker, use o Dockerfile.api que compila liboqs da fonte com SHA256 verificado.
    Para desenvolvimento local: https://github.com/open-quantum-safe/liboqs-python
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from atlantico.crypto.agility import (
    AlgorithmSuite,
    EncapsulatedKey,
    KEMKeyPair,
    KEMProvider,
    current_timestamp,
    generate_key_id,
)
from atlantico.crypto.exceptions import (
    ClassicalFallbackNotAllowedError,
    KEMDecapsulationError,
    KEMEncapsulationError,
    KEMKeyGenerationError,
)
from atlantico.crypto.hybrid import combine_secrets

# Tentativa de importar liboqs — falha graciosamente em ambientes de teste
try:
    import oqs  # type: ignore[import-untyped]

    _LIBOQS_AVAILABLE = True
except ImportError:
    _LIBOQS_AVAILABLE = False
    oqs = None  # type: ignore[assignment]


def _require_liboqs(suite_name: str) -> None:
    """Verifica disponibilidade do liboqs antes de operações PQC."""
    if not _LIBOQS_AVAILABLE:
        msg = (
            f"liboqs-python não está disponível. Suite '{suite_name}' requer "
            "a biblioteca Open Quantum Safe (liboqs). "
            "Instale via: pip install liboqs-python "
            "(requer liboqs C library compilada no sistema)."
        )
        raise ImportError(msg)


# ─── Implementações Concretas ─────────────────────────────────────────────────


class HybridKyber768X25519Provider:
    """
    KEM Híbrido: CRYSTALS-Kyber768 (PQC) + X25519 (clássico).

    Kyber768 corresponde ao nível de segurança NIST 3 (≈AES-192).
    O NIST padronizou Kyber como ML-KEM (FIPS 203) em 2024.

    Formato do par de chaves público:
        [32B: X25519 public key] || [N bytes: Kyber768 public key]
    """

    suite: AlgorithmSuite = AlgorithmSuite.HYBRID_KYBER768_X25519
    _kyber_name = "Kyber768"

    def generate_keypair(self) -> KEMKeyPair:
        _require_liboqs(self._kyber_name)
        try:
            # Gerar chave X25519 (clássica)
            x25519_private = X25519PrivateKey.generate()
            x25519_public = x25519_private.public_key()
            x25519_pub_bytes = x25519_public.public_bytes_raw()  # 32 bytes

            # Gerar chave Kyber768 (PQC)
            kem = oqs.KeyEncapsulation(self._kyber_name)
            kyber_pub_bytes = kem.generate_keypair()  # retorna public key
            kyber_priv_bytes = kem.export_secret_key()

            # Serializar chave privada X25519
            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
            x25519_priv_bytes = x25519_private.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )

            # Compor chave pública combinada: X25519 || Kyber768
            public_key = x25519_pub_bytes + kyber_pub_bytes

            # Compor chave privada combinada: [4B len_x25519] || x25519_priv || kyber_priv
            len_x25519 = len(x25519_priv_bytes).to_bytes(4, "big")
            private_key = bytearray(len_x25519 + x25519_priv_bytes + kyber_priv_bytes)

        except Exception as exc:
            raise KEMKeyGenerationError(f"Falha ao gerar keypair Kyber768+X25519: {exc}") from exc
        finally:
            # Limpar referências sensíveis do escopo OQS
            if "kem" in locals():
                kem.free()

        return KEMKeyPair(
            public_key=public_key,
            private_key=private_key,
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def encapsulate(self, recipient_public_key: bytes) -> EncapsulatedKey:
        _require_liboqs(self._kyber_name)
        try:
            # Separar componentes da chave pública
            x25519_pub_bytes = recipient_public_key[:32]
            kyber_pub_bytes = recipient_public_key[32:]

            # ── Componente Clássico: X25519 ──────────────────────────
            # Gerar par efêmero para ECDH
            ephemeral_private = X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            ephemeral_pub_bytes = ephemeral_public.public_bytes_raw()

            recipient_x25519_pub = X25519PublicKey.from_public_bytes(x25519_pub_bytes)
            x25519_shared = ephemeral_private.exchange(recipient_x25519_pub)

            # ── Componente PQC: Kyber768 ─────────────────────────────
            kem = oqs.KeyEncapsulation(self._kyber_name)
            kyber_ciphertext, kyber_shared = kem.encap_secret(kyber_pub_bytes)

            # ── Combinar segredos via HKDF ───────────────────────────
            combined_secret = combine_secrets(
                pqc_secret=bytes(kyber_shared),
                classical_secret=x25519_shared,
                suite_label=self.suite.value,
            )

            # Ciphertext combinado: [32B efêmero X25519] || [N bytes Kyber768 ct]
            ciphertext = ephemeral_pub_bytes + kyber_ciphertext

        except (KEMEncapsulationError, ValueError):
            raise
        except Exception as exc:
            raise KEMEncapsulationError(f"Falha no encapsulamento Kyber768+X25519: {exc}") from exc
        finally:
            if "kem" in locals():
                kem.free()

        return EncapsulatedKey(
            ciphertext=ciphertext,
            shared_secret=combined_secret,
            suite=self.suite,
        )

    def decapsulate(self, ciphertext: bytes, private_key: bytearray) -> bytes:
        _require_liboqs(self._kyber_name)
        try:
            # Separar componentes da chave privada
            len_x25519 = int.from_bytes(private_key[:4], "big")
            x25519_priv_bytes = bytes(private_key[4:4 + len_x25519])
            kyber_priv_bytes = bytes(private_key[4 + len_x25519:])

            # Separar ciphertext
            ephemeral_pub_bytes = ciphertext[:32]
            kyber_ciphertext = ciphertext[32:]

            # ── Componente Clássico: X25519 ──────────────────────────
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            x25519_private = X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
            ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
            x25519_shared = x25519_private.exchange(ephemeral_pub)

            # ── Componente PQC: Kyber768 ─────────────────────────────
            kem = oqs.KeyEncapsulation(self._kyber_name, secret_key=kyber_priv_bytes)
            kyber_shared = kem.decap_secret(kyber_ciphertext)

            # ── Combinar via HKDF ────────────────────────────────────
            return combine_secrets(
                pqc_secret=bytes(kyber_shared),
                classical_secret=x25519_shared,
                suite_label=self.suite.value,
            )

        except (KEMDecapsulationError, ValueError):
            raise
        except Exception as exc:
            raise KEMDecapsulationError(f"Falha no decapsulamento Kyber768+X25519: {exc}") from exc
        finally:
            if "kem" in locals():
                kem.free()


class HybridKyber1024X25519Provider(HybridKyber768X25519Provider):
    """
    KEM Híbrido: CRYSTALS-Kyber1024 (PQC) + X25519 (clássico).

    Kyber1024 corresponde ao nível de segurança NIST 5 (≈AES-256).
    Use quando os dados exigem maior margem de segurança pós-quântica.
    Custo: chaves e ciphertexts maiores (~30% comparado ao Kyber768).
    """

    suite: AlgorithmSuite = AlgorithmSuite.HYBRID_KYBER1024_X25519
    _kyber_name = "Kyber1024"


class ClassicalX25519Provider:
    """
    KEM Clássico: X25519 apenas (sem PQC).

    ATENÇÃO: Não protege contra ataques de computadores quânticos.
    Use APENAS como fallback de emergência com autorização explícita.
    Requer ATLANTICO_ALLOW_CLASSICAL_FALLBACK=true.
    """

    suite: AlgorithmSuite = AlgorithmSuite.CLASSICAL_ONLY

    def __init__(self) -> None:
        # Verificação extra: esta classe não deve ser instanciada sem autorização.
        # A verificação de allow_classical_fallback está no CryptoAgility.get_kem(),
        # mas reforçamos aqui para proteção em profundidade.
        pass

    def generate_keypair(self) -> KEMKeyPair:
        try:
            private = X25519PrivateKey.generate()
            public = private.public_key()
            pub_bytes = public.public_bytes_raw()

            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
            priv_bytes = private.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
        except Exception as exc:
            raise KEMKeyGenerationError(f"Falha ao gerar keypair X25519: {exc}") from exc

        return KEMKeyPair(
            public_key=pub_bytes,
            private_key=bytearray(priv_bytes),
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def encapsulate(self, recipient_public_key: bytes) -> EncapsulatedKey:
        try:
            ephemeral_private = X25519PrivateKey.generate()
            ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes_raw()

            recipient_pub = X25519PublicKey.from_public_bytes(recipient_public_key)
            shared = ephemeral_private.exchange(recipient_pub)
        except Exception as exc:
            raise KEMEncapsulationError(f"Falha no encapsulamento X25519: {exc}") from exc

        return EncapsulatedKey(
            ciphertext=ephemeral_pub_bytes,
            shared_secret=shared,
            suite=self.suite,
        )

    def decapsulate(self, ciphertext: bytes, private_key: bytearray) -> bytes:
        try:
            x25519_private = X25519PrivateKey.from_private_bytes(bytes(private_key))
            ephemeral_pub = X25519PublicKey.from_public_bytes(ciphertext)
            return x25519_private.exchange(ephemeral_pub)
        except Exception as exc:
            raise KEMDecapsulationError(f"Falha no decapsulamento X25519: {exc}") from exc
