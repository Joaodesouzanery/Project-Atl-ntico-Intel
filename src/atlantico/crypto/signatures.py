"""
Implementações de Assinatura Digital Híbrida.

Provê assinaturas que combinam CRYSTALS-Dilithium (PQC) com Ed25519 (clássico).

PROPRIEDADE DE SEGURANÇA:
    A assinatura combinada é válida somente se AMBAS as assinaturas individuais
    forem válidas. Isso é mais seguro que o esquema "weakest-link" (onde basta
    uma ser válida). Um adversário quântico que quebre Ed25519 ainda precisaria
    forjar uma assinatura Dilithium válida.

FORMATO DE ASSINATURA COMBINADA (binário, big-endian):
    [4B: versão = 0x0001] || [4B: len(dilithium_sig)] || [dilithium_sig]
    || [4B: len(ed25519_sig)] || [ed25519_sig]

    O campo de versão permite evolução futura do formato sem quebrar
    compatibilidade retroativa.

REFERÊNCIAS:
    - NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Standard)
    - Dilithium3 ≈ nível de segurança NIST 3 (≈128-bit pós-quântico)
    - Dilithium5 ≈ nível de segurança NIST 5 (≈256-bit pós-quântico)
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from atlantico.crypto.agility import (
    SignatureSuite,
    SignedPayload,
    SignatureProvider,
    SigningKeyPair,
    current_timestamp,
    generate_key_id,
)
from atlantico.crypto.exceptions import (
    SignatureGenerationError,
    SignatureVerificationError,
    SigningKeyGenerationError,
)

# Versão do formato de assinatura combinada
_SIGNATURE_FORMAT_VERSION = 1

try:
    import oqs  # type: ignore[import-untyped]

    _LIBOQS_AVAILABLE = True
except ImportError:
    _LIBOQS_AVAILABLE = False
    oqs = None  # type: ignore[assignment]


def _require_liboqs(suite_name: str) -> None:
    if not _LIBOQS_AVAILABLE:
        msg = (
            f"liboqs-python não está disponível. Suite '{suite_name}' requer "
            "a biblioteca Open Quantum Safe (liboqs)."
        )
        raise ImportError(msg)


def _encode_combined_signature(dilithium_sig: bytes, ed25519_sig: bytes) -> bytes:
    """
    Serializa assinatura combinada em formato binário.
    Formato: [4B versão] [4B len_dil] [dil_sig] [4B len_ed] [ed_sig]
    """
    version_bytes = struct.pack(">I", _SIGNATURE_FORMAT_VERSION)
    dil_len = struct.pack(">I", len(dilithium_sig))
    ed_len = struct.pack(">I", len(ed25519_sig))
    return version_bytes + dil_len + dilithium_sig + ed_len + ed25519_sig


def _decode_combined_signature(combined: bytes) -> tuple[bytes, bytes]:
    """
    Desserializa assinatura combinada. Retorna (dilithium_sig, ed25519_sig).
    Levanta ValueError se o formato for inválido.
    """
    if len(combined) < 12:  # mínimo: 4B versão + 4B len_dil + 4B len_ed
        msg = "Assinatura combinada muito curta."
        raise ValueError(msg)

    version = struct.unpack(">I", combined[:4])[0]
    if version != _SIGNATURE_FORMAT_VERSION:
        msg = f"Versão de assinatura não suportada: {version}."
        raise ValueError(msg)

    offset = 4
    dil_len = struct.unpack(">I", combined[offset:offset + 4])[0]
    offset += 4

    dilithium_sig = combined[offset:offset + dil_len]
    offset += dil_len

    ed_len = struct.unpack(">I", combined[offset:offset + 4])[0]
    offset += 4

    ed25519_sig = combined[offset:offset + ed_len]

    return dilithium_sig, ed25519_sig


# ─── Formato de Chave Privada Combinada ──────────────────────────────────────
# [4B: len_ed25519_priv] || [ed25519_priv_bytes] || [dilithium_priv_bytes]
# [4B: len_ed25519_pub]  || [ed25519_pub_bytes]  || [dilithium_pub_bytes]

def _encode_private_keypair(
    ed25519_priv: bytes,
    dilithium_priv: bytes,
) -> bytearray:
    len_ed = struct.pack(">I", len(ed25519_priv))
    return bytearray(len_ed + ed25519_priv + dilithium_priv)


def _decode_private_keypair(combined: bytearray) -> tuple[bytes, bytes]:
    len_ed = struct.unpack(">I", bytes(combined[:4]))[0]
    ed25519_priv = bytes(combined[4:4 + len_ed])
    dilithium_priv = bytes(combined[4 + len_ed:])
    return ed25519_priv, dilithium_priv


def _encode_public_key(ed25519_pub: bytes, dilithium_pub: bytes) -> bytes:
    len_ed = struct.pack(">I", len(ed25519_pub))
    return len_ed + ed25519_pub + dilithium_pub


def _decode_public_key(combined: bytes) -> tuple[bytes, bytes]:
    len_ed = struct.unpack(">I", combined[:4])[0]
    ed25519_pub = combined[4:4 + len_ed]
    dilithium_pub = combined[4 + len_ed:]
    return ed25519_pub, dilithium_pub


# ─── Implementações Concretas ─────────────────────────────────────────────────


class HybridDilithium3Ed25519Provider:
    """
    Assinatura Híbrida: CRYSTALS-Dilithium3 (PQC) + Ed25519 (clássico).

    Dilithium3 ≈ nível NIST 3. Assinatura PQC padrão para Fase 1.
    """

    suite: SignatureSuite = SignatureSuite.HYBRID_DILITHIUM3_ED25519
    _dilithium_name = "Dilithium3"

    def generate_keypair(self) -> SigningKeyPair:
        _require_liboqs(self._dilithium_name)
        try:
            # Gerar chave Ed25519 (clássica)
            ed25519_priv = Ed25519PrivateKey.generate()
            ed25519_pub = ed25519_priv.public_key()

            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
            ed25519_priv_bytes = ed25519_priv.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            ed25519_pub_bytes = ed25519_pub.public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )

            # Gerar chave Dilithium3 (PQC)
            signer = oqs.Signature(self._dilithium_name)
            dilithium_pub_bytes = signer.generate_keypair()
            dilithium_priv_bytes = signer.export_secret_key()

            # Compor chave pública e privada combinadas
            public_key = _encode_public_key(ed25519_pub_bytes, dilithium_pub_bytes)
            private_key = _encode_private_keypair(ed25519_priv_bytes, dilithium_priv_bytes)

        except Exception as exc:
            raise SigningKeyGenerationError(
                f"Falha ao gerar keypair Dilithium3+Ed25519: {exc}"
            ) from exc
        finally:
            if "signer" in locals():
                signer.free()

        return SigningKeyPair(
            public_key=public_key,
            private_key=private_key,
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def sign(self, payload: bytes, private_key: bytearray) -> bytes:
        _require_liboqs(self._dilithium_name)
        try:
            ed25519_priv_bytes, dilithium_priv_bytes = _decode_private_keypair(private_key)

            # Assinatura Dilithium3 (PQC)
            signer = oqs.Signature(self._dilithium_name, secret_key=dilithium_priv_bytes)
            dilithium_sig = signer.sign(payload)

            # Assinatura Ed25519 (clássica)
            ed25519_priv = Ed25519PrivateKey.from_private_bytes(ed25519_priv_bytes)
            ed25519_sig = ed25519_priv.sign(payload)

            return _encode_combined_signature(bytes(dilithium_sig), ed25519_sig)

        except (SignatureGenerationError, ValueError):
            raise
        except Exception as exc:
            raise SignatureGenerationError(
                f"Falha na assinatura Dilithium3+Ed25519: {exc}"
            ) from exc
        finally:
            if "signer" in locals():
                signer.free()

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        _require_liboqs(self._dilithium_name)
        try:
            dilithium_sig, ed25519_sig = _decode_combined_signature(signature)
            ed25519_pub_bytes, dilithium_pub_bytes = _decode_public_key(public_key)

            # Verificar Dilithium3 (PQC) — AMBAS devem ser válidas
            verifier = oqs.Signature(self._dilithium_name)
            dilithium_valid = verifier.verify(payload, dilithium_sig, dilithium_pub_bytes)

            if not dilithium_valid:
                return False

            # Verificar Ed25519 (clássica)
            try:
                ed25519_pub = Ed25519PublicKey.from_public_bytes(ed25519_pub_bytes)
                ed25519_pub.verify(ed25519_sig, payload)
                return True
            except Exception:
                return False

        except (SignatureVerificationError, ValueError):
            raise
        except Exception as exc:
            raise SignatureVerificationError(
                f"Erro técnico na verificação Dilithium3+Ed25519: {exc}"
            ) from exc
        finally:
            if "verifier" in locals():
                verifier.free()


class HybridDilithium5Ed25519Provider(HybridDilithium3Ed25519Provider):
    """
    Assinatura Híbrida: CRYSTALS-Dilithium5 (PQC) + Ed25519 (clássico).

    Dilithium5 ≈ nível NIST 5. Para dados de alta sensibilidade.
    Assinaturas ~30% maiores que Dilithium3.
    """

    suite: SignatureSuite = SignatureSuite.HYBRID_DILITHIUM5_ED25519
    _dilithium_name = "Dilithium5"


class ClassicalEd25519Provider:
    """
    Assinatura Clássica: Ed25519 apenas (sem PQC).

    ATENÇÃO: Não protege contra computadores quânticos.
    Use apenas como fallback de emergência com autorização explícita.
    """

    suite: SignatureSuite = SignatureSuite.CLASSICAL_ONLY

    def generate_keypair(self) -> SigningKeyPair:
        try:
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key()

            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
            priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        except Exception as exc:
            raise SigningKeyGenerationError(f"Falha ao gerar keypair Ed25519: {exc}") from exc

        return SigningKeyPair(
            public_key=pub_bytes,
            private_key=bytearray(priv_bytes),
            suite=self.suite,
            key_id=generate_key_id(),
            created_at=current_timestamp(),
        )

    def sign(self, payload: bytes, private_key: bytearray) -> bytes:
        try:
            priv = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
            return priv.sign(payload)
        except Exception as exc:
            raise SignatureGenerationError(f"Falha na assinatura Ed25519: {exc}") from exc

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, payload)
            return True
        except Exception:
            return False
