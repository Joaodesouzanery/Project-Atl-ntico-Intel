"""
Envelope Criptográfico do Projeto Atlântico.

Primitiva de criptografia autenticada usada por todo o sistema para
proteger dados em repouso (storage) e em trânsito entre serviços internos.

FORMATO BINÁRIO DO ENVELOPE (big-endian):
    [4B: versão]             — versão do formato (atualmente 0x0001)
    [4B: suite_flags]        — AlgorithmSuite encoded como uint32
    [32B: kem_key_id]        — key_id da chave KEM usada (hex, 32 chars ASCII)
    [4B: kem_ct_len]         — comprimento do ciphertext KEM
    [N: kem_ciphertext]      — ciphertext do KEM (para decapsulamento)
    [12B: aes_nonce]         — nonce AES-256-GCM (96 bits)
    [4B: ct_len]             — comprimento do ciphertext AES
    [N: ciphertext]          — dados criptografados
    [16B: aes_tag]           — tag de autenticação AES-GCM
    [32B: sig_key_id]        — key_id da chave de assinatura (hex, 32 chars)
    [4B: sig_suite_flags]    — SignatureSuite encoded como uint32
    [4B: sig_len]            — comprimento da assinatura
    [N: signature]           — assinatura sobre todo o envelope (exceto a si mesma)

A assinatura cobre tudo até (exclusive) o campo sig_key_id, garantindo
integridade e autenticidade de todos os campos do envelope.

PROPRIEDADE CRIPTOGRÁFICA:
    Confidencialidade: AES-256-GCM com chave derivada por KEM PQC híbrido.
    Integridade: AES-256-GCM tag + assinatura Dilithium+Ed25519.
    Autenticidade: assinatura do sistema emissora.
    Cripto-agilidade: suite registrada no envelope, decriptação independente de config atual.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    SignatureSuite,
)
from atlantico.crypto.exceptions import (
    EnvelopeDecryptionError,
    EnvelopeEncryptionError,
    EnvelopeFormatError,
    IntegrityViolationError,
)
from atlantico.crypto.hybrid import derive_symmetric_key

# Constantes do formato
_ENVELOPE_VERSION = 1
_KEY_ID_LEN = 32       # 32 bytes hex = 64 ASCII chars; armazenamos como 32 bytes raw
_AES_NONCE_LEN = 12    # 96 bits
_AES_TAG_LEN = 16      # 128 bits

# Mapeamento AlgorithmSuite → uint32 (não alterar valores existentes)
_KEM_SUITE_TO_INT: dict[AlgorithmSuite, int] = {
    AlgorithmSuite.HYBRID_KYBER768_X25519: 1,
    AlgorithmSuite.HYBRID_KYBER1024_X25519: 2,
    AlgorithmSuite.PQC_ONLY_MLKEM768: 3,
    AlgorithmSuite.PQC_ONLY_MLKEM1024: 4,
    AlgorithmSuite.CLASSICAL_ONLY: 0xFF,
}
_INT_TO_KEM_SUITE = {v: k for k, v in _KEM_SUITE_TO_INT.items()}

_SIG_SUITE_TO_INT: dict[SignatureSuite, int] = {
    SignatureSuite.HYBRID_DILITHIUM3_ED25519: 1,
    SignatureSuite.HYBRID_DILITHIUM5_ED25519: 2,
    SignatureSuite.PQC_ONLY_MLDSA65: 3,
    SignatureSuite.PQC_ONLY_MLDSA87: 4,
    SignatureSuite.CLASSICAL_ONLY: 0xFF,
}
_INT_TO_SIG_SUITE = {v: k for k, v in _SIG_SUITE_TO_INT.items()}


@dataclass(frozen=True)
class Envelope:
    """Representação deserializada de um envelope."""

    version: int
    kem_suite: AlgorithmSuite
    kem_key_id: str
    kem_ciphertext: bytes
    aes_nonce: bytes
    ciphertext: bytes
    aes_tag: bytes
    sig_key_id: str
    sig_suite: SignatureSuite
    signature: bytes

    def to_bytes(self) -> bytes:
        """Serializa o envelope para o formato binário."""
        return _serialize_envelope(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        """Desserializa o envelope a partir do formato binário."""
        return _deserialize_envelope(data)


def encrypt(
    plaintext: bytes,
    recipient_kem_public_key: bytes,
    signing_private_key: "bytearray",
    signing_key_id: str,
    kem_key_id: str,
    context: bytes = b"",
) -> bytes:
    """
    Criptografa e autentica dados, produzindo um envelope binário.

    Args:
        plaintext: Dados a criptografar.
        recipient_kem_public_key: Chave pública KEM do destinatário.
        signing_private_key: Chave privada de assinatura do sistema.
        signing_key_id: key_id da chave de assinatura.
        kem_key_id: key_id da chave KEM usada.
        context: Bytes de contexto adicionais para derivação de chave (ex: record_id).

    Returns:
        Bytes do envelope criptografado e assinado.
    """
    try:
        kem = CryptoAgility.get_kem()
        signer = CryptoAgility.get_signer()

        # 1. KEM: gerar shared_secret encapsulado para o destinatário
        encapsulated = kem.encapsulate(recipient_kem_public_key)

        # 2. Derivar chave AES a partir do shared_secret + contexto
        aes_key = derive_symmetric_key(
            master_secret=encapsulated.shared_secret,
            context=context,
            suite_label=kem.suite.value,
        )

        # 3. Criptografar com AES-256-GCM
        nonce = os.urandom(_AES_NONCE_LEN)
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, context or None)

        # AES-GCM do Python retorna ciphertext || tag (últimos 16 bytes = tag)
        ciphertext = ciphertext_with_tag[:-_AES_TAG_LEN]
        aes_tag = ciphertext_with_tag[-_AES_TAG_LEN:]

        # 4. Construir envelope parcial (sem assinatura)
        envelope_partial = _serialize_envelope_without_signature(
            kem_suite=kem.suite,
            kem_key_id=kem_key_id,
            kem_ciphertext=encapsulated.ciphertext,
            nonce=nonce,
            ciphertext=ciphertext,
            aes_tag=aes_tag,
        )

        # 5. Assinar o envelope parcial
        signature = signer.sign(envelope_partial, signing_private_key)

        # 6. Montar envelope completo
        envelope = Envelope(
            version=_ENVELOPE_VERSION,
            kem_suite=kem.suite,
            kem_key_id=kem_key_id,
            kem_ciphertext=encapsulated.ciphertext,
            aes_nonce=nonce,
            ciphertext=ciphertext,
            aes_tag=aes_tag,
            sig_key_id=signing_key_id,
            sig_suite=signer.suite,
            signature=signature,
        )

        return envelope.to_bytes()

    except (EnvelopeEncryptionError, EnvelopeFormatError):
        raise
    except Exception as exc:
        raise EnvelopeEncryptionError(f"Falha ao criar envelope: {exc}") from exc


def decrypt(
    envelope_bytes: bytes,
    recipient_kem_private_key: "bytearray",
    verifier_public_keys: dict[str, bytes],
    context: bytes = b"",
) -> bytes:
    """
    Decriptografa e verifica um envelope.

    Args:
        envelope_bytes: Bytes do envelope criptografado.
        recipient_kem_private_key: Chave privada KEM do destinatário.
        verifier_public_keys: Mapa {key_id → chave pública de assinatura}.
                              Deve conter a chave referenciada pelo sig_key_id do envelope.
        context: Mesmo contexto usado na criptografia.

    Returns:
        Plaintext decriptografado.

    Raises:
        EnvelopeFormatError: Formato de envelope inválido.
        EnvelopeDecryptionError: Falha na decriptação ou verificação.
        IntegrityViolationError: Assinatura inválida — possível adulteração.
    """
    try:
        envelope = Envelope.from_bytes(envelope_bytes)

        # 1. Verificar assinatura ANTES de decriptografar (evitar oracle de decriptação)
        sig_public_key = verifier_public_keys.get(envelope.sig_key_id)
        if sig_public_key is None:
            raise EnvelopeDecryptionError(
                f"Chave de assinatura '{envelope.sig_key_id}' não encontrada."
            )

        signer = CryptoAgility.get_signer(envelope.sig_suite)
        envelope_partial = _serialize_envelope_without_signature(
            kem_suite=envelope.kem_suite,
            kem_key_id=envelope.kem_key_id,
            kem_ciphertext=envelope.kem_ciphertext,
            nonce=envelope.aes_nonce,
            ciphertext=envelope.ciphertext,
            aes_tag=envelope.aes_tag,
        )

        if not signer.verify(envelope_partial, envelope.signature, sig_public_key):
            raise IntegrityViolationError(f"envelope sig_key_id={envelope.sig_key_id}")

        # 2. KEM: recuperar shared_secret
        kem = CryptoAgility.get_kem(envelope.kem_suite)
        shared_secret = kem.decapsulate(envelope.kem_ciphertext, recipient_kem_private_key)

        # 3. Derivar chave AES
        aes_key = derive_symmetric_key(
            master_secret=shared_secret,
            context=context,
            suite_label=kem.suite.value,
        )

        # 4. Decriptografar AES-256-GCM
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = envelope.ciphertext + envelope.aes_tag
        plaintext = aesgcm.decrypt(envelope.aes_nonce, ciphertext_with_tag, context or None)

        return plaintext

    except (EnvelopeDecryptionError, EnvelopeFormatError, IntegrityViolationError):
        raise
    except Exception as exc:
        raise EnvelopeDecryptionError(f"Falha ao decriptografar envelope: {exc}") from exc


# ─── Serialização Interna ─────────────────────────────────────────────────────


def _serialize_envelope_without_signature(
    kem_suite: AlgorithmSuite,
    kem_key_id: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aes_tag: bytes,
) -> bytes:
    """Serializa o envelope sem o campo de assinatura (para assinar/verificar)."""
    parts = [
        struct.pack(">I", _ENVELOPE_VERSION),
        struct.pack(">I", _KEM_SUITE_TO_INT[kem_suite]),
        kem_key_id.encode("ascii")[:_KEY_ID_LEN].ljust(_KEY_ID_LEN, b"\x00"),
        struct.pack(">I", len(kem_ciphertext)),
        kem_ciphertext,
        nonce,
        struct.pack(">I", len(ciphertext)),
        ciphertext,
        aes_tag,
    ]
    return b"".join(parts)


def _serialize_envelope(envelope: "Envelope") -> bytes:
    """Serializa o envelope completo incluindo assinatura."""
    partial = _serialize_envelope_without_signature(
        kem_suite=envelope.kem_suite,
        kem_key_id=envelope.kem_key_id,
        kem_ciphertext=envelope.kem_ciphertext,
        nonce=envelope.aes_nonce,
        ciphertext=envelope.ciphertext,
        aes_tag=envelope.aes_tag,
    )

    sig_part = b"".join([
        envelope.sig_key_id.encode("ascii")[:_KEY_ID_LEN].ljust(_KEY_ID_LEN, b"\x00"),
        struct.pack(">I", _SIG_SUITE_TO_INT[envelope.sig_suite]),
        struct.pack(">I", len(envelope.signature)),
        envelope.signature,
    ])

    return partial + sig_part


def _deserialize_envelope(data: bytes) -> "Envelope":
    """Desserializa envelope a partir de bytes."""
    try:
        offset = 0

        def read(n: int) -> bytes:
            nonlocal offset
            chunk = data[offset:offset + n]
            if len(chunk) != n:
                raise EnvelopeFormatError(
                    f"Envelope truncado: esperado {n} bytes em offset {offset}, "
                    f"disponível {len(chunk)}."
                )
            offset += n
            return chunk

        version = struct.unpack(">I", read(4))[0]
        if version != _ENVELOPE_VERSION:
            raise EnvelopeFormatError(f"Versão de envelope não suportada: {version}.")

        suite_int = struct.unpack(">I", read(4))[0]
        if suite_int not in _INT_TO_KEM_SUITE:
            raise EnvelopeFormatError(f"Suite KEM desconhecida: {suite_int}.")
        kem_suite = _INT_TO_KEM_SUITE[suite_int]

        kem_key_id = read(_KEY_ID_LEN).rstrip(b"\x00").decode("ascii")

        kem_ct_len = struct.unpack(">I", read(4))[0]
        kem_ciphertext = read(kem_ct_len)

        nonce = read(_AES_NONCE_LEN)

        ct_len = struct.unpack(">I", read(4))[0]
        ciphertext = read(ct_len)

        aes_tag = read(_AES_TAG_LEN)

        sig_key_id = read(_KEY_ID_LEN).rstrip(b"\x00").decode("ascii")

        sig_suite_int = struct.unpack(">I", read(4))[0]
        if sig_suite_int not in _INT_TO_SIG_SUITE:
            raise EnvelopeFormatError(f"Suite de assinatura desconhecida: {sig_suite_int}.")
        sig_suite = _INT_TO_SIG_SUITE[sig_suite_int]

        sig_len = struct.unpack(">I", read(4))[0]
        signature = read(sig_len)

        return Envelope(
            version=version,
            kem_suite=kem_suite,
            kem_key_id=kem_key_id,
            kem_ciphertext=kem_ciphertext,
            aes_nonce=nonce,
            ciphertext=ciphertext,
            aes_tag=aes_tag,
            sig_key_id=sig_key_id,
            sig_suite=sig_suite,
            signature=signature,
        )

    except (EnvelopeFormatError,):
        raise
    except Exception as exc:
        raise EnvelopeFormatError(f"Falha ao desserializar envelope: {exc}") from exc
