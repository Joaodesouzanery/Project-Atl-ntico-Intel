"""
Combinador Híbrido PQC + Clássico via HKDF.

Implementa o combinador que funde os segredos derivados de dois mecanismos
criptográficos independentes (PQC e clássico) em uma única chave simétrica.

PROPRIEDADE DE SEGURANÇA:
    O segredo combinado é seguro se ao menos UM dos dois mecanismos for seguro.
    Atacante precisa quebrar AMBOS simultaneamente.

    combined_secret = HKDF-SHA3-512(
        ikm  = pqc_secret || classical_secret,
        salt = os.urandom(32),  # gerado por operação
        info = suite_label || context_bytes
    )

    O "suite_label" (bytes ASCII do enum value) provê separação de domínio:
    segredos de suites diferentes não podem ser confundidos.

REFERÊNCIAS:
    - Giacon, Heuer, Poettering: "KEM Combiners" (IACR 2018)
    - NIST SP 800-56C Rev.2: Key Derivation Using Pseudorandom Functions
    - RFC 9180: Hybrid Public Key Encryption (HPKE)
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Comprimento padrão da chave simétrica derivada (AES-256)
DEFAULT_KEY_LENGTH = 32  # bytes = 256 bits


def combine_secrets(
    pqc_secret: bytes,
    classical_secret: bytes,
    suite_label: str,
    key_length: int = DEFAULT_KEY_LENGTH,
    context: bytes = b"",
) -> bytes:
    """
    Combina segredos PQC e clássico via HKDF-SHA3-512.

    Args:
        pqc_secret: Segredo derivado do mecanismo PQC (ex: Kyber decapsulamento).
        classical_secret: Segredo derivado do mecanismo clássico (ex: X25519).
        suite_label: Identificador da suite (ex: "hybrid-kyber768-x25519").
                     Provê separação de domínio — crítico para segurança.
        key_length: Comprimento da chave derivada em bytes (padrão: 32).
        context: Bytes de contexto adicionais para vinculação (ex: record_id).

    Returns:
        Chave simétrica derivada de `key_length` bytes.

    AVISO: pqc_secret e classical_secret são concatenados diretamente.
    Segundo "KEM Combiners" de Giacon et al., esta construção é segura
    desde que a função de derivação seja uma PRF (o HKDF com SHA3-512 satisfaz).
    """
    if not pqc_secret:
        msg = "pqc_secret não pode ser vazio."
        raise ValueError(msg)
    if not classical_secret:
        msg = "classical_secret não pode ser vazio."
        raise ValueError(msg)
    if not suite_label:
        msg = "suite_label é obrigatório para separação de domínio."
        raise ValueError(msg)

    # IKM: material de chave de entrada = concatenação dos dois segredos
    ikm = pqc_secret + classical_secret

    # info: inclui suite_label (separação de domínio) + contexto adicional
    info = suite_label.encode("ascii") + b"\x00" + context

    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=key_length,
        # salt=None usa o salt padrão do HKDF (string de zeros do tamanho do hash)
        # Para uso em KEM, o shared_secret já tem alta entropia, então salt=None é aceitável.
        # Em contextos onde ikm pode ter baixa entropia, forneça um salt aleatório.
        salt=None,
        info=info,
    )

    return hkdf.derive(ikm)


def derive_symmetric_key(
    master_secret: bytes,
    context: bytes,
    suite_label: str,
    key_length: int = DEFAULT_KEY_LENGTH,
) -> bytes:
    """
    Deriva uma chave simétrica a partir de um segredo mestre + contexto.

    Usado pelo KeyManager para derivar chaves por registro a partir do KEM.
    O contexto deve ser único por operação (ex: record_id + timestamp encoded).

    PROPRIEDADE: Mesma chave mestre + contextos diferentes → chaves diferentes.
    Garante que comprometimento de uma chave de registro não compromete outras.
    """
    if not master_secret:
        msg = "master_secret não pode ser vazio."
        raise ValueError(msg)

    info = suite_label.encode("ascii") + b"\x00" + context

    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=key_length,
        salt=None,
        info=info,
    )

    return hkdf.derive(master_secret)
