"""
Módulo de Criptografia Pós-Quântica do Projeto Atlântico.

Ponto de entrada público do módulo crypto. Importe daqui, não dos submódulos.

Exemplo de uso:
    from atlantico.crypto import CryptoAgility, AlgorithmSuite

    kem = CryptoAgility.get_kem()
    keypair = kem.generate_keypair()
    encapsulated = kem.encapsulate(keypair.public_key)
    shared_secret = kem.decapsulate(encapsulated.ciphertext, keypair.private_key)
"""

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    EncapsulatedKey,
    KEMKeyPair,
    KEMProvider,
    SignatureProvider,
    SignatureSuite,
    SignedPayload,
    SigningKeyPair,
)

__all__ = [
    "AlgorithmSuite",
    "CryptoAgility",
    "EncapsulatedKey",
    "KEMKeyPair",
    "KEMProvider",
    "SignatureProvider",
    "SignatureSuite",
    "SignedPayload",
    "SigningKeyPair",
]
