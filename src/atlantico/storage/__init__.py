"""
Camada de Storage Segura do Projeto Atlântico.

Fornece persistência criptografada para todos os dados da plataforma.

Hierarquia de proteção:
    Nível 1 — Campos semi-sensíveis: EncryptedBytes TypeDecorator (AES-256-GCM, chave por coluna)
    Nível 2 — Dados operacionais: envelope PQC completo por registro (Kyber768+X25519 + Dilithium3)
    Nível 3 — Audit trail: encadeamento SHA3-256 + Row-Level Security PostgreSQL
"""

from atlantico.storage.encrypted_field import EncryptedBytes, EncryptionContext

__all__ = ["EncryptedBytes", "EncryptionContext"]
