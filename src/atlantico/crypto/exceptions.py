"""
Exceções do módulo de criptografia pós-quântica.

Hierarquia clara para que código de negócio possa capturar categorias
específicas de falha sem depender de exceções de bibliotecas de terceiros
(liboqs, cryptography). Isso também faz parte da cripto-agilidade: trocar
a biblioteca subjacente não muda as exceções que o código de negócio captura.
"""

from __future__ import annotations


class AtlanticoCryptoError(Exception):
    """Exceção base para todos os erros do módulo crypto."""


# ─── Erros de Configuração ────────────────────────────────────────────────────


class UnknownAlgorithmSuiteError(AtlanticoCryptoError):
    """Suite de algoritmo não registrada no CryptoAgility registry."""

    def __init__(self, suite_name: str) -> None:
        super().__init__(
            f"Suite '{suite_name}' não está registrada. "
            "Verifique ATLANTICO_KEM_SUITE ou ATLANTICO_SIG_SUITE."
        )
        self.suite_name = suite_name


class ClassicalFallbackNotAllowedError(AtlanticoCryptoError):
    """
    Tentativa de usar suite clássica (sem PQC) sem autorização explícita.
    Previne downgrade acidental da proteção pós-quântica.
    """

    def __init__(self) -> None:
        super().__init__(
            "Suite clássica (sem PQC) requer ATLANTICO_ALLOW_CLASSICAL_FALLBACK=true. "
            "Esta proteção previne degradação acidental da segurança pós-quântica."
        )


# ─── Erros de Operação KEM ────────────────────────────────────────────────────


class KEMEncapsulationError(AtlanticoCryptoError):
    """Falha durante encapsulamento KEM."""


class KEMDecapsulationError(AtlanticoCryptoError):
    """
    Falha durante decapsulamento KEM.
    Pode indicar chave inválida, ciphertext corrompido ou ataque.
    """


class KEMKeyGenerationError(AtlanticoCryptoError):
    """Falha na geração de par de chaves KEM."""


# ─── Erros de Operação de Assinatura ─────────────────────────────────────────


class SignatureGenerationError(AtlanticoCryptoError):
    """Falha na geração de assinatura digital."""


class SignatureVerificationError(AtlanticoCryptoError):
    """
    Assinatura inválida ou verificação falhou.
    Pode indicar dados corrompidos, chave incorreta ou adulteração.
    """


class SigningKeyGenerationError(AtlanticoCryptoError):
    """Falha na geração de par de chaves de assinatura."""


# ─── Erros de Envelope ────────────────────────────────────────────────────────


class EnvelopeEncryptionError(AtlanticoCryptoError):
    """Falha na criação de envelope criptografado."""


class EnvelopeDecryptionError(AtlanticoCryptoError):
    """
    Falha na decriptação de envelope.
    Pode indicar chave incorreta, dados corrompidos ou adulteração (tag AES-GCM falhou).
    """


class EnvelopeFormatError(AtlanticoCryptoError):
    """Formato de envelope binário inválido ou versão não suportada."""


# ─── Erros de Gerenciamento de Chaves ────────────────────────────────────────


class KeyNotFoundError(AtlanticoCryptoError):
    """Chave com o key_id especificado não encontrada no store."""

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Chave '{key_id}' não encontrada.")
        self.key_id = key_id


class KeyRetiredError(AtlanticoCryptoError):
    """
    Chave foi aposentada (retired) e não pode mais ser usada para decriptação.
    Indica que o período de graça expirou.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(
            f"Chave '{key_id}' foi aposentada e não pode mais ser usada. "
            "Dados cifrados com esta chave podem ser irrecuperáveis."
        )
        self.key_id = key_id


class KeyRotationError(AtlanticoCryptoError):
    """Falha durante o processo de rotação de chaves."""


class MasterKeyError(AtlanticoCryptoError):
    """Erro relacionado à chave mestra (KEK) — chave das chaves."""


# ─── Erros de Integridade ────────────────────────────────────────────────────


class IntegrityViolationError(AtlanticoCryptoError):
    """
    Violação de integridade detectada.
    Pode indicar adulteração de dados ou ataque ativo.
    SEMPRE registre este erro no audit log com nível CRITICAL.
    """

    def __init__(self, context: str) -> None:
        super().__init__(
            f"VIOLAÇÃO DE INTEGRIDADE em '{context}'. "
            "Possível adulteração de dados detectada. Registrar no audit log."
        )
        self.context = context
