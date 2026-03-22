"""
Abstração de Cripto-Agilidade do Projeto Atlântico.

Este é o arquivo mais importante do sistema de criptografia.
Define os contratos (Protocols) que todos os provedores de algoritmo
devem implementar, e o registry central CryptoAgility.

PRINCÍPIO FUNDAMENTAL:
    Nenhum módulo externo ao pacote crypto/ importa liboqs ou cryptography diretamente.
    Todo código de negócio (storage, ingestion, api, correlation) usa apenas:
        - CryptoAgility.get_kem()
        - CryptoAgility.get_signer()

Trocar de Kyber768 para outro algoritmo = 1 env var + 1 classe nova.
Zero mudanças em código de negócio.

DEFESA HARVEST-NOW-DECRYPT-LATER:
    O KEM híbrido (PQC + clássico) garante que um adversário precisa quebrar
    AMBOS os algoritmos simultaneamente para comprometer a confidencialidade.
    Dados capturados hoje permanecem seguros mesmo após o advento de
    computadores quânticos suficientemente poderosos.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from atlantico.crypto.exceptions import (
    ClassicalFallbackNotAllowedError,
    UnknownAlgorithmSuiteError,
)

if TYPE_CHECKING:
    pass


# ─── Suites de Algoritmo ──────────────────────────────────────────────────────


class AlgorithmSuite(str, Enum):
    """
    Suites KEM disponíveis.

    Valores string são usados no envelope binário e em logs — não altere
    valores existentes, pois dados históricos dependem deles para decriptação.
    Adicione apenas novas entradas.
    """

    # ── Híbrido (PQC + Clássico) — RECOMENDADO para Fase 1 ──────────
    HYBRID_KYBER768_X25519 = "hybrid-kyber768-x25519"
    HYBRID_KYBER1024_X25519 = "hybrid-kyber1024-x25519"

    # ── PQC Puro — Para uso futuro após consolidação dos padrões NIST ─
    PQC_ONLY_MLKEM768 = "pqc-mlkem768"
    PQC_ONLY_MLKEM1024 = "pqc-mlkem1024"

    # ── Clássico Apenas — Fallback de emergência (requer autorização) ─
    CLASSICAL_ONLY = "classical-x25519"

    @property
    def is_classical_only(self) -> bool:
        return self == AlgorithmSuite.CLASSICAL_ONLY

    @property
    def is_hybrid(self) -> bool:
        return self.value.startswith("hybrid-")

    @property
    def is_pqc_only(self) -> bool:
        return self.value.startswith("pqc-")

    @classmethod
    def from_string(cls, value: str) -> "AlgorithmSuite":
        try:
            return cls(value)
        except ValueError as exc:
            valid = [s.value for s in cls]
            msg = f"Suite KEM inválida: '{value}'. Válidas: {valid}"
            raise UnknownAlgorithmSuiteError(value) from exc


class SignatureSuite(str, Enum):
    """
    Suites de assinatura digital disponíveis.

    Mesmas regras de AlgorithmSuite: não altere valores existentes.
    """

    # ── Híbrido (PQC + Clássico) — RECOMENDADO para Fase 1 ──────────
    HYBRID_DILITHIUM3_ED25519 = "hybrid-dilithium3-ed25519"
    HYBRID_DILITHIUM5_ED25519 = "hybrid-dilithium5-ed25519"

    # ── PQC Puro ──────────────────────────────────────────────────────
    PQC_ONLY_MLDSA65 = "pqc-mldsa65"
    PQC_ONLY_MLDSA87 = "pqc-mldsa87"

    # ── Clássico Apenas ───────────────────────────────────────────────
    CLASSICAL_ONLY = "classical-ed25519"

    @property
    def is_classical_only(self) -> bool:
        return self == SignatureSuite.CLASSICAL_ONLY

    @classmethod
    def from_string(cls, value: str) -> "SignatureSuite":
        try:
            return cls(value)
        except ValueError:
            valid = [s.value for s in cls]
            msg = f"Suite de assinatura inválida: '{value}'. Válidas: {valid}"
            raise UnknownAlgorithmSuiteError(value)


# ─── Tipos de Dados Imutáveis ────────────────────────────────────────────────


@dataclass(frozen=True)
class KEMKeyPair:
    """
    Par de chaves KEM.

    ATENÇÃO DE SEGURANÇA:
    - private_key é um bytearray para permitir zeroing após uso.
    - Nunca converta private_key para bytes imutável.
    - Nunca serialize private_key para logs ou respostas de API.
    """

    public_key: bytes
    private_key: bytearray  # Mutável para zeroing seguro
    suite: AlgorithmSuite
    key_id: str  # UUID para rastreamento de ciclo de vida
    created_at: int  # Unix timestamp (segundos)

    def zero_private_key(self) -> None:
        """Zera a chave privada na memória. Chame após uso."""
        for i in range(len(self.private_key)):
            self.private_key[i] = 0

    def __repr__(self) -> str:
        return (
            f"KEMKeyPair(key_id={self.key_id!r}, suite={self.suite.value!r}, "
            f"public_key_len={len(self.public_key)}, [PRIVATE KEY OCULTA])"
        )


@dataclass(frozen=True)
class SigningKeyPair:
    """Par de chaves de assinatura digital."""

    public_key: bytes
    private_key: bytearray  # Mutável para zeroing seguro
    suite: SignatureSuite
    key_id: str
    created_at: int

    def zero_private_key(self) -> None:
        """Zera a chave privada na memória. Chame após uso."""
        for i in range(len(self.private_key)):
            self.private_key[i] = 0

    def __repr__(self) -> str:
        return (
            f"SigningKeyPair(key_id={self.key_id!r}, suite={self.suite.value!r}, "
            f"public_key_len={len(self.public_key)}, [PRIVATE KEY OCULTA])"
        )


@dataclass(frozen=True)
class EncapsulatedKey:
    """
    Resultado de uma operação de encapsulamento KEM.

    ciphertext: enviado ao destinatário para decapsulamento.
    shared_secret: segredo derivado — NUNCA transmitir, usar apenas localmente.
    """

    ciphertext: bytes
    shared_secret: bytes  # Nunca sai deste objeto; use para derivar chave simétrica
    suite: AlgorithmSuite

    def __repr__(self) -> str:
        return (
            f"EncapsulatedKey(suite={self.suite.value!r}, "
            f"ciphertext_len={len(self.ciphertext)}, [SHARED SECRET OCULTO])"
        )


@dataclass(frozen=True)
class SignedPayload:
    """Payload com assinatura digital anexada."""

    payload: bytes
    signature: bytes
    suite: SignatureSuite
    signer_key_id: str
    signed_at: int = field(default_factory=lambda: int(time.time()))


# ─── Protocols (Contratos de Interface) ─────────────────────────────────────


@runtime_checkable
class KEMProvider(Protocol):
    """
    Interface que todo provedor KEM deve implementar.

    runtime_checkable permite usar isinstance() para verificar conformidade,
    mas a verificação é apenas estrutural — útil para testes.
    """

    suite: AlgorithmSuite

    def generate_keypair(self) -> KEMKeyPair:
        """Gera novo par de chaves KEM com key_id único."""
        ...

    def encapsulate(self, recipient_public_key: bytes) -> EncapsulatedKey:
        """
        Encapsula uma chave simétrica para o destinatário.
        Retorna ciphertext (para transmitir) e shared_secret (usar localmente).
        """
        ...

    def decapsulate(self, ciphertext: bytes, private_key: bytearray) -> bytes:
        """
        Decapsula e recupera o shared_secret a partir do ciphertext.
        Requer a chave privada correspondente à chave pública usada no encapsulamento.
        """
        ...


@runtime_checkable
class SignatureProvider(Protocol):
    """Interface que todo provedor de assinatura deve implementar."""

    suite: SignatureSuite

    def generate_keypair(self) -> SigningKeyPair:
        """Gera novo par de chaves de assinatura com key_id único."""
        ...

    def sign(self, payload: bytes, private_key: bytearray) -> bytes:
        """Assina payload com a chave privada. Retorna bytes da assinatura."""
        ...

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifica assinatura. Retorna True se válida.
        NUNCA lança exceção por assinatura inválida — apenas retorna False.
        Exceções indicam erros técnicos (formato inválido, etc.).
        """
        ...


# ─── Registry Central ────────────────────────────────────────────────────────


class CryptoAgility:
    """
    Registry central de provedores de algoritmos criptográficos.

    RESPONSABILIDADE ÚNICA: mapear AlgorithmSuite/SignatureSuite → instância
    de provider. Todo o resto do sistema usa esta classe como ponto de acesso.

    USO:
        # No startup da aplicação (ex: main.py):
        CryptoAgility.initialize(settings)

        # Em qualquer módulo de negócio:
        kem = CryptoAgility.get_kem()
        signer = CryptoAgility.get_signer()

    NÃO instanciar providers diretamente fora de crypto/.
    """

    _kem_providers: dict[AlgorithmSuite, KEMProvider] = {}
    _sig_providers: dict[SignatureSuite, SignatureProvider] = {}
    _default_kem_suite: AlgorithmSuite = AlgorithmSuite.HYBRID_KYBER768_X25519
    _default_sig_suite: SignatureSuite = SignatureSuite.HYBRID_DILITHIUM3_ED25519
    _initialized: bool = False
    _allow_classical_fallback: bool = False

    @classmethod
    def register_kem_provider(
        cls,
        suite: AlgorithmSuite,
        provider: KEMProvider,
        *,
        allow_classical: bool = False,
    ) -> None:
        """
        Registra um provedor KEM para uma suite.
        Chamado no startup da aplicação ao importar os providers concretos.
        """
        if suite.is_classical_only and not allow_classical:
            raise ClassicalFallbackNotAllowedError()
        cls._kem_providers[suite] = provider

    @classmethod
    def register_sig_provider(
        cls,
        suite: SignatureSuite,
        provider: SignatureProvider,
        *,
        allow_classical: bool = False,
    ) -> None:
        """Registra um provedor de assinatura para uma suite."""
        if suite.is_classical_only and not allow_classical:
            raise ClassicalFallbackNotAllowedError()
        cls._sig_providers[suite] = provider

    @classmethod
    def initialize(cls, settings: object) -> None:
        """
        Inicializa o registry com as configurações da aplicação.
        Importa e registra os providers concretos.
        Deve ser chamado UMA VEZ no startup da aplicação.
        """
        from atlantico.config.settings import Settings

        if not isinstance(settings, Settings):
            msg = "settings deve ser instância de Settings"
            raise TypeError(msg)

        s: "Settings" = settings
        allow_classical = s.allow_classical_fallback
        cls._allow_classical_fallback = allow_classical

        # Importação tardia para evitar ciclos e garantir que liboqs
        # só seja carregado quando necessário (facilita testes sem a lib)
        from atlantico.crypto.kem import (
            ClassicalX25519Provider,
            HybridKyber1024X25519Provider,
            HybridKyber768X25519Provider,
        )
        from atlantico.crypto.signatures import (
            ClassicalEd25519Provider,
            HybridDilithium3Ed25519Provider,
            HybridDilithium5Ed25519Provider,
        )

        # Registrar providers KEM
        cls._kem_providers = {
            AlgorithmSuite.HYBRID_KYBER768_X25519: HybridKyber768X25519Provider(),
            AlgorithmSuite.HYBRID_KYBER1024_X25519: HybridKyber1024X25519Provider(),
        }
        if allow_classical:
            cls._kem_providers[AlgorithmSuite.CLASSICAL_ONLY] = ClassicalX25519Provider()

        # Registrar providers de assinatura
        cls._sig_providers = {
            SignatureSuite.HYBRID_DILITHIUM3_ED25519: HybridDilithium3Ed25519Provider(),
            SignatureSuite.HYBRID_DILITHIUM5_ED25519: HybridDilithium5Ed25519Provider(),
        }
        if allow_classical:
            cls._sig_providers[SignatureSuite.CLASSICAL_ONLY] = ClassicalEd25519Provider()

        # Configurar suites padrão a partir das settings
        cls._default_kem_suite = AlgorithmSuite.from_string(s.kem_suite)
        cls._default_sig_suite = SignatureSuite.from_string(s.sig_suite)

        # Validar que a suite padrão está registrada
        if cls._default_kem_suite not in cls._kem_providers:
            raise UnknownAlgorithmSuiteError(cls._default_kem_suite.value)
        if cls._default_sig_suite not in cls._sig_providers:
            raise UnknownAlgorithmSuiteError(cls._default_sig_suite.value)

        cls._initialized = True

    @classmethod
    def get_kem(cls, suite: AlgorithmSuite | None = None) -> KEMProvider:
        """
        Retorna o provider KEM para a suite especificada.
        Se suite=None, retorna o provider da suite padrão configurada.
        """
        target = suite or cls._default_kem_suite
        if target not in cls._kem_providers:
            raise UnknownAlgorithmSuiteError(target.value)
        provider = cls._kem_providers[target]
        if target.is_classical_only and not cls._allow_classical_fallback:
            raise ClassicalFallbackNotAllowedError()
        return provider

    @classmethod
    def get_signer(cls, suite: SignatureSuite | None = None) -> SignatureProvider:
        """
        Retorna o provider de assinatura para a suite especificada.
        Se suite=None, retorna o provider da suite padrão configurada.
        """
        target = suite or cls._default_sig_suite
        if target not in cls._sig_providers:
            raise UnknownAlgorithmSuiteError(target.value)
        provider = cls._sig_providers[target]
        if target.is_classical_only and not cls._allow_classical_fallback:
            raise ClassicalFallbackNotAllowedError()
        return provider

    @classmethod
    def get_default_kem_suite(cls) -> AlgorithmSuite:
        return cls._default_kem_suite

    @classmethod
    def get_default_sig_suite(cls) -> SignatureSuite:
        return cls._default_sig_suite

    @classmethod
    def is_initialized(cls) -> bool:
        return cls._initialized

    @classmethod
    def _reset_for_testing(cls) -> None:
        """APENAS PARA TESTES. Reseta o estado do registry."""
        cls._kem_providers = {}
        cls._sig_providers = {}
        cls._default_kem_suite = AlgorithmSuite.HYBRID_KYBER768_X25519
        cls._default_sig_suite = SignatureSuite.HYBRID_DILITHIUM3_ED25519
        cls._initialized = False
        cls._allow_classical_fallback = False


def generate_key_id() -> str:
    """
    Gera um key_id único e opaco.
    Usa 16 bytes aleatórios criptograficamente seguros, codificados em hex.
    Formato opaco (não UUID) para não vazar informação de timing via versão UUID.
    """
    return os.urandom(16).hex()


def current_timestamp() -> int:
    """Retorna timestamp Unix atual em segundos."""
    return int(time.time())
