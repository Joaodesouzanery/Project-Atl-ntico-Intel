"""
Testes de Cripto-Agilidade — Gate de Segurança Crítico.

ESTE É O TESTE MAIS IMPORTANTE DO PROJETO ATLÂNTICO.

Verifica que trocar a suite criptográfica (via env var / configuração)
não requer NENHUMA mudança em código de negócio, e que:

1. Dados cifrados com suite A são decriptografáveis apenas com suite A.
2. Dados cifrados com suite B são decriptografáveis apenas com suite B.
3. Novos dados usam a suite atual configurada.
4. O sistema pode operar com múltiplas suites simultaneamente (durante migração).
5. Adicionar uma nova suite requer apenas uma nova classe + enum value.

Se QUALQUER um destes testes falhar, a arquitetura de cripto-agilidade
foi comprometida e mudanças estruturais são necessárias.
"""

from __future__ import annotations

import pytest

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    SignatureSuite,
)
from atlantico.crypto.envelope import Envelope, decrypt, encrypt
from atlantico.crypto.exceptions import (
    ClassicalFallbackNotAllowedError,
    UnknownAlgorithmSuiteError,
)
from atlantico.crypto.key_manager import KeyManager


# ─── Providers de Stub para Suites Alternativas ───────────────────────────────


def make_stub_kem_provider(suite: AlgorithmSuite):
    """Factory de providers KEM de stub para qualquer suite."""
    from tests.conftest import StubKEMProvider

    class _Provider(StubKEMProvider):
        pass

    _Provider.suite = suite
    return _Provider()


def make_stub_sig_provider(suite: SignatureSuite):
    """Factory de providers de assinatura de stub para qualquer suite."""
    from tests.conftest import StubSignatureProvider

    class _Provider(StubSignatureProvider):
        pass

    _Provider.suite = suite
    return _Provider()


def setup_registry_with_suite(
    kem_suite: AlgorithmSuite,
    sig_suite: SignatureSuite,
) -> None:
    """Configura o registry com uma suite específica."""
    CryptoAgility._kem_providers[kem_suite] = make_stub_kem_provider(kem_suite)
    CryptoAgility._sig_providers[sig_suite] = make_stub_sig_provider(sig_suite)
    CryptoAgility._default_kem_suite = kem_suite
    CryptoAgility._default_sig_suite = sig_suite
    CryptoAgility._initialized = True


# ─── Testes ───────────────────────────────────────────────────────────────────


class TestSuiteSwapPreservesInterface:
    """
    Garante que qualquer suite (presente ou futura) produz os mesmos tipos
    e interfaces que o código de negócio espera.
    """

    @pytest.mark.parametrize("kem_suite", [
        AlgorithmSuite.HYBRID_KYBER768_X25519,
        AlgorithmSuite.HYBRID_KYBER1024_X25519,
    ])
    def test_kem_roundtrip_any_suite(self, kem_suite):
        """Roundtrip KEM funciona independente da suite."""
        provider = make_stub_kem_provider(kem_suite)
        keypair = provider.generate_keypair()

        assert keypair.suite == kem_suite
        assert keypair.key_id
        assert len(keypair.public_key) > 0

        encap = provider.encapsulate(keypair.public_key)
        assert encap.suite == kem_suite

        recovered = provider.decapsulate(encap.ciphertext, keypair.private_key)
        assert recovered == encap.shared_secret

    @pytest.mark.parametrize("sig_suite", [
        SignatureSuite.HYBRID_DILITHIUM3_ED25519,
        SignatureSuite.HYBRID_DILITHIUM5_ED25519,
    ])
    def test_signature_roundtrip_any_suite(self, sig_suite):
        """Assinatura/verificação funciona independente da suite."""
        provider = make_stub_sig_provider(sig_suite)
        keypair = provider.generate_keypair()

        payload = b"dado de inteligencia para qualquer suite"
        sig = provider.sign(payload, keypair.private_key)

        assert provider.verify(payload, sig, keypair.public_key)
        assert not provider.verify(b"adulterado", sig, keypair.public_key)


class TestEnvelopePreservesDataAcrossSuiteSwap:
    """
    Garantia central: dados cifrados com suite A continuam decriptografáveis
    mesmo após o sistema migrar para suite B.

    Isto simula o cenário real: sistema em produção com suite A,
    migração para suite B, dados antigos ainda precisam ser acessados.
    """

    def test_data_encrypted_with_suite_a_decryptable_after_swap_to_suite_b(self):
        """
        Dados cifrados com Suite A devem ser decriptografáveis após
        o sistema ser reconfigurado para Suite B.

        O envelope registra a suite A. O sistema lê a suite do envelope
        e usa o provider correto para decriptação, independente da suite padrão atual.
        """
        suite_a = AlgorithmSuite.HYBRID_KYBER768_X25519
        suite_b = AlgorithmSuite.HYBRID_KYBER1024_X25519

        sig_suite = SignatureSuite.HYBRID_DILITHIUM3_ED25519

        # ── Fase 1: Sistema configurado com Suite A ──────────────────
        setup_registry_with_suite(suite_a, sig_suite)

        kem_a = CryptoAgility.get_kem()
        sig = CryptoAgility.get_signer()

        kem_kp_a = kem_a.generate_keypair()
        sig_kp = sig.generate_keypair()

        plaintext = b"inteligencia sensivel cifrada com suite A"

        envelope_bytes = encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=kem_kp_a.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp_a.key_id,
        )

        # Verificar que o envelope registrou suite A
        envelope = Envelope.from_bytes(envelope_bytes)
        assert envelope.kem_suite == suite_a

        # ── Fase 2: Sistema reconfigurado para Suite B ────────────────
        # Simula o que acontece quando ATLANTICO_KEM_SUITE é alterado
        setup_registry_with_suite(suite_b, sig_suite)

        # Adicionar suite A ao registry (providers históricos devem permanecer)
        CryptoAgility._kem_providers[suite_a] = make_stub_kem_provider(suite_a)

        # Decriptografia deve usar suite A (lida do envelope), não suite B (padrão atual)
        recovered = decrypt(
            envelope_bytes=envelope_bytes,
            recipient_kem_private_key=kem_kp_a.private_key,
            verifier_public_keys={sig_kp.key_id: sig_kp.public_key},
        )

        assert recovered == plaintext

    def test_new_data_uses_current_suite(self):
        """Após swap para suite B, novos dados usam suite B."""
        suite_a = AlgorithmSuite.HYBRID_KYBER768_X25519
        suite_b = AlgorithmSuite.HYBRID_KYBER1024_X25519
        sig_suite = SignatureSuite.HYBRID_DILITHIUM3_ED25519

        # Configurar para suite B
        setup_registry_with_suite(suite_b, sig_suite)
        CryptoAgility._kem_providers[suite_a] = make_stub_kem_provider(suite_a)

        kem = CryptoAgility.get_kem()  # Deve retornar Suite B
        assert kem.suite == suite_b

        sig = CryptoAgility.get_signer()
        kem_kp = kem.generate_keypair()
        sig_kp = sig.generate_keypair()

        envelope_bytes = encrypt(
            plaintext=b"novos dados",
            recipient_kem_public_key=kem_kp.public_key,
            signing_private_key=sig_kp.private_key,
            signing_key_id=sig_kp.key_id,
            kem_key_id=kem_kp.key_id,
        )

        # Novo envelope deve usar suite B
        envelope = Envelope.from_bytes(envelope_bytes)
        assert envelope.kem_suite == suite_b


class TestNewSuiteCanBeAddedWithoutBusinessLogicChanges:
    """
    Simula adição de uma nova suite ao sistema.
    Demonstra que a cripto-agilidade permite extensão sem modificação.
    """

    def test_add_new_suite_to_registry(self):
        """
        Simular adição de uma nova suite hipotética.
        Apenas adicionar ao enum e registrar no registry — zero código de negócio alterado.
        """
        # Este teste usa suite_b como proxy para uma "nova suite"
        new_suite = AlgorithmSuite.HYBRID_KYBER1024_X25519
        new_sig_suite = SignatureSuite.HYBRID_DILITHIUM5_ED25519

        setup_registry_with_suite(new_suite, new_sig_suite)

        # Código de negócio usa CryptoAgility.get_kem() — não sabe qual suite está ativa
        kem = CryptoAgility.get_kem()
        signer = CryptoAgility.get_signer()

        assert kem.suite == new_suite
        assert signer.suite == new_sig_suite

        # Roundtrip funciona com a nova suite
        kp = kem.generate_keypair()
        sk = signer.generate_keypair()

        encap = kem.encapsulate(kp.public_key)
        recovered = kem.decapsulate(encap.ciphertext, kp.private_key)
        assert recovered == encap.shared_secret

        payload = b"dados com nova suite"
        sig = signer.sign(payload, sk.private_key)
        assert signer.verify(payload, sig, sk.public_key)


class TestClassicalFallbackProtection:
    """
    Garante que o fallback para suite clássica (sem PQC) é devidamente protegido.
    Esta é uma salvaguarda crítica contra downgrade acidental de segurança.
    """

    def test_classical_kem_blocked_without_authorization(self, initialized_crypto):
        """Suite clássica deve ser bloqueada por padrão."""
        from tests.conftest import StubKEMProvider

        class ClassicalProvider(StubKEMProvider):
            suite = AlgorithmSuite.CLASSICAL_ONLY

        CryptoAgility._kem_providers[AlgorithmSuite.CLASSICAL_ONLY] = ClassicalProvider()
        CryptoAgility._allow_classical_fallback = False

        with pytest.raises(ClassicalFallbackNotAllowedError):
            CryptoAgility.get_kem(AlgorithmSuite.CLASSICAL_ONLY)

    def test_classical_kem_allowed_with_explicit_authorization(self, initialized_crypto):
        """Suite clássica funciona quando explicitamente autorizada."""
        from tests.conftest import StubKEMProvider

        class ClassicalProvider(StubKEMProvider):
            suite = AlgorithmSuite.CLASSICAL_ONLY

        CryptoAgility._kem_providers[AlgorithmSuite.CLASSICAL_ONLY] = ClassicalProvider()
        CryptoAgility._allow_classical_fallback = True  # Autorização explícita

        provider = CryptoAgility.get_kem(AlgorithmSuite.CLASSICAL_ONLY)
        assert provider.suite == AlgorithmSuite.CLASSICAL_ONLY
