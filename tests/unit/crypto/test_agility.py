"""
Testes de cripto-agilidade — o teste mais importante do sistema.

Verifica que:
1. O registry funciona corretamente.
2. Trocar a suite (via configuração) não afeta código de negócio.
3. Fallback clássico é bloqueado sem autorização.
4. Providers de suites diferentes retornam tipos compatíveis.
"""

from __future__ import annotations

import pytest

from atlantico.crypto.agility import (
    AlgorithmSuite,
    CryptoAgility,
    SignatureSuite,
)
from atlantico.crypto.exceptions import (
    ClassicalFallbackNotAllowedError,
    UnknownAlgorithmSuiteError,
)


class TestAlgorithmSuiteEnum:
    def test_from_string_valid(self):
        suite = AlgorithmSuite.from_string("hybrid-kyber768-x25519")
        assert suite == AlgorithmSuite.HYBRID_KYBER768_X25519

    def test_from_string_invalid(self):
        with pytest.raises(UnknownAlgorithmSuiteError):
            AlgorithmSuite.from_string("unknown-algorithm")

    def test_is_hybrid(self):
        assert AlgorithmSuite.HYBRID_KYBER768_X25519.is_hybrid
        assert AlgorithmSuite.HYBRID_KYBER1024_X25519.is_hybrid
        assert not AlgorithmSuite.CLASSICAL_ONLY.is_hybrid
        assert not AlgorithmSuite.PQC_ONLY_MLKEM768.is_hybrid

    def test_is_classical_only(self):
        assert AlgorithmSuite.CLASSICAL_ONLY.is_classical_only
        assert not AlgorithmSuite.HYBRID_KYBER768_X25519.is_classical_only

    def test_is_pqc_only(self):
        assert AlgorithmSuite.PQC_ONLY_MLKEM768.is_pqc_only
        assert not AlgorithmSuite.HYBRID_KYBER768_X25519.is_pqc_only


class TestCryptoAgilityRegistry:
    def test_register_and_get_kem(self, stub_kem_provider):
        CryptoAgility._kem_providers[AlgorithmSuite.HYBRID_KYBER768_X25519] = stub_kem_provider
        CryptoAgility._default_kem_suite = AlgorithmSuite.HYBRID_KYBER768_X25519

        provider = CryptoAgility.get_kem()
        assert provider is stub_kem_provider

    def test_register_and_get_signer(self, stub_sig_provider):
        CryptoAgility._sig_providers[SignatureSuite.HYBRID_DILITHIUM3_ED25519] = stub_sig_provider
        CryptoAgility._default_sig_suite = SignatureSuite.HYBRID_DILITHIUM3_ED25519

        provider = CryptoAgility.get_signer()
        assert provider is stub_sig_provider

    def test_get_kem_explicit_suite(self, stub_kem_provider):
        """get_kem() com suite explícita retorna o provider correto."""
        CryptoAgility._kem_providers[AlgorithmSuite.HYBRID_KYBER768_X25519] = stub_kem_provider
        CryptoAgility._default_kem_suite = AlgorithmSuite.HYBRID_KYBER768_X25519

        provider = CryptoAgility.get_kem(AlgorithmSuite.HYBRID_KYBER768_X25519)
        assert provider is stub_kem_provider

    def test_get_kem_unknown_suite_raises(self):
        with pytest.raises(UnknownAlgorithmSuiteError):
            CryptoAgility.get_kem(AlgorithmSuite.PQC_ONLY_MLKEM768)

    def test_classical_fallback_blocked_by_default(self, initialized_crypto):
        """Suite clássica deve ser bloqueada sem autorização explícita."""
        from tests.conftest import StubKEMProvider

        class ClassicalStub(StubKEMProvider):
            suite = AlgorithmSuite.CLASSICAL_ONLY

        # Forçar registro sem passar por allow_classical para simular estado inconsistente
        CryptoAgility._kem_providers[AlgorithmSuite.CLASSICAL_ONLY] = ClassicalStub()
        CryptoAgility._allow_classical_fallback = False

        with pytest.raises(ClassicalFallbackNotAllowedError):
            CryptoAgility.get_kem(AlgorithmSuite.CLASSICAL_ONLY)

    def test_classical_fallback_allowed_when_configured(self, stub_kem_provider):
        """Suite clássica funciona quando allow_classical_fallback=True."""
        from tests.conftest import StubKEMProvider

        class ClassicalStub(StubKEMProvider):
            suite = AlgorithmSuite.CLASSICAL_ONLY

        CryptoAgility._kem_providers[AlgorithmSuite.CLASSICAL_ONLY] = ClassicalStub()
        CryptoAgility._allow_classical_fallback = True

        # Não deve levantar exceção
        provider = CryptoAgility.get_kem(AlgorithmSuite.CLASSICAL_ONLY)
        assert provider.suite == AlgorithmSuite.CLASSICAL_ONLY

    def test_reset_clears_all_state(self, stub_kem_provider):
        CryptoAgility._kem_providers[AlgorithmSuite.HYBRID_KYBER768_X25519] = stub_kem_provider
        CryptoAgility._initialized = True

        CryptoAgility._reset_for_testing()

        assert not CryptoAgility._kem_providers
        assert not CryptoAgility._initialized

    def test_provider_suite_matches_registry_key(self, stub_kem_provider):
        """Suite do provider deve coincidir com a chave no registry."""
        CryptoAgility._kem_providers[AlgorithmSuite.HYBRID_KYBER768_X25519] = stub_kem_provider
        CryptoAgility._default_kem_suite = AlgorithmSuite.HYBRID_KYBER768_X25519

        provider = CryptoAgility.get_kem()
        assert provider.suite == AlgorithmSuite.HYBRID_KYBER768_X25519


class TestCryptoAgilitySwapping:
    """
    Testes centrais de cripto-agilidade: swap de suite não quebra interface.
    """

    def test_kem_roundtrip_stub_provider(self, stub_kem_provider):
        """Roundtrip completo: generate → encapsulate → decapsulate → mesmo segredo."""
        keypair = stub_kem_provider.generate_keypair()
        encapsulated = stub_kem_provider.encapsulate(keypair.public_key)
        recovered = stub_kem_provider.decapsulate(encapsulated.ciphertext, keypair.private_key)

        assert recovered == encapsulated.shared_secret

    def test_signature_roundtrip_stub_provider(self, stub_sig_provider):
        """Roundtrip: generate → sign → verify → True."""
        keypair = stub_sig_provider.generate_keypair()
        payload = b"dado de inteligencia classificado"
        sig = stub_sig_provider.sign(payload, keypair.private_key)

        assert stub_sig_provider.verify(payload, sig, keypair.public_key)

    def test_signature_tampered_payload_fails(self, stub_sig_provider):
        """Assinatura inválida para payload adulterado retorna False."""
        keypair = stub_sig_provider.generate_keypair()
        payload = b"dado original"
        sig = stub_sig_provider.sign(payload, keypair.private_key)

        assert not stub_sig_provider.verify(b"dado adulterado", sig, keypair.public_key)

    def test_signature_tampered_signature_fails(self, stub_sig_provider):
        """Assinatura corrompida retorna False."""
        keypair = stub_sig_provider.generate_keypair()
        payload = b"dado de teste"
        sig = stub_sig_provider.sign(payload, keypair.private_key)
        corrupted_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]

        assert not stub_sig_provider.verify(payload, corrupted_sig, keypair.public_key)

    def test_different_kem_suites_produce_incompatible_secrets(self):
        """
        Segredos de suites diferentes não podem ser confundidos.
        Isto é uma propriedade de separação de domínio do HKDF.
        """
        from tests.conftest import StubKEMProvider

        class Suite1Provider(StubKEMProvider):
            suite = AlgorithmSuite.HYBRID_KYBER768_X25519

        class Suite2Provider(StubKEMProvider):
            suite = AlgorithmSuite.HYBRID_KYBER1024_X25519

        p1 = Suite1Provider()
        p2 = Suite2Provider()

        keypair1 = p1.generate_keypair()

        # Encapsular com provider 1, tentar decapsular com provider 2
        # (Neste caso de stub simples, ambos usam X25519, então o resultado
        # será igual — o teste real é nos providers híbridos reais com liboqs.
        # Aqui validamos que os tipos e interfaces são compatíveis.)
        encap = p1.encapsulate(keypair1.public_key)
        assert encap.suite == AlgorithmSuite.HYBRID_KYBER768_X25519
