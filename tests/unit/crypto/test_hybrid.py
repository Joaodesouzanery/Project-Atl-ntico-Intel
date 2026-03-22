"""
Testes do combinador HKDF híbrido.
"""

from __future__ import annotations

import os

import pytest

from atlantico.crypto.hybrid import combine_secrets, derive_symmetric_key


class TestCombineSecrets:
    def test_deterministic_with_same_inputs(self):
        """Mesmos inputs → mesmo output (HKDF é determinístico sem salt aleatório)."""
        pqc = os.urandom(32)
        classical = os.urandom(32)
        label = "hybrid-kyber768-x25519"

        result1 = combine_secrets(pqc, classical, label)
        result2 = combine_secrets(pqc, classical, label)

        assert result1 == result2

    def test_different_pqc_secrets_produce_different_keys(self):
        classical = os.urandom(32)
        label = "hybrid-kyber768-x25519"

        key1 = combine_secrets(os.urandom(32), classical, label)
        key2 = combine_secrets(os.urandom(32), classical, label)

        assert key1 != key2

    def test_different_classical_secrets_produce_different_keys(self):
        pqc = os.urandom(32)
        label = "hybrid-kyber768-x25519"

        key1 = combine_secrets(pqc, os.urandom(32), label)
        key2 = combine_secrets(pqc, os.urandom(32), label)

        assert key1 != key2

    def test_different_suite_labels_produce_different_keys(self):
        """Separação de domínio: mesmos segredos + label diferente → chave diferente."""
        pqc = os.urandom(32)
        classical = os.urandom(32)

        key1 = combine_secrets(pqc, classical, "hybrid-kyber768-x25519")
        key2 = combine_secrets(pqc, classical, "hybrid-kyber1024-x25519")

        assert key1 != key2

    def test_output_length_default(self):
        key = combine_secrets(os.urandom(32), os.urandom(32), "test-suite")
        assert len(key) == 32  # AES-256

    def test_output_length_custom(self):
        key = combine_secrets(os.urandom(32), os.urandom(32), "test-suite", key_length=64)
        assert len(key) == 64

    def test_empty_pqc_secret_raises(self):
        with pytest.raises(ValueError, match="pqc_secret"):
            combine_secrets(b"", os.urandom(32), "test-suite")

    def test_empty_classical_secret_raises(self):
        with pytest.raises(ValueError, match="classical_secret"):
            combine_secrets(os.urandom(32), b"", "test-suite")

    def test_empty_suite_label_raises(self):
        with pytest.raises(ValueError, match="suite_label"):
            combine_secrets(os.urandom(32), os.urandom(32), "")

    def test_context_changes_output(self):
        """Contexto adicional muda o output — útil para binding por registro."""
        pqc = os.urandom(32)
        classical = os.urandom(32)
        label = "test-suite"

        key1 = combine_secrets(pqc, classical, label, context=b"record-1")
        key2 = combine_secrets(pqc, classical, label, context=b"record-2")

        assert key1 != key2

    def test_output_is_uniformly_distributed(self):
        """Output não deve ser todos zeros ou um padrão óbvio."""
        key = combine_secrets(os.urandom(32), os.urandom(32), "test-suite")
        assert key != b"\x00" * 32
        assert len(set(key)) > 10  # Verifica distribuição mínima


class TestDeriveSymmetricKey:
    def test_same_inputs_same_output(self):
        master = os.urandom(32)
        context = b"record-123:inpe:1700000000"
        label = "data-key-derivation-v1"

        k1 = derive_symmetric_key(master, context, label)
        k2 = derive_symmetric_key(master, context, label)

        assert k1 == k2

    def test_different_contexts_different_keys(self):
        master = os.urandom(32)
        label = "data-key-derivation-v1"

        k1 = derive_symmetric_key(master, b"record-1:inpe:1700000000", label)
        k2 = derive_symmetric_key(master, b"record-2:inpe:1700000000", label)

        assert k1 != k2

    def test_output_length_is_32_bytes(self):
        key = derive_symmetric_key(os.urandom(32), b"ctx", "label")
        assert len(key) == 32

    def test_empty_master_secret_raises(self):
        with pytest.raises(ValueError, match="master_secret"):
            derive_symmetric_key(b"", b"ctx", "label")
