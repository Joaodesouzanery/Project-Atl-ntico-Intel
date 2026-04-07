"""Testes do módulo _common.py."""

from datetime import datetime, timezone

import pytest

from atlantico.atlas.ontology._common import (
    compute_sha3_256,
    hash_cpf,
    normalize_cnpj,
    require_classification,
    require_confidence,
    require_tz,
    validate_numero_cnj,
    validate_numero_sei,
    validate_urn_lex,
)


def test_require_tz_accepts_aware():
    require_tz(datetime(2026, 4, 7, tzinfo=timezone.utc), "x")


def test_require_tz_rejects_naive():
    with pytest.raises(ValueError, match="timezone-aware"):
        require_tz(datetime(2026, 4, 7), "x")


def test_compute_sha3_256_deterministic():
    assert compute_sha3_256("oi") == compute_sha3_256("oi")
    assert len(compute_sha3_256("oi")) == 64


def test_hash_cpf_normalizes_and_hashes():
    h1 = hash_cpf("123.456.789-09")
    h2 = hash_cpf("12345678909")
    assert h1 == h2
    assert len(h1) == 64


def test_hash_cpf_rejects_invalid():
    with pytest.raises(ValueError, match="CPF"):
        hash_cpf("123")


def test_normalize_cnpj_strips_punct():
    assert normalize_cnpj("12.345.678/0001-95") == "12345678000195"


def test_normalize_cnpj_rejects_short():
    with pytest.raises(ValueError):
        normalize_cnpj("123")


def test_validate_numero_cnj_formats():
    assert validate_numero_cnj("00000010120238260100") == "0000001-01.2023.8.26.0100"
    assert validate_numero_cnj("0000001-01.2023.8.26.0100") == "0000001-01.2023.8.26.0100"


def test_validate_numero_cnj_rejects():
    with pytest.raises(ValueError):
        validate_numero_cnj("123")


def test_validate_urn_lex_ok():
    validate_urn_lex("urn:lex:br:agencia.nacional.mineracao:resolucao:2026;123")


def test_validate_urn_lex_rejects():
    with pytest.raises(ValueError):
        validate_urn_lex("not-a-urn")


def test_validate_numero_sei_ok():
    validate_numero_sei("12345.123456/2026-01")


def test_validate_numero_sei_rejects():
    with pytest.raises(ValueError):
        validate_numero_sei("123/456")


def test_require_confidence_bounds():
    require_confidence(0.5)
    with pytest.raises(ValueError):
        require_confidence(1.5)
    with pytest.raises(ValueError):
        require_confidence(-0.1)


def test_require_classification():
    require_classification("PUBLIC")
    with pytest.raises(ValueError):
        require_classification("OPEN")
