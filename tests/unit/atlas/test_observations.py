"""Cobertura básica de AtlasObservation."""

from datetime import datetime, timezone

import pytest

from atlantico.atlas.observations import AtlasObservation


def _now():
    return datetime(2026, 4, 7, tzinfo=timezone.utc)


def test_basic_construction():
    obs = AtlasObservation(
        source_id="br.gov.in.dou.v1",
        external_id="abc",
        observation_type="norma",
        reference_date=_now(),
    )
    assert obs.data_classification == "PUBLIC"


def test_rejects_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        AtlasObservation(
            source_id="x",
            external_id="y",
            observation_type="norma",
            reference_date=datetime(2026, 4, 7),
        )


def test_rejects_invalid_type():
    with pytest.raises(ValueError, match="observation_type"):
        AtlasObservation(
            source_id="x",
            external_id="y",
            observation_type="lixo",
            reference_date=_now(),
        )


def test_rejects_invalid_classification():
    with pytest.raises(ValueError, match="data_classification"):
        AtlasObservation(
            source_id="x",
            external_id="y",
            observation_type="norma",
            reference_date=_now(),
            data_classification="OPEN",
        )


def test_rejects_invalid_norma_tipo():
    with pytest.raises(ValueError, match="norma_tipo"):
        AtlasObservation(
            source_id="x",
            external_id="y",
            observation_type="norma",
            reference_date=_now(),
            norma_tipo="manifesto",
        )


def test_rejects_invalid_urn():
    with pytest.raises(ValueError, match="urn_lex"):
        AtlasObservation(
            source_id="x",
            external_id="y",
            observation_type="norma",
            reference_date=_now(),
            urn_lex="urn:other:foo",
        )


def test_compute_text_hash():
    obs = AtlasObservation(
        source_id="x",
        external_id="y",
        observation_type="norma",
        reference_date=_now(),
    )
    h = obs.compute_text_hash("texto da norma")
    assert len(h) == 64
    assert obs.text_hash_sha3_256 == h
