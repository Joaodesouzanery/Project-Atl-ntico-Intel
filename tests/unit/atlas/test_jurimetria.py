"""Testes do módulo de jurimetria."""

from datetime import datetime, timedelta, timezone

import pytest

from atlantico.atlas.analytics.jurimetria import (
    _logit,
    _sigmoid,
    compute_alignment_matrix,
    compute_colegiado_profile,
    compute_director_profile,
    detect_temporal_inflection,
    predict_deferment,
)
from atlantico.atlas.ontology import Deliberacao, Voto

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _delib(
    *,
    numero: int,
    data: datetime,
    relator: str = "d1",
    dispositivo: str = "deferido",
    votos: list[tuple[str, str]] | None = None,
    tags: list[str] | None = None,
    colegiado: str = "diretoria_colegiada",
) -> Deliberacao:
    """Helper para construir deliberações de teste (sempre shifta numero por +1)."""
    return Deliberacao(
        orgao="ANM",
        colegiado=colegiado,
        numero=numero + 1,
        ano=2026,
        data_sessao=data,
        relator_id=relator,
        dispositivo=dispositivo,
        ementa=f"caso {numero}",
        votos=[Voto(d_id, sentido) for d_id, sentido in (votos or [])],
        tags=tags or [],
    )


# ─── compute_director_profile ────────────────────────────────────────────────


def test_director_profile_basic():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel"), ("d2", "favoravel")]),
        _delib(numero=2, data=T0 + timedelta(days=10), dispositivo="indeferido",
               votos=[("d1", "contrario"), ("d2", "favoravel")]),
        _delib(numero=3, data=T0 + timedelta(days=20),
               votos=[("d1", "favoravel"), ("d2", "contrario")]),
    ]
    profile = compute_director_profile(delibs, "d1")
    assert profile.director_id == "d1"
    assert profile.total_votes == 3
    assert profile.sentido_distribution["favoravel"] == 2
    assert profile.sentido_distribution["contrario"] == 1
    # d1 votou de acordo com o dispositivo em todas as 3 → divergencia 0
    assert profile.taxa_divergencia == 0.0


def test_director_profile_detects_divergence():
    # d2 vota favoravel mas a decisao é indeferida → 1 divergência em 2 votos
    delibs = [
        _delib(numero=1, data=T0, dispositivo="indeferido",
               votos=[("d1", "contrario"), ("d2", "favoravel")]),
        _delib(numero=2, data=T0 + timedelta(days=5), dispositivo="deferido",
               votos=[("d1", "favoravel"), ("d2", "favoravel")]),
    ]
    p = compute_director_profile(delibs, "d2")
    assert p.total_votes == 2
    assert p.taxa_divergencia == 0.5  # 1 de 2


def test_director_profile_relator_count():
    delibs = [
        _delib(numero=1, data=T0, relator="d1", votos=[("d1", "favoravel")]),
        _delib(numero=2, data=T0 + timedelta(days=1), relator="d2", votos=[("d1", "favoravel")]),
        _delib(numero=3, data=T0 + timedelta(days=2), relator="d1", votos=[("d1", "favoravel")]),
    ]
    p = compute_director_profile(delibs, "d1")
    assert p.relator_count == 2


def test_director_profile_handles_no_participation():
    delibs = [_delib(numero=1, data=T0, votos=[("d1", "favoravel")])]
    p = compute_director_profile(delibs, "d99")
    assert p.total_votes == 0
    assert p.sentido_dominante == "indefinido"
    assert p.taxa_divergencia == 0.0


def test_director_profile_microtemas():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel")], tags=["lavra", "ANM"]),
        _delib(numero=2, data=T0 + timedelta(days=1), votos=[("d1", "favoravel")], tags=["lavra"]),
    ]
    p = compute_director_profile(delibs, "d1")
    top = dict(p.microtemas_top)
    assert top["lavra"] == 2
    assert top["ANM"] == 1


def test_director_profile_requires_director_id():
    with pytest.raises(ValueError):
        compute_director_profile([], "")


# ─── compute_colegiado_profile ───────────────────────────────────────────────


def test_colegiado_profile_basic():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel"), ("d2", "favoravel")]),
        _delib(numero=2, data=T0 + timedelta(days=1), dispositivo="indeferido",
               votos=[("d1", "contrario"), ("d2", "contrario")]),
        _delib(numero=3, data=T0 + timedelta(days=2),
               votos=[("d1", "favoravel"), ("d2", "contrario")]),
    ]
    p = compute_colegiado_profile(delibs)
    assert p.total_deliberacoes == 3
    # 2 unanimes (1 favoravel, 2 contrario)
    assert p.taxa_unanimidade == round(2 / 3, 4)
    assert p.dispositivo_distribution["deferido"] == 2
    assert p.dispositivo_distribution["indeferido"] == 1


def test_colegiado_profile_filter_by_orgao():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel")]),
    ]
    p = compute_colegiado_profile(delibs, orgao="ANEEL")  # diferente
    assert p.total_deliberacoes == 0
    assert p.periodo_inicio is None


def test_colegiado_profile_top_relatores():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i),
               relator="d1" if i < 3 else "d2",
               votos=[("d1", "favoravel")])
        for i in range(5)
    ]
    p = compute_colegiado_profile(delibs)
    top = dict(p.top_relatores)
    assert top["d1"] == 3
    assert top["d2"] == 2


# ─── compute_alignment_matrix ────────────────────────────────────────────────


def test_alignment_matrix_perfect_agreement():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i),
               votos=[("d1", "favoravel"), ("d2", "favoravel")])
        for i in range(3)
    ]
    m = compute_alignment_matrix(delibs)
    assert m.get("d1", "d2") == 1.0
    assert m.get("d1", "d1") == 1.0  # auto


def test_alignment_matrix_partial_agreement():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel"), ("d2", "favoravel")]),
        _delib(numero=2, data=T0 + timedelta(days=1), votos=[("d1", "favoravel"), ("d2", "contrario")]),
    ]
    m = compute_alignment_matrix(delibs)
    assert m.get("d1", "d2") == 0.5  # 1 of 2


def test_alignment_matrix_top_pairs():
    delibs = [
        _delib(numero=1, data=T0, votos=[
            ("d1", "favoravel"), ("d2", "favoravel"), ("d3", "contrario")
        ]),
        _delib(numero=2, data=T0 + timedelta(days=1), votos=[
            ("d1", "favoravel"), ("d2", "favoravel"), ("d3", "contrario")
        ]),
    ]
    m = compute_alignment_matrix(delibs)
    top = m.top_pairs(n=1)
    assert top[0][2] == 1.0
    assert {top[0][0], top[0][1]} == {"d1", "d2"}


def test_alignment_matrix_ignores_abstencao():
    delibs = [
        _delib(numero=1, data=T0, votos=[("d1", "favoravel"), ("d2", "abstencao")]),
    ]
    m = compute_alignment_matrix(delibs)
    # d2 só absteve → não entra no jaccard
    assert m.get("d1", "d2") == 0.0


# ─── detect_temporal_inflection ──────────────────────────────────────────────


def test_temporal_inflection_detects_endurecimento():
    # 10 deferidos seguidos por 10 indeferidos
    delibs = []
    for i in range(10):
        delibs.append(_delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")]))
    for i in range(10):
        delibs.append(_delib(numero=100 + i, data=T0 + timedelta(days=11 + i),
                             dispositivo="indeferido", votos=[("d1", "contrario")]))

    inflections = detect_temporal_inflection(delibs, window_size=10, min_delta=0.5)
    assert len(inflections) >= 1
    assert inflections[0].direction == "endurecimento"
    assert inflections[0].rate_before == 1.0
    assert inflections[0].rate_after == 0.0


def test_temporal_inflection_no_change_returns_empty():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")])
        for i in range(20)
    ]
    inflections = detect_temporal_inflection(delibs, window_size=5, min_delta=0.2)
    assert inflections == []


def test_temporal_inflection_too_few_samples():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")])
        for i in range(5)
    ]
    assert detect_temporal_inflection(delibs, window_size=10) == []


# ─── predict_deferment ───────────────────────────────────────────────────────


def test_predict_with_no_history_returns_prior():
    r = predict_deferment([], orgao="ANM")
    assert r.probability_deferimento == 0.5
    assert r.sample_size == 0


def test_predict_high_deferment_base():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")])
        for i in range(20)  # todos deferidos
    ]
    r = predict_deferment(delibs, orgao="ANM")
    assert r.sample_size == 20
    assert r.probability_deferimento > 0.85


def test_predict_low_deferment_base():
    delibs = [
        _delib(numero=i, data=T0 + timedelta(days=i),
               dispositivo="indeferido", votos=[("d1", "contrario")])
        for i in range(20)
    ]
    r = predict_deferment(delibs, orgao="ANM")
    assert r.probability_deferimento < 0.15


def test_predict_relator_factor_increases_probability():
    # 10 totais, 5 deferidos. Mas relator R1 sempre defere.
    delibs = []
    for i in range(5):
        delibs.append(_delib(numero=i, data=T0 + timedelta(days=i),
                             relator="r1", votos=[("d1", "favoravel")]))
    for i in range(5):
        delibs.append(_delib(numero=10 + i, data=T0 + timedelta(days=10 + i),
                             relator="r2", dispositivo="indeferido",
                             votos=[("d1", "contrario")]))
    r = predict_deferment(delibs, relator_id="r1")
    # base ~0.5, relator r1 100% → adj positivo significativo
    assert r.probability_deferimento > 0.7
    assert any("relator:r1" in f[0] for f in r.top_factors)


def test_predict_tag_factor():
    delibs = []
    for i in range(10):
        delibs.append(_delib(numero=i, data=T0 + timedelta(days=i),
                             tags=["fast_track"], votos=[("d1", "favoravel")]))
    for i in range(10):
        delibs.append(_delib(numero=10 + i, data=T0 + timedelta(days=10 + i),
                             dispositivo="indeferido", votos=[("d1", "contrario")]))
    r = predict_deferment(delibs, tags=["fast_track"])
    assert r.probability_deferimento > 0.7
    assert any("tag:fast_track" in f[0] for f in r.top_factors)


def test_predict_confidence_interval_shrinks_with_data():
    small = [_delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")]) for i in range(5)]
    big   = [_delib(numero=i, data=T0 + timedelta(days=i), votos=[("d1", "favoravel")]) for i in range(100)]
    r_small = predict_deferment(small)
    r_big   = predict_deferment(big)
    width_small = r_small.confidence_interval_95[1] - r_small.confidence_interval_95[0]
    width_big   = r_big.confidence_interval_95[1] - r_big.confidence_interval_95[0]
    assert width_big < width_small


# ─── helpers numéricos ───────────────────────────────────────────────────────


def test_logit_sigmoid_roundtrip():
    for p in (0.1, 0.3, 0.5, 0.7, 0.9):
        assert abs(_sigmoid(_logit(p)) - p) < 1e-6
