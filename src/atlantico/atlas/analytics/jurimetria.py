"""
Jurimetria — Módulo 2 do conceito Atlântico Atlas.

Análise estatística do comportamento decisório de colegiados regulatórios
sobre listas de ``Deliberacao`` da ontologia. Tudo stdlib (statistics,
math, collections, datetime). Sem numpy/scipy/sklearn — manter o footprint
do Lambda Vercel pequeno.

Funções principais:
    - compute_director_profile(deliberacoes, director_id)
        Perfil individual: total de votos, distribuição por sentido,
        taxa de divergência (votos contrários ao dispositivo da decisão),
        microtemas dominantes, tendência temporal.

    - compute_colegiado_profile(deliberacoes)
        Perfil agregado do colegiado: taxa de unanimidade, distribuição
        por dispositivo, média de votos por decisão, top relatores.

    - compute_alignment_matrix(deliberacoes)
        Matriz diretor × diretor de coeficiente de alinhamento (Jaccard
        sobre votos coincidentes em deliberações comuns).

    - detect_temporal_inflection(deliberacoes, window_size=10)
        Detecta pontos onde a taxa de deferimento muda significativamente
        entre janelas consecutivas (mudança de jurisprudência interna).

    - predict_deferment(deliberacoes, query)
        Predição calibrada (Laplace-smoothed) da probabilidade de
        deferimento para uma deliberação hipotética, com fatores
        explicativos ranqueados.

Inspirado na seção 1.5.2-D (jurimetria) do conceito Atlas e no Módulo 2
do roadmap.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from atlantico.atlas.ontology import Deliberacao


# ─── Dataclasses de resultado ─────────────────────────────────────────────────


@dataclass
class DirectorProfile:
    """Perfil estatístico de um diretor sobre N deliberações."""

    director_id: str
    total_votes: int
    sentido_distribution: dict[str, int]   # favoravel/contrario/abstencao/impedido
    sentido_dominante: str
    taxa_divergencia: float                # % votos contra o dispositivo da decisão
    taxa_abstencao: float
    microtemas_top: list[tuple[str, int]]  # (tag, count)
    relator_count: int                     # quantas vezes foi relator
    activity_window_days: int              # range temporal coberto
    pares_mais_alinhados: list[tuple[str, float]]  # (other_director_id, jaccard)


@dataclass
class ColegiadoProfile:
    """Perfil agregado do colegiado."""

    orgao: str
    colegiado: str
    total_deliberacoes: int
    taxa_unanimidade: float                # % de deliberações com 100% favoravel ou 100% contrario
    dispositivo_distribution: dict[str, int]
    mean_votos_por_decisao: float
    top_relatores: list[tuple[str, int]]
    periodo_inicio: datetime | None
    periodo_fim: datetime | None
    microtemas_top: list[tuple[str, int]]


@dataclass
class AlignmentMatrix:
    """Matriz simétrica de alinhamento entre diretores."""

    directors: list[str]
    matrix: dict[tuple[str, str], float]   # (a, b) → jaccard ∈ [0, 1]

    def get(self, a: str, b: str) -> float:
        if a == b:
            return 1.0
        key = (a, b) if (a, b) in self.matrix else (b, a)
        return self.matrix.get(key, 0.0)

    def top_pairs(self, n: int = 5) -> list[tuple[str, str, float]]:
        items = [(a, b, score) for (a, b), score in self.matrix.items() if a != b]
        items.sort(key=lambda x: x[2], reverse=True)
        return items[:n]


@dataclass
class TemporalInflection:
    """Ponto de inflexão jurisprudencial detectado."""

    boundary_index: int
    boundary_date: datetime
    rate_before: float
    rate_after: float
    delta: float
    direction: str  # "endurecimento" | "relaxamento"


@dataclass
class PredictionResult:
    """Resultado de uma predição calibrada de deferimento."""

    probability_deferimento: float
    confidence_interval_95: tuple[float, float]
    sample_size: int
    top_factors: list[tuple[str, float]] = field(default_factory=list)
    explanation: str = ""


# ─── Helpers internos ─────────────────────────────────────────────────────────


_DEFERIDOS = frozenset({"deferido", "parcialmente_deferido"})


def _filter_by_colegiado(
    deliberacoes: Iterable[Deliberacao],
    orgao: str | None = None,
    colegiado: str | None = None,
) -> list[Deliberacao]:
    out = []
    for d in deliberacoes:
        if orgao and d.orgao != orgao:
            continue
        if colegiado and d.colegiado != colegiado:
            continue
        out.append(d)
    return out


def _votes_by_director(
    deliberacoes: Iterable[Deliberacao], director_id: str
) -> list[tuple[Deliberacao, str]]:
    """Retorna [(delib, sentido_voto)] em que ``director_id`` participou."""
    out = []
    for d in deliberacoes:
        for v in d.votos:
            if v.diretor_id == director_id:
                out.append((d, v.sentido))
                break
    return out


def _is_unanime(d: Deliberacao) -> bool:
    if not d.votos:
        return False
    sentidos = {v.sentido for v in d.votos if v.sentido != "impedido"}
    return len(sentidos) == 1


# ─── compute_director_profile ─────────────────────────────────────────────────


def compute_director_profile(
    deliberacoes: list[Deliberacao],
    director_id: str,
) -> DirectorProfile:
    """Constrói perfil estatístico para um diretor específico."""
    if not director_id:
        raise ValueError("director_id obrigatório")

    participacoes = _votes_by_director(deliberacoes, director_id)
    total = len(participacoes)

    sentidos = Counter(s for _, s in participacoes)
    sentido_dominante = sentidos.most_common(1)[0][0] if sentidos else "indefinido"

    # Taxa de divergência: voto != alinhamento com o dispositivo
    # ("favoravel" alinha com "deferido"; "contrario" alinha com "indeferido")
    divergencias = 0
    for delib, sentido in participacoes:
        deferido = delib.dispositivo in _DEFERIDOS
        if sentido == "favoravel" and not deferido:
            divergencias += 1
        elif sentido == "contrario" and deferido:
            divergencias += 1

    taxa_div = divergencias / total if total else 0.0
    abstencoes = sentidos.get("abstencao", 0) + sentidos.get("impedido", 0)
    taxa_abs = abstencoes / total if total else 0.0

    # Microtemas — agregamos por tags das deliberações onde votou
    tags_count: Counter[str] = Counter()
    for delib, _ in participacoes:
        for tag in delib.tags:
            tags_count[tag] += 1
    microtemas_top = tags_count.most_common(5)

    # Quantas vezes foi relator
    relator_count = sum(
        1 for d in deliberacoes if d.relator_id == director_id
    )

    # Janela temporal
    if participacoes:
        datas = [d.data_sessao for d, _ in participacoes]
        window_days = int((max(datas) - min(datas)).days)
    else:
        window_days = 0

    # Alinhamento com pares — top 3
    align_matrix = compute_alignment_matrix(deliberacoes)
    pares = []
    for other in align_matrix.directors:
        if other == director_id:
            continue
        score = align_matrix.get(director_id, other)
        if score > 0:
            pares.append((other, round(score, 3)))
    pares.sort(key=lambda x: x[1], reverse=True)

    return DirectorProfile(
        director_id=director_id,
        total_votes=total,
        sentido_distribution=dict(sentidos),
        sentido_dominante=sentido_dominante,
        taxa_divergencia=round(taxa_div, 4),
        taxa_abstencao=round(taxa_abs, 4),
        microtemas_top=microtemas_top,
        relator_count=relator_count,
        activity_window_days=window_days,
        pares_mais_alinhados=pares[:3],
    )


# ─── compute_colegiado_profile ────────────────────────────────────────────────


def compute_colegiado_profile(
    deliberacoes: list[Deliberacao],
    orgao: str | None = None,
    colegiado: str | None = None,
) -> ColegiadoProfile:
    """Perfil agregado de um colegiado (filtra opcionalmente por orgao/colegiado)."""
    filtradas = _filter_by_colegiado(deliberacoes, orgao, colegiado)
    total = len(filtradas)

    if total == 0:
        return ColegiadoProfile(
            orgao=orgao or "",
            colegiado=colegiado or "",
            total_deliberacoes=0,
            taxa_unanimidade=0.0,
            dispositivo_distribution={},
            mean_votos_por_decisao=0.0,
            top_relatores=[],
            periodo_inicio=None,
            periodo_fim=None,
            microtemas_top=[],
        )

    unanimes = sum(1 for d in filtradas if _is_unanime(d))
    taxa_unan = unanimes / total

    dispositivos = Counter(d.dispositivo for d in filtradas)
    mean_votos = statistics.fmean(len(d.votos) for d in filtradas)

    relatores = Counter(d.relator_id for d in filtradas)
    top_relatores = relatores.most_common(5)

    datas = [d.data_sessao for d in filtradas]
    periodo_inicio, periodo_fim = min(datas), max(datas)

    tags_count: Counter[str] = Counter()
    for d in filtradas:
        for tag in d.tags:
            tags_count[tag] += 1

    return ColegiadoProfile(
        orgao=orgao or filtradas[0].orgao,
        colegiado=colegiado or filtradas[0].colegiado,
        total_deliberacoes=total,
        taxa_unanimidade=round(taxa_unan, 4),
        dispositivo_distribution=dict(dispositivos),
        mean_votos_por_decisao=round(mean_votos, 2),
        top_relatores=top_relatores,
        periodo_inicio=periodo_inicio,
        periodo_fim=periodo_fim,
        microtemas_top=tags_count.most_common(5),
    )


# ─── compute_alignment_matrix ─────────────────────────────────────────────────


def compute_alignment_matrix(deliberacoes: list[Deliberacao]) -> AlignmentMatrix:
    """
    Constrói matriz de alinhamento via Jaccard sobre votos coincidentes.

    Para cada par (a, b) que votou em pelo menos N deliberações em comum,
    score = (#votos no mesmo sentido) / (#deliberações em comum).
    """
    # director → list of (delib_id, sentido)
    by_director: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for d in deliberacoes:
        delib_key = f"{d.orgao}|{d.colegiado}|{d.numero}|{d.ano}"
        for v in d.votos:
            if v.sentido in ("favoravel", "contrario"):  # ignora abstencao/impedido
                by_director[v.diretor_id].append((delib_key, v.sentido))

    directors = sorted(by_director.keys())
    matrix: dict[tuple[str, str], float] = {}

    for i, a in enumerate(directors):
        a_map = dict(by_director[a])
        for b in directors[i + 1 :]:
            b_map = dict(by_director[b])
            common_keys = set(a_map.keys()) & set(b_map.keys())
            if not common_keys:
                continue
            agree = sum(1 for k in common_keys if a_map[k] == b_map[k])
            score = agree / len(common_keys)
            matrix[(a, b)] = round(score, 4)

    return AlignmentMatrix(directors=directors, matrix=matrix)


# ─── detect_temporal_inflection ───────────────────────────────────────────────


def detect_temporal_inflection(
    deliberacoes: list[Deliberacao],
    window_size: int = 10,
    min_delta: float = 0.20,
) -> list[TemporalInflection]:
    """
    Detecta pontos onde a taxa de deferimento muda mais que ``min_delta``
    entre janelas consecutivas (cada janela = ``window_size`` deliberações).
    """
    if len(deliberacoes) < window_size * 2:
        return []

    sorted_d = sorted(deliberacoes, key=lambda d: d.data_sessao)
    inflections: list[TemporalInflection] = []

    for i in range(window_size, len(sorted_d) - window_size + 1):
        before = sorted_d[i - window_size : i]
        after = sorted_d[i : i + window_size]
        rate_before = sum(1 for d in before if d.dispositivo in _DEFERIDOS) / window_size
        rate_after = sum(1 for d in after if d.dispositivo in _DEFERIDOS) / window_size
        delta = rate_after - rate_before
        if abs(delta) >= min_delta:
            inflections.append(
                TemporalInflection(
                    boundary_index=i,
                    boundary_date=sorted_d[i].data_sessao,
                    rate_before=round(rate_before, 3),
                    rate_after=round(rate_after, 3),
                    delta=round(delta, 3),
                    direction="endurecimento" if delta < 0 else "relaxamento",
                )
            )
    return inflections


# ─── predict_deferment ────────────────────────────────────────────────────────


def predict_deferment(
    deliberacoes: list[Deliberacao],
    *,
    orgao: str | None = None,
    colegiado: str | None = None,
    relator_id: str | None = None,
    tags: list[str] | None = None,
) -> PredictionResult:
    """
    Probabilidade calibrada de deferimento dada uma deliberação hipotética.

    Filtra a base por (orgao, colegiado), aplica Laplace smoothing
    (k=1) à frequência base, e ajusta a probabilidade pelos *fatores*
    relator (se fornecido) e tags (se fornecidas) usando log-odds.

    Confiança 95%: aproximação Wilson sobre a contagem efetiva.
    """
    base = _filter_by_colegiado(deliberacoes, orgao, colegiado)
    n = len(base)

    if n == 0:
        return PredictionResult(
            probability_deferimento=0.5,
            confidence_interval_95=(0.0, 1.0),
            sample_size=0,
            explanation="Sem amostra histórica para o filtro — retornando prior 0.5.",
        )

    deferidos = sum(1 for d in base if d.dispositivo in _DEFERIDOS)
    # Laplace smoothing — k=1 prior uniforme
    p_base = (deferidos + 1) / (n + 2)

    # Wilson 95% interval
    z = 1.96
    denom = 1 + z**2 / n
    centre = (p_base + z**2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p_base * (1 - p_base) / n + z**2 / (4 * n**2))
    ci = (max(0.0, round(centre - half, 4)), min(1.0, round(centre + half, 4)))

    factors: list[tuple[str, float]] = []
    log_odds_adjustment = 0.0

    if relator_id:
        relator_subset = [d for d in base if d.relator_id == relator_id]
        if relator_subset:
            r_n = len(relator_subset)
            r_def = sum(1 for d in relator_subset if d.dispositivo in _DEFERIDOS)
            p_relator = (r_def + 1) / (r_n + 2)
            adj = _logit(p_relator) - _logit(p_base)
            log_odds_adjustment += adj
            factors.append((f"relator:{relator_id}", round(adj, 3)))

    if tags:
        for tag in tags:
            tag_subset = [d for d in base if tag in d.tags]
            if not tag_subset:
                continue
            t_n = len(tag_subset)
            t_def = sum(1 for d in tag_subset if d.dispositivo in _DEFERIDOS)
            p_tag = (t_def + 1) / (t_n + 2)
            adj = _logit(p_tag) - _logit(p_base)
            log_odds_adjustment += adj
            factors.append((f"tag:{tag}", round(adj, 3)))

    final_p = _sigmoid(_logit(p_base) + log_odds_adjustment)

    factors.sort(key=lambda x: abs(x[1]), reverse=True)

    return PredictionResult(
        probability_deferimento=round(final_p, 4),
        confidence_interval_95=ci,
        sample_size=n,
        top_factors=factors[:5],
        explanation=(
            f"Base histórica: {n} deliberações no filtro, {deferidos} deferidas. "
            f"Probabilidade base (Laplace): {round(p_base, 3)}. "
            f"Ajuste por fatores log-odds: {round(log_odds_adjustment, 3)}."
        ),
    )


def _logit(p: float, eps: float = 1e-6) -> float:
    p = min(max(p, eps), 1 - eps)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))
