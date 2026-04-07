"""GET /api/atlas_demo — Demo do Atlântico Atlas (vertical regulatória).

Demonstra o caminho completo *sem* depender de banco de dados:

  1. Parser do DOUConnector aplicado a um payload JSON sintético
  2. Parser do LexMLConnector aplicado a XML OAI-PMH sintético
  3. Normalizador (AtlasObservation → Norma) usando código real
  4. Entity resolution DOU↔LexML simulada em memória (chave natural)
  5. Estatísticas de count_by_tipo + top órgãos + timeline

Usa **código de produção real** dos PRs anteriores — só os dados são
sintéticos. A intenção é o mesmo padrão de api/sigint_demo.py.
"""
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler

# Vercel bundles project root; src/ must be on sys.path
_src = os.path.join(os.path.dirname(__file__), "..", "src")
if _src not in sys.path:
    sys.path.insert(0, _src)


def _build_demo() -> dict:
    from atlantico.atlas.analytics import (
        compute_alignment_matrix,
        compute_colegiado_profile,
        predict_deferment,
    )
    from atlantico.atlas.connectors.dou import DOUConnector
    from atlantico.atlas.connectors.lexml import LexMLConnector
    from atlantico.atlas.ingestion.normalizer import observation_to_norma
    from atlantico.atlas.ontology import Deliberacao, Regulado, Voto

    now = datetime.now(timezone.utc)
    today = now.date()

    # ── 1. Payload DOU sintético — vai pelo parser REAL do DOUConnector ──
    dou_raw = [
        {"id": "dou-001", "title": "RESOLUÇÃO ANM Nº 7, DE 7 DE ABRIL DE 2026", "orgao": "Agência Nacional de Mineração"},
        {"id": "dou-002", "title": "PORTARIA ANM Nº 50, DE 5 DE ABRIL DE 2026", "orgao": "Agência Nacional de Mineração"},
        {"id": "dou-003", "title": "DECRETO Nº 12.000, DE 1 DE ABRIL DE 2026", "orgao": "Casa Civil da Presidência"},
        {"id": "dou-004", "title": "INSTRUÇÃO NORMATIVA RFB Nº 2.150, DE 4 DE ABRIL DE 2026", "orgao": "Receita Federal do Brasil"},
        {"id": "dou-005", "title": "MEDIDA PROVISÓRIA Nº 1.317, DE 3 DE ABRIL DE 2026", "orgao": "Casa Civil da Presidência"},
        {"id": "dou-006", "title": "RESOLUÇÃO ANEEL Nº 1.020, DE 2 DE ABRIL DE 2026", "orgao": "Agência Nacional de Energia Elétrica"},
        {"id": "dou-007", "title": "Aviso de licitação SRP", "orgao": "Ministério da Fazenda"},
    ]
    dou = DOUConnector()
    dou_observations = []
    for raw in dou_raw:
        obs = dou._build_observation(raw, "do1", today)
        if obs is not None:
            dou_observations.append(obs)

    # ── 2. XML LexML sintético — vai pelo parser REAL do LexMLConnector ──
    def _record(*, oid, urn, titulo, tipo, creator):
        return f"""
        <record>
          <header>
            <identifier>{oid}</identifier>
            <datestamp>2026-04-07</datestamp>
          </header>
          <metadata>
            <oai_dc:dc xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/"
                       xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:identifier>{urn}</dc:identifier>
              <dc:title>{titulo}</dc:title>
              <dc:date>2026-04-07</dc:date>
              <dc:type>{tipo}</dc:type>
              <dc:creator>{creator}</dc:creator>
            </oai_dc:dc>
          </metadata>
        </record>
        """

    xml = f"""<?xml version="1.0"?>
    <OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">
      <ListRecords>
        {_record(oid="oai:lexml:res-anm-7-2026",
                 urn="urn:lex:br:agencia.nacional.mineracao:resolucao:2026;7",
                 titulo="Resolução ANM nº 7, de 2026",
                 tipo="Resolução",
                 creator="Agência Nacional de Mineração")}
        {_record(oid="oai:lexml:lei-14500-2026",
                 urn="urn:lex:br:federal:lei:2026;14500",
                 titulo="Lei nº 14.500, de 2026",
                 tipo="Lei",
                 creator="Congresso Nacional")}
        {_record(oid="oai:lexml:dec-12000-2026",
                 urn="urn:lex:br:federal:decreto:2026;12000",
                 titulo="Decreto nº 12.000, de 2026",
                 tipo="Decreto",
                 creator="Casa Civil da Presidência")}
      </ListRecords>
    </OAI-PMH>"""

    lex = LexMLConnector()
    records, _ = lex._parse_list_records(xml)
    lex_observations = []
    for r in records:
        obs = lex._build_observation(r)
        if obs is not None:
            lex_observations.append(obs)

    # ── 3. Normalização: observation → Norma (best-effort) ───────────────
    all_observations = dou_observations + lex_observations
    normas: list = []
    skipped: list = []
    for obs in all_observations:
        result = observation_to_norma(obs)
        if result.norma is not None:
            normas.append(result.norma)
        else:
            skipped.append({"external_id": obs.external_id, "reason": result.reason})

    # ── 4. Entity resolution DOU ↔ LexML em memória ──────────────────────
    by_natural_key: dict[tuple, dict] = {}
    for n in normas:
        key = (n.orgao, n.tipo, n.numero, n.ano)
        if key not in by_natural_key:
            by_natural_key[key] = {
                "key": f"{n.tipo}/{n.orgao}/{n.numero}/{n.ano}",
                "tipo": n.tipo,
                "orgao": n.orgao,
                "numero": n.numero,
                "ano": n.ano,
                "ementa": n.ementa,
                "urn_lex": n.urn_lex,
                "sources": [n.source_id],
                "merged": False,
            }
        else:
            existing = by_natural_key[key]
            existing["sources"].append(n.source_id)
            existing["merged"] = True
            if existing["urn_lex"] is None and n.urn_lex is not None:
                existing["urn_lex"] = n.urn_lex  # LexML preenche a URN canônica

    resolved = list(by_natural_key.values())
    matched_pairs = [r for r in resolved if r["merged"]]

    # ── 5. Stats agregados (simulando NormaRepository.count_by_tipo) ─────
    counts_by_tipo = Counter(r["tipo"] for r in resolved)
    counts_by_orgao = Counter(r["orgao"] for r in resolved)

    # Timeline simulada — distribui as normas em últimos 7 dias (round-robin)
    timeline = defaultdict(int)
    for i, _ in enumerate(resolved):
        day = (today - timedelta(days=i % 7)).isoformat()
        timeline[day] += 1
    timeline_sorted = sorted(timeline.items())

    # ── 6. Showcase de outros objetos da ontologia ───────────────────────
    sample_delib = Deliberacao(
        orgao="ANM",
        colegiado="diretoria_colegiada",
        numero=42,
        ano=2026,
        data_sessao=now,
        relator_id="diretor-anm-1",
        dispositivo="deferido",
        ementa="Aprovação do Plano de Lavra do Polígono Sudeste, com condicionantes ambientais.",
        votos=[
            Voto("diretor-anm-1", "favoravel", "Voto técnico do relator com fundamento no parecer SGM/ANM 215/2026"),
            Voto("diretor-anm-2", "favoravel"),
            Voto("diretor-anm-3", "contrario", "Discorda da definição do raio de impacto"),
        ],
        tags=["outorga"],
        norma_citada_urns=["urn:lex:br:agencia.nacional.mineracao:resolucao:2026;7"],
    )

    # ── 6.5 Histórico sintético de deliberações ANM (Módulo 2 — Jurimetria) ─
    # 12 deliberações ao longo de ~18 meses, 3 diretores, mix de microtemas.
    # Construído para que `predict_deferment` produza um sinal explicável.
    diretores = ["diretor-anm-1", "diretor-anm-2", "diretor-anm-3"]
    delib_specs = [
        # (offset_dias, relator_idx, dispositivo, tags, votos)
        (540, 0, "deferido",            ["outorga"],          ["favoravel", "favoravel", "favoravel"]),
        (510, 1, "deferido",            ["revisao_tarifaria"],["favoravel", "favoravel", "contrario"]),
        (470, 2, "indeferido",          ["sancionamento"],    ["contrario", "contrario", "favoravel"]),
        (430, 0, "deferido",            ["outorga"],          ["favoravel", "favoravel", "favoravel"]),
        (390, 1, "parcialmente_deferido",["revisao_tarifaria"],["favoravel", "favoravel", "contrario"]),
        (340, 2, "indeferido",          ["sancionamento"],    ["contrario", "contrario", "contrario"]),
        (290, 0, "deferido",            ["outorga"],          ["favoravel", "favoravel", "abstencao"]),
        (240, 1, "deferido",            ["revisao_tarifaria"],["favoravel", "favoravel", "favoravel"]),
        (190, 2, "indeferido",          ["sancionamento"],    ["contrario", "favoravel", "contrario"]),
        (140, 0, "deferido",            ["outorga"],          ["favoravel", "favoravel", "contrario"]),
        ( 80, 1, "parcialmente_deferido",["revisao_tarifaria"],["favoravel", "favoravel", "favoravel"]),
        ( 30, 2, "indeferido",          ["sancionamento"],    ["contrario", "contrario", "favoravel"]),
    ]
    historico_delibs: list[Deliberacao] = []
    for idx, (offset, rel_idx, disp, tags, votos_sentidos) in enumerate(delib_specs):
        historico_delibs.append(Deliberacao(
            orgao="ANM",
            colegiado="diretoria_colegiada",
            numero=100 + idx,
            ano=2025,
            data_sessao=now - timedelta(days=offset),
            relator_id=diretores[rel_idx],
            dispositivo=disp,
            ementa=f"Deliberação histórica #{idx} sobre {tags[0]}",
            votos=[Voto(diretores[i], s) for i, s in enumerate(votos_sentidos)],
            tags=tags,
        ))

    colegiado_profile = compute_colegiado_profile(historico_delibs, orgao="ANM")
    align_matrix = compute_alignment_matrix(historico_delibs)
    pleito_hipotetico = predict_deferment(
        historico_delibs,
        orgao="ANM",
        relator_id="diretor-anm-2",
        tags=["revisao_tarifaria"],
    )

    # Distribuição por diretor — para tabela do dashboard
    diretor_stats = []
    for did in diretores:
        votos_dir = [v for d in historico_delibs for v in d.votos if v.diretor_id == did]
        n = len(votos_dir)
        favs = sum(1 for v in votos_dir if v.sentido == "favoravel")
        tags_dir = Counter(
            t for d in historico_delibs for v in d.votos
            if v.diretor_id == did for t in d.tags
        )
        microtema_top = tags_dir.most_common(1)[0][0] if tags_dir else "—"
        diretor_stats.append({
            "diretor_id":     did,
            "n_votos":        n,
            "pct_favoravel":  round(100 * favs / n, 1) if n else 0.0,
            "microtema_top":  microtema_top,
        })

    sample_regulado = Regulado(
        razao_social="Mineração Atlântico Sul S.A.",
        setor="mineracao",
        cnpj="12345678000195",
        nome_fantasia="MAS Mineração",
        grupo_economico="Grupo Atlântico Holding",
        tier_risco="ALTO",
        tags=["alvos:fiscalizacao_2026", "cfem:atrasada"],
    )

    return {
        "scenario": "Atlântico Atlas — Inteligência Regulatória ANM",
        "generated_at": now.isoformat(),
        "ontology": {
            "object_types_total": 15,
            "core_materialized": 5,
            "core_objects": [
                "Norma", "ProcessoAdministrativo", "Deliberacao",
                "Regulado", "ContratoConcessao",
            ],
        },
        "ingestion_summary": {
            "dou_observations":   len(dou_observations),
            "lexml_observations": len(lex_observations),
            "total_observations": len(all_observations),
            "normas_built":       len(normas),
            "skipped":            len(skipped),
            "skip_examples":      skipped[:3],
        },
        "entity_resolution": {
            "explanation": (
                "Observações DOU (sem URN) e LexML (com URN) convergem na mesma "
                "Norma quando coincidem em (orgao, tipo, numero, ano). Esta é a "
                "primeira manifestação real do entity resolution Gotham-style "
                "no setor regulatório brasileiro."
            ),
            "natural_key": "(orgao, tipo, numero, ano)",
            "total_resolved":   len(resolved),
            "matched_pairs":    len(matched_pairs),
            "merged_examples":  matched_pairs[:3],
        },
        "norma_stats": {
            "count_by_tipo":  dict(counts_by_tipo),
            "top_orgaos": [
                {"orgao": orgao, "count": cnt}
                for orgao, cnt in counts_by_orgao.most_common(5)
            ],
            "timeline_last_7d": [
                {"date": d, "count": c} for d, c in timeline_sorted
            ],
        },
        "sample_normas": [
            {
                "tipo":           r["tipo"],
                "orgao":          r["orgao"],
                "numero":         r["numero"],
                "ano":            r["ano"],
                "ementa":         r["ementa"][:160],
                "urn_lex":        r["urn_lex"],
                "fontes":         r["sources"],
                "merged":         r["merged"],
            }
            for r in resolved[:8]
        ],
        "jurimetria": {
            "explanation": (
                "Módulo 2 do Atlântico Atlas — análise estatística do "
                "comportamento decisório do colegiado. Stdlib-only (sem "
                "scipy/sklearn) para rodar dentro do limite do Lambda Vercel."
            ),
            "colegiado": {
                "orgao":                colegiado_profile.orgao,
                "colegiado":            colegiado_profile.colegiado,
                "total_deliberacoes":   colegiado_profile.total_deliberacoes,
                "taxa_unanimidade":     colegiado_profile.taxa_unanimidade,
                "dispositivo_distribution": colegiado_profile.dispositivo_distribution,
                "mean_votos_por_decisao":   colegiado_profile.mean_votos_por_decisao,
                "top_relatores":        colegiado_profile.top_relatores,
                "microtemas_top":       colegiado_profile.microtemas_top,
                "diretor_stats":        diretor_stats,
            },
            "alignment": {
                "directors":  align_matrix.directors,
                "top_pairs": [
                    {"a": a, "b": b, "score": round(s, 3)}
                    for a, b, s in align_matrix.top_pairs(5)
                ],
            },
            "prediction_demo": {
                "pleito": "Pleito hipotético: revisão tarifária com diretor-anm-2 como relator",
                "probability_deferimento": pleito_hipotetico.probability_deferimento,
                "confidence_interval_95":  list(pleito_hipotetico.confidence_interval_95),
                "sample_size":             pleito_hipotetico.sample_size,
                "top_factors": [
                    {"factor": f, "log_odds": adj}
                    for f, adj in pleito_hipotetico.top_factors
                ],
                "explanation": pleito_hipotetico.explanation,
            },
        },
        "sample_deliberacao": {
            "orgao":       sample_delib.orgao,
            "identifier":  sample_delib.identificador_humano,
            "dispositivo": sample_delib.dispositivo,
            "ementa":      sample_delib.ementa,
            "relator_id":  sample_delib.relator_id,
            "votos": [
                {"diretor_id": v.diretor_id, "sentido": v.sentido,
                 "fundamento": v.fundamento_resumo or None}
                for v in sample_delib.votos
            ],
            "norma_citada_urns": sample_delib.norma_citada_urns,
        },
        "sample_regulado": {
            "razao_social":     sample_regulado.razao_social,
            "cnpj":             sample_regulado.cnpj,
            "setor":            sample_regulado.setor,
            "tier_risco":       sample_regulado.tier_risco,
            "grupo_economico":  sample_regulado.grupo_economico,
            "tags":             sample_regulado.tags,
            "lgpd_note": (
                "Para PF, este objeto armazena APENAS cpf_hash (SHA3-256), "
                "nunca CPF cru — princípio LGPD-by-design da ontologia Atlas."
            ),
        },
        "principios_atlas": [
            "Default público (LAI by design)",
            "Provenance via SHA3-256 (chain-of-custody)",
            "LGPD-by-design (CPF apenas como hash)",
            "Datetimes timezone-aware obrigatórios",
            "Zero imports cruzados com finint/geoint/sigint",
            "Soberania de dados (cloud BR ou on-prem)",
        ],
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            data = _build_demo()
            body = json.dumps(data, ensure_ascii=False, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            error = json.dumps({"error": str(exc)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(error)

    def log_message(self, *_):
        pass
