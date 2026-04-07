"""
AtlasObservation — DTO compartilhado entre conectores e pipeline de ingestão Atlas.

Objeto puro Python (sem SQLAlchemy, sem crypto) que normaliza observações
regulatórias de fontes heterogêneas (DOU, LexML, SEI, DataJud, TCU) para
uma interface unificada.

Tipos de observação:
    norma                — Lei, decreto, resolução, portaria, instrução normativa
    ato_administrativo   — Despacho, ofício, parecer técnico
    deliberacao          — Decisão de colegiado regulatório
    documento_bruto      — PDF/HTML não classificado, aguardando triagem
    processo             — Marco de processo administrativo (autuação, conclusão, recurso)

Princípios:
    - Default público (LAI by design)
    - reference_date sempre timezone-aware
    - URN LexML (urn:lex:br:...) é o identificador canônico de normas
    - text_hash_sha3_256 garante chain-of-custody (provenance)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AtlasObservation:
    """
    Observação regulatória bruta retornada por um conector Atlas.

    Campos:
        source_id:           Identificador canônico da fonte.
                             Ex: "br.gov.in.dou.v1" | "br.gov.lexml.oai.v1"
        external_id:         ID único do registro na fonte (para deduplication).
                             Para DOU: id_materia. Para LexML: URN.
        observation_type:    Tipo semântico:
                             "norma" | "ato_administrativo" | "deliberacao" |
                             "documento_bruto" | "processo"
        reference_date:      Data de publicação/produção (timezone-aware UTC).
        payload:             Dict com todos os campos brutos da fonte.
        data_classification: "PUBLIC" (padrão LAI) | "RESTRICTED" | "CONFIDENTIAL"
        orgao_publicador:    Sigla/nome do órgão emissor.
                             Ex: "ANM", "ANEEL", "Casa Civil", "Congresso"
        norma_tipo:          Tipo de ato normativo, se aplicável.
                             Ex: "lei" | "decreto" | "resolucao" | "portaria" |
                                 "instrucao_normativa" | "deliberacao"
        urn_lex:             URN LexML canônica (None se ainda não consolidada).
                             Ex: "urn:lex:br:agencia.nacional.mineracao:resolucao:2026;123"
        text_hash_sha3_256:  Hash SHA3-256 do texto bruto da norma — chain-of-custody
                             (qualquer alteração no texto invalida o hash).
        language:            Idioma do conteúdo (ISO 639-1, default "pt").
        tags:                Lista de tags para classificação e busca.
    """

    source_id: str
    external_id: str
    observation_type: str
    reference_date: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    data_classification: str = "PUBLIC"
    orgao_publicador: str | None = None
    norma_tipo: str | None = None
    urn_lex: str | None = None
    text_hash_sha3_256: str | None = None
    language: str = "pt"
    tags: list[str] = field(default_factory=list)

    _VALID_TYPES = frozenset(
        {"norma", "ato_administrativo", "deliberacao", "documento_bruto", "processo"}
    )
    _VALID_CLASSIFICATIONS = frozenset({"PUBLIC", "RESTRICTED", "CONFIDENTIAL"})
    _VALID_NORMA_TIPOS = frozenset(
        {
            "lei",
            "lei_complementar",
            "decreto",
            "decreto_legislativo",
            "medida_provisoria",
            "resolucao",
            "portaria",
            "instrucao_normativa",
            "deliberacao",
            "circular",
            "edital",
            "ato_normativo",
        }
    )

    def __post_init__(self) -> None:
        # Lição aprendida do bug NVD do SIGINT — datetime sempre timezone-aware
        if self.reference_date.tzinfo is None:
            raise ValueError(
                f"AtlasObservation.reference_date deve ser timezone-aware. "
                f"Recebido: {self.reference_date!r} (sem tzinfo)."
            )
        if self.observation_type not in self._VALID_TYPES:
            raise ValueError(
                f"observation_type inválido: {self.observation_type!r}. "
                f"Valores válidos: {sorted(self._VALID_TYPES)}"
            )
        if self.data_classification not in self._VALID_CLASSIFICATIONS:
            raise ValueError(
                f"data_classification inválida: {self.data_classification!r}. "
                f"Valores válidos: {sorted(self._VALID_CLASSIFICATIONS)}"
            )
        if self.norma_tipo is not None and self.norma_tipo not in self._VALID_NORMA_TIPOS:
            raise ValueError(
                f"norma_tipo inválido: {self.norma_tipo!r}. "
                f"Valores válidos: {sorted(self._VALID_NORMA_TIPOS)}"
            )
        if self.urn_lex is not None and not self.urn_lex.startswith("urn:lex:br:"):
            raise ValueError(
                f"urn_lex deve começar com 'urn:lex:br:'. Recebido: {self.urn_lex!r}"
            )

    def compute_text_hash(self, text: str) -> str:
        """Calcula e armazena SHA3-256 do texto bruto (chain-of-custody)."""
        digest = hashlib.sha3_256(text.encode("utf-8")).hexdigest()
        self.text_hash_sha3_256 = digest
        return digest
