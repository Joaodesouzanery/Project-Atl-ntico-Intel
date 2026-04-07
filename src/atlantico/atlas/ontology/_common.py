"""
Helpers compartilhados pela ontologia Atlas.

Sem dependências fora de stdlib — Atlas é vertical paralela e não importa
de finint/geoint/sigint/crypto/storage.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

# ---------------------------------------------------------------------------
# Datetime: timezone-aware obrigatório (lição do bug NVD do SIGINT)
# ---------------------------------------------------------------------------


def require_tz(value: datetime, field_name: str) -> None:
    """Levanta ValueError se o datetime for naive."""
    if value.tzinfo is None:
        raise ValueError(
            f"{field_name} deve ser timezone-aware (UTC). "
            f"Recebido: {value!r} (sem tzinfo)."
        )


# ---------------------------------------------------------------------------
# Hashing — chain-of-custody (provenance) e LGPD-by-design
# ---------------------------------------------------------------------------


def compute_sha3_256(text: str) -> str:
    """SHA3-256 hex digest do texto bruto."""
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def hash_cpf(cpf: str) -> str:
    """
    Hash determinístico de CPF para LGPD-by-design.

    A ontologia Atlas NUNCA armazena CPF cru. Esta função normaliza
    (remove formatação) e retorna SHA3-256 hex.

    Aceita "123.456.789-09" ou "12345678909".
    """
    digits = re.sub(r"\D", "", cpf)
    if len(digits) != 11:
        raise ValueError(f"CPF inválido: esperado 11 dígitos, recebido {len(digits)}")
    return hashlib.sha3_256(digits.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# CNPJ — validação estrutural (não checa dígito verificador para flexibilidade
# de teste; objetos de produção devem usar validação completa upstream)
# ---------------------------------------------------------------------------

_CNPJ_RE = re.compile(r"^\d{14}$")


def normalize_cnpj(cnpj: str) -> str:
    """Remove formatação e valida estrutura. Retorna 14 dígitos."""
    digits = re.sub(r"\D", "", cnpj)
    if not _CNPJ_RE.match(digits):
        raise ValueError(f"CNPJ inválido: esperado 14 dígitos, recebido {cnpj!r}")
    return digits


# ---------------------------------------------------------------------------
# Numero CNJ — formato 20 dígitos: NNNNNNN-DD.AAAA.J.TR.OOOO
# ---------------------------------------------------------------------------

_CNJ_RE = re.compile(r"^\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}$")


def validate_numero_cnj(numero: str) -> str:
    """
    Valida o formato CNJ (Resolução CNJ 65/2008).

    Aceita formatado (com pontuação) ou só dígitos. Retorna a forma formatada.
    """
    digits_only = re.sub(r"\D", "", numero)
    if len(digits_only) != 20:
        raise ValueError(
            f"numero_cnj inválido: esperado 20 dígitos, recebido {numero!r}"
        )
    formatted = (
        f"{digits_only[0:7]}-{digits_only[7:9]}.{digits_only[9:13]}."
        f"{digits_only[13:14]}.{digits_only[14:16]}.{digits_only[16:20]}"
    )
    if not _CNJ_RE.match(formatted):
        raise ValueError(f"numero_cnj inválido: {numero!r}")
    return formatted


# ---------------------------------------------------------------------------
# URN LexML
# ---------------------------------------------------------------------------

_URN_RE = re.compile(
    r"^urn:lex:br:[a-z0-9.\-]+:[a-z_]+:\d{4};\d+(?:\:[a-zA-Z0-9.\-]+)?$"
)


def validate_urn_lex(urn: str) -> str:
    """Valida URN LexML brasileira. Levanta ValueError se inválida."""
    if not _URN_RE.match(urn):
        raise ValueError(
            f"urn_lex inválida: {urn!r}. "
            "Esperado: urn:lex:br:<orgao>:<tipo>:<ano>;<numero>"
        )
    return urn


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def require_confidence(value: float, field_name: str = "confidence") -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} deve estar em [0.0, 1.0], recebido: {value}")


# ---------------------------------------------------------------------------
# Numero SEI — formato NNNNN.NNNNNN/AAAA-DD (17 dígitos + máscara)
# ---------------------------------------------------------------------------

_SEI_RE = re.compile(r"^\d{5}\.\d{6}/\d{4}-\d{2}$")


def validate_numero_sei(numero: str) -> str:
    if not _SEI_RE.match(numero):
        raise ValueError(
            f"numero_sei inválido: {numero!r}. "
            "Esperado formato NNNNN.NNNNNN/AAAA-DD."
        )
    return numero


# ---------------------------------------------------------------------------
# Data classification (LAI by default)
# ---------------------------------------------------------------------------

VALID_CLASSIFICATIONS = frozenset({"PUBLIC", "RESTRICTED", "CONFIDENTIAL"})


def require_classification(value: str) -> None:
    if value not in VALID_CLASSIFICATIONS:
        raise ValueError(
            f"data_classification inválida: {value!r}. "
            f"Valores válidos: {sorted(VALID_CLASSIFICATIONS)}"
        )
