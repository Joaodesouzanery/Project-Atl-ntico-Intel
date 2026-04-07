"""DocumentoBruto — PDF/HTML não classificado, aguardando triagem."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    compute_sha3_256,
    require_classification,
    require_confidence,
    require_tz,
)

MIME_VALIDOS = frozenset(
    {"application/pdf", "text/html", "text/plain", "application/xml", "application/json"}
)


@dataclass
class DocumentoBruto:
    """
    Documento bruto ingerido por crawler, ainda não classificado em
    Norma/Deliberação/Acórdão/etc.

    Identificador canônico: ``text_hash_sha3_256``.
    """

    text_hash_sha3_256: str
    source_url: str
    mime_type: str
    fetched_at: datetime
    snapshot_storage_uri: str | None = None
    texto_extraido: str | None = None
    ocr_confidence: float | None = None
    titulo_estimado: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.text_hash_sha3_256) != 64:
            raise ValueError(
                f"text_hash_sha3_256 deve ter 64 chars hex. "
                f"Recebido len={len(self.text_hash_sha3_256)}"
            )
        if self.mime_type not in MIME_VALIDOS:
            raise ValueError(
                f"mime_type inválido: {self.mime_type!r}. Válidos: {sorted(MIME_VALIDOS)}"
            )
        require_tz(self.fetched_at, "fetched_at")
        if self.ocr_confidence is not None and not 0.0 <= self.ocr_confidence <= 1.0:
            raise ValueError(f"ocr_confidence fora de [0,1]: {self.ocr_confidence}")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @classmethod
    def from_text(
        cls,
        text: str,
        source_url: str,
        mime_type: str,
        fetched_at: datetime,
        **kwargs: object,
    ) -> "DocumentoBruto":
        """Constrói calculando SHA3-256 do texto bruto."""
        return cls(
            text_hash_sha3_256=compute_sha3_256(text),
            source_url=source_url,
            mime_type=mime_type,
            fetched_at=fetched_at,
            texto_extraido=text,
            **kwargs,  # type: ignore[arg-type]
        )

    @property
    def identificador_humano(self) -> str:
        return f"Doc[{self.text_hash_sha3_256[:12]}] {self.titulo_estimado or self.source_url}"
