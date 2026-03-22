"""
Modelos SQLAlchemy da camada de storage do Projeto Atlântico.

Hierarquia:
    base.py         — DeclarativeBase + mixins compartilhados
    key_store.py    — Persistência de KeyRecord (crypto/)
    source_record.py — Dados ingeridos das fontes OSINT (envelope PQC por registro)
    alert.py        — Alertas de correlação assinados com Dilithium
    audit_log.py    — Audit trail append-only encadeado SHA3-256
"""

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin
from atlantico.storage.models.alert import Alert
from atlantico.storage.models.audit_log import AuditLogEntry, AUDIT_LOG_GENESIS_HASH
from atlantico.storage.models.key_store import KeyStoreEntry
from atlantico.storage.models.source_record import SourceRecord

__all__ = [
    "Base",
    "TimestampMixin",
    "UUIDPKMixin",
    "Alert",
    "AuditLogEntry",
    "AUDIT_LOG_GENESIS_HASH",
    "KeyStoreEntry",
    "SourceRecord",
]
