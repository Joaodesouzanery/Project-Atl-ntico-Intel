"""
Repositórios da camada de storage do Projeto Atlântico.

Implementam acesso a dados seguro para cada entidade do domínio.

PostgreSQLKeyStore — implementa exatamente a mesma interface do InMemoryKeyStore,
    permitindo substituição direta no KeyManager sem modificações.

AuditLogRepository — append-only com encadeamento SHA3-256 + assinatura Dilithium.

SourceRecordRepository — criptografia de envelope PQC por registro.

AlertRepository — criação e busca de alertas assinados.
"""

from atlantico.storage.repositories.key_store_repo import PostgreSQLKeyStore
from atlantico.storage.repositories.audit_log_repo import AuditLogRepository
from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
from atlantico.storage.repositories.alert_repo import AlertRepository

__all__ = [
    "PostgreSQLKeyStore",
    "AuditLogRepository",
    "SourceRecordRepository",
    "AlertRepository",
]
