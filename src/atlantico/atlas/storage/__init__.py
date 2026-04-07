"""
Camada de persistência da plataforma Atlântico Atlas.

Princípio: Atlas reusa **somente** ``atlantico.storage.models.base`` (Base,
UUIDPKMixin, TimestampMixin) — explicitamente permitido pelo memory item 2
de project_atlas_pivot.md como infra compartilhada. Nenhum outro import
de finint/geoint/sigint/crypto/storage é permitido.

Tipos portáveis: usamos ``JSON`` (não JSONB) e ``String(36)`` para UUIDs
para garantir que os modelos podem ser carregados tanto em PostgreSQL
(produção) quanto em SQLite (testes unitários).
"""
