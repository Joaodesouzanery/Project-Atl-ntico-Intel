"""
PostgreSQLKeyStore — substitui InMemoryKeyStore com persistência real.

Implementa EXATAMENTE a mesma interface do InMemoryKeyStore:
    save(record: KeyRecord) -> None
    get(key_id: str) -> KeyRecord | None
    list_active(key_type: str) -> list[KeyRecord]
    list_all(key_type: str) -> list[KeyRecord]
    update_status(key_id: str, status: KeyStatus, timestamp: int) -> None

CONVERSÃO DE TIPOS:
    KeyRecord.public_key_hex   ↔ KeyStoreEntry.public_key (BYTEA)
    KeyRecord.private_key_encrypted_hex ↔ KeyStoreEntry.private_key_enc (BYTEA, TypeDecorator)

    O TypeDecorator EncryptedBytes criptografa/decriptografa private_key_enc
    automaticamente. O KeyManager ainda criptografa a chave com a KEK antes
    de salvar (private_key_encrypted_hex), e o TypeDecorator adiciona uma
    camada extra de criptografia na coluna. Isso fornece defesa em profundidade:
    mesmo com acesso ao DB, a chave privada está duplamente criptografada.

VERSÕES:
    PostgreSQLKeyStore (sync) — drop-in para InMemoryKeyStore em KeyManager.
        Usa SQLAlchemy sync com psycopg. Requer init_sync_engine().
    AsyncPostgreSQLKeyStore (async) — para uso em corrotinas FastAPI.
        Requer AsyncSession injetada via get_db_session().
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlantico.crypto.exceptions import KeyNotFoundError
from atlantico.crypto.key_manager import KeyRecord, KeyStatus
from atlantico.storage.models.key_store import KeyStoreEntry


def _record_to_entry(record: KeyRecord) -> KeyStoreEntry:
    """Converte KeyRecord → KeyStoreEntry para persistência."""
    return KeyStoreEntry(
        key_id=record.key_id,
        suite=record.suite,
        key_type=record.key_type,
        # Converte hex → bytes para BYTEA
        public_key=bytes.fromhex(record.public_key_hex),
        # private_key_encrypted_hex → bytes (o TypeDecorator adiciona outra camada)
        private_key_enc=bytes.fromhex(record.private_key_encrypted_hex),
        status=record.status.value,
        created_at=record.created_at,
        deprecated_at=record.deprecated_at,
        retired_at=record.retired_at,
        rotation_reason=record.rotation_reason,
    )


def _entry_to_record(entry: KeyStoreEntry) -> KeyRecord:
    """Converte KeyStoreEntry → KeyRecord após leitura do DB."""
    return KeyRecord(
        key_id=entry.key_id,
        suite=entry.suite,
        key_type=entry.key_type,
        # Converte bytes → hex
        public_key_hex=entry.public_key.hex(),
        # TypeDecorator já decriptografou private_key_enc → bytes → hex
        private_key_encrypted_hex=entry.private_key_enc.hex(),
        status=KeyStatus(entry.status),
        created_at=entry.created_at,
        deprecated_at=entry.deprecated_at,
        retired_at=entry.retired_at,
        rotation_reason=entry.rotation_reason or "",
    )


class PostgreSQLKeyStore:
    """
    Store de chaves criptográficas persistido em PostgreSQL.

    Drop-in replacement para InMemoryKeyStore — mesma interface síncrona,
    permite uso direto com KeyManager sem modificações.

    Requer SQLAlchemy sync Session (psycopg driver).

    Uso:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine(settings.database_url_sync)
        Session = sessionmaker(engine)

        with Session() as session:
            store = PostgreSQLKeyStore(session)
            km = KeyManager(master_key=settings.master_key_bytes, store=store)
            keypair = km.generate_kem_keypair()
            session.commit()
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, record: KeyRecord) -> None:
        """
        Persiste ou atualiza um KeyRecord no PostgreSQL.

        Usa merge() para suportar tanto INSERT quanto UPDATE,
        respeitando a chave primária key_id.
        """
        entry = _record_to_entry(record)
        self._session.merge(entry)

    def get(self, key_id: str) -> KeyRecord | None:
        """Busca KeyRecord por key_id. Retorna None se não encontrado."""
        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_id == key_id)
        entry = self._session.execute(stmt).scalar_one_or_none()
        if entry is None:
            return None
        return _entry_to_record(entry)

    def list_active(self, key_type: str) -> list[KeyRecord]:
        """Retorna todas as chaves ativas do tipo especificado."""
        stmt = select(KeyStoreEntry).where(
            KeyStoreEntry.key_type == key_type,
            KeyStoreEntry.status == KeyStatus.ACTIVE.value,
        )
        entries = self._session.execute(stmt).scalars().all()
        return [_entry_to_record(e) for e in entries]

    def list_all(self, key_type: str) -> list[KeyRecord]:
        """Retorna todas as chaves (qualquer status) do tipo especificado."""
        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_type == key_type)
        entries = self._session.execute(stmt).scalars().all()
        return [_entry_to_record(e) for e in entries]

    def update_status(
        self, key_id: str, status: KeyStatus, timestamp: int
    ) -> None:
        """
        Atualiza o status e o timestamp correspondente de uma chave.

        Raises:
            KeyNotFoundError: Se key_id não existir no banco.
        """
        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_id == key_id)
        entry = self._session.execute(stmt).scalar_one_or_none()
        if entry is None:
            raise KeyNotFoundError(key_id)

        entry.status = status.value
        if status == KeyStatus.DEPRECATED:
            entry.deprecated_at = timestamp
        elif status == KeyStatus.RETIRED:
            entry.retired_at = timestamp


class AsyncPostgreSQLKeyStore:
    """
    Versão assíncrona do PostgreSQLKeyStore para uso em FastAPI / Celery async.

    Requer AsyncSession injetada via Depends(get_db_session).
    Não é drop-in para InMemoryKeyStore (métodos são corrotinas).

    Uso:
        async def some_endpoint(session: AsyncSession = Depends(get_db_session)):
            store = AsyncPostgreSQLKeyStore(session)
            keypair = await store.get("key-id-here")
    """

    def __init__(self, session) -> None:
        self._session = session

    async def save(self, record: KeyRecord) -> None:
        entry = _record_to_entry(record)
        self._session.add(entry)

    async def get(self, key_id: str) -> KeyRecord | None:
        from sqlalchemy import select

        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_id == key_id)
        result = await self._session.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry is None:
            return None
        return _entry_to_record(entry)

    async def list_active(self, key_type: str) -> list[KeyRecord]:
        from sqlalchemy import select

        stmt = select(KeyStoreEntry).where(
            KeyStoreEntry.key_type == key_type,
            KeyStoreEntry.status == KeyStatus.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [_entry_to_record(e) for e in result.scalars().all()]

    async def list_all(self, key_type: str) -> list[KeyRecord]:
        from sqlalchemy import select

        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_type == key_type)
        result = await self._session.execute(stmt)
        return [_entry_to_record(e) for e in result.scalars().all()]

    async def update_status(
        self, key_id: str, status: KeyStatus, timestamp: int
    ) -> None:
        from sqlalchemy import select

        stmt = select(KeyStoreEntry).where(KeyStoreEntry.key_id == key_id)
        result = await self._session.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry is None:
            raise KeyNotFoundError(key_id)

        entry.status = status.value
        if status == KeyStatus.DEPRECATED:
            entry.deprecated_at = timestamp
        elif status == KeyStatus.RETIRED:
            entry.retired_at = timestamp
