"""
Testes unitários para PostgreSQLKeyStore.

Usa SQLite em memória via SQLAlchemy sync para testar a interface
sem precisar de um PostgreSQL real. O esquema é criado via create_all()
com as tabelas relevantes. TypeDecorator EncryptedBytes é testado
indiretamente.

NOTA: PostgreSQLKeyStore deve ser um drop-in replacement para
InMemoryKeyStore — todos os testes de KeyManager devem passar
sem modificação quando usam PostgreSQLKeyStore.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from atlantico.crypto.exceptions import KeyNotFoundError
from atlantico.crypto.key_manager import KeyManager, KeyRecord, KeyStatus
from atlantico.storage.encrypted_field import EncryptionContext
from atlantico.storage.models.base import Base
from atlantico.storage.models.key_store import KeyStoreEntry
from atlantico.storage.repositories.key_store_repo import PostgreSQLKeyStore


@pytest.fixture(autouse=True)
def reset_context():
    """Reseta EncryptionContext antes de cada teste."""
    EncryptionContext._reset_for_testing()
    yield
    EncryptionContext._reset_for_testing()


@pytest.fixture
def master_key() -> bytes:
    return bytes(range(32))


@pytest.fixture
def db_session(master_key):
    """
    Sessão SQLite em memória com schema criado.

    SQLite não suporta BYTEA nativo, mas para fins de teste
    o LargeBinary TypeDecorator funciona corretamente.
    O EncryptionContext é inicializado para que EncryptedBytes funcione.
    """
    EncryptionContext.initialize(master_key)

    # SQLite com suporte a CHECK constraints
    engine = create_engine("sqlite:///:memory:", echo=False)

    # Habilita CHECK constraints no SQLite (desabilitados por padrão)
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Cria apenas a tabela key_store (independente das outras)
    KeyStoreEntry.__table__.create(engine, checkfirst=True)

    Session = sessionmaker(engine)
    with Session() as session:
        yield session

    engine.dispose()


@pytest.fixture
def store(db_session) -> PostgreSQLKeyStore:
    return PostgreSQLKeyStore(db_session)


def _make_record(
    key_id: str = "test-key-001",
    key_type: str = "kem",
    status: KeyStatus = KeyStatus.ACTIVE,
) -> KeyRecord:
    """Cria um KeyRecord de teste."""
    return KeyRecord(
        key_id=key_id,
        suite="hybrid-kyber768-x25519",
        key_type=key_type,
        public_key_hex="abcd" * 8,   # 32 bytes em hex
        private_key_encrypted_hex="1234" * 16,  # 64 bytes em hex (nonce+ct+tag)
        status=status,
        created_at=1700000000,
        deprecated_at=None,
        retired_at=None,
        rotation_reason="",
    )


# ─── Interface Idêntica ao InMemoryKeyStore ────────────────────────────────────


class TestPostgreSQLKeyStoreSave:
    def test_save_and_get_roundtrip(self, store):
        record = _make_record()
        store.save(record)
        store._session.flush()

        retrieved = store.get("test-key-001")
        assert retrieved is not None
        assert retrieved.key_id == "test-key-001"
        assert retrieved.suite == "hybrid-kyber768-x25519"
        assert retrieved.key_type == "kem"
        assert retrieved.status == KeyStatus.ACTIVE

    def test_save_preserves_hex_keys(self, store):
        record = _make_record()
        store.save(record)
        store._session.flush()

        retrieved = store.get(record.key_id)
        assert retrieved.public_key_hex == record.public_key_hex
        assert retrieved.private_key_encrypted_hex == record.private_key_encrypted_hex

    def test_save_is_upsert(self, store):
        """save() deve atualizar o registro existente (comportamento idêntico ao InMemory)."""
        record = _make_record()
        store.save(record)
        store._session.flush()

        # Atualiza o registro
        record.status = KeyStatus.DEPRECATED
        record.deprecated_at = 1700001000
        store.save(record)
        store._session.flush()

        retrieved = store.get(record.key_id)
        assert retrieved.status == KeyStatus.DEPRECATED
        assert retrieved.deprecated_at == 1700001000


class TestPostgreSQLKeyStoreGet:
    def test_get_returns_none_for_unknown_key(self, store):
        assert store.get("nonexistent-key") is None

    def test_get_returns_correct_record(self, store):
        r1 = _make_record(key_id="key-001")
        r2 = _make_record(key_id="key-002")
        store.save(r1)
        store.save(r2)
        store._session.flush()

        assert store.get("key-001").key_id == "key-001"
        assert store.get("key-002").key_id == "key-002"


class TestPostgreSQLKeyStoreListActive:
    def test_list_active_returns_only_active(self, store):
        active = _make_record(key_id="active-001", status=KeyStatus.ACTIVE)
        deprecated = _make_record(key_id="deprecated-001", status=KeyStatus.DEPRECATED)
        retired = _make_record(key_id="retired-001", status=KeyStatus.RETIRED)

        for r in [active, deprecated, retired]:
            store.save(r)
        store._session.flush()

        result = store.list_active("kem")
        assert len(result) == 1
        assert result[0].key_id == "active-001"

    def test_list_active_filters_by_key_type(self, store):
        kem_key = _make_record(key_id="kem-001", key_type="kem")
        sig_key = _make_record(key_id="sig-001", key_type="signing")
        store.save(kem_key)
        store.save(sig_key)
        store._session.flush()

        kem_result = store.list_active("kem")
        sig_result = store.list_active("signing")

        assert len(kem_result) == 1
        assert kem_result[0].key_id == "kem-001"
        assert len(sig_result) == 1
        assert sig_result[0].key_id == "sig-001"

    def test_list_active_returns_empty_when_no_active(self, store):
        deprecated = _make_record(key_id="dep-001", status=KeyStatus.DEPRECATED)
        store.save(deprecated)
        store._session.flush()

        assert store.list_active("kem") == []


class TestPostgreSQLKeyStoreListAll:
    def test_list_all_returns_all_statuses(self, store):
        for i, status in enumerate([KeyStatus.ACTIVE, KeyStatus.DEPRECATED, KeyStatus.RETIRED]):
            store.save(_make_record(key_id=f"key-{i:03d}", status=status))
        store._session.flush()

        result = store.list_all("kem")
        assert len(result) == 3

    def test_list_all_filters_by_type(self, store):
        store.save(_make_record(key_id="kem-001", key_type="kem"))
        store.save(_make_record(key_id="sig-001", key_type="signing"))
        store._session.flush()

        assert len(store.list_all("kem")) == 1
        assert len(store.list_all("signing")) == 1


class TestPostgreSQLKeyStoreUpdateStatus:
    def test_update_to_deprecated(self, store):
        record = _make_record()
        store.save(record)
        store._session.flush()

        store.update_status("test-key-001", KeyStatus.DEPRECATED, 1700001000)
        store._session.flush()

        retrieved = store.get("test-key-001")
        assert retrieved.status == KeyStatus.DEPRECATED
        assert retrieved.deprecated_at == 1700001000

    def test_update_to_retired(self, store):
        record = _make_record()
        store.save(record)
        store._session.flush()

        store.update_status("test-key-001", KeyStatus.RETIRED, 1700002000)
        store._session.flush()

        retrieved = store.get("test-key-001")
        assert retrieved.status == KeyStatus.RETIRED
        assert retrieved.retired_at == 1700002000

    def test_update_nonexistent_raises(self, store):
        with pytest.raises(KeyNotFoundError):
            store.update_status("nonexistent", KeyStatus.DEPRECATED, 0)


# ─── Integração com KeyManager ─────────────────────────────────────────────────


class TestKeyManagerWithPostgreSQLStore:
    """
    Verifica que KeyManager funciona identicamente com PostgreSQLKeyStore.
    Estes testes são equivalentes aos de InMemoryKeyStore.
    """

    def test_generate_kem_keypair_persists(self, db_session, initialized_crypto, master_key):
        store = PostgreSQLKeyStore(db_session)
        km = KeyManager(master_key=master_key, store=store)

        keypair = km.generate_kem_keypair()
        db_session.flush()

        # Recuperar do store
        record = store.get(keypair.key_id)
        assert record is not None
        assert record.key_type == "kem"
        assert record.status == KeyStatus.ACTIVE

    def test_get_kem_private_key_roundtrip(self, db_session, initialized_crypto, master_key):
        store = PostgreSQLKeyStore(db_session)
        km = KeyManager(master_key=master_key, store=store)

        keypair = km.generate_kem_keypair()
        db_session.flush()

        # Recuperar chave privada
        recovered = km.get_kem_private_key(keypair.key_id)
        assert bytes(recovered) == bytes(keypair.private_key)
        recovered[:] = b"\x00" * len(recovered)  # Zerar após uso

    def test_rotate_kem_keys_with_postgresql_store(
        self, db_session, initialized_crypto, master_key
    ):
        store = PostgreSQLKeyStore(db_session)
        km = KeyManager(master_key=master_key, store=store)

        # Gera chave inicial
        old_keypair = km.generate_kem_keypair()
        db_session.flush()

        # Rotaciona
        rotation = km.rotate_kem_keys(reason="teste")
        db_session.flush()

        # Verifica estado
        old_record = store.get(old_keypair.key_id)
        new_record = store.get(rotation.new_key_id)

        assert old_record.status == KeyStatus.DEPRECATED
        assert new_record.status == KeyStatus.ACTIVE

    def test_key_survives_session_boundary(
        self, master_key, initialized_crypto
    ):
        """
        Verifica que dados persistidos em uma sessão são legíveis em outra.
        """
        EncryptionContext.initialize(master_key)
        engine = create_engine("sqlite:///:memory:", echo=False)
        KeyStoreEntry.__table__.create(engine, checkfirst=True)
        Session = sessionmaker(engine)

        key_id = None

        # Sessão 1: grava
        with Session() as session1:
            store1 = PostgreSQLKeyStore(session1)
            km1 = KeyManager(master_key=master_key, store=store1)
            keypair = km1.generate_kem_keypair()
            key_id = keypair.key_id
            session1.commit()

        # Sessão 2: lê e decriptografa
        with Session() as session2:
            store2 = PostgreSQLKeyStore(session2)
            km2 = KeyManager(master_key=master_key, store=store2)
            recovered = km2.get_kem_private_key(key_id)
            assert bytes(recovered) == bytes(keypair.private_key)
            recovered[:] = b"\x00" * len(recovered)

        engine.dispose()
