"""
Testes unitários para AuditLogRepository.

Usa SQLite em memória (aiosqlite) para testar encadeamento SHA3-256 e
verificação de integridade sem PostgreSQL real.

NOTA: Row-Level Security (PostgreSQL-only) não é testado aqui —
é testado nos testes de integração com PostgreSQL real.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from atlantico.storage.encrypted_field import EncryptionContext
from atlantico.storage.models.audit_log import AUDIT_LOG_GENESIS_HASH, AuditLogEntry
from atlantico.storage.repositories.audit_log_repo import (
    AuditLogRepository,
    compute_entry_hash,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_context():
    EncryptionContext._reset_for_testing()
    yield
    EncryptionContext._reset_for_testing()


@pytest.fixture
def master_key() -> bytes:
    return bytes(range(32))


@pytest_asyncio.fixture
async def async_engine(master_key):
    """Engine async SQLite em memória para testes.

    Cria a tabela audit_log com SQL raw porque AuditLogEntry usa JSONB
    (PostgreSQL-específico). SQLite armazena JSON como TEXT.
    """
    from sqlalchemy import text

    EncryptionContext.initialize(master_key)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                target_id TEXT,
                event_data TEXT NOT NULL DEFAULT '{}',
                occurred_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                entry_signature BLOB NOT NULL,
                signer_key_id TEXT NOT NULL
            )
        """))
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(async_engine) -> async_sessionmaker:
    """Session factory para os testes."""
    return async_sessionmaker(async_engine, expire_on_commit=False)


@pytest.fixture
def km_with_keys(key_manager):
    """KeyManager com par de chaves de assinatura gerado (necessário para audit log)."""
    key_manager.generate_signing_keypair()
    return key_manager


# ─── compute_entry_hash ────────────────────────────────────────────────────────


class TestComputeEntryHash:
    def test_deterministic(self):
        """Mesmas entradas produzem sempre o mesmo hash."""
        h1 = compute_entry_hash(
            event_id="uuid-001",
            event_type="KEY_GENERATED",
            actor_id="system",
            target_id="key-001",
            event_data={"suite": "hybrid-kyber768"},
            occurred_at_iso="2024-01-15T10:30:00+00:00",
            prev_hash=AUDIT_LOG_GENESIS_HASH,
        )
        h2 = compute_entry_hash(
            event_id="uuid-001",
            event_type="KEY_GENERATED",
            actor_id="system",
            target_id="key-001",
            event_data={"suite": "hybrid-kyber768"},
            occurred_at_iso="2024-01-15T10:30:00+00:00",
            prev_hash=AUDIT_LOG_GENESIS_HASH,
        )
        assert h1 == h2

    def test_different_inputs_produce_different_hashes(self):
        """Qualquer mudança nos campos produz hash diferente."""
        base_args = dict(
            event_id="uuid-001",
            event_type="KEY_GENERATED",
            actor_id="system",
            target_id="key-001",
            event_data={"suite": "hybrid-kyber768"},
            occurred_at_iso="2024-01-15T10:30:00+00:00",
            prev_hash=AUDIT_LOG_GENESIS_HASH,
        )
        base_hash = compute_entry_hash(**base_args)

        for field, new_value in [
            ("event_id", "uuid-999"),
            ("event_type", "KEY_RETIRED"),
            ("actor_id", "user-001"),
            ("target_id", "key-999"),
            ("occurred_at_iso", "2024-01-16T10:30:00+00:00"),
            ("prev_hash", "different-hash"),
        ]:
            modified = {**base_args, field: new_value}
            assert compute_entry_hash(**modified) != base_hash, (
                f"Campo '{field}' não afeta o hash"
            )

    def test_target_id_none_same_as_empty(self):
        """target_id=None e target_id='' produzem o mesmo hash (ambos → '')."""
        h_none = compute_entry_hash(
            event_id="x", event_type="A", actor_id="y",
            target_id=None, event_data={},
            occurred_at_iso="2024-01-01T00:00:00+00:00",
            prev_hash="prev",
        )
        h_empty = compute_entry_hash(
            event_id="x", event_type="A", actor_id="y",
            target_id="", event_data={},
            occurred_at_iso="2024-01-01T00:00:00+00:00",
            prev_hash="prev",
        )
        assert h_none == h_empty

    def test_event_data_order_independent(self):
        """sort_keys=True: ordem dos campos não afeta o hash."""
        h1 = compute_entry_hash(
            event_id="x", event_type="A", actor_id="y", target_id=None,
            event_data={"b": 2, "a": 1},
            occurred_at_iso="2024-01-01T00:00:00+00:00",
            prev_hash="prev",
        )
        h2 = compute_entry_hash(
            event_id="x", event_type="A", actor_id="y", target_id=None,
            event_data={"a": 1, "b": 2},
            occurred_at_iso="2024-01-01T00:00:00+00:00",
            prev_hash="prev",
        )
        assert h1 == h2

    def test_hash_is_sha3_256_length(self):
        """Hash deve ser hexdigest SHA3-256 (64 caracteres hex)."""
        h = compute_entry_hash(
            event_id="x", event_type="A", actor_id="y", target_id=None,
            event_data={}, occurred_at_iso="2024-01-01T00:00:00+00:00",
            prev_hash="prev",
        )
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ─── AUDIT_LOG_GENESIS_HASH ────────────────────────────────────────────────────


class TestGenesisHash:
    def test_genesis_hash_is_deterministic(self):
        expected = hashlib.sha3_256(b"ATLANTICO-AUDIT-GENESIS-v1").hexdigest()
        assert AUDIT_LOG_GENESIS_HASH == expected

    def test_genesis_hash_is_64_hex_chars(self):
        assert len(AUDIT_LOG_GENESIS_HASH) == 64


# ─── AuditLogRepository ────────────────────────────────────────────────────────


class TestAuditLogRepositoryAppend:
    @pytest.mark.asyncio
    async def test_append_single_entry(self, session_factory, km_with_keys):
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            entry = await repo.append(
                event_type="KEY_GENERATED",
                actor_id="system",
                event_data={"suite": "hybrid-kyber768-x25519"},
                target_id="key-001",
            )
            await session.flush()

        assert entry.event_type == "KEY_GENERATED"
        assert entry.prev_hash == AUDIT_LOG_GENESIS_HASH
        assert len(entry.entry_hash) == 64
        assert entry.entry_signature is not None

    @pytest.mark.asyncio
    async def test_append_chains_correctly(self, session_factory, km_with_keys):
        """Segunda entrada deve referenciar hash da primeira."""
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)

            entry1 = await repo.append(
                event_type="KEY_GENERATED",
                actor_id="system",
                event_data={},
            )
            await session.flush()

            entry2 = await repo.append(
                event_type="RECORD_INGESTED",
                actor_id="system",
                event_data={"source": "inpe"},
            )
            await session.flush()

        assert entry2.prev_hash == entry1.entry_hash

    @pytest.mark.asyncio
    async def test_append_uses_provided_occurred_at(self, session_factory, km_with_keys):
        """occurred_at fornecido é preservado no registro."""
        ts = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            entry = await repo.append(
                event_type="TEST_EVENT",
                actor_id="test",
                event_data={},
                occurred_at=ts,
            )
            await session.flush()

        assert "2024-03-15" in entry.occurred_at
        assert "12:00:00" in entry.occurred_at

    @pytest.mark.asyncio
    async def test_entry_hash_matches_computed(self, session_factory, km_with_keys):
        """entry_hash armazenado deve coincidir com recálculo manual."""
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            entry = await repo.append(
                event_type="SYSTEM_STARTUP",
                actor_id="system",
                event_data={"version": "1.0.0"},
            )
            await session.flush()

        expected_hash = compute_entry_hash(
            event_id=entry.event_id,
            event_type=entry.event_type,
            actor_id=entry.actor_id,
            target_id=entry.target_id,
            event_data=entry.event_data,
            occurred_at_iso=entry.occurred_at,
            prev_hash=entry.prev_hash,
        )
        assert entry.entry_hash == expected_hash


class TestAuditLogRepositoryVerifyChain:
    @pytest.mark.asyncio
    async def test_empty_chain_is_valid(self, session_factory, km_with_keys):
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            is_valid, fail_seq = await repo.verify_chain()

        assert is_valid is True
        assert fail_seq is None

    @pytest.mark.asyncio
    async def test_valid_chain_of_five(self, session_factory, km_with_keys):
        """Cadeia de 5 entradas íntegras deve verificar como válida."""
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            for i in range(5):
                await repo.append(
                    event_type=f"EVENT_{i}",
                    actor_id="system",
                    event_data={"seq": i},
                )
            await session.commit()

        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            is_valid, fail_seq = await repo.verify_chain()

        assert is_valid is True
        assert fail_seq is None

    @pytest.mark.asyncio
    async def test_tampered_entry_detected(self, session_factory, km_with_keys):
        """Adulteração em uma entrada deve ser detectada por verify_chain."""
        from sqlalchemy import update as sql_update

        # Insere 3 entradas
        tampered_seq = None
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            entries = []
            for i in range(3):
                e = await repo.append(
                    event_type=f"EVENT_{i}",
                    actor_id="system",
                    event_data={"n": i},
                )
                entries.append(e)
            await session.flush()
            tampered_seq = entries[1].seq
            await session.commit()

        # Adultera a entrada do meio modificando o entry_hash
        async with session_factory() as session:
            stmt = (
                sql_update(AuditLogEntry)
                .where(AuditLogEntry.seq == tampered_seq)
                .values(entry_hash="tampered" + "0" * 57)
            )
            await session.execute(stmt)
            await session.commit()

        # verify_chain deve detectar a adulteração
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            is_valid, fail_seq = await repo.verify_chain()

        assert is_valid is False
        assert fail_seq is not None


class TestAuditLogRepositoryCount:
    @pytest.mark.asyncio
    async def test_count_empty(self, session_factory, km_with_keys):
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            count = await repo.count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_count_after_appends(self, session_factory, km_with_keys):
        async with session_factory() as session:
            repo = AuditLogRepository(session, km_with_keys)
            for _ in range(5):
                await repo.append(event_type="TEST", actor_id="x", event_data={})
            await session.flush()
            count = await repo.count()
        assert count == 5
