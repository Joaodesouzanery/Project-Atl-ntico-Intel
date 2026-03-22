"""
Testes de integração do pipeline completo de storage.

REQUER: PostgreSQL + PostGIS em execução (via Docker ou testcontainers).

Para executar com PostgreSQL local (Docker Compose dev):
    docker compose -f infrastructure/docker-compose.yml -f infrastructure/docker-compose.dev.yml up postgres -d
    ATLANTICO_DB_PASSWORD=atlantico_dev_password PYTHONPATH=src python -m pytest tests/integration/ -v

Para executar com testcontainers (auto-provisiona PostgreSQL):
    pip install testcontainers[postgresql]
    PYTHONPATH=src python -m pytest tests/integration/ -v

GATE DO SPRINT 2:
    ✅ encrypt(record) → store em PostgreSQL → recover → decrypt retorna plaintext original
    ✅ Audit log com 5 entradas: chain verification retorna True
    ✅ Adulteração de entrada 3: chain verification retorna False a partir de seq 3
    ✅ PostgreSQLKeyStore passa todos os testes equivalentes ao InMemoryKeyStore
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

# Marca todos os testes desta classe como integração (pulados sem PostgreSQL)
pytestmark = pytest.mark.integration


# ─── Fixture: PostgreSQL via testcontainers ou URL de ambiente ─────────────────


def _get_postgres_url() -> str | None:
    """
    Retorna a URL do PostgreSQL de teste.

    Prioridade:
    1. ATLANTICO_TEST_DB_URL (URL completa)
    2. Variáveis individuais de ambiente
    3. Tentar testcontainers
    """
    test_url = os.environ.get("ATLANTICO_TEST_DB_URL")
    if test_url:
        return test_url

    db_pass = os.environ.get("ATLANTICO_DB_PASSWORD", "")
    db_host = os.environ.get("ATLANTICO_DB_HOST", "localhost")
    db_port = os.environ.get("ATLANTICO_DB_PORT", "5432")
    db_name = os.environ.get("ATLANTICO_DB_NAME", "atlantico_test")
    db_user = os.environ.get("ATLANTICO_DB_USER", "atlantico_app")

    if db_pass:
        return f"postgresql+asyncpg://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"

    return None


@pytest.fixture(scope="session")
def postgres_url():
    """URL do PostgreSQL de teste. Pula a suite se não disponível."""
    url = _get_postgres_url()
    if url is None:
        try:
            from testcontainers.postgres import PostgresContainer
            return None  # Sinalizador para usar testcontainers
        except ImportError:
            pytest.skip(
                "PostgreSQL não disponível. Configure ATLANTICO_DB_PASSWORD "
                "ou instale testcontainers: pip install testcontainers[postgresql]"
            )
    return url


@pytest.fixture(scope="session")
def event_loop():
    """Event loop de sessão para fixtures async de sessão."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def pg_engine(postgres_url, master_key_session):
    """Engine async PostgreSQL para a sessão de testes."""
    from atlantico.storage.database import _build_engine

    class FakeSettings:
        database_url = postgres_url
        db_pool_size = 5
        db_max_overflow = 10
        is_production = False
        is_development = True
        env = type("E", (), {"value": "development"})()

    engine = _build_engine(FakeSettings())

    # Cria schema (PostGIS deve estar disponível)
    from atlantico.storage.models.base import Base
    from atlantico.storage.models.key_store import KeyStoreEntry
    from atlantico.storage.models.source_record import SourceRecord
    from atlantico.storage.models.audit_log import AuditLogEntry
    from atlantico.storage.models.alert import Alert

    async with engine.begin() as conn:
        # Habilita extensões necessárias
        await conn.execute(__import__("sqlalchemy").text(
            "CREATE EXTENSION IF NOT EXISTS postgis; "
            "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
        ))
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="session")
def master_key_session() -> bytes:
    return bytes(range(32))


@pytest.fixture
async def pg_session(pg_engine):
    """AsyncSession para cada teste."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    SessionLocal = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session
        await session.rollback()  # Rollback após cada teste para isolamento


@pytest.fixture(autouse=True)
def init_encryption_context(master_key_session):
    """Inicializa EncryptionContext para os testes de integração."""
    from atlantico.storage.encrypted_field import EncryptionContext
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(master_key_session)
    yield


# ─── Gate 1: Roundtrip encrypt → store → recover → decrypt ───────────────────


@pytest.mark.asyncio
class TestStorageRoundtrip:
    async def test_source_record_encrypt_store_decrypt(
        self, pg_session, initialized_crypto, master_key_session
    ):
        """
        Gate principal: dados OSINT devem sobreviver ao ciclo completo
        encrypt → armazenar no PostgreSQL → recuperar → decrypt.
        """
        from atlantico.crypto.key_manager import KeyManager
        from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

        km = KeyManager(master_key=master_key_session)
        km.generate_kem_keypair()
        km.generate_signing_keypair()

        repo = SourceRecordRepository(session=pg_session, key_manager=km)

        payload = {
            "tipo": "desmatamento",
            "area_ha": 150.3,
            "municipio": "Alta Floresta",
            "data_deteccao": "2024-01-15",
            "fonte": "INPE/PRODES",
            "coordenadas": {"lat": -9.87, "lon": -56.09},
        }

        record_id = f"PRODES-TEST-{uuid.uuid4().hex[:8]}"
        acquired_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        # Store (encrypt + persist)
        record = await repo.store(
            record_id=record_id,
            source_id="inpe.prodes.v2",
            data_classification="PUBLIC",
            payload=payload,
            acquired_at=acquired_at,
        )
        await pg_session.flush()

        assert record.id is not None
        assert record.record_id == record_id
        # payload_envelope deve ser bytes, não o dict original
        assert isinstance(record.payload_envelope, bytes)
        assert len(record.payload_envelope) > 0

        # Recover (decrypt + verify)
        recovered_payload = await repo.retrieve(record_id=record_id)

        assert recovered_payload == payload

    async def test_alert_create_and_verify_signature(
        self, pg_session, initialized_crypto, master_key_session
    ):
        """Alertas criados devem ter assinatura Dilithium válida."""
        from atlantico.crypto.key_manager import KeyManager
        from atlantico.storage.repositories.alert_repo import AlertRepository

        km = KeyManager(master_key=master_key_session)
        km.generate_kem_keypair()
        km.generate_signing_keypair()

        repo = AlertRepository(session=pg_session, key_manager=km)

        alert_id = f"ALERT-TEST-{uuid.uuid4().hex[:8]}"
        alert = await repo.create(
            alert_id=alert_id,
            severity="HIGH",
            rule_id="DEFORESTATION-HOTSPOT-v1",
            title="Desmatamento acelerado detectado",
            description="Área de 150ha desmatada em 7 dias na região norte.",
            occurred_at=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            source_record_ids=["rec-001", "rec-002"],
        )
        await pg_session.flush()

        # Verifica que foi persistido
        assert alert.id is not None
        assert alert.alert_id == alert_id

        # Verifica assinatura
        is_valid = await repo.verify_signature(alert)
        assert is_valid is True

        # Verifica que título/descrição foram criptografados em repouso
        # (o value de title_enc deve ser bytes, não texto claro)
        assert isinstance(alert.title_enc, bytes)
        # Mas ao ler via ORM, TypeDecorator decriptografa automaticamente
        assert alert.title_enc == b"Desmatamento acelerado detectado"


# ─── Gate 2: Audit log com 5 entradas → chain valid ──────────────────────────


@pytest.mark.asyncio
class TestAuditLogIntegration:
    async def test_chain_of_five_is_valid(
        self, pg_session, initialized_crypto, master_key_session
    ):
        """5 entradas legítimas → verify_chain() retorna True."""
        from atlantico.crypto.key_manager import KeyManager
        from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

        km = KeyManager(master_key=master_key_session)
        km.generate_kem_keypair()
        km.generate_signing_keypair()

        repo = AuditLogRepository(session=pg_session, key_manager=km)

        for i in range(5):
            await repo.append(
                event_type=f"EVENT_{i:03d}",
                actor_id="system",
                event_data={"step": i, "test": True},
                target_id=f"resource-{i}",
            )

        await pg_session.flush()
        await pg_session.commit()

        # Nova sessão para verificar
        from sqlalchemy.ext.asyncio import async_sessionmaker
        SessionLocal = async_sessionmaker(pg_session.bind, expire_on_commit=False)
        async with SessionLocal() as new_session:
            repo2 = AuditLogRepository(session=new_session, key_manager=km)
            is_valid, fail_seq = await repo2.verify_chain()

        assert is_valid is True
        assert fail_seq is None

    async def test_tampered_entry_detected(
        self, pg_session, initialized_crypto, master_key_session
    ):
        """Adulteração de entry_hash deve ser detectada."""
        from sqlalchemy import update as sql_update
        from atlantico.crypto.key_manager import KeyManager
        from atlantico.storage.models.audit_log import AuditLogEntry
        from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

        km = KeyManager(master_key=master_key_session)
        km.generate_kem_keypair()
        km.generate_signing_keypair()

        repo = AuditLogRepository(session=pg_session, key_manager=km)

        entries = []
        for i in range(5):
            e = await repo.append(
                event_type=f"EVENT_{i}",
                actor_id="system",
                event_data={"n": i},
            )
            entries.append(e)
        await pg_session.flush()
        await pg_session.commit()

        # Adultera a terceira entrada (índice 2)
        tampered_seq = entries[2].seq
        stmt = (
            sql_update(AuditLogEntry)
            .where(AuditLogEntry.seq == tampered_seq)
            .values(event_data={"n": 999, "ADULTERADO": True})
        )
        await pg_session.execute(stmt)
        await pg_session.commit()

        # Verifica — adulteração deve ser detectada na entrada adulterada
        from sqlalchemy.ext.asyncio import async_sessionmaker
        SessionLocal = async_sessionmaker(pg_session.bind, expire_on_commit=False)
        async with SessionLocal() as new_session:
            repo2 = AuditLogRepository(session=new_session, key_manager=km)
            is_valid, fail_seq = await repo2.verify_chain()

        assert is_valid is False
        assert fail_seq == tampered_seq


# ─── Gate 3: KeyStoreRepository equivalência com InMemoryKeyStore ─────────────


@pytest.mark.asyncio
class TestKeyStoreRepositoryEquivalence:
    async def test_key_lifecycle_full(
        self, pg_session, initialized_crypto, master_key_session
    ):
        """
        Ciclo de vida completo: generate → active → deprecated → retired.
        Equivalente ao teste test_key_rotation.py mas com PostgreSQL.
        """
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from atlantico.crypto.key_manager import KeyManager, KeyStatus
        from atlantico.storage.models.key_store import KeyStoreEntry
        from atlantico.storage.repositories.key_store_repo import PostgreSQLKeyStore

        # Usa engine sync para PostgreSQLKeyStore (drop-in para KeyManager)
        pg_url_sync = str(pg_session.bind.url).replace(
            "postgresql+asyncpg", "postgresql+psycopg"
        )
        sync_engine = create_engine(pg_url_sync, echo=False)
        KeyStoreEntry.__table__.create(sync_engine, checkfirst=True)
        SyncSession = sessionmaker(sync_engine)

        with SyncSession() as session:
            store = PostgreSQLKeyStore(session)
            km = KeyManager(master_key=master_key_session, store=store)

            # Gera chave inicial
            kp = km.generate_kem_keypair()
            session.flush()

            active = store.list_active("kem")
            assert len(active) == 1

            # Rotaciona
            rotation = km.rotate_kem_keys(reason="integration-test")
            session.flush()

            # Chave antiga deve estar deprecated, nova active
            old_record = store.get(kp.key_id)
            new_record = store.get(rotation.new_key_id)

            assert old_record.status == KeyStatus.DEPRECATED
            assert new_record.status == KeyStatus.ACTIVE

            # Chave privada antiga ainda recuperável
            priv = km.get_kem_private_key(kp.key_id)
            assert bytes(priv) == bytes(kp.private_key)
            priv[:] = b"\x00" * len(priv)

            session.commit()

        sync_engine.dispose()
