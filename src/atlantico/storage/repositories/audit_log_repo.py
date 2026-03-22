"""
AuditLogRepository — Repositório de audit log append-only encadeado.

PROTOCOLO DE INSERÇÃO:
    Cada nova entrada:
    1. Busca entry_hash da entrada mais recente (ou GENESIS_HASH se vazia)
    2. Serializa os campos em bytes canônicos (ordem determinística)
    3. Calcula entry_hash = SHA3-256(canonical_bytes)
    4. Assina entry_hash com chave de assinatura ativa (Dilithium3+Ed25519)
    5. Insere a entrada — NUNCA faz UPDATE/DELETE (RLS bloqueia no PostgreSQL)

CANONICAL BYTES (para cálculo de entry_hash):
    b"\\x00".join([
        event_id.encode(),
        event_type.encode(),
        actor_id.encode(),
        (target_id or "").encode(),
        json.dumps(event_data, sort_keys=True, separators=(",",":")).encode(),
        occurred_at_iso.encode(),
        prev_hash.encode(),
    ])
    Separador \\x00 previne ataques de concatenação (length-extension não se
    aplica ao SHA3, mas o separador garante canonicidade mesmo assim).

VERIFICAÇÃO DE CADEIA:
    verify_chain() recalcula entry_hash de cada entrada e verifica:
    1. entry_hash calculado == entry_hash armazenado
    2. prev_hash == entry_hash da entrada anterior
    3. entry_signature válida para entry_hash e signer_key_id
    Qualquer adulteração (incluída por RLS bypass externo) é detectada.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.storage.models.audit_log import AUDIT_LOG_GENESIS_HASH, AuditLogEntry


def _canonical_bytes(
    event_id: str,
    event_type: str,
    actor_id: str,
    target_id: str | None,
    event_data: dict,
    occurred_at_iso: str,
    prev_hash: str,
) -> bytes:
    """
    Serializa os campos do evento em bytes canônicos para o hash SHA3-256.

    Separador \\x00 garante que concatenações diferentes produzam resultados
    diferentes (ex: "abc"+"def" ≠ "ab"+"cdef" quando separados por \\x00).
    """
    parts = [
        event_id.encode("utf-8"),
        event_type.encode("utf-8"),
        actor_id.encode("utf-8"),
        (target_id or "").encode("utf-8"),
        json.dumps(event_data, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        occurred_at_iso.encode("utf-8"),
        prev_hash.encode("utf-8"),
    ]
    return b"\x00".join(parts)


def compute_entry_hash(
    event_id: str,
    event_type: str,
    actor_id: str,
    target_id: str | None,
    event_data: dict,
    occurred_at_iso: str,
    prev_hash: str,
) -> str:
    """
    Calcula o SHA3-256 dos campos canônicos de uma entrada de audit log.

    Exportado para uso em verify_chain() e em testes.
    """
    data = _canonical_bytes(
        event_id, event_type, actor_id, target_id,
        event_data, occurred_at_iso, prev_hash,
    )
    return hashlib.sha3_256(data).hexdigest()


class AuditLogRepository:
    """
    Repositório de audit log append-only com encadeamento criptográfico.

    Cada entrada é encadeada via SHA3-256 e assinada com Dilithium3+Ed25519.
    Row-Level Security no PostgreSQL bloqueia UPDATE/DELETE no nível do banco.

    Requer:
        - AsyncSession do SQLAlchemy (via get_db_session())
        - key_manager.KeyManager para assinar entradas
        - EncryptionContext inicializado (indiretamente via TypeDecorators)
    """

    def __init__(self, session: AsyncSession, key_manager) -> None:
        """
        Args:
            session: AsyncSession do SQLAlchemy.
            key_manager: KeyManager com chave de assinatura ativa disponível.
        """
        self._session = session
        self._km = key_manager

    async def get_last_entry(self) -> AuditLogEntry | None:
        """
        Retorna a entrada mais recente (maior seq).
        Retorna None se o log estiver vazio.
        """
        stmt = (
            select(AuditLogEntry)
            .order_by(AuditLogEntry.seq.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def append(
        self,
        event_type: str,
        actor_id: str,
        event_data: dict,
        target_id: str | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditLogEntry:
        """
        Adiciona entrada ao audit log com encadeamento e assinatura automáticos.

        1. Determina prev_hash (último entry_hash ou GENESIS_HASH)
        2. Serializa em bytes canônicos
        3. Calcula entry_hash = SHA3-256(canonical_bytes)
        4. Assina com chave de assinatura ativa
        5. Insere — RLS bloqueia qualquer UPDATE/DELETE futuro

        Args:
            event_type: Tipo do evento (ex: "KEY_GENERATED", "RECORD_INGESTED")
            actor_id: Identificador do ator (user_id, service_account, "system")
            event_data: Dict com dados contextuais (sem dados sensíveis)
            target_id: ID do objeto alvo (opcional)
            occurred_at: Momento do evento (default: agora em UTC)

        Returns:
            AuditLogEntry inserida com seq preenchido pelo PostgreSQL.
        """
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc)

        # Normaliza para UTC com offset explícito (determinístico para o hash)
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        occurred_at_iso = occurred_at.isoformat()

        # Encadeamento: busca hash da última entrada
        last_entry = await self.get_last_entry()
        prev_hash = last_entry.entry_hash if last_entry else AUDIT_LOG_GENESIS_HASH

        # Gera event_id único (UUID4 como string)
        event_id = str(uuid.uuid4())

        # Calcula entry_hash sobre os campos canônicos
        entry_hash = compute_entry_hash(
            event_id=event_id,
            event_type=event_type,
            actor_id=actor_id,
            target_id=target_id,
            event_data=event_data,
            occurred_at_iso=occurred_at_iso,
            prev_hash=prev_hash,
        )

        # Assina o entry_hash com a chave de assinatura ativa
        sig_key_id, signing_pub_key = self._km.get_active_signing_public_key()
        signing_priv_key = self._km.get_signing_private_key(sig_key_id)
        try:
            from atlantico.crypto.agility import CryptoAgility
            signer = CryptoAgility.get_signer()
            entry_signature = signer.sign(
                payload=entry_hash.encode("utf-8"),
                private_key=signing_priv_key,
            )
        finally:
            # Zeramos a chave privada imediatamente após uso
            signing_priv_key[:] = b"\x00" * len(signing_priv_key)

        # Cria e persiste a entrada
        entry = AuditLogEntry(
            event_id=event_id,
            event_type=event_type,
            actor_id=actor_id,
            target_id=target_id,
            event_data=event_data,
            occurred_at=occurred_at_iso,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            entry_signature=entry_signature,
            signer_key_id=sig_key_id,
        )
        self._session.add(entry)
        await self._session.flush()  # Popula seq sem fazer commit

        return entry

    async def verify_chain(self, from_seq: int = 1) -> tuple[bool, int | None]:
        """
        Verifica integridade do encadeamento a partir de from_seq.

        Para cada entrada:
        1. Recalcula entry_hash e verifica igualdade com o armazenado
        2. Verifica que prev_hash == entry_hash da entrada anterior
        3. Verifica assinatura entry_signature sobre entry_hash

        Returns:
            (True, None) se a cadeia está íntegra.
            (False, seq_da_primeira_falha) se adulteração detectada.
        """
        stmt = (
            select(AuditLogEntry)
            .where(AuditLogEntry.seq >= from_seq)
            .order_by(AuditLogEntry.seq.asc())
        )
        result = await self._session.execute(stmt)
        entries = result.scalars().all()

        if not entries:
            return True, None

        # Determina o prev_hash esperado para a primeira entrada
        if from_seq == 1:
            expected_prev_hash: str | None = AUDIT_LOG_GENESIS_HASH
        else:
            # Busca a entrada anterior para encadeamento parcial
            prev_stmt = (
                select(AuditLogEntry)
                .where(AuditLogEntry.seq == from_seq - 1)
            )
            prev_result = await self._session.execute(prev_stmt)
            prev_entry = prev_result.scalar_one_or_none()
            expected_prev_hash = prev_entry.entry_hash if prev_entry else None

        from atlantico.crypto.agility import CryptoAgility

        for entry in entries:
            # 1. Verifica prev_hash (encadeamento)
            if expected_prev_hash is not None and entry.prev_hash != expected_prev_hash:
                return False, entry.seq

            # 2. Recalcula entry_hash
            expected_hash = compute_entry_hash(
                event_id=entry.event_id,
                event_type=entry.event_type,
                actor_id=entry.actor_id,
                target_id=entry.target_id,
                event_data=entry.event_data,
                occurred_at_iso=entry.occurred_at,
                prev_hash=entry.prev_hash,
            )
            if entry.entry_hash != expected_hash:
                return False, entry.seq

            # 3. Verifica assinatura
            try:
                signing_pub = self._km.get_signing_public_key(entry.signer_key_id)
                signer = CryptoAgility.get_signer()
                if not signer.verify(
                    payload=entry.entry_hash.encode("utf-8"),
                    signature=entry.entry_signature,
                    public_key=signing_pub,
                ):
                    return False, entry.seq
            except Exception:
                return False, entry.seq

            expected_prev_hash = entry.entry_hash

        return True, None

    async def count(self) -> int:
        """Retorna o número total de entradas no audit log."""
        stmt = select(func.count()).select_from(AuditLogEntry)
        result = await self._session.execute(stmt)
        return result.scalar_one()
