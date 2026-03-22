"""
SourceRecordRepository — Repositório de dados OSINT com envelope PQC por registro.

PIPELINE DE INGESTÃO (store):
    1. payload dict → JSON bytes
    2. JSON bytes → envelope PQC (encrypt com chave KEM ativa + assinar com Dilithium)
    3. provenance_hash = SHA3-256(envelope_bytes || source_id || acquired_at_iso)
    4. Salvar SourceRecord no PostgreSQL
    5. Registrar no audit_log

PIPELINE DE RECUPERAÇÃO (retrieve):
    1. Buscar SourceRecord por record_id
    2. Recuperar chave KEM privada por kem_key_id (via KeyManager)
    3. Verificar provenance_hash (integridade dos metadados)
    4. Decriptografar envelope → JSON bytes → dict
    5. Registrar acesso no audit_log

BUSCA GEOESPACIAL (search_by_geo):
    Usa PostGIS ST_Intersects com índice GIST para performance.
    Retorna SourceRecords cujo geo_bounds intersecta o polygon fornecido.
    Não decriptografa — retorna os registros brutos para eficiência.

NOTA SOBRE ISOLAMENTO POR REGISTRO:
    Cada SourceRecord usa um envelope PQC independente, gerado com a
    chave KEM pública ativa NO MOMENTO DA INGESTÃO. Isso garante que:
    - Comprometimento de uma chave privada KEM não expõe outros registros
      (somente os registros cifrados com aquela chave específica)
    - Rotação de chaves protege novos registros imediatamente
    - Registros antigos permanecem acessíveis enquanto a chave antiga
      não for RETIRED
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.crypto import envelope as _envelope_module
from atlantico.storage.models.source_record import SourceRecord


class SourceRecordRepository:
    """
    Repositório para dados OSINT ingeridos, com criptografia de envelope PQC por registro.

    Requer:
        - AsyncSession injetada via get_db_session()
        - key_manager.KeyManager com chaves KEM e de assinatura ativas
        - audit_log: AuditLogRepository para rastreamento de operações
        - EncryptionContext inicializado (usado pelos TypeDecorators nos modelos)
    """

    def __init__(
        self,
        session: AsyncSession,
        key_manager,
        audit_log=None,
    ) -> None:
        """
        Args:
            session: AsyncSession do SQLAlchemy.
            key_manager: KeyManager com chaves ativas para encrypt/decrypt.
            audit_log: AuditLogRepository (opcional — se None, não registra audit).
        """
        self._session = session
        self._km = key_manager
        self._audit_log = audit_log

    async def store(
        self,
        record_id: str,
        source_id: str,
        data_classification: str,
        payload: dict,
        acquired_at: datetime,
        geo_bounds_wkt: str | None = None,
        actor_id: str = "system",
    ) -> SourceRecord:
        """
        Criptografa e persiste um registro OSINT.

        Args:
            record_id: ID externo único (ex: "PRODES-2024-0123456")
            source_id: Identificador da fonte (ex: "inpe.prodes.v2")
            data_classification: Nível de classificação ("PUBLIC", "RESTRICTED", etc.)
            payload: Dict com os dados brutos da fonte
            acquired_at: Momento de aquisição na fonte (timezone-aware)
            geo_bounds_wkt: Bounding box em WKT (ex: "POLYGON((-70 -10, ...))")
            actor_id: Identificador do ator que ingere o dado

        Returns:
            SourceRecord persistido com ID gerado pelo PostgreSQL.

        Raises:
            ValueError: Se record_id já existir no banco (UNIQUE constraint).
        """
        # Normaliza timestamp para UTC
        if acquired_at.tzinfo is None:
            acquired_at = acquired_at.replace(tzinfo=timezone.utc)

        # 1. Serializa payload → JSON bytes (sort_keys para determinismo)
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

        # 2. Obtém chaves ativas
        kem_key_id, kem_pub = self._km.get_active_kem_public_key()
        sig_key_id, _ = self._km.get_active_signing_public_key()
        signing_priv = self._km.get_signing_private_key(sig_key_id)

        # 3. Criptografa com envelope PQC (Kyber768+X25519 + AES-GCM + Dilithium3+Ed25519)
        #    context vincula o envelope ao record_id (proteção contra transposição)
        context = f"{record_id}:{source_id}:{acquired_at.isoformat()}".encode("utf-8")
        try:
            envelope_bytes = _envelope_module.encrypt(
                plaintext=payload_json,
                recipient_kem_public_key=kem_pub,
                signing_private_key=signing_priv,
                signing_key_id=sig_key_id,
                kem_key_id=kem_key_id,
                context=context,
            )
        finally:
            signing_priv[:] = b"\x00" * len(signing_priv)

        # 4. Calcula provenance_hash para integridade dos metadados
        provenance_data = (
            envelope_bytes
            + source_id.encode("utf-8")
            + acquired_at.isoformat().encode("utf-8")
        )
        provenance_hash = hashlib.sha3_256(provenance_data).hexdigest()

        # 5. Monta e persiste o SourceRecord
        record = SourceRecord(
            record_id=record_id,
            source_id=source_id,
            data_classification=data_classification,
            acquired_at=acquired_at,
            kem_key_id=kem_key_id,
            sig_key_id=sig_key_id,
            payload_envelope=envelope_bytes,
            geo_bounds=f"SRID=4326;{geo_bounds_wkt}" if geo_bounds_wkt else None,
            provenance_hash=provenance_hash,
        )
        self._session.add(record)
        await self._session.flush()  # Popula id sem commit

        # 6. Registra no audit log
        if self._audit_log is not None:
            await self._audit_log.append(
                event_type="RECORD_INGESTED",
                actor_id=actor_id,
                target_id=record_id,
                event_data={
                    "source_id": source_id,
                    "classification": data_classification,
                    "kem_key_id": kem_key_id,
                    "sig_key_id": sig_key_id,
                    "envelope_size_bytes": len(envelope_bytes),
                },
            )

        return record

    async def retrieve(
        self,
        record_id: str,
        actor_id: str = "system",
    ) -> dict:
        """
        Recupera e decriptografa o payload de um SourceRecord.

        1. Busca o SourceRecord no banco
        2. Verifica provenance_hash (integridade)
        3. Decriptografa o envelope PQC
        4. Registra acesso no audit log

        Args:
            record_id: ID externo do registro
            actor_id: Identificador do ator que acessa o dado

        Returns:
            Payload original como dict.

        Raises:
            KeyError: Se record_id não existir.
            StorageEncryptionError: Se o envelope estiver corrompido.
        """
        stmt = select(SourceRecord).where(SourceRecord.record_id == record_id)
        result = await self._session.execute(stmt)
        record = result.scalar_one_or_none()

        if record is None:
            msg = f"SourceRecord '{record_id}' não encontrado."
            raise KeyError(msg)

        # Verifica provenance_hash
        provenance_data = (
            record.payload_envelope
            + record.source_id.encode("utf-8")
            + record.acquired_at.isoformat().encode("utf-8")
        )
        expected_hash = hashlib.sha3_256(provenance_data).hexdigest()
        if expected_hash != record.provenance_hash:
            from atlantico.storage.encrypted_field import StorageEncryptionError
            msg = (
                f"SourceRecord '{record_id}': provenance_hash inválido. "
                "Possível adulteração dos metadados."
            )
            raise StorageEncryptionError(msg)

        # Decriptografa o envelope
        kem_priv = self._km.get_kem_private_key(record.kem_key_id)
        verifier_keys = self._km.get_all_signing_public_keys()
        context = f"{record_id}:{record.source_id}:{record.acquired_at.isoformat()}".encode("utf-8")

        try:
            payload_json = _envelope_module.decrypt(
                envelope_bytes=record.payload_envelope,
                recipient_kem_private_key=kem_priv,
                verifier_public_keys=verifier_keys,
                context=context,
            )
        finally:
            kem_priv[:] = b"\x00" * len(kem_priv)

        # Registra acesso no audit log
        if self._audit_log is not None:
            await self._audit_log.append(
                event_type="RECORD_RETRIEVED",
                actor_id=actor_id,
                target_id=record_id,
                event_data={
                    "source_id": record.source_id,
                    "kem_key_id": record.kem_key_id,
                },
            )

        return json.loads(payload_json.decode("utf-8"))

    async def search_by_geo(
        self,
        polygon_wkt: str,
        since: datetime | None = None,
        source_id: str | None = None,
        limit: int = 100,
    ) -> list[SourceRecord]:
        """
        Busca SourceRecords cujo geo_bounds intersecta o polígono fornecido.

        Usa PostGIS ST_Intersects com índice GIST para performance.
        Retorna registros brutos (sem decriptografar) para eficiência.

        Args:
            polygon_wkt: Polígono de busca em WKT (EPSG:4326)
            since: Filtro temporal (acquired_at >= since)
            source_id: Filtrar por fonte específica (opcional)
            limit: Máximo de registros retornados (padrão: 100)

        Returns:
            Lista de SourceRecord com payload_envelope ainda criptografado.
        """
        from geoalchemy2.functions import ST_Intersects
        from sqlalchemy import func as sql_func

        stmt = select(SourceRecord).where(
            ST_Intersects(
                SourceRecord.geo_bounds,
                sql_func.ST_GeomFromText(polygon_wkt, 4326),
            )
        )

        if since is not None:
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            stmt = stmt.where(SourceRecord.acquired_at >= since)

        if source_id is not None:
            stmt = stmt.where(SourceRecord.source_id == source_id)

        stmt = stmt.order_by(SourceRecord.acquired_at.desc()).limit(limit)

        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_by_id(self, record_id: str) -> SourceRecord | None:
        """Retorna o SourceRecord bruto (sem decriptografar) por record_id."""
        stmt = select(SourceRecord).where(SourceRecord.record_id == record_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
