"""
AlertRepository — Repositório de alertas de correlação assinados com Dilithium.

CRIAÇÃO DE ALERTAS:
    1. title e description são criptografados via EncryptedBytes TypeDecorator
       (AES-256-GCM, chave por coluna derivada da master_key KEK)
    2. O conteúdo do alerta é assinado com Dilithium3+Ed25519
       para garantir não-repúdio e integridade pós-criação
    3. O alerta é registrado no audit_log

ASSINATURA DO ALERTA:
    Cobre (em bytes canônicos): alert_id || severity || rule_id ||
    title_bytes || description_bytes || source_record_ids_json || occurred_at_iso
    Isso garante que qualquer modificação nos campos do alerta invalida
    a assinatura — mesmo que o banco seja comprometido.

BUSCA:
    - Por severidade e status (dashboard operacional)
    - Por localização geoespacial (ST_DWithin para alertas próximos)
    - Por regra de correlação
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.storage.models.alert import Alert


def _compute_alert_signature_message(
    alert_id: str,
    severity: str,
    rule_id: str,
    title_bytes: bytes,
    description_bytes: bytes,
    source_record_ids: list[str],
    occurred_at_iso: str,
) -> bytes:
    """
    Computa os bytes que serão assinados para o alerta.

    Usa SHA3-256 sobre a concatenação canônica dos campos —
    reduz o custo da operação de assinatura PQC (que assina um hash fixo
    em vez do conteúdo completo).
    """
    canonical = b"\x00".join([
        alert_id.encode("utf-8"),
        severity.encode("utf-8"),
        rule_id.encode("utf-8"),
        title_bytes,
        description_bytes,
        json.dumps(sorted(source_record_ids), separators=(",", ":")).encode("utf-8"),
        occurred_at_iso.encode("utf-8"),
    ])
    return hashlib.sha3_256(canonical).digest()


class AlertRepository:
    """
    Repositório de alertas de correlação assinados.

    Requer:
        - AsyncSession injetada via get_db_session()
        - key_manager.KeyManager com chaves ativas
        - audit_log: AuditLogRepository para rastreamento (opcional)
    """

    def __init__(
        self,
        session: AsyncSession,
        key_manager,
        audit_log=None,
    ) -> None:
        self._session = session
        self._km = key_manager
        self._audit_log = audit_log

    async def create(
        self,
        alert_id: str,
        severity: str,
        rule_id: str,
        title: str,
        description: str,
        occurred_at: datetime,
        source_record_ids: list[str] | None = None,
        geo_location_wkt: str | None = None,
        actor_id: str = "correlation-engine",
    ) -> Alert:
        """
        Cria e persiste um novo alerta de correlação.

        1. Codifica title/description em bytes
        2. Calcula SHA3-256 sobre os campos canônicos
        3. Assina o hash com Dilithium3+Ed25519
        4. Persiste com title_enc e description_enc criptografados via TypeDecorator
        5. Registra no audit_log

        Args:
            alert_id: ID único do alerta (gerado pela aplicação)
            severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            rule_id: ID da regra de correlação
            title: Título do alerta (texto claro — será criptografado em repouso)
            description: Descrição completa (texto claro — será criptografada)
            occurred_at: Momento do evento (timezone-aware)
            source_record_ids: UUIDs dos SourceRecords correlacionados
            geo_location_wkt: Localização em WKT ponto (ex: "POINT(-49.25 -16.68)")
            actor_id: Identificador do motor de correlação

        Returns:
            Alert persistido com assinatura válida.
        """
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        occurred_at_iso = occurred_at.isoformat()

        if source_record_ids is None:
            source_record_ids = []

        # Codifica title e description para assinatura
        title_bytes = title.encode("utf-8")
        description_bytes = description.encode("utf-8")

        # Obtém chaves ativas
        kem_key_id, _ = self._km.get_active_kem_public_key()
        sig_key_id, _ = self._km.get_active_signing_public_key()
        signing_priv = self._km.get_signing_private_key(sig_key_id)

        # Calcula mensagem a assinar e assina
        sign_message = _compute_alert_signature_message(
            alert_id=alert_id,
            severity=severity,
            rule_id=rule_id,
            title_bytes=title_bytes,
            description_bytes=description_bytes,
            source_record_ids=source_record_ids,
            occurred_at_iso=occurred_at_iso,
        )
        try:
            from atlantico.crypto.agility import CryptoAgility
            signer = CryptoAgility.get_signer()
            signature = signer.sign(
                payload=sign_message,
                private_key=signing_priv,
            )
        finally:
            signing_priv[:] = b"\x00" * len(signing_priv)

        # Monta o Alert — TypeDecorator criptografa title_enc e description_enc
        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            rule_id=rule_id,
            title_enc=title_bytes,       # TypeDecorator EncryptedBytes("alerts.title")
            description_enc=description_bytes,  # TypeDecorator EncryptedBytes("alerts.description")
            source_record_ids=source_record_ids,
            geo_location=f"SRID=4326;{geo_location_wkt}" if geo_location_wkt else None,
            status="open",
            signature=signature,
            kem_key_id=kem_key_id,
            sig_key_id=sig_key_id,
            occurred_at=occurred_at,
        )
        self._session.add(alert)
        await self._session.flush()

        # Registra no audit log
        if self._audit_log is not None:
            await self._audit_log.append(
                event_type="ALERT_CREATED",
                actor_id=actor_id,
                target_id=alert_id,
                event_data={
                    "severity": severity,
                    "rule_id": rule_id,
                    "source_count": len(source_record_ids),
                    "sig_key_id": sig_key_id,
                },
            )

        return alert

    async def verify_signature(self, alert: Alert) -> bool:
        """
        Verifica a assinatura Dilithium3+Ed25519 do alerta.

        Recalcula a mensagem original a partir dos campos decriptografados
        e verifica contra a assinatura armazenada.

        Returns:
            True se a assinatura é válida. False se o alerta foi adulterado.
        """
        try:
            sign_message = _compute_alert_signature_message(
                alert_id=alert.alert_id,
                severity=alert.severity,
                rule_id=alert.rule_id,
                title_bytes=alert.title_enc,          # TypeDecorator já decriptografou
                description_bytes=alert.description_enc,
                source_record_ids=alert.source_record_ids,
                occurred_at_iso=alert.occurred_at.isoformat(),
            )
            signing_pub = self._km.get_signing_public_key(alert.sig_key_id)
            from atlantico.crypto.agility import CryptoAgility
            signer = CryptoAgility.get_signer()
            return signer.verify(
                payload=sign_message,
                signature=alert.signature,
                public_key=signing_pub,
            )
        except Exception:
            return False

    async def get_by_alert_id(self, alert_id: str) -> Alert | None:
        """Busca um alerta pelo ID único."""
        stmt = select(Alert).where(Alert.alert_id == alert_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_open(
        self,
        severity: str | None = None,
        limit: int = 50,
    ) -> list[Alert]:
        """
        Lista alertas abertos, opcionalmente filtrados por severidade.

        Args:
            severity: Filtro de severidade (opcional)
            limit: Máximo de registros (padrão: 50)
        """
        stmt = select(Alert).where(Alert.status == "open")
        if severity is not None:
            stmt = stmt.where(Alert.severity == severity)
        stmt = stmt.order_by(Alert.occurred_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def update_status(
        self,
        alert_id: str,
        new_status: str,
        actor_id: str,
        notes: str | None = None,
    ) -> Alert:
        """
        Atualiza o status operacional de um alerta.

        Registra a mudança no audit_log. NÃO re-assina o alerta —
        apenas o status operacional muda (que não faz parte da assinatura).

        Args:
            alert_id: ID do alerta
            new_status: "investigating" | "closed" | "false_positive"
            actor_id: Analista responsável
            notes: Notas de investigação (opcional)

        Returns:
            Alert atualizado.
        """
        alert = await self.get_by_alert_id(alert_id)
        if alert is None:
            msg = f"Alerta '{alert_id}' não encontrado."
            raise KeyError(msg)

        old_status = alert.status
        alert.status = new_status
        alert.assigned_to = actor_id
        if notes is not None:
            alert.investigation_notes = notes

        if self._audit_log is not None:
            await self._audit_log.append(
                event_type="ALERT_UPDATED",
                actor_id=actor_id,
                target_id=alert_id,
                event_data={
                    "old_status": old_status,
                    "new_status": new_status,
                    "has_notes": notes is not None,
                },
            )

        return alert
