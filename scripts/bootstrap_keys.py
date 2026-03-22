"""
Bootstrap de Chaves Criptográficas — Projeto Atlântico.

Executa na primeira inicialização do sistema para gerar:
- Par de chaves KEM (Key Encapsulation Mechanism) do sistema.
- Par de chaves de assinatura digital do sistema.

SEGURANÇA:
    As chaves privadas são armazenadas criptografadas com a KEK (Master Key).
    A KEK vem de ATLANTICO_MASTER_KEY_HEX no ambiente.
    NUNCA execute este script sem configurar uma KEK forte em produção.

USO:
    python scripts/bootstrap_keys.py

    Ou via docker-compose:
        docker-compose run --rm api python scripts/bootstrap_keys.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Adicionar src/ ao path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import os

from atlantico.config.logging import configure_logging
from atlantico.config.settings import Environment, get_settings
from atlantico.crypto.agility import CryptoAgility
from atlantico.crypto.key_manager import KeyManager

import structlog

configure_logging()
log = structlog.get_logger(__name__)


def main() -> None:
    settings = get_settings()

    if settings.is_production and not os.environ.get("ATLANTICO_BOOTSTRAP_CONFIRMED"):
        log.error(
            "bootstrap_blocked",
            reason="Em produção, defina ATLANTICO_BOOTSTRAP_CONFIRMED=yes para prosseguir.",
        )
        sys.exit(1)

    log.info(
        "bootstrap_starting",
        env=settings.env.value,
        kem_suite=settings.kem_suite,
        sig_suite=settings.sig_suite,
    )

    # Inicializar registry de cripto-agilidade
    CryptoAgility.initialize(settings)

    # Criar KeyManager
    km = KeyManager(
        master_key=settings.master_key_bytes,
        rotation_interval_days=settings.key_rotation_interval_days,
        retirement_grace_period_days=settings.key_retirement_grace_period_days,
    )

    # Gerar chaves
    log.info("generating_kem_keypair")
    kem_kp = km.generate_kem_keypair()
    log.info(
        "kem_keypair_generated",
        key_id=kem_kp.key_id,
        suite=kem_kp.suite.value,
        public_key_hex=kem_kp.public_key.hex()[:20] + "...",  # Parcial para log seguro
    )

    log.info("generating_signing_keypair")
    sig_kp = km.generate_signing_keypair()
    log.info(
        "signing_keypair_generated",
        key_id=sig_kp.key_id,
        suite=sig_kp.suite.value,
    )

    # Zerar chaves privadas da memória após uso
    kem_kp.zero_private_key()
    sig_kp.zero_private_key()

    log.info(
        "bootstrap_complete",
        kem_key_id=kem_kp.key_id,
        signing_key_id=sig_kp.key_id,
        message="Chaves geradas com sucesso. Armazenadas criptografadas com KEK.",
    )

    print("\n✓ Bootstrap completo.")
    print(f"  KEM Key ID:     {kem_kp.key_id}")
    print(f"  Signing Key ID: {sig_kp.key_id}")
    print(f"  Suite KEM:      {kem_kp.suite.value}")
    print(f"  Suite Sig:      {sig_kp.suite.value}")
    print("\nPróximos passos:")
    print("  1. Salvar os Key IDs no registro de configuração do ambiente.")
    print("  2. Verificar que a KEK está protegida (Docker Secret / HSM).")
    print("  3. Executar: python scripts/migrate.py")


if __name__ == "__main__":
    main()
