"""
Atlântico Atlas — Plataforma de Inteligência Regulatória Brasileira.

Vertical paralela ao Projeto Atlântico (FININT/GEOINT/SIGINT). Vive como
namespace independente, sem imports cruzados — coexistência limpa no
mesmo monorepo.

Inspirado no Palantir Gotham, mas adaptado para o ambiente regulatório
brasileiro: default público (LAI), provenance/chain-of-custody mandatório,
LGPD-by-design, soberania nacional, IA como copiloto técnico (não oráculo).

Ontologia central: 15 tipos de objetos primários (Norma, Processo
Administrativo, Deliberação, Diretor, Regulado, Contrato de Concessão,
Auto de Infração, Indicador de Mercado, Consulta Pública, AIR, Ação
Judicial, Acórdão TCU, Stakeholder Político, Evento Regulatório,
Documento Bruto).

Sprint 4 (Foundation): ontologia core + 2 conectores públicos
(DOU Imprensa Nacional + LexML federal) + NormaResolver entity
resolution + 5 modelos SQLAlchemy materializados + alertas Dilithium-
assinados + tab "Atlas Regulatório" no dashboard.

Agência alvo inicial: ANM (Agência Nacional de Mineração).
"""

__all__ = ["observations", "ontology", "connectors", "models", "repositories",
           "processing", "alerts", "tasks"]
