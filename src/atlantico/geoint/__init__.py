"""
Módulo GEOINT — Geospatial Intelligence do Projeto Atlântico.

Responsabilidades:
- Ingestão de dados de 5 fontes abertas (INPE, ESA, ANA)
- Processamento geoespacial (NDVI, DBSCAN, Z-score)
- Geração de alertas Dilithium-assinados para eventos ambientais e de infraestrutura

Arquitetura:
    connectors/   — Adaptadores para APIs externas
    models/       — Modelos SQLAlchemy com PostGIS
    repositories/ — Repositórios async
    processing/   — Algoritmos de análise geoespacial
    alerts/       — Engine de geração de alertas
    tasks/        — Workers Celery + Celery Beat schedule
"""
