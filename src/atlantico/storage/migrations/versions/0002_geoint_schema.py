"""
0002 — Schema GEOINT: tabelas geoespaciais para monitoramento ambiental.

Cria 6 tabelas com índices PostGIS para o módulo GEOINT:
  - geoint_infrastructure_assets  (ativos de infraestrutura crítica)
  - geoint_satellite_imagery      (metadados Sentinel-2)
  - geoint_deforestation_events   (polígonos PRODES/DETER)
  - geoint_fire_clusters          (clusters DBSCAN de focos de calor)
  - geoint_fire_hotspots          (focos individuais BDQueimadas)
  - geoint_water_observations     (leituras ANA HidroWeb)

Revisão: 0002
Down-revision: 0001
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── geoint_infrastructure_assets ─────────────────────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")

    op.create_table(
        "geoint_infrastructure_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("external_id", sa.String(128), nullable=False, unique=True),
        sa.Column("asset_type", sa.String(64), nullable=False),
        sa.Column("criticality", sa.String(16), nullable=False),
        sa.Column("geom", sa.Text(), nullable=False, comment="Geometry(GEOMETRY, 4326) via PostGIS"),
        sa.Column("name_enc", sa.LargeBinary(), nullable=False, comment="Nome criptografado AES-256-GCM"),
        sa.Column("operator_enc", sa.LargeBinary(), nullable=True),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("capacity_mw", sa.Numeric(12, 2), nullable=True),
        sa.Column("length_km", sa.Numeric(10, 2), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("monitoring_enabled", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "asset_type IN ('hydroelectric','pipeline','transmission_line','substation','dam','port','railroad','water_treatment','gas_terminal')",
            name="ck_infra_asset_type",
        ),
        sa.CheckConstraint(
            "criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_infra_criticality",
        ),
    )

    # Converte coluna geom para tipo PostGIS
    op.execute("ALTER TABLE geoint_infrastructure_assets ALTER COLUMN geom TYPE geometry(GEOMETRY, 4326) USING ST_GeomFromText(geom, 4326)")
    op.execute("CREATE INDEX idx_infra_geom ON geoint_infrastructure_assets USING GIST(geom)")
    op.execute("CREATE INDEX idx_infra_type_criticality ON geoint_infrastructure_assets(asset_type, criticality)")
    op.execute("CREATE UNIQUE INDEX idx_infra_external_id ON geoint_infrastructure_assets(external_id)")
    op.execute("CREATE INDEX idx_infra_active ON geoint_infrastructure_assets(active)")

    op.execute("""
        CREATE TRIGGER update_geoint_infrastructure_assets_updated_at
        BEFORE UPDATE ON geoint_infrastructure_assets
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── geoint_satellite_imagery ─────────────────────────────────────────────
    op.create_table(
        "geoint_satellite_imagery",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("product_id", sa.String(256), nullable=False, unique=True),
        sa.Column("product_name", sa.String(512), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("satellite", sa.String(32), nullable=False),
        sa.Column("product_type", sa.String(32), nullable=False),
        sa.Column("tile_id", sa.String(32), nullable=True),
        sa.Column("relative_orbit", sa.Integer(), nullable=True),
        sa.Column("cloud_cover_pct", sa.Numeric(5, 2), nullable=False),
        sa.Column("footprint", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("online", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("ndvi_computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "analysis_status IN ('pending','ndvi_computed','correlated')",
            name="ck_imagery_analysis_status",
        ),
    )

    op.execute("ALTER TABLE geoint_satellite_imagery ALTER COLUMN footprint TYPE geometry(POLYGON, 4326) USING ST_GeomFromText(footprint, 4326)")
    op.execute("CREATE INDEX idx_imagery_acquired_at ON geoint_satellite_imagery(acquired_at)")
    op.execute("CREATE INDEX idx_imagery_footprint ON geoint_satellite_imagery USING GIST(footprint)")
    op.execute("CREATE UNIQUE INDEX idx_imagery_product_id ON geoint_satellite_imagery(product_id)")
    op.execute("CREATE INDEX idx_imagery_cloud_cover ON geoint_satellite_imagery(cloud_cover_pct)")
    op.execute("CREATE INDEX idx_imagery_analysis_status ON geoint_satellite_imagery(analysis_status)")

    op.execute("""
        CREATE TRIGGER update_geoint_satellite_imagery_updated_at
        BEFORE UPDATE ON geoint_satellite_imagery
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── geoint_deforestation_events ─────────────────────────────────────────
    op.create_table(
        "geoint_deforestation_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False, unique=True),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("area_ha", sa.Numeric(12, 4), nullable=False),
        sa.Column("biome", sa.String(64), nullable=False),
        sa.Column("state", sa.String(2), nullable=False),
        sa.Column("municipality", sa.String(128), nullable=True),
        sa.Column("classname", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default=sa.text("'LOW'")),
        sa.Column("geom", sa.Text(), nullable=False),
        sa.Column("ndvi_before", sa.Numeric(6, 4), nullable=True),
        sa.Column("ndvi_after", sa.Numeric(6, 4), nullable=True),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("source_type IN ('prodes','deter')", name="ck_defor_source_type"),
        sa.CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_defor_severity"),
        sa.CheckConstraint("analysis_status IN ('pending','processed','alerted')", name="ck_defor_analysis_status"),
    )

    op.execute("ALTER TABLE geoint_deforestation_events ALTER COLUMN geom TYPE geometry(POLYGON, 4326) USING ST_GeomFromText(geom, 4326)")
    op.execute("CREATE UNIQUE INDEX idx_defor_external_id ON geoint_deforestation_events(external_id)")
    op.execute("CREATE INDEX idx_defor_source_record ON geoint_deforestation_events(source_record_id)")
    op.execute("CREATE INDEX idx_defor_acquired_severity ON geoint_deforestation_events(acquired_at, severity)")
    op.execute("CREATE INDEX idx_defor_biome_state ON geoint_deforestation_events(biome, state)")
    op.execute("CREATE INDEX idx_defor_geom ON geoint_deforestation_events USING GIST(geom)")

    op.execute("""
        CREATE TRIGGER update_geoint_deforestation_events_updated_at
        BEFORE UPDATE ON geoint_deforestation_events
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── geoint_fire_clusters ─────────────────────────────────────────────────
    op.create_table(
        "geoint_fire_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("cluster_run_id", sa.String(64), nullable=False),
        sa.Column("hotspot_count", sa.Integer(), nullable=False),
        sa.Column("centroid_geom", sa.Text(), nullable=False),
        sa.Column("convex_hull", sa.Text(), nullable=True),
        sa.Column("total_frp_mw", sa.Numeric(12, 2), nullable=True),
        sa.Column("max_frp_mw", sa.Numeric(10, 2), nullable=True),
        sa.Column("mean_frp_mw", sa.Numeric(10, 2), nullable=True),
        sa.Column("min_acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("biome", sa.String(64), nullable=True),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default=sa.text("'LOW'")),
        sa.Column("near_infrastructure", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column("infra_asset_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_fcluster_severity"),
        sa.CheckConstraint("analysis_status IN ('pending','processed','alerted')", name="ck_fcluster_analysis_status"),
    )

    op.execute("ALTER TABLE geoint_fire_clusters ALTER COLUMN centroid_geom TYPE geometry(POINT, 4326) USING ST_GeomFromText(centroid_geom, 4326)")
    op.execute("ALTER TABLE geoint_fire_clusters ALTER COLUMN convex_hull TYPE geometry(POLYGON, 4326) USING CASE WHEN convex_hull IS NOT NULL THEN ST_GeomFromText(convex_hull, 4326) ELSE NULL END")
    op.execute("CREATE INDEX idx_fcluster_created_at ON geoint_fire_clusters(created_at)")
    op.execute("CREATE INDEX idx_fcluster_centroid ON geoint_fire_clusters USING GIST(centroid_geom)")
    op.execute("CREATE INDEX idx_fcluster_severity ON geoint_fire_clusters(severity)")
    op.execute("CREATE INDEX idx_fcluster_run_id ON geoint_fire_clusters(cluster_run_id)")

    op.execute("""
        CREATE TRIGGER update_geoint_fire_clusters_updated_at
        BEFORE UPDATE ON geoint_fire_clusters
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── geoint_fire_hotspots ─────────────────────────────────────────────────
    op.create_table(
        "geoint_fire_hotspots",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("geom", sa.Text(), nullable=False),
        sa.Column("satellite", sa.String(64), nullable=True),
        sa.Column("frp", sa.Numeric(10, 2), nullable=True),
        sa.Column("brightness", sa.Numeric(8, 2), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("biome", sa.String(64), nullable=True),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("municipality", sa.String(128), nullable=True),
        sa.Column("days_without_rain", sa.Integer(), nullable=True),
        sa.Column("fire_risk", sa.Numeric(5, 2), nullable=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["cluster_id"], ["geoint_fire_clusters.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("external_id", "source_id", name="uq_hotspot_external_source"),
        sa.CheckConstraint(
            "analysis_status IN ('pending','processed','clustered','alerted')",
            name="ck_hotspot_analysis_status",
        ),
    )

    op.execute("ALTER TABLE geoint_fire_hotspots ALTER COLUMN geom TYPE geometry(POINT, 4326) USING ST_GeomFromText(geom, 4326)")
    op.execute("CREATE INDEX idx_hotspot_source_record ON geoint_fire_hotspots(source_record_id)")
    op.execute("CREATE INDEX idx_hotspot_acquired_at ON geoint_fire_hotspots(acquired_at)")
    op.execute("CREATE INDEX idx_hotspot_geom ON geoint_fire_hotspots USING GIST(geom)")
    op.execute("CREATE INDEX idx_hotspot_cluster ON geoint_fire_hotspots(cluster_id)")
    op.execute("CREATE INDEX idx_hotspot_biome ON geoint_fire_hotspots(biome)")
    op.execute("CREATE INDEX idx_hotspot_analysis_status ON geoint_fire_hotspots(analysis_status)")

    op.execute("""
        CREATE TRIGGER update_geoint_fire_hotspots_updated_at
        BEFORE UPDATE ON geoint_fire_hotspots
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── geoint_water_observations ────────────────────────────────────────────
    op.create_table(
        "geoint_water_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("station_code", sa.String(32), nullable=False),
        sa.Column("station_name", sa.String(256), nullable=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("geom", sa.Text(), nullable=False),
        sa.Column("measurement_type", sa.String(32), nullable=False),
        sa.Column("value", sa.Numeric(14, 4), nullable=False),
        sa.Column("unit", sa.String(16), nullable=False),
        sa.Column("data_quality", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("historical_mean", sa.Numeric(14, 4), nullable=True),
        sa.Column("historical_stddev", sa.Numeric(14, 4), nullable=True),
        sa.Column("z_score", sa.Numeric(8, 4), nullable=True),
        sa.Column("anomaly_type", sa.String(32), nullable=True),
        sa.Column("anomaly_severity", sa.String(16), nullable=True),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("station_code", "acquired_at", "measurement_type", name="uq_water_station_time_type"),
        sa.CheckConstraint("measurement_type IN ('nivel','vazao','chuva')", name="ck_water_measurement_type"),
        sa.CheckConstraint("data_quality IN (1,2)", name="ck_water_data_quality"),
        sa.CheckConstraint("analysis_status IN ('pending','processed','alerted')", name="ck_water_analysis_status"),
    )

    op.execute("ALTER TABLE geoint_water_observations ALTER COLUMN geom TYPE geometry(POINT, 4326) USING ST_GeomFromText(geom, 4326)")
    op.execute("CREATE INDEX idx_water_station_acquired ON geoint_water_observations(station_code, acquired_at)")
    op.execute("CREATE INDEX idx_water_geom ON geoint_water_observations USING GIST(geom)")
    op.execute("CREATE INDEX idx_water_anomaly_type ON geoint_water_observations(anomaly_type)")
    op.execute("CREATE INDEX idx_water_analysis_status ON geoint_water_observations(analysis_status)")

    op.execute("""
        CREATE TRIGGER update_geoint_water_observations_updated_at
        BEFORE UPDATE ON geoint_water_observations
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)


def downgrade() -> None:
    # Remove em ordem reversa de dependência de FK
    op.execute("DROP TABLE IF EXISTS geoint_water_observations CASCADE")
    op.execute("DROP TABLE IF EXISTS geoint_fire_hotspots CASCADE")
    op.execute("DROP TABLE IF EXISTS geoint_fire_clusters CASCADE")
    op.execute("DROP TABLE IF EXISTS geoint_deforestation_events CASCADE")
    op.execute("DROP TABLE IF EXISTS geoint_satellite_imagery CASCADE")
    op.execute("DROP TABLE IF EXISTS geoint_infrastructure_assets CASCADE")
