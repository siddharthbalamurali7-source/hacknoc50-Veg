"""SQLAlchemy model definitions for CyberSentry."""
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    TIMESTAMP,
    JSON,
    Boolean,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class AssetModel(Base):
    """Represents a network asset discovered by the scanner."""

    __tablename__ = "assets"

    # Use explicit IDs instead of relying on a Postgres-owned sequence.
    # This avoids permission issues when the connected user cannot access the sequence.
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    os = Column(String, nullable=True)
    internet_exposed = Column(Boolean, default=False)

    # stored as JSON so we can easily store list structures
    open_ports = Column(JSON, nullable=True)
    software_list = Column(JSON, nullable=True)

    # set by the scanner / business owner
    criticality = Column(Integer, default=2)

    # calculated by the scorer
    risk_score = Column(Float, nullable=True)
    severity_label = Column(String, nullable=True)
    last_scanned = Column(TIMESTAMP(timezone=True), nullable=True)


class RiskScoreModel(Base):
    """Historical risk scores for assets."""

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    score = Column(Float, nullable=False)
    severity = Column(String, nullable=False)
    breakdown = Column(JSON, nullable=True)
    top_cves = Column(JSON, nullable=True)

    calculated_at = Column(TIMESTAMP(timezone=True), nullable=True)
