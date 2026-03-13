"""SQLAlchemy model definitions for CyberSentry."""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class AssetModel(Base):
    """Represents a network asset discovered by the scanner."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    os = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)

    # stored as JSON so we can easily store list structures
    open_ports = Column(JSON, nullable=True)
    software_list = Column(JSON, nullable=True)

    # set by the scanner / business owner
    criticality = Column(Integer, default=2)
    last_scanned = Column(DateTime, nullable=True)

    # calculated by the scorer
    risk_score = Column(Float, nullable=True)
    severity_label = Column(String, nullable=True)
    last_scored = Column(DateTime, nullable=True)


class RiskScoreModel(Base):
    """Historical risk scores for assets."""

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    score = Column(Float, nullable=False)
    severity = Column(String, nullable=False)
    breakdown = Column(JSON, nullable=True)
    top_cves = Column(JSON, nullable=True)

    calculated_at = Column(DateTime, nullable=False)
