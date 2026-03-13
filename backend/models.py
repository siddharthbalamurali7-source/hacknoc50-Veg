"""SQLAlchemy model definitions for CyberSentry."""

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class Asset(Base):
    """Represents a network asset."""

    __tablename__ = "assets"


class CVE(Base):
    """Represents a CVE entry."""

    __tablename__ = "cves"


class Misconfig(Base):
    """Represents a configuration issue found on an asset."""

    __tablename__ = "misconfigs"
