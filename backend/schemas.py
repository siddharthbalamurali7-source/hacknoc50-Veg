"""Pydantic schema definitions for the CyberSentry API."""

from pydantic import BaseModel


class AssetOut(BaseModel):
    """An asset representation returned by the API."""


class AssetScanRequest(BaseModel):
    """Request schema for initiating a scan on an asset."""
