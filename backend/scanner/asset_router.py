"""API router for asset-related operations."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="List assets")
async def list_assets():
    """Return a list of assets (placeholder)."""
    return []
