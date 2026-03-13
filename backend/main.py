"""Entry point for the CyberSentry FastAPI application.

This module creates the FastAPI app instance and registers routers.
"""

from fastapi import FastAPI

from backend.scanner.asset_router import router as asset_router


app = FastAPI(title="CyberSentry")

# Register routers
app.include_router(asset_router, prefix="/assets", tags=["assets"])
