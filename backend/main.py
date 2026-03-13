from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner.asset_router import router as asset_router
from scorer.scorer_router import router as scorer_router

app = FastAPI(title="CyberSentry")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(asset_router, prefix="/assets")
app.include_router(scorer_router, prefix="/scores")

@app.get("/")
def root():
    return {"message": "CyberSentry backend running"}