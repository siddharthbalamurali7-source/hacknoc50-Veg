from dotenv import load_dotenv

load_dotenv()


from fastapi import FastAPI
from scanner.asset_router import router as asset_router
from scorer.scorer_router import router as scorer_router
from analyzer.analyzer_router import router as analyzer_router

app = FastAPI(title="CyberSentry")

app.include_router(asset_router, prefix="/assets")
app.include_router(scorer_router, prefix="/scores")
app.include_router(analyzer_router, prefix="/analyzer")

@app.get("/")
def root():
    return {"message": "CyberSentry backend running"}