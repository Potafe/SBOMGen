from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.api import api_router
from app.core.config import settings

app = FastAPI(
    title="SBOM Generator Beta",
    description="API for generating SBOM using trivy, syft and cdxgen",
    version="0.0.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
    allow_origins=["*"] # For now
)

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "SBOM Generator is running."}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}