from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.v1.api import api_router
from app.core.config import settings
from app.database import init_db

from pathlib import Path

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown (nothing to do for now)

app = FastAPI(
    title="SBOM Generator Beta",
    description="API for generating SBOM using trivy, syft and cdxgen",
    version="0.0.1",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
    allow_origins=["*"] # For now
)

static_dir = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(api_router, prefix="/api/v1")

@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = static_dir / "repository-scanner.html"
    return FileResponse(index_path)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}