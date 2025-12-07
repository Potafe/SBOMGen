import logging

from pydantic_settings import BaseSettings
from typing import Optional

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    API_V1_STRING: str = "/api/v1"
    PROJECT_NAME: str = "SBOM Generator"

    DOCKER_REGISTRY: Optional[str] = None
    SCANNER_IMAGE_TAG: str = "latest"

    # REDIS_URL: str = "redis://localhost:6379"

    TEMP_DIR: str = "./temp"
    RESULTS_DIR: str = "./results"

    LOG_DIR: str = "./logs"
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/sbom_generator.log"

    TRIVY_TIMEOUT: int = 5000
    SYFT_TIMEOUT: int = 5000
    CDXGEN_TIMEOUT: int = 5000
    GHAS_TIMEOUT: int = 30  # GitHub API timeout in seconds
    BD_TIMEOUT: int = 60  # Black Duck API timeout in seconds
    CYCLONEDX_CONVERT_TIMEOUT: int = 100

    class Config:
        env_file = ".env"

settings = Settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(settings.LOG_FILE),
        logging.StreamHandler()  # Also log to console for Docker
    ]
)

logger = logging.getLogger(__name__)