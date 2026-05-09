import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:E2B")
    UPLOAD_DIR: str = "uploads"
    CHROMA_DIR: str = "chroma_data"
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: set = {".yaml", ".yml", ".tf", ".json", ".hcl"}


settings = Settings()
