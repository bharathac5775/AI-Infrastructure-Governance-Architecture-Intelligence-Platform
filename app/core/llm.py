from langchain_ollama import ChatOllama
from app.config import settings


def get_llm(temperature: float = 0.1, num_ctx: int = 4096) -> ChatOllama:
    """Get configured local Ollama LLM instance."""
    return ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_BASE_URL,
        temperature=temperature,
        num_ctx=num_ctx,
        timeout=300,
    )
