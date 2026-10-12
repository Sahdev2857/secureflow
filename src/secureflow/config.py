"""Runtime configuration, read from explicit values or environment variables."""

from dataclasses import dataclass
import os


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class SecureFlowConfig:
    model: str = os.getenv("SECUREFLOW_MODEL", "gemma4:e4b")
    ollama_url: str = os.getenv("SECUREFLOW_OLLAMA_URL", "http://localhost:11434")
    num_ctx: int = int(os.getenv("SECUREFLOW_NUM_CTX", "8192"))
    temperature: float = float(os.getenv("SECUREFLOW_TEMPERATURE", "0.2"))
    request_timeout: float = float(os.getenv("SECUREFLOW_TIMEOUT", "60"))
    think: bool = _env_bool("SECUREFLOW_THINK", False)
    max_message_chars: int = int(os.getenv("SECUREFLOW_MAX_MESSAGE_CHARS", "20000"))
    block_on_critical: bool = _env_bool("SECUREFLOW_BLOCK_ON_CRITICAL", False)
    assembly_enabled: bool = _env_bool("SECUREFLOW_ASSEMBLY_ENABLED", True)
    assembly_window: int = int(os.getenv("SECUREFLOW_ASSEMBLY_WINDOW", "5"))
    assembly_max_chars: int = int(os.getenv("SECUREFLOW_ASSEMBLY_MAX_CHARS", "20000"))
    classifier_threshold: float = float(os.getenv("SECUREFLOW_CLASSIFIER_THRESHOLD", "0.75"))
