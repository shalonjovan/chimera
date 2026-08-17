from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CHIMERA_",
        env_file=".env",
        extra="ignore",
    )

    project_name: str = "chimera"
    version: str = "0.1.0"

    data_dir: Path = Path("data")
    plugins_dir: Path = Path("plugins")
    knowledge_dir: Path = Path("knowledge")
    patterns_dir: Path = Path("patterns")
    generated_dir: Path = Path("generated")

    log_level: str = "INFO"
    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    mcp_transport: str = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8100

    sandbox_enabled: bool = False
    sandbox_image: str = "python:3.12-slim"

    cyberchef_enabled: bool = True
    cyberchef_node_path: str = "node"
    cyberchef_bridge_path: Path = Path("vendor/cyberchef-bridge/bridge.mjs")
    cyberchef_timeout: float = 30.0

    llm_provider: str = "openai"
    llm_model: str = "gpt-4o"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_temperature: float = 0.2
    llm_max_tokens: int = 4096


settings = Settings()
