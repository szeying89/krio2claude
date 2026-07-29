import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TM_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000
    allow_non_loopback: bool = False

    data_dir: Path = Path("./data")
    database_url: str = "sqlite+aiosqlite:///./app.db"

    max_upload_bytes: int = 20 * 1024 * 1024  # 20 MiB

    # Strict allowlist, never a wildcard: this is a local, single-tenant,
    # no-auth v1 (Requirement 1) -- the only legitimate cross-origin
    # caller is the bundled React/TS frontend's own dev server.
    cors_allowed_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    llm_provider: str = "anthropic"  # "anthropic" | "openai"
    llm_model: str = "claude-sonnet-5"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def kb_dir(self) -> Path:
        return self.data_dir / "kb"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def llm_cache_dir(self) -> Path:
        return self.cache_dir / "llm"

    @property
    def projects_dir(self) -> Path:
        return self.data_dir / "projects"

    @property
    def cri_dir(self) -> Path:
        return self.data_dir / "cri"

    @property
    def intel_dir(self) -> Path:
        return self.data_dir / "intel"


def get_settings() -> Settings:
    return Settings()


def assert_bind_allowed(host: str, allow_non_loopback: bool) -> None:
    """Fail fast unless binding loopback-only, or the override flag is explicitly set.

    v1 ships with no authentication, so binding beyond loopback silently would
    expose an unauthenticated instance. This is a deliberate startup guard, not
    a runtime-configurable default.
    """
    if host in LOOPBACK_HOSTS:
        return
    if allow_non_loopback:
        logger.warning(
            "binding to non-loopback host %r with --allow-non-loopback: this build has "
            "no authentication in v1 -- anyone who can reach this host and port has full "
            "access. Put a reverse proxy with auth in front of it before doing this "
            "outside a trusted local network.",
            host,
        )
        return
    raise RuntimeError(
        f"Refusing to bind to non-loopback host {host!r} without authentication. "
        "This build has no auth in v1. Pass --allow-non-loopback (or set "
        "TM_ALLOW_NON_LOOPBACK=true) only if you understand the exposure, and put "
        "a reverse proxy with auth in front of it."
    )
