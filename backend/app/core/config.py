from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TM_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000
    allow_non_loopback: bool = False

    data_dir: Path = Path("./data")
    database_url: str = "sqlite+aiosqlite:///./app.db"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def kb_dir(self) -> Path:
        return self.data_dir / "kb"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"


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
        return
    raise RuntimeError(
        f"Refusing to bind to non-loopback host {host!r} without authentication. "
        "This build has no auth in v1. Pass --allow-non-loopback (or set "
        "TM_ALLOW_NON_LOOPBACK=true) only if you understand the exposure, and put "
        "a reverse proxy with auth in front of it."
    )
