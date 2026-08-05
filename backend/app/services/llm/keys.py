"""API key resolution: real env var first, `.env` file second, OS keyring
third. Neither the key nor any error here ever includes the resolved
value — only the provider name and where to configure it.

Fixed here: `app/core/config.py`'s `Settings` loads `backend/.env` via
pydantic-settings, but only for that model's own `TM_`-prefixed fields --
it never touches `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, since those are
resolved independently, right here, and previously checked only real
process environment variables. A key placed in `.env` was silently never
found, even though `.env` is the exact mechanism this codebase already
uses for every other piece of local configuration. `dotenv_values` reads
the file without mutating `os.environ`, so this never overrides a real
env var and has no effect on anything else that reads the environment.
"""

from __future__ import annotations


class MissingAPIKeyError(Exception):
    pass


def get_api_key(provider_name: str) -> str:
    import os

    env_var = f"{provider_name.upper()}_API_KEY"

    key = os.environ.get(env_var)
    if key:
        return key

    key = _read_from_dotenv(env_var)
    if key:
        return key

    try:
        import keyring

        key = keyring.get_password("threatmodel-platform", provider_name)
        if key:
            return key
    except ImportError:
        pass

    raise MissingAPIKeyError(
        f"no API key found for provider {provider_name!r}; set the {env_var} "
        f"environment variable, add it to a .env file, or store it in the OS "
        f"keyring under service 'threatmodel-platform', account {provider_name!r}"
    )


def _read_from_dotenv(env_var: str) -> str | None:
    try:
        from dotenv import dotenv_values
    except ImportError:
        return None
    return dotenv_values(".env").get(env_var) or None
