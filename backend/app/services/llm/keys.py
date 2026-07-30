"""API key resolution: env var first, OS keyring second. Neither the key
nor any error here ever includes the resolved value — only the provider
name and where to configure it."""

from __future__ import annotations


class MissingAPIKeyError(Exception):
    pass


def get_api_key(provider_name: str) -> str:
    import os

    env_var = f"{provider_name.upper()}_API_KEY"
    key = os.environ.get(env_var)
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
        f"environment variable, or store it in the OS keyring under service "
        f"'threatmodel-platform', account {provider_name!r}"
    )
