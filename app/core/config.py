# What is this file?   All settings in one place (database URL, secret key...).
# Why?                 Wrong settings should fail at startup, not later.
# Connects to:         everything calls get_settings() to read values.
# Flutter/Dart idea:   a `Config` class that reads --dart-define / .env values
#                      once and exposes them as typed fields.
"""Application configuration.

Responsibility: read every setting from environment variables (or a local `.env`
file) in ONE place, validate it at startup, and expose it as a typed object.

Why: scattering `os.getenv()` calls through the codebase makes misconfiguration
show up as random runtime errors. Validating once at boot means a bad deployment
fails immediately with a clear message instead of failing on the first login.
"""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# A short signing key is brute-forceable, which would let an attacker forge JWTs.
# A short secret key is easy to guess. So we require at least 32 characters.
MIN_SECRET_KEY_LENGTH = 32


# Purpose: a class whose fields are filled from environment variables.
#   DATABASE_URL in the environment  ->  `database_url` field here.
# Closest Dart idea: a config class with `final` fields, filled by
# `String.fromEnvironment('DATABASE_URL')`. Here Pydantic does it for you
# and also checks the types (a bad value stops the app at start).
class Settings(BaseSettings):
    """Typed view of the environment. Field names map to UPPER_CASE env vars."""

    # Settings for the settings class: also read a local `.env` file,
    # and ignore variables we do not know.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"

    # Infrastructure
    # `str` has no `?`, so it is REQUIRED. If it is missing, the app will not start.
    # Fields with `= something` have a default value (like optional named params).
    database_url: str
    redis_url: str | None = None  # When unset, rate limiting falls back to in-process memory.

    # Auth
    secret_key: SecretStr
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 30

    # HTTP
    cors_origins: list[str] = []

    # Rate limiting for unauthenticated auth endpoints (login/register/refresh).
    auth_rate_limit_attempts: int = 10
    auth_rate_limit_window_seconds: int = 60

    # A validator runs when the value is loaded. If it raises an error, startup stops.
    # Flutter idea: an `assert` in a constructor.
    @field_validator("secret_key")
    @classmethod
    def secret_key_must_be_long_enough(cls, value: SecretStr) -> SecretStr:
        """Reject weak signing keys at startup.

        Why: JWT signatures are only as strong as the key. Failing at boot is
        safer than silently running with a guessable key.

        Args:
            value: the candidate secret key.
        Returns:
            The same value if it is long enough.
        Raises:
            ValueError: if shorter than MIN_SECRET_KEY_LENGTH characters.
        """
        if len(value.get_secret_value()) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        return value


# `lru_cache` remembers the result of the function. First call builds Settings.
# Next calls return the SAME object. Flutter idea: a singleton / `late final`.
@lru_cache
def get_settings() -> Settings:
    """Return the process-wide Settings instance (built once, then cached).

    Why cached: parsing the environment on every request is wasteful, and a
    single shared instance guarantees every module sees identical values.
    Tests that need different values call `get_settings.cache_clear()`.

    Returns:
        The validated Settings object.
    """
    return Settings()
