"""Runtime settings, read only from OPENVERDICT_* environment variables."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

AUTH_KEY_PLACEHOLDER = "{auth_key}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPENVERDICT_", env_ignore_empty=True)

    database_url: str = "postgresql+asyncpg://openverdict:openverdict@localhost:5432/openverdict"
    valkey_url: str = "redis://localhost:6379/0"

    urlhaus_auth_key: SecretStr | None = None
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    urlhaus_interval_seconds: int = 900
    phishing_db_links_url: str = (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
        "phishing-links-ACTIVE.txt"
    )
    phishing_db_domains_url: str = (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
        "phishing-domains-ACTIVE.txt"
    )
    phishing_db_interval_seconds: int = 21600
    tranco_url: str = "https://tranco-list.eu/top-1m.csv.zip"
    tranco_interval_seconds: int = 86400
    allowlist_size: int = 10000

    safe_browsing_enabled: bool = False
    safe_browsing_api_key: SecretStr | None = None

    detector_timeout_seconds: float = 2.0
    cache_ttl_seconds: int = 900
    job_reclaim_idle_seconds: int = 300
    job_sweep_after_seconds: int = 300
    job_retention_days: int = 7

    api_host: str = "0.0.0.0"  # noqa: S104 - container listens on all interfaces
    api_port: int = 8000
    worker_metrics_port: int = 9100
    log_level: str = "INFO"

    def urlhaus_download_url(self) -> str | None:
        """URLhaus export URL with the Auth-Key filled in; None if a key is needed but unset."""
        if AUTH_KEY_PLACEHOLDER not in self.urlhaus_url:
            return self.urlhaus_url
        if self.urlhaus_auth_key is None:
            return None
        return self.urlhaus_url.replace(
            AUTH_KEY_PLACEHOLDER, self.urlhaus_auth_key.get_secret_value()
        )
