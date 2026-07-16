from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379"
    geoip_db_path: str = "./GeoLite2-City.mmdb"
    ids_api_key: str = "change-me-secret"
    alert_webhook_url: str = ""

    risk_block_threshold: int = 80
    risk_alert_threshold: int = 50

    rate_limit_window: int = 60
    rate_limit_max_requests: int = 100
    brute_force_max: int = 5
    brute_force_window: int = 300

    # IPS settings
    ips_enabled: bool = True
    ips_auto_block_ttl: int = 3600  # seconds; 0 = permanent

    # Email alert settings
    # Set RESEND_API_KEY to use Resend HTTP API (recommended on Render / cloud).
    # If blank, falls back to SMTP via aiosmtplib.
    resend_api_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    alert_email_to: str = ""

    # Email resolution links
    # Base URL of this IDS service reachable from your email client (no trailing slash)
    # e.g. https://ids.example.com or http://localhost:8000
    resolution_base_url: str = "http://localhost:8000"
    # Token expiry in seconds (default 24 hours)
    resolution_token_ttl: int = 86400

    model_config = {"env_file": ".env"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
