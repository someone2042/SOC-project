from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Wazuh API
    wazuh_api_url: str
    wazuh_api_user: str
    wazuh_api_password: str

    # LLM
    gemini_api_key: str

    # Threat Intel
    virustotal_api_key: str
    abuseipdb_api_key: str

    # SIEM / OpenSearch
    opensearch_url: str
    opensearch_user: str
    opensearch_password: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
