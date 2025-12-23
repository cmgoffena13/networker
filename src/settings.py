import os
from functools import lru_cache
from typing import Literal, Optional

from pydantic import HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.utils import aws_secret_helper, azure_secret_helper, gcp_secret_helper

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class BaseConfig(BaseSettings):
    ENV_STATE: Optional[str] = None

    @classmethod
    def _get_secret_field_mapping(cls):
        return {
            "aws": [],
            "azure": [],
            "gcp": [],
        }

    @model_validator(mode="before")
    @classmethod
    def resolve_secrets(cls, data: dict):
        resolved = {}
        secret_mapping = cls._get_secret_field_mapping()
        for field_name, value in data.items():
            if not value or not isinstance(value, str):
                resolved[field_name] = value
                continue

            if field_name in secret_mapping.get("aws", []):
                resolved[field_name] = aws_secret_helper(value)
            elif field_name in secret_mapping.get("azure", []):
                resolved[field_name] = azure_secret_helper(value)
            elif field_name in secret_mapping.get("gcp", []):
                resolved[field_name] = gcp_secret_helper(value)
            else:
                resolved[field_name] = value

        return resolved

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# Store all environment variables that can be accessed globally
class GlobalConfig(BaseConfig):
    LOG_LEVEL: LogLevel = "INFO"
    OTEL_PYTHON_LOG_CORRELATION: Optional[bool] = None
    OPEN_TELEMETRY_TRACE_ENDPOINT: Optional[HttpUrl] = None
    OPEN_TELEMETRY_LOG_ENDPOINT: Optional[HttpUrl] = None
    OPEN_TELEMETRY_AUTHORIZATION_TOKEN: Optional[str] = None
    OPEN_TELEMETRY_FLAG: bool = False

    # AWS Secrets Manager settings
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_SESSION_TOKEN: Optional[str] = None  # For temporary credentials
    AWS_REGION: Optional[str] = None  # Defaults to boto3's default region chain

    # Azure Key Vault settings (for secret manager access)
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_KEY_VAULT_URL: Optional[str] = None

    # GCP Secret Manager settings
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None
    GOOGLE_CLOUD_PROJECT: Optional[str] = None


class DevConfig(GlobalConfig):
    LOG_LEVEL: LogLevel = "DEBUG"  # Overrides the global LOG_LEVEL
    OTEL_PYTHON_LOG_CORRELATION: bool = False

    model_config = SettingsConfigDict(env_prefix="DEV_")


class TestConfig(GlobalConfig):
    LOG_LEVEL: LogLevel = "DEBUG"
    OTEL_PYTHON_LOG_CORRELATION: bool = False

    model_config = SettingsConfigDict(env_prefix="TEST_")


class ProdConfig(GlobalConfig):
    LOG_LEVEL: LogLevel = "WARNING"
    OTEL_PYTHON_LOG_CORRELATION: bool = True
    OPEN_TELEMETRY_FLAG: bool = True

    model_config = SettingsConfigDict(env_prefix="PROD_")


@lru_cache()
def get_config(env_state: str):
    if not env_state:
        raise ValueError("ENV_STATE is not set. Possible values are: DEV, TEST, PROD")
    env_state = env_state.lower()
    if env_state == "dev":
        prefix = "DEV_"

        # Assign any dev config credentials to env to authenticate with get_secret() functions
        aws_access_key_id = os.environ.get(f"{prefix}AWS_ACCESS_KEY_ID")
        if aws_access_key_id:
            os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key_id
        aws_secret_access_key = os.environ.get(f"{prefix}AWS_SECRET_ACCESS_KEY")
        if aws_secret_access_key:
            os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key
        aws_session_token = os.environ.get(f"{prefix}AWS_SESSION_TOKEN")
        if aws_session_token:
            os.environ["AWS_SESSION_TOKEN"] = aws_session_token
        aws_region = os.environ.get(f"{prefix}AWS_REGION")
        if aws_region:
            os.environ["AWS_REGION"] = aws_region
        gcp_creds = os.environ.get(f"{prefix}GOOGLE_APPLICATION_CREDENTIALS")
        if gcp_creds:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = gcp_creds
        azure_client_id = os.environ.get(f"{prefix}AZURE_CLIENT_ID")
        if azure_client_id:
            os.environ["AZURE_CLIENT_ID"] = azure_client_id
        azure_client_secret = os.environ.get(f"{prefix}AZURE_CLIENT_SECRET")
        if azure_client_secret:
            os.environ["AZURE_CLIENT_SECRET"] = azure_client_secret
        azure_tenant_id = os.environ.get(f"{prefix}AZURE_TENANT_ID")
        if azure_tenant_id:
            os.environ["AZURE_TENANT_ID"] = azure_tenant_id
        azure_vault_url = os.environ.get(f"{prefix}AZURE_KEY_VAULT_URL")
        if azure_vault_url:
            os.environ["AZURE_KEY_VAULT_URL"] = azure_vault_url

    configs = {"dev": DevConfig, "prod": ProdConfig, "test": TestConfig}
    return configs[env_state]()


config = get_config(BaseConfig().ENV_STATE)
