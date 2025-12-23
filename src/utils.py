import logging
import os
import time
from functools import wraps

import boto3
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from botocore.exceptions import ClientError
from google.cloud import secretmanager

logger = logging.getLogger(__name__)


def retry(attempts: int = 3, delay: float = 0.25, backoff: float = 2.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            wait = delay
            for index in range(attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if index == attempts - 1:
                        raise e
                    logger.warning(
                        f"Retrying {func.__name__} (attempt {index + 2}/{attempts}) after {type(e).__name__}: {e}"
                    )
                    time.sleep(wait)
                    wait *= backoff

        return wrapper

    return decorator


def aws_secret_helper(value: str) -> str:
    client = boto3.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=value)
        secret_value = response.get("SecretString")
        if not secret_value:
            secret_binary = response.get("SecretBinary")
            if secret_binary:
                secret_value = secret_binary.decode("utf-8")
            else:
                raise ValueError(
                    f"AWS secret {value} has no SecretString or SecretBinary"
                )
        logger.debug(f"Fetched secret from AWS Secrets Manager: {value}")
        return secret_value
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            logger.error(f"AWS secret not found: {value}")
            raise ValueError(f"AWS secret not found: {value}") from e
        logger.error(f"Error fetching AWS secret {value}: {e}")
        raise


def gcp_secret_helper(value: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    try:
        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project_id:
            raise ValueError("GOOGLE_CLOUD_PROJECT environment variable must be set")

        name = f"projects/{project_id}/secrets/{value}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8")
        logger.debug(f"Fetched secret from GCP Secret Manager: {value}")
        return secret_value
    except Exception as e:
        logger.error(f"Error fetching GCP secret {value}: {e}")
        raise


def azure_secret_helper(value: str) -> str:
    vault_url = os.environ.get("AZURE_KEY_VAULT_URL")
    if not vault_url:
        raise ValueError("AZURE_KEY_VAULT_URL environment variable must be set")

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    try:
        secret_value = client.get_secret(value).value
        logger.debug(f"Fetched secret from Azure Key Vault: {value}")
        return secret_value
    except Exception as e:
        logger.error(f"Error fetching Azure secret {value}: {e}")
        raise
