import logging
import os

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


class KeyVaultHelper:
    """Azure Key Vault client — Service Principal from tenant azure block or env."""

    def __init__(
        self,
        vault_url: str,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ):
        self.vault_url = vault_url
        _tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        _client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        _client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        if _tenant_id and _client_id and _client_secret:
            self.credential = ClientSecretCredential(
                tenant_id=_tenant_id,
                client_id=_client_id,
                client_secret=_client_secret,
            )
        else:
            mi_client_id = os.getenv("MANAGED_IDENTITY_CLIENT_ID")
            if not mi_client_id:
                raise RuntimeError(
                    "Azure identity incomplete — set azure.{tenant_id,client_id,client_secret} "
                    "in config.json or AZURE_* env vars"
                )
            self.credential = ManagedIdentityCredential(client_id=mi_client_id)

        self.client = SecretClient(vault_url=self.vault_url, credential=self.credential)

    @classmethod
    def from_azure(cls, azure: dict) -> "KeyVaultHelper":
        return cls(
            vault_url=azure["vault_url"],
            tenant_id=azure.get("tenant_id"),
            client_id=azure.get("client_id"),
            client_secret=azure.get("client_secret"),
        )

    @classmethod
    def from_tenant_config(cls, cfg: dict) -> "KeyVaultHelper":
        """Compat: accepts normalized tenant or legacy flat config."""
        if cfg.get("azure"):
            return cls.from_azure(cfg["azure"])
        return cls(
            vault_url=cfg["vault_url"],
            tenant_id=cfg.get("AZURE_TENANT_ID") or cfg.get("tenant_id"),
            client_id=cfg.get("AZURE_CLIENT_ID") or cfg.get("client_id"),
            client_secret=cfg.get("AZURE_CLIENT_SECRET") or cfg.get("client_secret"),
        )

    def get_secret(self, secret_name: str) -> str | None:
        try:
            return self.client.get_secret(secret_name).value
        except ResourceNotFoundError:
            logger.error("Secret not found in Key Vault: %s", secret_name)
            return None
        except HttpResponseError as e:
            logger.error("HTTP error retrieving secret '%s': %s", secret_name, e.status_code)
            Path = __import__("pathlib").Path
            Path("/workspace/sentinelone-mcp/kv_mcp.log").write_text(
                f"HttpResponseError {e.status_code} {secret_name} {e}\n", encoding="utf-8"
            )
            raise RuntimeError(f"Key Vault HTTP {e.status_code} for '{secret_name}': {e}") from e
        except Exception as e:
            logger.error("Unexpected error retrieving secret '%s': %s", secret_name, type(e).__name__)
            Path = __import__("pathlib").Path
            Path("/workspace/sentinelone-mcp/kv_mcp.log").write_text(
                f"{type(e).__name__} {secret_name} {e}\n", encoding="utf-8"
            )
            raise RuntimeError(f"Key Vault {type(e).__name__} for '{secret_name}': {e}") from e

    def set_secret(self, secret_name: str, secret_value: str) -> bool:
        try:
            self.client.set_secret(secret_name, secret_value)
            logger.info("Stored secret '%s' in %s", secret_name, self.vault_url)
            return True
        except HttpResponseError as e:
            logger.error("HTTP error storing secret '%s': %s", secret_name, e.status_code)
            return False
        except Exception as e:
            logger.error("Unexpected error storing secret '%s': %s", secret_name, type(e).__name__)
            return False
