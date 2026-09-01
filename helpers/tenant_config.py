"""Tenant config: Azure KV identity + secret name references only."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

_cfg_env = os.environ.get("SENTINELONE_CONFIG")
CONFIG_PATH = (
    Path(_cfg_env)
    if _cfg_env
    else Path(__file__).resolve().parent.parent / "config.json"
)

# ponytail: only xdr_region has a code default; URLs must come from KV
DEFAULT_XDR_REGION = "eu1"

SECRET_DEFAULTS: dict[str, str] = {
    "xdr_region": DEFAULT_XDR_REGION,
}

DEFAULT_SECRET_NAMES: dict[str, str] = {
    "login_email": "S1-LOGIN-EMAIL",
    "login_password": "S1-LOGIN-PASSWORD",
    "login_totp": "S1-LOGIN-TOTP",
    "login_url": "S1-LOGIN-URL",
    "api_url": "S1-API-URL",
    "api_key": "SENTINELONE-API-KEY",
    "xdr_token": "SENTINELONE-XDR-TOKEN",
    "xdr_region": "S1-XDR-REGION",
    "site_id": "S1-SITE-ID",
    "session_cookies": "SENTINELONE-SESSION-COOKIES",
    "session_cookies_visibility": "SENTINELONE-SESSION-COOKIES-VISIBILITY",
}


def normalize_tenant(raw: dict) -> dict:
    """Accept current nested/legacy shapes; output azure + secrets only."""
    name = raw.get("name", "unknown")

    azure = raw.get("azure") or {}
    if not azure.get("vault_url") and raw.get("vault_url"):
        azure = {
            "vault_url": raw["vault_url"],
            "tenant_id": raw.get("AZURE_TENANT_ID") or raw.get("tenant_id"),
            "client_id": raw.get("AZURE_CLIENT_ID") or raw.get("client_id"),
            "client_secret": raw.get("AZURE_CLIENT_SECRET") or raw.get("client_secret"),
        }

    secrets = dict(DEFAULT_SECRET_NAMES)
    secrets.update(raw.get("secrets") or {})

    # Legacy nested → secret name refs (drop inline values)
    if raw.get("session"):
        s = raw["session"]
        if s.get("cookies_key"):
            secrets["session_cookies"] = s["cookies_key"]
        if s.get("cookies_visibility_key"):
            secrets["session_cookies_visibility"] = s["cookies_visibility_key"]
    if raw.get("management_api"):
        m = raw["management_api"]
        if m.get("api_key_secret"):
            secrets["api_key"] = m["api_key_secret"]
        if m.get("url_secret"):
            secrets["api_url"] = m["url_secret"]
    if raw.get("xdr"):
        x = raw["xdr"]
        if x.get("token_secret"):
            secrets["xdr_token"] = x["token_secret"]
        if x.get("region_secret"):
            secrets["xdr_region"] = x["region_secret"]

    # Legacy flat secret name keys
    for old, new in (
        ("cookies", "session_cookies"),
        ("cookies_visibility", "session_cookies_visibility"),
        ("api_key_secret", "api_key"),
        ("xdr_token_secret", "xdr_token"),
    ):
        if raw.get(old):
            secrets[new] = raw[old]

    return {"name": name, "azure": azure, "secrets": secrets}


def load_tenant_configs() -> list[dict]:
    with open(CONFIG_PATH) as f:
        return [normalize_tenant(t) for t in json.load(f)]


def resolve_tenant(tenant_name: str | None = None) -> dict:
    tenants = load_tenant_configs()
    if not tenants:
        raise RuntimeError("No tenants in config.json")
    if tenant_name:
        for t in tenants:
            if t.get("name", "").upper() == tenant_name.upper():
                return t
        raise RuntimeError(f"Tenant '{tenant_name}' not found in config.json")
    return tenants[0]


class TenantSecrets:
    """KV accessor for one tenant. Caches fetched values per process."""

    def __init__(self, tenant: dict):
        from helpers.keyvault_helper import KeyVaultHelper

        self.tenant = tenant
        self._kv = KeyVaultHelper.from_azure(tenant["azure"])
        self._cache: dict[str, str | None] = {}

    def secret_name(self, logical_key: str) -> str:
        return self.tenant["secrets"].get(logical_key) or DEFAULT_SECRET_NAMES[logical_key]

    def get(self, logical_key: str, *, required: bool = False, default: str | None = None) -> str | None:
        if logical_key in self._cache:
            val = self._cache[logical_key]
        else:
            val = self._kv.get_secret(self.secret_name(logical_key))
            self._cache[logical_key] = val

        if val:
            return val
        if default is not None:
            return default
        if logical_key in SECRET_DEFAULTS:
            return SECRET_DEFAULTS[logical_key]
        if required:
            raise RuntimeError(
                f"[{self.tenant['name']}] KV secret '{self.secret_name(logical_key)}' "
                f"({logical_key}) not found"
            )
        return None

    def require(self, logical_key: str) -> str:
        val = self.get(logical_key, required=True)
        assert val is not None
        return val


@lru_cache(maxsize=8)
def _secrets_for(tenant_name: str) -> TenantSecrets:
    return TenantSecrets(resolve_tenant(tenant_name))


def tenant_secrets(tenant_name: str | None = None) -> TenantSecrets:
    name = resolve_tenant(tenant_name)["name"]
    return _secrets_for(name)


def resolve_login(tenant_name: str | None = None) -> dict[str, str]:
    ts = tenant_secrets(tenant_name)
    return {
        "url": ts.require("login_url"),
        "email": ts.require("login_email"),
        "password": ts.require("login_password"),
        "totp": ts.get("login_totp") or "",
    }


def resolve_api_key(tenant_name: str | None = None) -> str:
    return tenant_secrets(tenant_name).require("api_key")


def resolve_api_url(tenant_name: str | None = None) -> str:
    return tenant_secrets(tenant_name).require("api_url")


def resolve_xdr_token(tenant_name: str | None = None) -> str:
    return tenant_secrets(tenant_name).require("xdr_token")


def resolve_xdr_region(tenant_name: str | None = None) -> str:
    return tenant_secrets(tenant_name).get("xdr_region", default=DEFAULT_XDR_REGION) or DEFAULT_XDR_REGION


def resolve_site_id(tenant_name: str | None = None) -> str:
    return tenant_secrets(tenant_name).get("site_id") or ""


def session_cookie_keys(tenant_name: str | None = None) -> tuple[str, str]:
    ts = tenant_secrets(tenant_name)
    return ts.secret_name("session_cookies"), ts.secret_name("session_cookies_visibility")
