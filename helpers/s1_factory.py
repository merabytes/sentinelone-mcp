"""Resolve SentinelOneHelper / SentinelDataLakeHelper via Key Vault."""

from __future__ import annotations

from helpers.sentinelone import SentinelDataLakeHelper, SentinelOneHelper
from helpers.tenant_config import (
    resolve_api_key,
    resolve_api_url,
    resolve_site_id,
    resolve_xdr_region,
    resolve_xdr_token,
)


def resolve_s1_helper(tenant_name: str | None = None) -> SentinelOneHelper:
    helper = SentinelOneHelper(
        api_key=resolve_api_key(tenant_name),
        api_url=resolve_api_url(tenant_name),
    )
    site_id = resolve_site_id(tenant_name)
    if site_id:
        helper.site_id = site_id
    return helper


def resolve_xdr_helper(tenant_name: str | None = None) -> SentinelDataLakeHelper:
    return SentinelDataLakeHelper(
        xdr_token=resolve_xdr_token(tenant_name),
        region=resolve_xdr_region(tenant_name),
    )
