# sentinelone-mcp

FastMCP server for SentinelOne: session login, XDR alerts, Purple AI, and SOC investigation tools.

Credentials live in **Azure Key Vault** only. `config.json` holds Azure identity + KV secret **names**, not values.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
playwright install chromium
cp config.example.json config.json   # edit with your vault + secret names
```

Populate KV secrets (see `config.example.json` for logical keys). Required:

- `S1-LOGIN-EMAIL`, `S1-LOGIN-PASSWORD`, `S1-LOGIN-TOTP` (if MFA)
- `S1-LOGIN-URL`, `S1-API-URL` (your SentinelOne console/API base URLs)
- `SENTINELONE-API-KEY`, `SENTINELONE-XDR-TOKEN`
- Optional: `S1-XDR-REGION` (default `eu1`), `S1-SITE-ID`

Session cookies (`SENTINELONE-SESSION-COOKIES*`) are written by `refresh_login`.

## Run

```bash
python main.py                    # FastMCP stdio (default)
python main.py --mode login       # refresh Playwright session → KV
python -m sentinelone_mcp         # same as default MCP mode
```

## Cursor MCP config

```json
{
  "mcpServers": {
    "sentinelone": {
      "command": "python",
      "args": ["/path/to/sentinelone-sync/main.py"],
      "cwd": "/path/to/sentinelone-sync"
    }
  }
}
```

Override config path: `SENTINELONE_CONFIG=/path/to/config.json`
