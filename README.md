# tweetfeed-mcp

**Model Context Protocol (MCP) server for [tweetfeed.live](https://tweetfeed.live).**

Exposes the public IOC feed (URLs, domains, IPs, SHA256/MD5 hashes shared by the
infosec community on Twitter/X) as MCP tools so AI agents can query threat
intel programmatically.

- **Endpoint**: `https://mcp.tweetfeed.live/` (HTTP JSON-RPC 2.0, POST)
- **Protocol version**: 2025-11-25 (negotiated; older clients fall back automatically)
- **Auth**: none (all IOC data is CC0)
- **License (data)**: CC0-1.0 · **License (code)**: MIT

## Tools

| Name | Purpose |
|---|---|
| `query_iocs` | Query IOCs by time window (today/week/month) with optional user, tag, and type filters. |
| `check_url` | Check whether a specific URL appears in the feed. |
| `check_ip` | Check whether an IPv4/IPv6 address appears in the feed. |
| `check_hash` | Check whether an MD5 or SHA-256 hash appears in the feed (type auto-detected). |
| `list_recent_iocs` | List IOCs added since a given date, with optional type/tag filters. |
| `get_tag_info` | Window aggregates plus recent IOCs for a tag (leading `#` optional). |
| `get_trending` | Top tags and IOC-type distribution for a window (today/week/month/year). |
| `enrich_ioc` | Auto-detect an IOC's type (url/domain/ip/md5/sha256) and look it up over the past 30 days. |
| `get_campaigns` | AI-clustered campaign groupings from the last 7 days, with optional brand and min-confidence filters. |

## Use with Claude Desktop / Claude.ai / other MCP clients

```json
{
  "mcpServers": {
    "tweetfeed": {
      "url": "https://mcp.tweetfeed.live/"
    }
  }
}
```

Or from the Claude Code CLI:

```bash
claude mcp add tweetfeed https://mcp.tweetfeed.live/
```

## Quick test

```bash
curl -sX POST https://mcp.tweetfeed.live/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq .

# Example tool call:
curl -sX POST https://mcp.tweetfeed.live/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,
       "params":{"name":"query_iocs",
                 "arguments":{"time":"today","tag":"phishing","type":"url","limit":5}}}' | jq .
```

## Develop

```bash
npm install
npm run dev          # wrangler dev on http://localhost:8787
MCP_URL=http://localhost:8787 npm test
```

## Deploy

```bash
npm run deploy       # wrangler deploy (routes mcp.tweetfeed.live/*)
MCP_URL=https://mcp.tweetfeed.live npm test
```
