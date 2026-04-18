# tweetfeed-mcp

**Model Context Protocol (MCP) server for [tweetfeed.live](https://tweetfeed.live).**

Exposes the public IOC feed (URLs, domains, IPs, SHA256/MD5 hashes shared by the
infosec community on Twitter/X) as MCP tools so AI agents can query threat
intel programmatically.

- **Endpoint**: `https://mcp.tweetfeed.live/` (HTTP JSON-RPC 2.0, POST)
- **Protocol version**: 2025-03-26
- **Auth**: none (all IOC data is CC0)
- **License (data)**: CC0-1.0 · **License (code)**: MIT

## Tools

| Name | Purpose |
|---|---|
| `query_iocs` | Query IOCs by time window (today/week/month) with optional user, tag, and type filters. |

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
