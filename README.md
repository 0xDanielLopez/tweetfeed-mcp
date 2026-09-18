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
| `enrich_ioc` | Exact lookup of an IOC (auto-detected type: url/domain/ip/md5/sha256) over the past 365 days, with AI/external-corroboration/net/domain-registration (reg, including the domain's age in days at first report and a `newly_registered` flag) context and campaign membership when available, plus an archive of history older than 365 days when it exists (can accompany a live match); falls back to a 30-day substring scan on a miss. |
| `get_campaigns` | AI-clustered campaign groupings from the last 30 days, with optional brand and min-confidence filters. |
| `get_campaign_iocs` | Full IOC membership (header + rows) of one campaign by id, with optional type filter and limit. |
| `get_trends` | 31-day IOC trend analytics: daily volume by type, top moving tags week-over-week, most-abused TLDs, new vs recurring ratio, producer concentration. |
| `get_feed_status` | Live pipeline health: freshness verdict per artifact (stale, age_seconds) and source coverage (which hashtag/account feeds delivered rows in the last 24h, which account feeds are dead). |
| `search` | ChatGPT connector interface: find document ids (`ioc:<value>`, `tag:<tag>`, `campaign:<tfc-id>`) for an IOC value, tag, campaign id or free text. |
| `fetch` | ChatGPT connector interface: full document (`{id, title, text, url, metadata}`) for an id returned by `search`. |

## Resources

Besides the 14 tools, the server exposes the feed as MCP resources (`resources/list`, `resources/templates/list`, `resources/read`): 7 static documents plus 2 URI templates, each returning the raw JSON of the matching api.tweetfeed.live document. Tools are the filtered, size-bounded path; resources are for clients that want a whole document (a status panel, a whole-window blocklist sync).

| URI | Content |
|---|---|
| `tweetfeed://status` | Pipeline health plus per-source coverage (mirrors `/v1/status`, ~13 KB, refreshed every 15 min). |
| `tweetfeed://counts` | Aggregate IOC counts per window/type/tag (mirrors `/v1/counts`, ~3 KB). |
| `tweetfeed://trends` | 31-day trend analytics (mirrors `/v1/trends`, ~4 KB, daily). |
| `tweetfeed://campaigns` | AI-clustered campaigns of the trailing 30 days (mirrors `/v1/campaigns`, ~300 KB, daily). |
| `tweetfeed://iocs/today` | Every IOC row shared today (mirrors `/v1/today`, 10-50 KB). |
| `tweetfeed://iocs/week` | Last 7 days (mirrors `/v1/week`, 100-300 KB). |
| `tweetfeed://iocs/month` | Last 30 days (mirrors `/v1/month`, 0.5-1 MB, API caps at 10,000 rows). |
| `tweetfeed://iocs/{time}/{type}` | Template - time: today\|week\|month, type: url\|domain\|ip\|sha256\|md5 (mirrors `/v1/{time}/{type}`). |
| `tweetfeed://campaigns/{id}` | Template - id = `tfc-` plus 12 hex chars (mirrors `/v1/campaigns/{id}`). |

An unknown URI or an expired campaign id returns JSON-RPC error -32002 "Resource not found".

## Prompts

Besides the 14 tools and the resources above, the server also speaks MCP prompts (`prompts/list`, `prompts/get`, params `name` and `arguments` as strings): ready-made recipes that chain several tool calls into one instruction sequence for the model to run and report back on. Where tools are chosen by the model and resources are raw documents, prompts are recipes the user invokes directly - they show up as slash commands in Claude Desktop and Claude Code.

| Name | Arguments | Purpose |
|---|---|---|
| `triage_ioc` | `ioc` (required), `context` (optional) | Step-by-step triage of one IOC (URL/domain/IP/MD5/SHA-256): enrichment, campaign membership, verdict and recommended action. |
| `daily_brief` | `window` (optional, `today` default \| `week`) | Short brief: feed health, volume and mix, moving tags, active high-confidence campaigns, abused TLDs. |
| `campaign_summary` | `campaign_id` (required, `tfc-` plus 12 hex) | Hand-off summary of one campaign: context, targeting, ATT&CK techniques, IOC breakdown, infrastructure, block-ready lists, CSV/STIX links. |

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

## Use as a ChatGPT connector

ChatGPT (Settings > Connectors > Create, or a Deep research custom connector)
accepts `https://mcp.tweetfeed.live/` with no authentication. The server
exposes the required `search` and `fetch` tools alongside the others, and
every result carries a tweetfeed.live URL so ChatGPT can cite it.

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

# Example resource read:
curl -sX POST https://mcp.tweetfeed.live/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"resources/read","id":3,
       "params":{"uri":"tweetfeed://status"}}' | jq .

# Example prompt call:
curl -sX POST https://mcp.tweetfeed.live/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"prompts/get","id":4,
       "params":{"name":"triage_ioc","arguments":{"ioc":"example.com"}}}' | jq .
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
