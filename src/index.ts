// tweetfeed MCP server — wraps the public TweetFeed API as MCP tools.
//
// Protocol: Model Context Protocol over HTTP (JSON-RPC 2.0, single-shot).
// Spec: https://spec.modelcontextprotocol.io/specification/2025-03-26/
// Deploy: wrangler deploy — routes mcp.tweetfeed.live/*
//
// Read-only. No auth. IOC data is CC0 per tweetfeed.live TOS.

// Virtual host used in requests dispatched through the API service binding.
// The tweetfeed-api Worker is bound as env.API; we craft Request objects with
// this origin so the handler's URL parsing matches its production routes.
const API_BASE = "https://api.tweetfeed.live";
const UA = "tweetfeed-mcp/0.1";

interface Env {
	API: Fetcher;
}
const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "tweetfeed-mcp", version: "0.1.0" };

const VALID_TIMES = new Set(["today", "week", "month"]);
const VALID_TYPES = new Set(["url", "domain", "ip", "sha256", "md5"]);

// ── JSON-RPC types ─────────────────────────────────────────────────────────
type RpcRequest = {
	jsonrpc: "2.0";
	method: string;
	params?: Record<string, unknown>;
	id?: string | number | null;
};

type RpcResponse = {
	jsonrpc: "2.0";
	id: string | number | null;
	result?: unknown;
	error?: { code: number; message: string; data?: unknown };
};

const ERR = {
	PARSE: -32700,
	INVALID_REQUEST: -32600,
	METHOD_NOT_FOUND: -32601,
	INVALID_PARAMS: -32602,
	INTERNAL: -32603,
};

// ── Tool definitions ───────────────────────────────────────────────────────
const TOOLS = [
	{
		name: "query_iocs",
		description:
			"Query the TweetFeed API for Indicators of Compromise (IOCs: URLs, domains, IPs, MD5/SHA256 hashes) shared by the infosec community on Twitter/X. Returns matching rows with date, researcher handle, type, value, tags, and tweet URL. All data CC0 licensed. The 'year' time window is not supported here (too large for a tool response) - use the /v1/year HTTP redirect directly if you need it.",
		inputSchema: {
			type: "object",
			properties: {
				time: {
					type: "string",
					enum: ["today", "week", "month"],
					description:
						"Time window. 'today' = since UTC midnight, 'week' = last 7 days, 'month' = last 30 days.",
				},
				user: {
					type: "string",
					description:
						"Optional: filter by Twitter/X handle WITHOUT the @ prefix (e.g. 'malwrhunterteam', 'JCyberSec_').",
				},
				tag: {
					type: "string",
					description:
						"Optional: filter by tag, case-insensitive substring match. Examples: 'phishing', 'cobaltstrike', 'ransomware', 'APT', 'Lockbit'. ~122 tags exist — see https://tweetfeed.live/ for the live taxonomy.",
				},
				type: {
					type: "string",
					enum: ["url", "domain", "ip", "sha256", "md5"],
					description: "Optional: filter by IOC type.",
				},
				limit: {
					type: "number",
					description: "Optional: max rows to return (1-1000). Default 100.",
					default: 100,
				},
			},
			required: ["time"],
		},
	},
	{
		name: "check_url",
		description:
			"Check whether a URL (or substring) appears in the TweetFeed corpus over the past 30 days. Useful for confirming if an observed URL has been flagged by the public infosec Twitter/X community. Case-insensitive substring match against the 'value' field of type=url IOCs. Returns matching rows with date, researcher handle, value, tags, and source tweet URL.",
		inputSchema: {
			type: "object",
			properties: {
				url: {
					type: "string",
					description:
						"URL or URL substring to search (e.g. 'fake-bank.com/login', 'phish-domain.tld'). Case-insensitive.",
				},
			},
			required: ["url"],
		},
	},
	{
		name: "check_ip",
		description:
			"Check whether an IP address appears in the TweetFeed corpus over the past 30 days. Useful for confirming if an observed IP has been flagged as attacker infrastructure (C2, scanner, phishing host) by the public infosec Twitter/X community. Substring match against the 'value' field of type=ip IOCs (so '1.2.3' will also match '1.2.3.4'). Pass a full IPv4 / IPv6 string for an exact-match feel.",
		inputSchema: {
			type: "object",
			properties: {
				ip: {
					type: "string",
					description: "IPv4 or IPv6 address to search (e.g. '185.107.56.42', '2a02:...').",
				},
			},
			required: ["ip"],
		},
	},
	{
		name: "check_hash",
		description:
			"Check whether a file hash (MD5 or SHA-256) appears in the TweetFeed corpus over the past 30 days. Useful for confirming if a binary sample has been shared by the public infosec Twitter/X community. Hash type auto-detected from length (32 hex = MD5, 64 hex = SHA-256). Exact match on hex value, case-insensitive.",
		inputSchema: {
			type: "object",
			properties: {
				hash: {
					type: "string",
					description:
						"MD5 (32 hex chars) or SHA-256 (64 hex chars) hash. Case-insensitive. Non-hex characters or wrong length will return an INVALID_PARAMS error.",
				},
			},
			required: ["hash"],
		},
	},
	{
		name: "list_recent_iocs",
		description:
			"List TweetFeed IOCs added since a given date, useful for delta-syncing a blocklist or threat-intel pipeline. Source is the 30-day month window so 'since' must be within the past 30 days; older queries return only the part within the month window. Optional 'type' and 'tag' filters narrow the result. Sorted newest first.",
		inputSchema: {
			type: "object",
			properties: {
				since: {
					type: "string",
					description: "ISO date (YYYY-MM-DD) for the lower bound. Example: '2026-04-15'.",
				},
				limit: {
					type: "number",
					description: "Max results (1-1000). Default 100.",
					default: 100,
				},
				type: {
					type: "string",
					enum: ["url", "domain", "ip", "sha256", "md5"],
					description: "Optional: filter by IOC type.",
				},
				tag: {
					type: "string",
					description: "Optional: filter by tag (case-insensitive substring match on the tag list).",
				},
			},
			required: ["since"],
		},
	},
] as const;

// ── Tool implementations ───────────────────────────────────────────────────
async function callTool(env: Env, name: string, args: Record<string, unknown>) {
	if (name === "query_iocs") return await toolQueryIocs(env, args);
	if (name === "check_url") return await toolCheckUrl(env, args);
	if (name === "check_ip") return await toolCheckIp(env, args);
	if (name === "check_hash") return await toolCheckHash(env, args);
	if (name === "list_recent_iocs") return await toolListRecent(env, args);
	throw { code: ERR.METHOD_NOT_FOUND, message: `Unknown tool: ${name}` };
}

async function toolQueryIocs(env: Env, args: Record<string, unknown>) {
	const time = String(args.time ?? "").trim().toLowerCase();
	if (!VALID_TIMES.has(time)) {
		throw {
			code: ERR.INVALID_PARAMS,
			message: `'time' must be one of: today, week, month (got: '${time}')`,
		};
	}
	const limit = clampInt(args.limit, 1, 1000, 100);

	const userRaw = args.user ? String(args.user).trim() : "";
	const tag = args.tag ? String(args.tag).trim() : "";
	const typeArg = args.type ? String(args.type).trim().toLowerCase() : "";

	if (typeArg && !VALID_TYPES.has(typeArg)) {
		throw {
			code: ERR.INVALID_PARAMS,
			message: `'type' must be one of: url, domain, ip, sha256, md5 (got: '${typeArg}')`,
		};
	}

	// API supports up to 2 filters in the URL; if caller supplies 3, pass the
	// strongest two to the API and apply the third client-side below.
	// Priority: type (cheapest server-side) > user > tag.
	const apiFilters: string[] = [];
	let clientFilterTag = "";
	let clientFilterUser = "";
	const userParam = userRaw ? (userRaw.startsWith("@") ? userRaw : "@" + userRaw) : "";

	if (typeArg) apiFilters.push(typeArg);
	if (userParam) {
		if (apiFilters.length < 2) apiFilters.push(userParam);
		else clientFilterUser = userParam.slice(1).toLowerCase();
	}
	if (tag) {
		if (apiFilters.length < 2) apiFilters.push(tag);
		else clientFilterTag = tag.toLowerCase();
	}

	const pathSuffix = apiFilters.length > 0 ? "/" + apiFilters.map(encodeURIComponent).join("/") : "";
	const url = `${API_BASE}/v1/${time}${pathSuffix}`;

	const r = await env.API.fetch(new Request(url, { headers: { "User-Agent": UA } }));
	if (!r.ok) {
		throw { code: ERR.INTERNAL, message: `tweetfeed API returned HTTP ${r.status} for ${url}` };
	}
	let rows = (await r.json()) as Array<Record<string, unknown>>;

	if (clientFilterUser) {
		rows = rows.filter(
			(row) => typeof row.user === "string" && row.user.toLowerCase() === clientFilterUser,
		);
	}
	if (clientFilterTag) {
		rows = rows.filter((row) => {
			const tags = row.tags;
			if (Array.isArray(tags)) {
				return tags.some((t) => typeof t === "string" && t.toLowerCase().includes(clientFilterTag));
			}
			return false;
		});
	}

	const total = rows.length;
	const out = rows.slice(0, limit);

	if (total === 0) {
		const filterDesc = describeFilters(time, userRaw, tag, typeArg);
		return textContent(`No IOCs found for ${filterDesc}.`);
	}

	return textContent(
		`${total} IOC(s) matched ${describeFilters(time, userRaw, tag, typeArg)}${total > limit ? ` (showing first ${limit})` : ""}:\n\n` +
			JSON.stringify(out, null, 2),
	);
}

function describeFilters(time: string, user: string, tag: string, type: string): string {
	const parts = [`time=${time}`];
	if (user) parts.push(`user=@${user.replace(/^@/, "")}`);
	if (tag) parts.push(`tag=${tag}`);
	if (type) parts.push(`type=${type}`);
	return parts.join(", ");
}

// Fetch the past 30 days of IOCs of a given type via the API service binding.
async function fetchMonthByType(env: Env, type: string): Promise<Array<Record<string, unknown>>> {
	const url = `${API_BASE}/v1/month/${encodeURIComponent(type)}`;
	const r = await env.API.fetch(new Request(url, { headers: { "User-Agent": UA } }));
	if (!r.ok) {
		throw { code: ERR.INTERNAL, message: `tweetfeed API returned HTTP ${r.status} for ${url}` };
	}
	return (await r.json()) as Array<Record<string, unknown>>;
}

async function toolCheckUrl(env: Env, args: Record<string, unknown>) {
	const needle = String(args.url ?? "").trim().toLowerCase();
	if (!needle) throw { code: ERR.INVALID_PARAMS, message: "'url' is required" };

	const rows = await fetchMonthByType(env, "url");
	const matches = rows.filter(
		(row) => typeof row.value === "string" && row.value.toLowerCase().includes(needle),
	);
	if (matches.length === 0) {
		return textContent(
			`URL containing "${needle}" NOT found in the last 30 days of TweetFeed (${rows.length} URL IOCs scanned).`,
		);
	}
	const preview = matches.slice(0, 50);
	return textContent(
		`Found ${matches.length} URL match(es) for "${needle}" in the last 30 days of TweetFeed${matches.length > preview.length ? ` (showing first ${preview.length})` : ""}:\n\n` +
			JSON.stringify(preview, null, 2),
	);
}

async function toolCheckIp(env: Env, args: Record<string, unknown>) {
	const needle = String(args.ip ?? "").trim().toLowerCase();
	if (!needle) throw { code: ERR.INVALID_PARAMS, message: "'ip' is required" };

	const rows = await fetchMonthByType(env, "ip");
	const matches = rows.filter(
		(row) => typeof row.value === "string" && row.value.toLowerCase().includes(needle),
	);
	if (matches.length === 0) {
		return textContent(
			`IP "${needle}" NOT found in the last 30 days of TweetFeed (${rows.length} IP IOCs scanned).`,
		);
	}
	const preview = matches.slice(0, 50);
	return textContent(
		`Found ${matches.length} IP match(es) for "${needle}" in the last 30 days of TweetFeed${matches.length > preview.length ? ` (showing first ${preview.length})` : ""}:\n\n` +
			JSON.stringify(preview, null, 2),
	);
}

async function toolCheckHash(env: Env, args: Record<string, unknown>) {
	const raw = String(args.hash ?? "").trim().toLowerCase();
	if (!raw) throw { code: ERR.INVALID_PARAMS, message: "'hash' is required" };
	if (!/^[a-f0-9]+$/.test(raw)) {
		throw { code: ERR.INVALID_PARAMS, message: "'hash' must be hex (a-f, 0-9 only)" };
	}
	let hashType: "md5" | "sha256";
	if (raw.length === 32) hashType = "md5";
	else if (raw.length === 64) hashType = "sha256";
	else {
		throw {
			code: ERR.INVALID_PARAMS,
			message: `'hash' must be 32 hex chars (MD5) or 64 hex chars (SHA-256); got length ${raw.length}`,
		};
	}

	const rows = await fetchMonthByType(env, hashType);
	const matches = rows.filter(
		(row) => typeof row.value === "string" && row.value.toLowerCase() === raw,
	);
	if (matches.length === 0) {
		return textContent(
			`${hashType.toUpperCase()} hash "${raw}" NOT found in the last 30 days of TweetFeed (${rows.length} ${hashType.toUpperCase()} IOCs scanned).`,
		);
	}
	return textContent(
		`Found ${matches.length} match(es) for ${hashType.toUpperCase()} hash "${raw}" in the last 30 days of TweetFeed:\n\n` +
			JSON.stringify(matches, null, 2),
	);
}

async function toolListRecent(env: Env, args: Record<string, unknown>) {
	const since = String(args.since ?? "").trim();
	// Round-trip through Date so calendar-impossible dates ("2026-02-30") fail
	// loud here instead of silently slipping through to the filter.
	if (
		!since ||
		!/^\d{4}-\d{2}-\d{2}$/.test(since) ||
		!Number.isFinite(new Date(since + "T00:00:00Z").getTime()) ||
		new Date(since + "T00:00:00Z").toISOString().slice(0, 10) !== since
	) {
		throw { code: ERR.INVALID_PARAMS, message: "'since' must be a valid ISO date (YYYY-MM-DD)" };
	}
	const limit = clampInt(args.limit, 1, 1000, 100);
	const typeArg = args.type ? String(args.type).trim().toLowerCase() : "";
	if (typeArg && !VALID_TYPES.has(typeArg)) {
		throw {
			code: ERR.INVALID_PARAMS,
			message: `'type' must be one of: url, domain, ip, sha256, md5 (got: '${typeArg}')`,
		};
	}
	const tag = args.tag ? String(args.tag).trim() : "";

	// Fetch the month window then filter client-side. Priority for which filter
	// goes server-side mirrors query_iocs: type cheapest, then tag.
	const apiFilters: string[] = [];
	let clientFilterTag = "";
	if (typeArg) apiFilters.push(typeArg);
	if (tag) {
		if (apiFilters.length < 2) apiFilters.push(tag);
		else clientFilterTag = tag.toLowerCase();
	}
	const pathSuffix = apiFilters.length > 0 ? "/" + apiFilters.map(encodeURIComponent).join("/") : "";
	const url = `${API_BASE}/v1/month${pathSuffix}`;
	const r = await env.API.fetch(new Request(url, { headers: { "User-Agent": UA } }));
	if (!r.ok) {
		throw { code: ERR.INTERNAL, message: `tweetfeed API returned HTTP ${r.status} for ${url}` };
	}
	let rows = (await r.json()) as Array<Record<string, unknown>>;

	if (clientFilterTag) {
		rows = rows.filter((row) => {
			const tags = row.tags;
			if (Array.isArray(tags)) {
				return tags.some((t) => typeof t === "string" && t.toLowerCase().includes(clientFilterTag));
			}
			return false;
		});
	}

	// Filter by date >= since. Backend dates are "YYYY-MM-DD HH:MM:SS" UTC strings.
	rows = rows.filter((row) => typeof row.date === "string" && row.date.slice(0, 10) >= since);
	rows.sort((a, b) =>
		String(b.date ?? "").localeCompare(String(a.date ?? "")),
	);

	const total = rows.length;
	const out = rows.slice(0, limit);

	const filterDesc = `since=${since}` + (typeArg ? `, type=${typeArg}` : "") + (tag ? `, tag=${tag}` : "");
	if (total === 0) {
		return textContent(`No IOCs in the past 30 days match ${filterDesc}.`);
	}
	return textContent(
		`${total} IOC(s) match ${filterDesc}${total > limit ? ` (showing first ${limit})` : ""}:\n\n` +
			JSON.stringify(out, null, 2),
	);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function textContent(text: string) {
	return { content: [{ type: "text", text }] };
}

function clampInt(v: unknown, min: number, max: number, dflt: number): number {
	const n = Number(v);
	if (!Number.isFinite(n)) return dflt;
	return Math.min(max, Math.max(min, Math.floor(n)));
}

// ── JSON-RPC dispatcher ────────────────────────────────────────────────────
async function handleRpc(env: Env, req: RpcRequest): Promise<RpcResponse> {
	const id = req.id ?? null;

	try {
		if (req.method === "initialize") {
			return {
				jsonrpc: "2.0",
				id,
				result: {
					protocolVersion: PROTOCOL_VERSION,
					capabilities: { tools: {} },
					serverInfo: SERVER_INFO,
					instructions:
						"Query the tweetfeed.live public IOC feed (URLs, domains, IPs, SHA256/MD5 hashes from the infosec Twitter/X community). Data is CC0, read-only, updated every 15 min. Use query_iocs with a required 'time' window (today|week|month) and optional 'user'/'tag'/'type' filters.",
				},
			};
		}

		if (req.method === "ping") {
			return { jsonrpc: "2.0", id, result: {} };
		}

		if (req.method === "notifications/initialized") {
			return { jsonrpc: "2.0", id, result: {} };
		}

		if (req.method === "tools/list") {
			return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
		}

		if (req.method === "tools/call") {
			const params = (req.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
			if (!params.name) {
				return {
					jsonrpc: "2.0",
					id,
					error: { code: ERR.INVALID_PARAMS, message: "'name' is required" },
				};
			}
			const result = await callTool(env, params.name, params.arguments ?? {});
			return { jsonrpc: "2.0", id, result };
		}

		return {
			jsonrpc: "2.0",
			id,
			error: { code: ERR.METHOD_NOT_FOUND, message: `Method not found: ${req.method}` },
		};
	} catch (e: unknown) {
		if (e && typeof e === "object" && "code" in e && "message" in e) {
			return { jsonrpc: "2.0", id, error: e as { code: number; message: string } };
		}
		return {
			jsonrpc: "2.0",
			id,
			error: {
				code: ERR.INTERNAL,
				message: e instanceof Error ? e.message : "Internal error",
			},
		};
	}
}

// ── HTTP entrypoint ────────────────────────────────────────────────────────
export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type",
					"Access-Control-Max-Age": "86400",
				},
			});
		}

		if (request.method === "GET") {
			const body = {
				service: "tweetfeed-mcp",
				protocol: "Model Context Protocol (MCP)",
				protocolVersion: PROTOCOL_VERSION,
				transport: "HTTP JSON-RPC 2.0 (POST)",
				endpoint: `${url.origin}/`,
				tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
				docs: "https://tweetfeed.live/api.html",
				license: "CC0-1.0 (IOC data)",
				source: "https://github.com/0xDanielLopez/tweetfeed-mcp",
			};
			return Response.json(body, {
				headers: {
					"Cache-Control": "public, max-age=300",
					"Access-Control-Allow-Origin": "*",
				},
			});
		}

		if (request.method !== "POST") {
			return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST" } });
		}

		let req: RpcRequest | RpcRequest[];
		try {
			req = (await request.json()) as RpcRequest | RpcRequest[];
		} catch {
			return Response.json(
				{ jsonrpc: "2.0", id: null, error: { code: ERR.PARSE, message: "Parse error" } },
				{ status: 400 },
			);
		}

		if (Array.isArray(req)) {
			const out = await Promise.all(req.map((r) => handleRpc(env, r)));
			return Response.json(out);
		}

		const response = await handleRpc(env, req);
		return Response.json(response, {
			headers: {
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type",
			},
		});
	},
};
