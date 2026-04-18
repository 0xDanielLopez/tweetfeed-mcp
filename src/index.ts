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
						"Optional: filter by tag, case-insensitive substring match. Examples: 'phishing', 'cobaltstrike', 'ransomware', 'APT', 'Lockbit'. ~119 tags exist — see https://tweetfeed.live/ for the live taxonomy.",
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
] as const;

// ── Tool implementations ───────────────────────────────────────────────────
async function callTool(env: Env, name: string, args: Record<string, unknown>) {
	if (name === "query_iocs") return await toolQueryIocs(env, args);
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
				headers: { "Cache-Control": "public, max-age=300" },
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
