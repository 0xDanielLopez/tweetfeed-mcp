#!/usr/bin/env node
// tweetfeed-mcp integration tests.
// Usage: MCP_URL=https://mcp.tweetfeed.live node test/test.mjs
//        (or MCP_URL=http://localhost:8787 for local dev)

const URL_ENDPOINT = process.env.MCP_URL || "http://localhost:8787";

let passed = 0;
let failed = 0;
const failures = [];

async function rpc(method, params, id = 1) {
	const body = { jsonrpc: "2.0", method, params, id };
	const r = await fetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	return { status: r.status, body: await r.json(), headers: Object.fromEntries(r.headers) };
}

function assert(cond, msg) {
	if (!cond) throw new Error(msg);
}

async function test(name, fn) {
	try {
		await fn();
		console.log(`  ✓ ${name}`);
		passed++;
	} catch (e) {
		console.log(`  ✗ ${name}\n      ${e.message}`);
		failed++;
		failures.push({ name, error: e.message });
	}
}

console.log(`\nTarget: ${URL_ENDPOINT}\n`);

console.log("## Protocol handshake");

await test("initialize returns server info + protocol version + tools capability", async () => {
	const r = await rpc("initialize", {
		protocolVersion: "2025-03-26",
		capabilities: {},
		clientInfo: { name: "tweetfeed-mcp-test", version: "1" },
	});
	assert(r.status === 200, `HTTP ${r.status}`);
	assert(r.body.jsonrpc === "2.0", "missing jsonrpc version");
	assert(r.body.id === 1, `wrong id: ${r.body.id}`);
	assert(r.body.result, `no result: ${JSON.stringify(r.body.error)}`);
	assert(r.body.result.serverInfo?.name === "tweetfeed-mcp", "wrong server name");
	assert(r.body.result.protocolVersion === "2025-03-26", "wrong protocol version");
	assert(r.body.result.capabilities?.tools !== undefined, "missing tools capability");
});

await test("ping returns empty result", async () => {
	const r = await rpc("ping", {});
	assert(r.body.result !== undefined, "no result");
	assert(!r.body.error, `unexpected error: ${JSON.stringify(r.body.error)}`);
});

console.log("\n## Tool discovery");

await test("tools/list includes all 5 tools", async () => {
	const r = await rpc("tools/list", {});
	assert(r.body.result?.tools, "no tools");
	const names = r.body.result.tools.map((t) => t.name);
	for (const expected of ["query_iocs", "check_url", "check_ip", "check_hash", "list_recent_iocs"]) {
		assert(names.includes(expected), `missing ${expected}: ${names}`);
	}
});

await test("each tool has inputSchema + description", async () => {
	const r = await rpc("tools/list", {});
	for (const tool of r.body.result.tools) {
		assert(tool.description?.length > 10, `${tool.name} missing description`);
		assert(tool.inputSchema?.type === "object", `${tool.name} missing object schema`);
	}
});

console.log("\n## query_iocs");

await test("query_iocs with just time=today returns IOCs", async () => {
	const r = await rpc("tools/call", {
		name: "query_iocs",
		arguments: { time: "today", limit: 5 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0]?.text ?? "";
	assert(text.length > 20, `short response: ${text.substring(0, 100)}`);
});

await test("query_iocs with tag+type filter", async () => {
	const r = await rpc("tools/call", {
		name: "query_iocs",
		arguments: { time: "week", tag: "phishing", type: "url", limit: 3 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
});

await test("query_iocs rejects invalid time", async () => {
	const r = await rpc("tools/call", {
		name: "query_iocs",
		arguments: { time: "decade" },
	});
	assert(r.body.error, `expected error, got: ${JSON.stringify(r.body)}`);
	assert(r.body.error.code === -32602, `wrong error code: ${r.body.error.code}`);
});

await test("query_iocs rejects invalid type", async () => {
	const r = await rpc("tools/call", {
		name: "query_iocs",
		arguments: { time: "today", type: "dwarf" },
	});
	assert(r.body.error, `expected error, got: ${JSON.stringify(r.body)}`);
});

console.log("\n## check_url");

await test("check_url with common substring returns matches", async () => {
	const r = await rpc("tools/call", {
		name: "check_url",
		arguments: { url: ".com" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0]?.text ?? "";
	// ".com" is so common that "Found N URL match(es)" should appear.
	assert(text.includes("Found"), `expected matches, got: ${text.substring(0, 200)}`);
});

await test("check_url with unlikely substring returns NOT found", async () => {
	const r = await rpc("tools/call", {
		name: "check_url",
		arguments: { url: "definitely-not-a-real-string-xyz-9999" },
	});
	const text = r.body.result.content[0]?.text ?? "";
	assert(text.includes("NOT found"), `expected NOT found: ${text}`);
});

await test("check_url rejects empty string", async () => {
	const r = await rpc("tools/call", {
		name: "check_url",
		arguments: { url: "" },
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS, got: ${JSON.stringify(r.body)}`);
});

console.log("\n## check_ip");

await test("check_ip with substring '.' returns matches", async () => {
	const r = await rpc("tools/call", {
		name: "check_ip",
		arguments: { ip: "." },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0]?.text ?? "";
	// "." matches every IPv4; should always have results in a healthy month.
	assert(text.includes("Found"), `expected matches, got: ${text.substring(0, 200)}`);
});

await test("check_ip rejects empty string", async () => {
	const r = await rpc("tools/call", {
		name: "check_ip",
		arguments: { ip: "" },
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS`);
});

console.log("\n## check_hash");

await test("check_hash valid md5 length runs (likely NOT found)", async () => {
	const r = await rpc("tools/call", {
		name: "check_hash",
		arguments: { hash: "d41d8cd98f00b204e9800998ecf8427e" }, // empty-string MD5
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	// Empty-string MD5 is too generic, almost certainly NOT in the wild feed.
});

await test("check_hash valid sha256 length runs", async () => {
	const r = await rpc("tools/call", {
		name: "check_hash",
		arguments: { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
});

await test("check_hash rejects non-hex chars", async () => {
	const r = await rpc("tools/call", {
		name: "check_hash",
		arguments: { hash: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" },
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS`);
});

await test("check_hash rejects wrong-length hex", async () => {
	const r = await rpc("tools/call", {
		name: "check_hash",
		arguments: { hash: "abcdef0123456789" }, // 16 hex, neither MD5 nor SHA-256
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS`);
});

console.log("\n## list_recent_iocs");

await test("list_recent_iocs with recent since returns IOCs", async () => {
	const since = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString().slice(0, 10);
	const r = await rpc("tools/call", {
		name: "list_recent_iocs",
		arguments: { since, limit: 5 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0]?.text ?? "";
	// Healthy feed: 3 days back should always have IOCs.
	assert(text.includes("match"), `expected matches, got: ${text.substring(0, 200)}`);
});

await test("list_recent_iocs rejects malformed date", async () => {
	const r = await rpc("tools/call", {
		name: "list_recent_iocs",
		arguments: { since: "not-a-date" },
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS`);
});

await test("list_recent_iocs rejects calendar-impossible date", async () => {
	const r = await rpc("tools/call", {
		name: "list_recent_iocs",
		arguments: { since: "2026-02-30" },
	});
	assert(r.body.error?.code === -32602, `expected INVALID_PARAMS`);
});

await test("list_recent_iocs accepts type filter", async () => {
	const since = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString().slice(0, 10);
	const r = await rpc("tools/call", {
		name: "list_recent_iocs",
		arguments: { since, type: "url", limit: 3 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
});

console.log("\n## Error handling");

await test("unknown method returns METHOD_NOT_FOUND", async () => {
	const r = await rpc("nonexistent/method", {});
	assert(r.body.error?.code === -32601, `wrong error: ${JSON.stringify(r.body.error)}`);
});

await test("unknown tool returns METHOD_NOT_FOUND via tools/call", async () => {
	const r = await rpc("tools/call", { name: "nonexistent_tool", arguments: {} });
	assert(r.body.error?.code === -32601, `wrong error: ${JSON.stringify(r.body.error)}`);
});

console.log("\n## HTTP surface");

await test("GET / returns human-readable JSON", async () => {
	const r = await fetch(URL_ENDPOINT, { method: "GET" });
	assert(r.status === 200, `HTTP ${r.status}`);
	const body = await r.json();
	assert(body.service === "tweetfeed-mcp", `wrong service: ${body.service}`);
	assert(body.tools?.length >= 1, `no tools in landing: ${JSON.stringify(body)}`);
});

// ── Summary ────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	console.log("\nFailures:");
	for (const f of failures) console.log(`  - ${f.name}: ${f.error}`);
	process.exit(1);
}
