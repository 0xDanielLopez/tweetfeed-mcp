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

await test("tools/list includes query_iocs", async () => {
	const r = await rpc("tools/list", {});
	assert(r.body.result?.tools, "no tools");
	const names = r.body.result.tools.map((t) => t.name);
	assert(names.includes("query_iocs"), `missing query_iocs: ${names}`);
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
