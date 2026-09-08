import { createMcpHandler } from "agents/mcp/server";
import { authenticateAccess, subjectHash } from "./auth";
import { createPlaneMcpServer } from "./mcp";
import { PlaneClient } from "./plane";
import { handlePatApi, setupPage } from "./setup";
import { loadPat } from "./storage";
import type { AccessIdentity, Env, Fetcher } from "./types";

type Authenticator = (request: Request, env: Env) => Promise<AccessIdentity>;

const SECURITY_HEADERS = {
	"Cache-Control": "no-store",
	"Referrer-Policy": "no-referrer",
	"X-Content-Type-Options": "nosniff",
};

function jsonError(error: string, status: number): Response {
	return Response.json(
		{ error },
		{
			status,
			headers: { ...SECURITY_HEADERS, "Content-Type": "application/json" },
		},
	);
}

function validHost(request: Request, env: Env): boolean {
	const hostname = new URL(request.url).hostname.toLowerCase();
	return hostname === env.MCP_HOSTNAME.toLowerCase();
}

export function createWorker(
	options: { authenticate?: Authenticator; fetcher?: Fetcher } = {},
): ExportedHandler<Env> {
	const authenticate = options.authenticate ?? authenticateAccess;
	const fetcher =
		options.fetcher ?? ((input, init) => globalThis.fetch(input, init));

	return {
		async fetch(request, env, executionContext) {
			if (!validHost(request, env)) return jsonError("invalid host", 400);
			const path = new URL(request.url).pathname;
			if (path !== "/mcp" && path !== "/mcp/setup" && path !== "/mcp/api/pat") {
				return jsonError("not found", 404);
			}

			let identity: AccessIdentity;
			try {
				identity = await authenticate(request, env);
			} catch {
				return jsonError("unauthorized", 401);
			}

			if (path === "/mcp/setup") {
				if (request.method !== "GET") {
					return new Response(null, { status: 405, headers: { Allow: "GET" } });
				}
				return setupPage();
			}
			if (path === "/mcp/api/pat") {
				return handlePatApi(request, env, identity, fetcher);
			}

			const record = await loadPat(env.PAT_KV, identity.sub);
			if (!record || record.email !== identity.email) {
				return jsonError("plane PAT is not configured; open /mcp/setup", 428);
			}
			const hashedSubject = await subjectHash(identity.sub, env.LOG_HASH_KEY);
			const client = new PlaneClient(env, record.pat, fetcher);
			const handler = createMcpHandler(
				() => createPlaneMcpServer(client, hashedSubject),
				{
					route: "/mcp",
					allowedHostnames: [env.MCP_HOSTNAME],
					allowedOriginHostnames: [env.MCP_HOSTNAME],
					legacy: "stateless",
				},
			);
			const response = await handler(request, env, executionContext);
			const headers = new Headers(response.headers);
			for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
				headers.set(name, value);
			}
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers,
			});
		},
	};
}

export default createWorker();
