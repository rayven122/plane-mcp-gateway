import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { authenticateAccess, identityFromPayload } from "../src/auth";
import { PlaneClient, verifyPat } from "../src/plane";
import { createWorker } from "../src/server";
import { setupPage } from "../src/setup";
import type { AccessIdentity, Env, PatRecord } from "../src/types";

const SENTINEL_PAT = "RAYVEN_SENTINEL_PAT_MUST_NOT_LEAK_7d92";

class MemoryKv {
	readonly values = new Map<string, string>();

	async get<T>(key: string, type?: string): Promise<T | string | null> {
		const value = this.values.get(key);
		if (value === undefined) return null;
		return type === "json" ? (JSON.parse(value) as T) : value;
	}

	async put(key: string, value: string): Promise<void> {
		this.values.set(key, value);
	}

	async delete(key: string): Promise<void> {
		this.values.delete(key);
	}
}

function env(kv = new MemoryKv()): Env {
	return {
		PAT_KV: kv as unknown as KVNamespace,
		ACCESS_TEAM_DOMAIN: "https://rayven122.cloudflareaccess.com",
		ACCESS_AUD: "expected-audience",
		PLANE_ORIGIN: "https://tasks.rayven.cloud",
		PLANE_WORKSPACE: "rayven",
		PLANE_ACCESS_CLIENT_ID: "service-client-id",
		PLANE_ACCESS_CLIENT_SECRET: "service-client-secret",
		MCP_HOSTNAME: "tasks.rayven.cloud",
		LOG_HASH_KEY: "test-only-log-hash-key",
	};
}

function identity(
	sub = "access-user-a",
	email = "a@rayven.cloud",
): AccessIdentity {
	return { sub, email, expiresAt: Math.floor(Date.now() / 1000) + 300 };
}

function request(
	path: string,
	init: RequestInit = {},
	host = "tasks.rayven.cloud",
): Request<unknown, IncomingRequestCfProperties> {
	const headers = new Headers(init.headers);
	if (!headers.has("Host")) headers.set("Host", host);
	return new Request(`https://${host}${path}`, {
		...init,
		headers,
	}) as unknown as Request<unknown, IncomingRequestCfProperties>;
}

function planeFetcher(users: Record<string, { id: string; email: string }>) {
	return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input));
		const headers = new Headers(init?.headers);
		const pat = headers.get("X-API-Key") ?? "";
		const user = users[pat];
		if (!user)
			return Response.json({ detail: "credential rejected" }, { status: 401 });
		if (url.pathname === "/api/v1/users/me/") return Response.json(user);
		if (url.pathname === "/api/v1/workspaces/rayven/members/") {
			return Response.json({ results: [user] });
		}
		if (url.pathname === "/api/v1/workspaces/rayven/projects/") {
			return Response.json({ results: [{ id: "project-1", name: "Test" }] });
		}
		return Response.json({ detail: "not found" }, { status: 404 });
	});
}

async function putPat(
	worker: ExportedHandler<Env>,
	environment: Env,
	executionContext: ExecutionContext,
	pat: string,
): Promise<Response> {
	return invokeWorker(
		worker,
		request("/mcp/api/pat", {
			method: "PUT",
			headers: {
				"Content-Type": "application/json",
				Origin: "https://tasks.rayven.cloud",
			},
			body: JSON.stringify({ pat }),
		}),
		environment,
		executionContext,
	);
}

async function invokeWorker(
	worker: ExportedHandler<Env>,
	workerRequest: Request<unknown, IncomingRequestCfProperties>,
	environment: Env,
	executionContext: ExecutionContext,
): Promise<Response> {
	if (!worker.fetch) throw new Error("worker fetch handler is missing");
	return worker.fetch(workerRequest, environment, executionContext);
}

describe("Cloudflare Access authentication", () => {
	it("accepts only a valid RS256 token with exact issuer, audience, and domain", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256");
		const jwk = await exportJWK(publicKey);
		jwk.kid = "test-key";
		const resolver = createLocalJWKSet({ keys: [jwk] });
		const token = await new SignJWT({ email: "USER@rayven.cloud" })
			.setProtectedHeader({ alg: "RS256", kid: "test-key" })
			.setSubject("stable-subject")
			.setIssuer("https://rayven122.cloudflareaccess.com")
			.setAudience("expected-audience")
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(privateKey);
		const authenticated = await authenticateAccess(
			new Request("https://tasks.rayven.cloud/mcp", {
				headers: { "Cf-Access-Jwt-Assertion": token },
			}),
			env(),
			resolver,
		);
		expect(authenticated).toMatchObject({
			sub: "stable-subject",
			email: "user@rayven.cloud",
		});

		await expect(
			authenticateAccess(
				new Request("https://tasks.rayven.cloud/mcp", {
					headers: { "Cf-Access-Jwt-Assertion": token },
				}),
				{ ...env(), ACCESS_AUD: "wrong-audience" },
				resolver,
			),
		).rejects.toThrow();
		expect(() =>
			identityFromPayload({
				sub: "other",
				email: "user@example.com",
				exp: Math.floor(Date.now() / 1000) + 300,
			}),
		).toThrow("email domain");
	});

	it("fetches JWKS only from the fixed Access URL without redirects", async () => {
		const issuer = "https://test-rayven.cloudflareaccess.com";
		const { privateKey, publicKey } = await generateKeyPair("RS256");
		const jwk = await exportJWK(publicKey);
		jwk.kid = "remote-test-key";
		const token = await new SignJWT({ email: "user@rayven.cloud" })
			.setProtectedHeader({ alg: "RS256", kid: "remote-test-key" })
			.setSubject("remote-subject")
			.setIssuer(issuer)
			.setAudience("remote-audience")
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(privateKey);
		const fetchMock = vi.fn(async (_url: string, _init: RequestInit) =>
			Response.json({ keys: [jwk] }, { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		try {
			await authenticateAccess(
				new Request("https://tasks.rayven.cloud/mcp", {
					headers: { "Cf-Access-Jwt-Assertion": token },
				}),
				{ ACCESS_TEAM_DOMAIN: issuer, ACCESS_AUD: "remote-audience" },
			);
		} finally {
			vi.unstubAllGlobals();
		}
		const [url, init] = fetchMock.mock.calls[0] ?? [];
		expect(url).toBe(`${issuer}/cdn-cgi/access/certs`);
		expect(init?.redirect).toBe("manual");
	});
});

describe("Plane outbound boundary", () => {
	it("keeps hostile path content on the fixed host and never follows redirects", async () => {
		const fetcher = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(null, { status: 302 }),
		);
		const client = new PlaneClient(env(), "sentinel-pat-never-log", fetcher);
		await expect(
			client.request("GET", ["workspaces", "https://evil.example/steal"]),
		).rejects.toMatchObject({ status: 302 });
		const [target, init] = fetcher.mock.calls[0] ?? [];
		expect(new URL(String(target)).hostname).toBe("tasks.rayven.cloud");
		expect(new URL(String(target)).pathname).toContain(
			"https%3A%2F%2Fevil.example%2Fsteal",
		);
		expect(init?.redirect).toBe("manual");
	});

	it("rejects any configured Plane origin or workspace outside the fixed boundary", () => {
		expect(
			() =>
				new PlaneClient(
					{ ...env(), PLANE_ORIGIN: "https://evil.example" },
					"sentinel-pat",
				),
		).toThrow("Plane origin");
		expect(
			() =>
				new PlaneClient({ ...env(), PLANE_WORKSPACE: "other" }, "sentinel-pat"),
		).toThrow("workspace");
	});

	it("does not accept a PAT owned by another email", async () => {
		await expect(
			verifyPat(
				env(),
				"mismatch-pat",
				"access@rayven.cloud",
				planeFetcher({
					"mismatch-pat": { id: "plane-user", email: "other@rayven.cloud" },
				}),
			),
		).rejects.toMatchObject({ status: 403 });
	});
});

describe("per-user PAT API", () => {
	it("stores by Access sub, never returns the PAT, and isolates users", async () => {
		const kv = new MemoryKv();
		const environment = env(kv);
		let current = identity();
		const worker = createWorker({
			authenticate: async () => current,
			fetcher: planeFetcher({
				"sentinel-pat-user-a": { id: "plane-a", email: "a@rayven.cloud" },
				"sentinel-pat-user-b": { id: "plane-b", email: "b@rayven.cloud" },
			}),
		});
		const executionContext = {} as ExecutionContext;

		const savedA = await putPat(
			worker,
			environment,
			executionContext,
			"sentinel-pat-user-a",
		);
		expect(savedA.status).toBe(200);
		expect(await savedA.text()).not.toContain("sentinel-pat-user-a");

		current = identity("access-user-b", "b@rayven.cloud");
		const stateBefore = await invokeWorker(
			worker,
			request("/mcp/api/pat"),
			environment,
			executionContext,
		);
		expect(await stateBefore.json()).toEqual({
			configured: false,
			last4: null,
			verifiedAt: null,
		});
		const savedB = await putPat(
			worker,
			environment,
			executionContext,
			"sentinel-pat-user-b",
		);
		expect(savedB.status).toBe(200);

		expect(kv.values.size).toBe(2);
		expect([...kv.values.keys()]).toEqual(
			expect.arrayContaining([
				"plane:pat:v1:access-user-a",
				"plane:pat:v1:access-user-b",
			]),
		);
	});

	it("rejects cross-origin mutation and an unexpected Host", async () => {
		const worker = createWorker({ authenticate: async () => identity() });
		const environment = env();
		const executionContext = {} as ExecutionContext;
		const crossOrigin = await invokeWorker(
			worker,
			request("/mcp/api/pat", {
				method: "DELETE",
				headers: { Origin: "https://evil.example" },
			}),
			environment,
			executionContext,
		);
		expect(crossOrigin.status).toBe(403);
		const wrongHost = await invokeWorker(
			worker,
			request("/mcp", {}, "evil.example"),
			environment,
			executionContext,
		);
		expect(wrongHost.status).toBe(400);
	});

	it("keeps the setup page free of persistent browser storage", async () => {
		const page = setupPage();
		const html = await page.text();
		expect(html).not.toMatch(
			/localStorage|sessionStorage|indexedDB|document\.cookie/,
		);
		expect(page.headers.get("Set-Cookie")).toBeNull();
		expect(page.headers.get("Cache-Control")).toBe("no-store");
	});
});

describe("MCP surface", () => {
	it("publishes only the nine allowlisted CE tools and no delete tool", async () => {
		const kv = new MemoryKv();
		const record: PatRecord = {
			pat: SENTINEL_PAT,
			planeUserId: "plane-a",
			email: "a@rayven.cloud",
			last4: "7d92",
			verifiedAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
		};
		await kv.put("plane:pat:v1:access-user-a", JSON.stringify(record));
		const environment = env(kv);
		const fetcher = planeFetcher({
			[SENTINEL_PAT]: { id: "plane-a", email: "a@rayven.cloud" },
		});
		const worker = createWorker({
			authenticate: async () => identity(),
			fetcher,
		});
		const response = await invokeWorker(
			worker,
			request("/mcp", {
				method: "POST",
				headers: {
					Accept: "application/json, text/event-stream",
					Authorization: "Bearer client-oauth-token-must-not-reach-plane",
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					jsonrpc: "2.0",
					id: 1,
					method: "tools/list",
					params: {},
				}),
			}),
			environment,
			{} as ExecutionContext,
		);
		expect(response.status, await response.clone().text()).toBe(200);
		const body = await response.text();
		expect(body).not.toContain(SENTINEL_PAT);
		const expectedNames = [
			"plane_me",
			"plane_project",
			"plane_member",
			"plane_state",
			"plane_label",
			"plane_cycle",
			"plane_module",
			"plane_intake",
			"plane_workitem",
		];
		const dataLine = body.split("\n").find((line) => line.startsWith("data: "));
		if (!dataLine)
			throw new Error("MCP response did not contain an SSE data line");
		const payload = JSON.parse(dataLine.slice(6)) as {
			result: { tools: Array<{ name: string }> };
		};
		expect(payload.result.tools.map((tool) => tool.name)).toEqual(
			expectedNames,
		);
		expect(
			payload.result.tools.some((tool) => tool.name.includes("delete")),
		).toBe(false);

		const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
		const callResponse = await invokeWorker(
			worker,
			request("/mcp", {
				method: "POST",
				headers: {
					Accept: "application/json, text/event-stream",
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					jsonrpc: "2.0",
					id: 2,
					method: "tools/call",
					params: { name: "plane_me", arguments: {} },
				}),
			}),
			environment,
			{} as ExecutionContext,
		);
		expect(callResponse.status).toBe(200);
		expect(await callResponse.text()).not.toContain(SENTINEL_PAT);
		expect(JSON.stringify(log.mock.calls)).not.toContain(SENTINEL_PAT);
		const planeRequestHeaders = new Headers(
			fetcher.mock.calls.at(-1)?.[1]?.headers,
		);
		expect(planeRequestHeaders.get("Authorization")).toBeNull();
		expect(planeRequestHeaders.get("X-API-Key")).toBe(SENTINEL_PAT);
		expect(planeRequestHeaders.get("CF-Access-Client-Id")).toBe(
			"service-client-id",
		);
		log.mockRestore();
	});

	it("returns a generic error for a revoked PAT without exposing Plane body", async () => {
		const kv = new MemoryKv();
		const revokedPat = "revoked-sentinel-pat";
		await kv.put(
			"plane:pat:v1:access-user-a",
			JSON.stringify({
				pat: revokedPat,
				planeUserId: "plane-a",
				email: "a@rayven.cloud",
				last4: "-pat",
				verifiedAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			}),
		);
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
		const worker = createWorker({
			authenticate: async () => identity(),
			fetcher: vi.fn(async () =>
				Response.json(
					{ detail: `credential ${revokedPat} rejected` },
					{ status: 401 },
				),
			),
		});
		const response = await invokeWorker(
			worker,
			request("/mcp", {
				method: "POST",
				headers: {
					Accept: "application/json, text/event-stream",
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					jsonrpc: "2.0",
					id: 3,
					method: "tools/call",
					params: { name: "plane_me", arguments: {} },
				}),
			}),
			env(kv),
			{} as ExecutionContext,
		);
		const body = await response.text();
		expect(body).toContain("credential is invalid");
		expect(body).not.toContain(revokedPat);
		expect(body).not.toContain("detail");
		expect(JSON.stringify(log.mock.calls)).not.toContain(revokedPat);
		log.mockRestore();
	});
});
