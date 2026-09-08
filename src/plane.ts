import type { Env, Fetcher, PatRecord } from "./types";

const API_PREFIX = "/api/v1/";
const REQUEST_TIMEOUT_MS = 15_000;

export class PlaneApiError extends Error {
	constructor(public readonly status: number) {
		super("Plane API request failed");
		this.name = "PlaneApiError";
	}
}

function requireFixedOrigin(value: string): URL {
	const url = new URL(value);
	if (
		url.origin !== "https://tasks.rayven.cloud" ||
		url.pathname !== "/" ||
		url.search ||
		url.hash
	) {
		throw new Error("Plane origin must be https://tasks.rayven.cloud");
	}
	return url;
}

function encodePath(parts: string[]): string {
	return parts.map((part) => encodeURIComponent(part)).join("/");
}

function queryString(query?: Record<string, unknown>): string {
	if (!query) return "";
	const params = new URLSearchParams();
	for (const [name, value] of Object.entries(query)) {
		if (value === undefined || value === null) continue;
		if (Array.isArray(value)) {
			for (const item of value) params.append(name, String(item));
		} else {
			params.set(name, String(value));
		}
	}
	const value = params.toString();
	return value ? `?${value}` : "";
}

export class PlaneClient {
	private readonly origin: URL;

	constructor(
		private readonly env: Pick<
			Env,
			| "PLANE_ORIGIN"
			| "PLANE_WORKSPACE"
			| "PLANE_ACCESS_CLIENT_ID"
			| "PLANE_ACCESS_CLIENT_SECRET"
		>,
		private readonly pat: string,
		private readonly fetcher: Fetcher = (input, init) =>
			globalThis.fetch(input, init),
	) {
		this.origin = requireFixedOrigin(env.PLANE_ORIGIN);
		if (env.PLANE_WORKSPACE !== "rayven") {
			throw new Error("Plane workspace must be rayven");
		}
		if (!pat) throw new Error("missing Plane PAT");
		if (!env.PLANE_ACCESS_CLIENT_ID || !env.PLANE_ACCESS_CLIENT_SECRET) {
			throw new Error("missing Plane Access service token");
		}
	}

	async request(
		method: "GET" | "POST" | "PATCH",
		pathParts: string[],
		options: { body?: unknown; query?: Record<string, unknown> } = {},
	): Promise<{ data: unknown; status: number }> {
		const path = `${API_PREFIX}${encodePath(pathParts)}/`;
		const url = new URL(`${path}${queryString(options.query)}`, this.origin);
		if (
			url.origin !== this.origin.origin ||
			!url.pathname.startsWith(API_PREFIX)
		) {
			throw new Error("blocked Plane API destination");
		}

		const headers = new Headers({
			Accept: "application/json",
			"CF-Access-Client-Id": this.env.PLANE_ACCESS_CLIENT_ID,
			"CF-Access-Client-Secret": this.env.PLANE_ACCESS_CLIENT_SECRET,
			"X-API-Key": this.pat,
		});
		if (options.body !== undefined)
			headers.set("Content-Type", "application/json");

		let response: Response;
		try {
			response = await this.fetcher(url, {
				method,
				headers,
				body:
					options.body === undefined ? undefined : JSON.stringify(options.body),
				redirect: "manual",
				signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
			});
		} catch {
			throw new PlaneApiError(0);
		}

		if (response.status >= 300 && response.status < 400) {
			throw new PlaneApiError(response.status);
		}
		if (!response.ok) throw new PlaneApiError(response.status);
		if (response.status === 204) return { data: null, status: response.status };

		const contentType = response.headers.get("content-type") ?? "";
		if (!contentType.toLowerCase().includes("application/json")) {
			throw new PlaneApiError(response.status);
		}
		try {
			return { data: await response.json(), status: response.status };
		} catch {
			throw new PlaneApiError(response.status);
		}
	}

	workspacePath(...parts: string[]): string[] {
		return ["workspaces", this.env.PLANE_WORKSPACE, ...parts];
	}
}

function objectValue(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new PlaneApiError(502);
	}
	return value as Record<string, unknown>;
}

export async function verifyPat(
	env: Pick<
		Env,
		| "PLANE_ORIGIN"
		| "PLANE_WORKSPACE"
		| "PLANE_ACCESS_CLIENT_ID"
		| "PLANE_ACCESS_CLIENT_SECRET"
	>,
	pat: string,
	accessEmail: string,
	fetcher: Fetcher = (input, init) => globalThis.fetch(input, init),
	now: Date = new Date(),
): Promise<PatRecord> {
	const client = new PlaneClient(env, pat, fetcher);
	const meResponse = await client.request("GET", ["users", "me"]);
	const me = objectValue(meResponse.data);
	const planeEmail = String(me.email ?? "")
		.trim()
		.toLowerCase();
	const planeUserId = String(me.id ?? "");
	if (!planeEmail || !planeUserId || planeEmail !== accessEmail) {
		throw new PlaneApiError(403);
	}

	await client.request("GET", client.workspacePath("projects"));
	const timestamp = now.toISOString();
	return {
		pat,
		planeUserId,
		email: planeEmail,
		last4: pat.slice(-4),
		verifiedAt: timestamp,
		updatedAt: timestamp,
	};
}
