import {
	createRemoteJWKSet,
	customFetch,
	type JWTPayload,
	type JWTVerifyGetKey,
	jwtVerify,
} from "jose";
import type { AccessIdentity, Env } from "./types";

const jwksByIssuer = new Map<string, JWTVerifyGetKey>();

function normalizedTeamDomain(value: string): string {
	const url = new URL(value);
	if (
		url.protocol !== "https:" ||
		url.pathname !== "/" ||
		url.search ||
		url.hash ||
		!url.hostname.endsWith(".cloudflareaccess.com")
	) {
		throw new Error("invalid Access team domain");
	}
	return url.origin;
}

function remoteJwks(issuer: string): JWTVerifyGetKey {
	const existing = jwksByIssuer.get(issuer);
	if (existing) return existing;
	const jwksUrl = new URL("/cdn-cgi/access/certs", `${issuer}/`);
	const created = createRemoteJWKSet(jwksUrl, {
		[customFetch]: async (url, options) => {
			if (url !== jwksUrl.href) throw new Error("blocked JWKS destination");
			return fetch(url, { ...options, redirect: "manual" });
		},
	});
	jwksByIssuer.set(issuer, created);
	return created;
}

export function identityFromPayload(payload: JWTPayload): AccessIdentity {
	if (typeof payload.sub !== "string" || payload.sub.length < 1) {
		throw new Error("missing Access subject");
	}
	if (typeof payload.email !== "string") {
		throw new Error("missing Access email");
	}
	const email = payload.email.trim().toLowerCase();
	if (!email.endsWith("@rayven.cloud")) {
		throw new Error("email domain is not allowed");
	}
	if (typeof payload.exp !== "number") {
		throw new Error("missing Access expiration");
	}
	return { sub: payload.sub, email, expiresAt: payload.exp };
}

export async function authenticateAccess(
	request: Request,
	env: Pick<Env, "ACCESS_TEAM_DOMAIN" | "ACCESS_AUD">,
	keyResolver?: JWTVerifyGetKey,
): Promise<AccessIdentity> {
	const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
	if (!assertion) throw new Error("missing Access assertion");
	if (!env.ACCESS_AUD) throw new Error("missing Access audience");

	const issuer = normalizedTeamDomain(env.ACCESS_TEAM_DOMAIN);
	const { payload } = await jwtVerify(
		assertion,
		keyResolver ?? remoteJwks(issuer),
		{
			algorithms: ["RS256"],
			audience: env.ACCESS_AUD,
			issuer,
		},
	);
	return identityFromPayload(payload);
}

export async function subjectHash(sub: string, key: string): Promise<string> {
	if (!key) throw new Error("missing log hash key");
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign(
		"HMAC",
		cryptoKey,
		new TextEncoder().encode(sub),
	);
	return Array.from(new Uint8Array(signature))
		.slice(0, 16)
		.map((byte) => byte.toString(16).padStart(2, "0"))
		.join("");
}
