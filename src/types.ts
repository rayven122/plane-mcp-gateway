export interface Env {
	PAT_KV: KVNamespace;
	ACCESS_TEAM_DOMAIN: string;
	ACCESS_AUD: string;
	PLANE_ORIGIN: string;
	PLANE_WORKSPACE: string;
	PLANE_ACCESS_CLIENT_ID: string;
	PLANE_ACCESS_CLIENT_SECRET: string;
	MCP_HOSTNAME: string;
	LOG_HASH_KEY: string;
}

export interface AccessIdentity {
	sub: string;
	email: string;
	expiresAt: number;
}

export interface PatRecord {
	pat: string;
	planeUserId: string;
	email: string;
	last4: string;
	verifiedAt: string;
	updatedAt: string;
}

export type Fetcher = (
	input: RequestInfo | URL,
	init?: RequestInit,
) => Promise<Response>;
