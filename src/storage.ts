import type { PatRecord } from "./types";

const KEY_PREFIX = "plane:pat:v1:";

export function patKey(accessSub: string): string {
	if (!accessSub) throw new Error("missing Access subject");
	return `${KEY_PREFIX}${accessSub}`;
}

export async function loadPat(
	kv: KVNamespace,
	accessSub: string,
): Promise<PatRecord | null> {
	return kv.get<PatRecord>(patKey(accessSub), "json");
}

export async function savePat(
	kv: KVNamespace,
	accessSub: string,
	record: PatRecord,
): Promise<void> {
	await kv.put(patKey(accessSub), JSON.stringify(record));
}

export async function deletePat(
	kv: KVNamespace,
	accessSub: string,
): Promise<void> {
	await kv.delete(patKey(accessSub));
}
