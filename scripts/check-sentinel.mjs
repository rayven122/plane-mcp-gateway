import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";

const sentinel = "RAYVEN_SENTINEL_PAT_MUST_NOT_LEAK_7d92";
const textExtensions = new Set([
	".js",
	".json",
	".map",
	".txt",
	".html",
	".css",
]);

async function files(root) {
	const found = [];
	for (const entry of await readdir(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.isDirectory()) found.push(...(await files(path)));
		else if (textExtensions.has(extname(path))) found.push(path);
	}
	return found;
}

for (const path of await files("dist")) {
	if ((await readFile(path, "utf8")).includes(sentinel)) {
		throw new Error(`sentinel PAT found in build artifact: ${path}`);
	}
	if (path.endsWith(".map")) {
		throw new Error(`source map must not be published: ${path}`);
	}
}
