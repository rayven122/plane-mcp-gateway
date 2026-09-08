import { PlaneApiError, verifyPat } from "./plane";
import { deletePat, loadPat, savePat } from "./storage";
import type { AccessIdentity, Env, Fetcher } from "./types";

const JSON_HEADERS = {
	"Cache-Control": "no-store",
	"Content-Type": "application/json; charset=utf-8",
	"Referrer-Policy": "no-referrer",
	"X-Content-Type-Options": "nosniff",
};

function json(body: unknown, status = 200): Response {
	return Response.json(body, { status, headers: JSON_HEADERS });
}

function sameOriginMutation(request: Request): boolean {
	const origin = request.headers.get("Origin");
	return origin === new URL(request.url).origin;
}

export function setupPage(): Response {
	const nonce = crypto.randomUUID();
	const html = `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Plane MCP PAT 設定</title>
  <style nonce="${nonce}">
    :root{font-family:system-ui,sans-serif;color:#172033;background:#f4f6f8}body{margin:0;padding:32px 16px}.card{max-width:620px;margin:auto;background:#fff;border:1px solid #d9dee7;border-radius:12px;padding:28px;box-shadow:0 8px 28px #14213d12}h1{font-size:24px;margin:0 0 12px}p{line-height:1.6;color:#465168}label{display:block;font-weight:600;margin:24px 0 8px}input{box-sizing:border-box;width:100%;font:inherit;padding:12px;border:1px solid #aab3c2;border-radius:8px}button{font:inherit;font-weight:600;padding:10px 16px;border-radius:8px;border:0;background:#2f5bea;color:#fff;cursor:pointer;margin:12px 8px 0 0}.danger{background:#fff;color:#a51d2d;border:1px solid #d9a3aa}.status{min-height:24px;margin-top:18px}.note{font-size:14px}
  </style>
</head>
<body><main class="card">
  <h1>Plane MCP PAT 設定</h1>
  <p>Planeで発行した自分自身のPersonal Access Tokenを登録します。PATはこの画面やブラウザStorageには保存されず、登録後に入力欄から破棄されます。</p>
  <div id="current" class="status" aria-live="polite">状態を確認中…</div>
  <label for="pat">Personal Access Token</label>
  <input id="pat" type="password" autocomplete="off" spellcheck="false" maxlength="4096">
  <button id="save" type="button">検証して保存</button>
  <button id="remove" class="danger" type="button">登録を削除</button>
  <div id="result" class="status" role="status" aria-live="polite"></div>
  <p class="note">削除後、必要に応じてPlane側でもPATを失効してください。</p>
</main>
<script nonce="${nonce}">
(() => {
  const input = document.getElementById("pat");
  const current = document.getElementById("current");
  const result = document.getElementById("result");
  async function refresh() {
    const response = await fetch("/mcp/api/pat", { cache: "no-store" });
    const state = await response.json();
    current.textContent = state.configured
      ? "登録済み（末尾: " + state.last4 + "、最終検証: " + state.verifiedAt + "）"
      : "未登録";
  }
  document.getElementById("save").addEventListener("click", async () => {
    result.textContent = "検証中…";
    const pat = input.value;
    try {
      const response = await fetch("/mcp/api/pat", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pat })
      });
      const body = await response.json();
      result.textContent = response.ok ? "保存しました。" : (body.error || "保存できませんでした。");
    } finally {
      input.value = "";
    }
    await refresh();
  });
  document.getElementById("remove").addEventListener("click", async () => {
    if (!confirm("Gatewayに保存されたPATを削除しますか？")) return;
    const response = await fetch("/mcp/api/pat", { method: "DELETE" });
    result.textContent = response.ok ? "削除しました。Plane側の失効は必要に応じて行ってください。" : "削除できませんでした。";
    input.value = "";
    await refresh();
  });
  refresh().catch(() => { current.textContent = "状態を取得できませんでした。"; });
})();
</script></body></html>`;

	return new Response(html, {
		headers: {
			"Cache-Control": "no-store",
			"Content-Security-Policy": `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'`,
			"Content-Type": "text/html; charset=utf-8",
			"Referrer-Policy": "no-referrer",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options": "DENY",
		},
	});
}

export async function handlePatApi(
	request: Request,
	env: Env,
	identity: AccessIdentity,
	fetcher: Fetcher = fetch,
): Promise<Response> {
	if (request.method === "GET") {
		const record = await loadPat(env.PAT_KV, identity.sub);
		return json(
			record
				? {
						configured: true,
						last4: record.last4,
						verifiedAt: record.verifiedAt,
					}
				: { configured: false, last4: null, verifiedAt: null },
		);
	}

	if (request.method !== "PUT" && request.method !== "DELETE") {
		return new Response(null, {
			status: 405,
			headers: { Allow: "GET, PUT, DELETE" },
		});
	}
	if (!sameOriginMutation(request))
		return json({ error: "invalid request origin" }, 403);

	if (request.method === "DELETE") {
		await deletePat(env.PAT_KV, identity.sub);
		return new Response(null, { status: 204, headers: JSON_HEADERS });
	}

	if (
		!(request.headers.get("Content-Type") ?? "")
			.toLowerCase()
			.startsWith("application/json")
	) {
		return json({ error: "Content-Type must be application/json" }, 415);
	}
	const contentLength = Number(request.headers.get("Content-Length") ?? "0");
	if (contentLength > 16_384)
		return json({ error: "request is too large" }, 413);

	let body: unknown;
	try {
		const text = await request.text();
		if (text.length > 16_384)
			return json({ error: "request is too large" }, 413);
		body = JSON.parse(text);
	} catch {
		return json({ error: "invalid JSON" }, 400);
	}
	const pat =
		body && typeof body === "object" && "pat" in body
			? String((body as { pat: unknown }).pat).trim()
			: "";
	if (pat.length < 8 || pat.length > 4096) {
		return json({ error: "PATの形式が正しくありません。" }, 400);
	}

	try {
		const record = await verifyPat(env, pat, identity.email, fetcher);
		await savePat(env.PAT_KV, identity.sub, record);
		return json({
			configured: true,
			last4: record.last4,
			verifiedAt: record.verifiedAt,
		});
	} catch (error) {
		const status = error instanceof PlaneApiError ? error.status : 0;
		return json(
			{
				error:
					status === 403
						? "Cloudflare AccessとPlaneのメールアドレスが一致しないか、workspace権限がありません。"
						: "PATを検証できませんでした。",
			},
			400,
		);
	}
}
