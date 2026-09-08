# RAYVEN Plane MCP Gateway

Plane Community Edition向けの利用者別PAT Gatewayです。Cloudflare Access Managed OAuthでMCP利用者を認証し、Cloudflare KVに保存した本人のPlane PATを固定のPlane APIへだけ送ります。

```text
MCP client -- Cloudflare Managed OAuth --> /mcp
                                             |
                 Access sub --> PAT_KV ------+
                                             |
                                             +-- X-API-Key --> tasks.rayven.cloud/api/v1/
```

## Security boundary

- `Cf-Access-Jwt-Assertion`をAccessのJWKS、正確なissuer、Application AUD、有効期限で毎回検証します。
- Workerは`@rayven.cloud`のメールだけを受け入れます。`rayven-members`グループの判定は同じAccess ApplicationのAllow policyで行います。
- KV keyはAccess JWTの`sub`からのみ構成し、リクエストで指定できません。
- Plane originは`https://tasks.rayven.cloud`、workspaceは`rayven`、API pathは`/api/v1/`へ固定しています。
- Plane APIのredirectは追従しません。PATは`X-API-Key`、origin用Access Service TokenはWorker Secretから付与します。
- PAT、ヘッダー、KVレコード、Planeレスポンス本文はログへ出しません。ログはHMAC化したAccess subject、ツール名、成否、時間、HTTP statusだけです。
- PATはCloudflare KVの保存時暗号化に依存します。Cloudflareアカウント管理者とWorker runtimeが値を取得できる残余リスクは設計上の受容事項です。
- `/mcp`はStreamable HTTPのみです。SSE endpointと削除系Plane toolはありません。

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/mcp` | MCP Streamable HTTP |
| `GET` | `/mcp/setup` | PAT登録画面 |
| `GET` | `/mcp/api/pat` | 登録状態、末尾4文字、最終検証日時 |
| `PUT` | `/mcp/api/pat` | PATを検証して保存 |
| `DELETE` | `/mcp/api/pat` | Gateway上のPATを削除 |

登録時はPlaneの`/api/v1/users/me/`でPATを検証し、AccessのメールとPlaneのメールが一致すること、および`rayven` workspace members APIへアクセスできることを確認します。PAT本体はレスポンスに含めません。

## Exposed tools

初期版は次の9ツールに限定しています。

- `plane_me`
- `plane_project`
- `plane_member`
- `plane_state`
- `plane_label`
- `plane_cycle`
- `plane_module`
- `plane_intake`
- `plane_workitem`

`plane_workitem`はlist/retrieve/search/create/updateだけを提供します。他のツールは読み取り専用です。

## Configuration

公開設定は`wrangler.jsonc`で固定します。

- `ACCESS_TEAM_DOMAIN=https://rayven122.cloudflareaccess.com`
- `PLANE_ORIGIN=https://tasks.rayven.cloud`
- `PLANE_WORKSPACE=rayven`
- `MCP_HOSTNAME`: devでは一時hostname、本番では`tasks.rayven.cloud`

次の値はリポジトリ、Wrangler設定、GitHub Actions variablesへ保存せず、対象environmentのWorker Secretとして登録します。

- `ACCESS_AUD`
- `PLANE_ACCESS_CLIENT_ID`
- `PLANE_ACCESS_CLIENT_SECRET`
- `LOG_HASH_KEY`

`PAT_KV`のproduction/preview namespace IDも実際のnamespace作成後に設定します。値の登録やデプロイは承認されたrunbookに従います。

## Local verification

Node.js 24以上で実行します。

```bash
npm ci --ignore-scripts
npm run check
npm audit --omit=dev --audit-level=high
npm run security:sentinel
```

テストはJWT issuer/audience/domain、固定Plane host、redirect拒否、メール不一致、Access sub単位の分離、CSRF/Host拒否、MCP tool allowlistを確認します。`security:sentinel`はbuild成果物へのsentinel PATとsource map混入を拒否します。

## Rollout

1. dev用KV namespaceと一時hostnameを作成する。
2. dev environmentへ4つのWorker Secretを対話登録する。
3. 一時hostnameを同じ`rayven-members` Access policyで保護し、Managed OAuthを有効にする。
4. sentinel PATでHTTP response、Worker logs/trace、ブラウザStorage、Network、build成果物を確認する。
5. Codex、Claude.ai、ChatGPTでOAuth、`tools/list`、読み取りを各1回確認する。
6. 明示承認後にWorker routeを`tasks.rayven.cloud/mcp*`へ切り替える。

本番切替までは既存Tunnel `/mcp` routeと旧MCP Deploymentを残します。障害時はWorker routeを外して既存PATヘッダー方式へ戻し、KVとPlane側PATは保持します。

## Access policy requirements

- ApplicationはMCP serverまたはself-hosted applicationとして`/mcp*`を保護する。
- Managed OAuthを有効にする。
- AllowはGoogle Workspace IdPの`@rayven.cloud`かつ`rayven-members`だけにする。
- Bypass、Everyone、anonymousは設定しない。
- Plane originへのWorker通信専用Service TokenはService Auth policyだけで許可し、人のMCP認証には使わない。

Cloudflare公式資料: [Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)、[Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)、[KV data security](https://developers.cloudflare.com/kv/reference/data-security/)
