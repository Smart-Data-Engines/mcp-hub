# HTTP API

Authenticated APIs use `Authorization: Bearer <hub-access-token>`. Errors are JSON
with `error`; OAuth errors additionally contain an RFC-style code/description.
Opaque client secrets are returned once at creation. Secret values are absent from
credential and environment listings.

Management endpoints additionally require a token delegated to the first-party
console or a service client explicitly registered with `management_allowed: true`.
A dynamically registered MCP client does not inherit configuration access just
because the signed-in user is an administrator. `whoami` and personal credential
operations remain available with a normal MCP token. Role/ownership checks still
apply after this client boundary; management access does not grant a bot tools.

| Surface | Methods and paths | Authorization |
|---|---|---|
| MCP | `POST/GET/DELETE /mcp`, compatibility `/mcp/{alias}` | Bearer; anonymous `/mcp/public` only when explicitly enabled |
| Discovery | `GET /.well-known/oauth-authorization-server`, `GET /.well-known/oauth-protected-resource[/{path}]` | Public |
| OAuth | `POST /oauth/register`, `GET /authorize`, `GET /oauth/{provider}/callback`, `POST /oauth/consent`, `POST /token`, `POST /oauth/revoke` | OAuth client/browser flow |
| Runtime registration | `POST /register`, `POST /unregister` | Shared external or derived managed-server secret |
| Probes | `GET /health`, `/ready`, `/metrics` | Public; restrict exposure at your ingress as needed |
| Identity | `GET /admin/api/whoami` | Any principal |
| Credentials | `GET/POST /credentials`, `DELETE /credentials/{service}`, `GET/POST /credentials/mode` | Own data |
| Users | `GET /admin/api/users`, `GET /users/{id}/servers`, `GET/PUT /users/{id}/group`, `GET /users/{id}/personal`, `POST/DELETE /users/{id}/personal/{grant|deny}/{server}`, `POST /users/{id}/revoke` | Admin/manager; managers cannot change themselves or admins |
| Guided access | `GET /admin/api/access[?server=name]`, `PUT /users/{id}/access/{server}` | Admin/manager; only admins can expand a restricted audience |
| Groups | `GET/POST /admin/api/groups`, `PUT/DELETE /groups/{name}` | Admin |
| Roles | `GET /admin/api/admins`, `POST/DELETE /admins/{id}`, `POST/DELETE /managers/{id}` | Admin; last-admin guard is atomic |
| Bots | `GET/POST /admin/api/clients` | Admin; bot starts with zero capabilities |
| Catalog | `GET/POST /admin/api/servers` | Admin/manager; POST requests background refresh |
| Servers | `GET/POST /admin/api/servers-dynamic`, `GET/PUT/DELETE /servers-dynamic/{name}` | Visible metadata; ownership/admin for management |
| Lifecycle | `POST /servers-dynamic/{name}/{start|stop|restart}`, `GET .../logs` | Owner/admin |
| Files | `GET/POST .../{name}/files`, `GET/DELETE .../files/{path}`, `POST .../commit` | Owner/admin; manifest read-only, Docker limits admin-only |
| Source location | `GET .../{name}/source` | Owner/admin; sanitized repository location and running revision, without downloading code |
| Env/policy | `GET/POST/PATCH .../{name}/env`, `GET .../env/values`, `GET .../user-env-fields`, `GET/POST .../policy` | Explicit admin checks for global values/policy |
| Review | `GET /admin/api/approvals`, `POST /approvals/{id}` | Authorized human; browser cookie, same Origin and interactive CSRF proof for decisions |
| Outbox | `GET /admin/api/audit` | Admin |

`PATCH .../{name}/env` accepts `{"values":{"FIELD":"new value"},"remove":["OLD_FIELD"]}`.
Only declared fields may be changed. Omitted fields keep their saved values;
blank replacement values are rejected and removals must be explicit. Changes to
different fields merge atomically. GET returns configured field names and whether
a restart is needed; it does not return secret values. The explicit admin-only
`/env/values` endpoint is separate from the console form.

Abbreviated administrative paths in the table retain the `/admin/api` prefix.

Create a private server with `{"name":"my-service","description":"..."}`. Names
are globally unique, 1–64 ASCII lowercase letters/digits/underscore/hyphen. Create
does not start the server. Start/Restart return the resulting status and code version.

Batch source commit:

```json
{
  "files": {"server.py": "...", "requirements.txt": "mcp>=1.30,<2\n"},
  "expected_commit": "snapshot commit from GET files",
  "message": "Update adapter"
}
```

The Git branch update is optimistic: reload on 409 rather than overwriting another
author's commit. A successful commit reports `restart_required: true`.

Group server maps and personal grants contain capability arrays, for example
`{"servers":{"my-service":["read"]}}` and `{"caps":["read","write"]}`.
Effective servers are `(group − personal deny) ∪ personal grant`; capabilities are
the union of group and personal-grant masks, with visibility also enforced.

The guided console uses `PUT /admin/api/users/{id}/access/{server}` with
`{"mode":"grant","caps":["read"]}`, `{"mode":"inherit","caps":[]}` or
`{"mode":"block","caps":[]}`. Saving a grant replaces the personal mask and
clears a personal deny. Block removes any personal grant; inherit clears both.
When required, an administrator's grant or inherited group access also shares the
server with this person in the same Redis transaction. A private server becomes
selected-people shared with only that person; inactive entries from an old
private audience are not reactivated. Existing lifecycle fields and concurrent
grants to other people are preserved. Owner/admin access cannot be blocked by
personal rules. Managers receive an actionable 409 if sharing is required.

The directory lists signed-in accounts, assignable groups and both connected and
offline managed servers. A selected server includes each person's effective
capabilities and their sources from one ACL snapshot. The legacy individual
grant/deny endpoints retain their previous independent behavior.

`POST /credentials` optionally accepts boolean `only_mine`; when supplied, the
encrypted credential object, service index and preference are saved in one
transaction. Existing clients that omit it retain their current preference.

`X-Hub-Credentials` accepts JSON keyed by service/server name. The server policy
still governs its use. Tool arguments named `credentials` or Hub identity fields
are removed unconditionally and never treated as trusted overrides.
