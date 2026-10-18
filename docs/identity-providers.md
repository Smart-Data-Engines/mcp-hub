# Company identity providers

All presets use OIDC discovery and verify signed ID tokens, issuer, audience,
expiration, nonce, authorized party and browser-bound state. The provider name
selects the callback path; identity keys are derived from `(issuer, sub)` rather
than an editable email address.

Register a confidential web application at the provider. Its redirect URI is:

```text
https://your-hub.example.com/oauth/{IDP_PROVIDER}/callback
```

Configure `IDP_PROVIDER`, `IDP_ISSUER`, `IDP_CLIENT_ID` and `IDP_CLIENT_SECRET` in
`.env`. Use `IDP_SCOPES=openid profile email`. The hub does not forward the IdP's
access token to MCP clients: it issues its own opaque, immediately revocable tokens.

| Provider | IDP_PROVIDER | IDP_ISSUER |
|---|---|---|
| Google Workspace | `google` | `https://accounts.google.com` |
| Microsoft Entra ID | `entra` | `https://login.microsoftonline.com/TENANT-GUID/v2.0` |
| Keycloak | `keycloak` | `https://identity.example.com/realms/your-realm` |
| Okta | `okta` | The exact issuer of your authorization server |
| Auth0 | `auth0` | The exact issuer for your tenant/custom domain |
| GitLab | `gitlab` | The instance's exact OIDC issuer |
| Another provider | `oidc` | Its exact discovery issuer |

For Entra, use a specific tenant GUID. For any provider, the issuer must exactly
match its discovery document. Keep the trailing slash when the provider's issuer
contains one. `IDP_USERNAME_CLAIM` defaults to `preferred_username`, with email/sub
fallback. A username must be safe for upstream identity headers; display names are
not suitable as identifiers.

`IDP_ALLOWED_DOMAINS=company.example,subsidiary.example` optionally requires a
verified email claim in one of those domains. Providers that do not emit a verified
email claim should restrict membership in the configured tenant/realm instead.

`IDP_BACKCHANNEL_URL` is an optional operator-controlled internal proxy address for
discovery, token and JWKS requests. Browser authorization remains on the public IdP
endpoint and the public issuer is still verified. In production the proxy uses HTTPS.

Set `IDP_TOKEN_AUTH_METHOD=client_secret_basic` when the provider's application
requires HTTP Basic authentication at the token endpoint (for example an Okta
application configured that way). The default is `client_secret_post`. Select
the same method in the provider application and Hub configuration.

For a private company CA, mount its PEM bundle read-only and set `HUB_CA_BUNDLE`
to that path. `HUB_HTTP_PROXY` explicitly configures the trusted proxy for IdP,
registry and audit traffic. Internal upstream traffic uses direct connections and
the configured CA; implicit ambient proxy variables are not used.

Provision the first administrator using their verified OIDC `sub`:

```sh
docker compose exec hub mcp-hub bootstrap-admin SUBJECT USERNAME
```

Changing a person's group or revoking their Hub tokens takes effect on the next
request. Organization offboarding must also revoke their Hub sessions/permissions;
the upstream IdP is not consulted on every use of an existing Hub access token.

The local demo provider is test infrastructure. Provider presets and rejection
paths are tested against controlled OIDC responses; acceptance with a company's
actual tenant, claims and conditional-access policies is a deployment gate.

Primary references: [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html),
[Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect),
[Microsoft OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[Keycloak OIDC](https://www.keycloak.org/securing-apps/oidc-layers).

For Google Workspace, an allowed-domain restriction also requires the signed `hd`
claim to match an allowed Workspace domain. An email suffix alone is insufficient.

`ADMIN_EMAILS=owner@company.example` optionally makes the deployment's verified
email allowlist authoritative for administrator roles. The first successful OIDC
sign-in with an allowed verified email binds its stable issuer/subject identity.
Startup and subsequent sign-ins enforce the configured list, and the console
cannot add/remove administrators while this policy is active. No account is made
an administrator merely because its displayed username resembles that email.
With an empty setting, the existing operator bootstrap and role-management API
remain available. A prepared deployment may leave the IdP client credentials empty:
sign-in then remains disabled, rather than using the demonstration provider.
