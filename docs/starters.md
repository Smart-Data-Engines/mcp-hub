# Included starters

The built-in catalog contains neutral public examples. No company registry,
service credentials or private adapter code is included. Its versioned sources
live under `src/mcp_hub/starter_code/v1`; published versions must be preserved.
Add a new source version for changes rather than silently replacing an existing
version. Definitions store the selected starter ID/version, and running snapshots
have their own content revision just like Git-based servers.

## First tool

1. Sign in and open **MCP servers → Create server**.
2. Choose **Demo**, review its unique name, and select **Create and start Demo**.
3. In an authenticated AI client connected to the Hub, call `your-name.hello` or
   `your-name.who_am_i`. The result uses the caller's verified Hub identity.
4. Open **Access**, select a colleague, and grant read access to share the demo.

If your AI client cached its tool list, refresh/reconnect its MCP Hub connection
after starting the server so it discovers the new tools.

The Demo needs no third-party account, credentials or outbound service request.
The normal hosting prerequisites and Hub login still apply.

## GitHub.com

Create a GitHub starter and open **Connection**. Personal mode is the default:
each user saves a token and `owner/repository` for their own account. It does not
borrow missing fields from a shared account. The token must be a fine-grained
personal access token with the selected repository and read access to Metadata,
Issues and Pull requests. Organizations can require approval before that access
works. Follow [GitHub's token guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).

**Test GitHub connection** makes bounded GET requests to verify the account,
repository, issue and pull-request read surfaces. It tests saved configuration;
save drafts first. A successful test is a permission check at that moment, not a
guarantee against later token expiry or revocation. It never modifies GitHub data.

An administrator may select a shared connection for a dedicated service account.
It is encrypted in Global Env and only injected into this server. Shared changes
require a restart; personal changes are resolved per call. Members with Hub read
access can test/use the shared account without reading its token. An explicit
“only personal credentials” preference refuses shared access until the user
deliberately changes that preference.

The five tools are `get_repository`, `list_issues`, `get_issue`,
`list_pull_requests`, and `get_pull_request`. Lists return a bounded first page
(default 10, maximum 20); GitHub's issues feed may include pull requests, marked
with `kind`. Detailed bodies are limited to 12,000 characters with an explicit
truncation flag. GitHub.com is the fixed API host, response bytes are capped and
redirects are not followed. The starter supports PATs, not GitHub Enterprise or a
provider OAuth sign-in flow. API reference: [GitHub REST](https://docs.github.com/en/rest).

## Notion

Create a **Notion** starter, then open **Connection**. Create an internal
connection in [Notion's developer portal](https://www.notion.so/profile/integrations),
enable only **Read content**, and copy its secret token into the form. In Notion,
open the pages or databases you want to use and add that connection under
**Connections**. Access includes child content according to Notion's sharing
rules. See [connection capabilities](https://developers.notion.com/reference/capabilities).

Personal mode is the default: each person saves their own token. Administrators
can deliberately configure a shared connection instead. Token encryption, blank
field preservation, member access checks, the personal-only preference, and
restart requirements for shared changes work as for GitHub.

**Test Notion connection** checks the token's bot identity and makes one bounded
search read. If no results are returned, the form explains how to share a page
and allow time for search indexing; it does not claim the workspace is empty or
that all page content has been validated. The test never changes Notion content.

The six tools are `search`, `get_page`, `get_block`, `list_blocks`, `get_database`, and
`query_data_source`. Search matches titles, not full text, and is not a complete
workspace inventory. Databases expose data-source IDs; query those sources to
read rows. The implementation uses Notion API version `2026-03-11`. Search and
data-source queries use Notion's read-only POST endpoints; other reads use GET.
Only fixed routes on `api.notion.com` are available. Redirects and external
attachment downloads are not followed.

Lists return at most 20 items per call. When `has_more` is true, pass
`next_cursor` as the next call's `cursor`. Block children are not fetched
recursively: read child IDs with `has_children` separately. Inline page properties
may be partial according to Notion's API. The starter also caps each output item
and explicitly marks local truncation. The combined page budget preserves all
item IDs and the continuation cursor, including when text and structured output
are both present in MCP. Read a block separately with `get_block` for a larger
excerpt, or open oversized items in Notion to read them in full. Provider errors
omit response bodies and never include the token.

This is a neutral public example. An existing custom server connected to Notion
keeps its own code, credentials and tools. Use your own connection token; do not
reuse another integration's credentials for initial testing.

API references: [search](https://developers.notion.com/reference/post-search),
[database metadata](https://developers.notion.com/reference/retrieve-database),
[data-source queries](https://developers.notion.com/reference/query-a-data-source).

## Source and customization

Included source is read-only. **Source → Download complete starter** contains
the complete server, helper, declarations, pinned requirements and a README.
Create a Custom server and copy the example files into its registry folder,
keeping the `manifest.yaml` already generated for that Custom server. Commit the
files. Keep the authenticated `serve(mcp)` and
explicit `credentials` contract. See [server authoring](server-authoring.md).

Creation, source browsing, configuration, start/stop and deletion of an included
starter do not read or write the customer's Git repository. An empty local
registry with `REGISTRY_BACKEND=local` and `REGISTRY_READ_ONLY=true` can therefore
serve included starters without a Git provider account. Hosting still needs the
configured source directory, Docker socket and isolated networks; this does not
bypass runtime verification or admin-approved resource limits.

Custom Git servers retain the existing behavior. Their ordinary stored
definitions omit unused starter fields. When rolling back to a release predating
starters, stop/remove new starter instances first or restore the pre-upgrade
snapshot; older runtimes cannot recreate bundled source from Git.
