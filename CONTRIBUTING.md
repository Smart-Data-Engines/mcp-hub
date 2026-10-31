# Contributing

Start from the current `main`, create a branch, and open a pull request describing
the resulting behavior and validation. Main requires passing CI, resolved review
conversations and a squash merge. A second reviewer is not required for a sole
maintainer to merge their own tested changes.

Use Python 3.13 or 3.14, Node.js 22 and Docker Engine with Compose. Install Python
dependencies with `uv sync --frozen --extra dev` and console dependencies with
`npm ci` inside `frontend`. Run the commands in the README before opening a PR.
Docker/browser tests need the local demo stack and must run sequentially when
they share its first-party console login.

Routine Python and npm version-update PRs are limited to minor and patch releases.
Major API/compiler migrations need a dedicated review against the supported
gateway, adapter and browser profiles. Dependabot security updates use a separate
stream and are not restricted by `allow.update-types`; see the
[Dependabot reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#update-types-allow).
Base-image proposals are grouped into one monthly PR. GitHub Actions stay grouped
and pinned to verified full commit hashes. Keep security scanning and the required
CI checks enabled when adjusting dependency-update policy.

Enable the repository's local publication guard:

```sh
git config core.hooksPath .githooks
```

The guard checks the index and outgoing commit histories for private files.
Keep the product specification, private MCP registry, credentials, `.env` and
local deployment state outside public Git and Docker contexts. Removing a private
file from the latest commit does not remove it from earlier commits. Report
security issues using [the security policy](SECURITY.md).
