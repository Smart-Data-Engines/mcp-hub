# Security policy

Report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Smart-Data-Engines/mcp-hub/security/advisories/new).
Include the affected commit, expected behavior and a minimal reproduction.
Do not include production tokens, private adapters or personal data.

Security fixes target the latest `main` branch until versioned releases establish
a separate support policy. Company deployments should validate their identity
provider, access grants, network boundaries and recovery procedure as described
in [the deployment guide](docs/deployment.md).

The [security boundary notes](docs/security-model.md) describe trusted operator
configuration and the scope of static-analysis review.
