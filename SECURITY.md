# Security policy

This project processes untrusted email locally. Supported security fixes target the
latest release. Do not execute attachments or enable remote content while reviewing.
Keep Python, Evolution and your local mail transport updated.

For vulnerabilities, use this repository's GitHub **Security → Report a vulnerability**
if private reporting is enabled. If unavailable, open a minimal issue requesting a
private contact channel, without exploit payloads or private data. Do not include
personal mail, SpamCop tokens, credentials, full configuration or local paths.
Use synthetic reproductions only. Maintainers should enable GitHub private reporting
before advertising a public release.

The trust boundary includes your Unix account, config, local ASN dataset and local
mail transport. No protection against a malicious process running as the same user
is claimed. SQLite transport claims prevent automatic replay after uncertain failures,
but cannot prove remote delivery. See docs/architecture.md and docs/privacy.md.
