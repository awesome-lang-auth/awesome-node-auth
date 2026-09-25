# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ |
| Previous minor | ⚠️ Critical fixes only |
| Older | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a security issue, open a [GitHub Security Advisory](https://github.com/nik2208/awesome-node-auth/security/advisories/new) (private disclosure). You can also use the **"Report a vulnerability"** button on the [Security tab](https://github.com/nik2208/awesome-node-auth/security).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested fix, if you have one

## Response timeline

- **Acknowledgement** within 48 hours
- **Assessment and triage** within 5 business days
- **Fix and advisory** published after a patch is ready (coordinated disclosure)

## Scope

This policy covers the `awesome-node-auth` npm package and the code in this repository. It does **not** cover third-party dependencies — please report those directly to their respective maintainers.

## Security best practices for users

- Never commit `JWT_SECRET`, `REFRESH_TOKEN_SECRET`, or other secrets to source control.
- Rotate API keys and JWT secrets if you suspect they have been exposed.
- Keep the library updated to receive security patches (`npm update awesome-node-auth`).
- Review the [hardening guide](/docs/advanced) in the documentation.
