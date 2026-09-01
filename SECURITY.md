# Security Policy

## Supported Versions

| Version  | Supported |
| -------- | --------- |
| 0.11.x   | Yes       |
| < 0.11   | No        |

Only the latest minor receives security updates. While this package is pre-1.0
there are no maintained backport branches: a fix ships in the next release from
`main`, so staying current is a prerequisite for being covered by this policy.

Two high-severity advisories have been published to date
([GHSA-4c2f-96cf-f5fc](https://github.com/openeudi/openid4vp/security/advisories/GHSA-4c2f-96cf-f5fc),
[GHSA-h548-cr7v-4v97](https://github.com/openeudi/openid4vp/security/advisories/GHSA-h548-cr7v-4v97)),
fixed in 0.8.1 and 0.9.0 respectively. The library has not had an independent
third-party security audit; see the README's "Security and maturity" section.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's Private Vulnerability Reporting:

1. Go to the [Security tab](https://github.com/openeudi/openid4vp/security) of this repository
2. Click "Report a vulnerability"
3. Fill in the details

### Response Timeline

- **Acknowledge:** Within 72 hours
- **Assessment:** Within 1 week
- **Patch (critical):** Within 30 days
- **Patch (non-critical):** Next scheduled release

### After Resolution

- Security advisory published on GitHub
- Reporter credited (unless they prefer anonymity)
- Fix noted in CHANGELOG.md

## Scope

This policy covers the `@openeudi/openid4vp` npm package. For issues in dependencies, please report to the respective maintainers.
