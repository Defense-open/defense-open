# Security Policy

## Scope

This policy covers:

- `defense-agent` binary and source code
- `defense-core` library
- TOML rule engine and rule files
- CI/CD pipeline and dependencies

## Reporting a Vulnerability

**Please do not report security vulnerabilities as public GitHub Issues.**

### How to Report

Use GitHub's **Private Security Advisories**:

1. Go to the **Security** tab on this repository
2. Click **"Report a vulnerability"**
3. Fill in the form

Alternatively, you can reach us via the email address listed on our GitHub profile.

### What to Expect

| Stage | Timeline |
|-------|----------|
| Acknowledgement | 48 hours |
| Initial assessment and feedback | 7 days |
| Fix target (critical vulnerabilities) | 30 days |
| Fix target (other vulnerabilities) | 90 days |

After a fix is released, the vulnerability will be disclosed publicly at a time agreed upon with the reporter (Coordinated Disclosure).

## Reward

We don't have a formal bug bounty program yet. However, a valid critical vulnerability report earns **1 year of Pro license** (applicable in upcoming releases).

Valid reports include:
- Vulnerabilities that allow Defense agent to be exploited or bypassed
- Vulnerabilities that allow rule engine evasion
- Data leakage in alert output
- Critical (CVSS ≥ 7.0) vulnerabilities in dependencies

## Out of Scope

- Theoretical attacks without a proof of concept
- Vulnerabilities in the underlying operating system
- Ability to uninstall Defense (admin privileges can always do this — this is a limitation, not a vulnerability)
- Social engineering

## Our Security Model

Defense is a user-space tool. A privileged attacker can terminate it — this is an acknowledged limitation documented openly. Kernel-level protection (ELAM/eBPF) is planned for future phases.

Defense **never sends any data off your machine.** The source code is open and auditable.
