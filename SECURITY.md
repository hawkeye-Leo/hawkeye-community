# Security Policy

## Supported versions

Security fixes are provided for the [latest GitHub Release](https://github.com/hawkeye-Leo/hawkeye-community/releases/latest) only.

## Reporting a vulnerability

Email [hawkeye18485@gmail.com](mailto:hawkeye18485@gmail.com) with the subject `[Hawkeye Security]`.

Please do not open public issues for unfixed vulnerabilities.

Include:

- Hawkeye version or Release tag
- Windows version and build number
- Steps to reproduce
- Impact (privilege required, local vs remote, crash vs exploitable behavior)
- `!support` console output when relevant

## Scope

**In scope:** vulnerabilities in Hawkeye Community (application or kernel driver) that allow privilege escalation, unintended kernel or process memory access, or other behavior beyond documented, authorized use.

**Out of scope:**

- Use on systems you do not own or are not explicitly authorized to administer
- Requests to bypass or evade third-party software, games, or production systems
- Driver load blocked by test-signing policy, Memory Integrity / HVCI, Secure Boot, or similar environment restrictions
- Capabilities that require Administrator privileges and a loaded driver when used as documented

## Process

We acknowledge reports when possible and ship fixes in a future Release. We may credit reporters with their permission.

## Authorized use

Use Hawkeye only on systems you own or are explicitly authorized to administer. This is a research console, not a bypass kit.
