# Welcome to SASTBot

SASTBot is a self-hosted application that scans your source repositories for
two classes of security finding and helps you triage them toward EU CRA
(Cyber Resilience Act) compliance:

- **SCA findings** — known CVEs in your third-party dependencies, surfaced
  via OSV and CycloneDX SBOMs, then enriched by an LLM agent that decides
  whether each CVE is *reachable* from your code.
- **SAST findings** — security weaknesses (CWE-mapped) in your first-party
  code, identified by an LLM agent that reads the source directly, then
  verified by a second LLM pass that re-checks every finding against the
  live code.

The same scan also emits two CRA-grade artifacts you can hand to auditors or
ship to downstream consumers:

- **CycloneDX SBOM** of every scope (per scan, immutable, and per scope,
  operator-edited)
- **SARIF v2.1.0** report of SAST findings, with CWE taxonomy references
  and inline source context

If you're brand new to the system, read [quick-start](quick-start) first.
Then [How SASTBot works](overview) gives you the mental model in five
minutes; the rest of the manual is a section-per-feature reference you can
jump into as needed.

The [API reference](api-reference) is rendered live from the running
backend's OpenAPI schema, so it never drifts from the actual protocol.

---

## Who this manual is for

This document is written for both operators (people who use SASTBot
day-to-day to triage findings) and administrators (people who deploy,
upgrade, back up, and restore it). In small teams both roles are often
held by the same people in practice; the [Administration](credentials)
section is therefore as detailed as the day-to-day sections.

If you're an integrator wiring SASTBot into another system, jump straight
to the [API reference](api-reference).

## How the manual is laid out

- **Getting started** — quick-start and concepts.
- **Day-to-day use** — repositories → scopes → scans → SCA, SAST,
  components — in the order you'll meet them.
- **Administration** — credentials, settings, backup/restore, versioning,
  deployment.
- **Reference** — troubleshooting and the API protocol.

> Every section in this manual is self-contained, so you can land on any
> page and read just it. Cross-links use the section's slug — they're real
> links you can follow.
