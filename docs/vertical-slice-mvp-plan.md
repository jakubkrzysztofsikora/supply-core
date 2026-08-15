# Rust Vertical-Slice MVP Plan

## Goal

Implement the first credible local-first dependency firewall slice for npm packages and GitHub Actions. The MVP is intentionally Rust-first, Dockerized, test-driven, and shaped around ports and adapters.

## Implemented slice

1. Domain models for packages, versions, vulnerability findings, decisions, frozen artifacts, policy, and GitHub Action references.
2. Ports for clock, vulnerability source, metadata store, artifact store, hasher, upstream npm registry, and workflow reader.
3. Application services for npm package evaluation and GitHub Actions workflow scanning.
4. Adapters for YAML config, filesystem workflow reading, hashing/integrity verification, HTTP npm metadata fetching, in-memory metadata, filesystem artifact storage, and HTTP health serving.
5. CLI commands:
   - `supply scan-actions . --json`
   - `supply serve --addr 127.0.0.1:4873`
6. Tests for the highest-risk policy and parsing behavior.

## Fallback requirement

Blocked, vulnerable, missing-integrity, or quarantined npm versions should not hard-error when an approved frozen version exists. The evaluator returns a `Fallback` decision with warnings and the served frozen version. It only returns `Block` when no frozen fallback exists.

## Remaining production hardening

- Full npm registry-compatible metadata endpoint and tarball endpoint.
- SQLite persistence instead of in-memory metadata for runtime state.
- OSV API adapter with cache and severity normalization.
- Semver-aware latest-frozen-satisfying-range fallback rather than latest-frozen-any-version.
- GitHub annotations emitter.
- Coverage threshold job once the codebase has more than bootstrap modules.
- Manual acceptance scripts running Docker plus fixture npm projects.
