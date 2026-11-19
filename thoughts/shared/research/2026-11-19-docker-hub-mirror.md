---
date: 2026-11-19
commit: 17ca3db
branch: work
tags: [docker, quarantine, registry]
status: complete
---

# Docker Hub mirror research

The Axum server serves status, artifacts and workflow scanning. It has no registry routes. The Docker policy checks whether workflow and Compose image references are pinned. The package evaluator and image archive scanner are separate entry points.

| File | Purpose |
|---|---|
| `src/main.rs:289` | Starts the server and constructs its config |
| `src/adapters/http/mod.rs:192` | Mounts HTTP routes |
| `src/domain/mod.rs:574` | Sets the seven-day quarantine window and the default to hold versions with CVEs |
| `src/domain/mod.rs:1033` | Applies the age gate to a known time |
| `src/application/mod.rs:93` | Evaluates package integrity, advisories, and age |
| `src/application/image_scanner.rs:192` | Runs archive integrity, Trivy, YaraHunter, and conditional capa scanning |
| `src/application/image_scanner/engines.rs:27` | Runs offline Trivy through Bubblewrap and parses its report |
| `src/adapters/command_scanner/mod.rs:1084` | Bounds and isolates external scanners |
| `Dockerfile:23` | Builds the existing server runner |

Docker Hub tag pulls resolve mutable references to a manifest digest. Registry V2 responses do not supply a trustworthy publish date. Docker Hub indexes commonly include BuildKit attestation descriptors beside runnable platforms. Trivy opens an OCI layout directory and selects a single image, so one scan across a multi-platform index cannot establish coverage for all variants. The Registry V2 mirror protocol allows clients such as Docker Engine to fall back to upstream after a mirror rejects a request.

No related research or decision files existed in `thoughts/shared/` before this work.
