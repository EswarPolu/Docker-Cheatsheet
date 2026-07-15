# 🛡️ Enterprise Docker DevSecOps — Best Practices & Security Guide

> A senior-engineer reference for building, shipping, running, and observing containers securely at
> MNC scale. Written from the perspective of a 10+ year Docker/DevSecOps engineer, optimized both as
> an operational playbook **and** as deep interview-prep material.
>
> **Version 2** · Last reviewed **July 2026** · Standards baseline: CIS Docker Benchmark **v1.8.0**
> (Aug 2025, Docker v28), NIST **SP 800-190**, OWASP **Docker Top 10**, SLSA **v1.0**, PCI-DSS **4.0.1**.

---

## Table of Contents

0. [Mental Model & Threat Model](#0-mental-model--threat-model)
- **Part I — BUILD:** [1. Base images](#1-base-image-selection) · [2. Dockerfile hardening](#2-multi-stage--dockerfile-hardening) · [3. BuildKit advanced](#3-buildkit-advanced-mounts--attestations) · [4. Reproducible & multi-arch](#4-reproducible--multi-arch-builds)
- **Part II — SHIP:** [5. SBOM & SLSA](#5-supply-chain-sbom--slsa-provenance) · [6. Signing](#6-signing--verification) · [7. Registry](#7-registry-hardening) · [8. Vuln mgmt](#8-vulnerability-management) · [9. Admission](#9-admission-control--deploy-time-enforcement)
- **Part III — RUN:** [10. Least privilege](#10-runtime-least-privilege) · [11. Rootless](#11-rootless--userns-remap-deep-dive) · [12. Sandboxed runtimes](#12-sandboxed-runtimes) · [13. Secrets](#13-secrets-management) · [14. Networking](#14-network-security) · [15. Host/daemon](#15-host--daemon-hardening)
- **Part IV — OBSERVE:** [16. Runtime detection](#16-runtime-threat-detection) · [17. Logging & drift](#17-logging--drift-detection) · [18. Incident response](#18-incident-response--forensics)
- **Part V — GOVERN:** [19. Compliance](#19-compliance--standards) · [20. CI/CD pipeline](#20-cicd-devsecops-pipeline)
21. [Incident case studies](#21-incident-case-studies) · 22. [Audit checklist](#22-audit-checklist) · 23. [Interview Q&A](#23-interview-qa) · [References](#references--standards)

---

## 0. Mental Model & Threat Model

Containers are **not** a security boundary by default — they are process isolation via Linux
**namespaces + cgroups + capabilities + seccomp/LSM**, all sharing **one host kernel**. A container
escape is a kernel/`runc` problem, not a hypervisor problem. Security is *defense in depth* across
four planes plus governance:

| Plane | You defend | Primary controls |
|:--|:--|:--|
| **Build** | The image & how it's produced | Minimal base, multi-stage, no secrets in layers, SBOM, reproducibility |
| **Ship** | Integrity in transit & at rest | Signing (Cosign/Notation), provenance (SLSA), trusted registry, admission |
| **Run** | The live container & host | Non-root, cap-drop, seccomp/AppArmor, read-only FS, sandboxed runtimes |
| **Observe** | The breach you didn't prevent | Falco/Tetragon, audit logs, drift detection, forensics |
| **Govern** | Provable, repeatable assurance | CIS/NIST/STIG/PCI/FIPS, policy-as-code, evidence |

**Golden rule:** *shift left, but don't trust left.* Prevent at build/admission time, and still watch
at runtime — prevention always leaks (see [Leaky Vessels §21](#21-incident-case-studies)).

> 💬 **Soundbite:** "A container shares the host kernel, so I treat isolation as defense-in-depth,
> not a wall. Harden the build, sign & verify the supply chain, drop privileges at runtime, and run
> eBPF detection to catch what slips through."

---

# Part I — BUILD

## 1. Base Image Selection

Attack surface scales with package count. Fewer packages → fewer CVEs → smaller blast radius, faster
pulls, less to patch. Preference order: **`scratch` → distroless → Chainguard/Wolfi → `alpine` →
`-slim` → full OS.**

### The minimal-base ecosystem (2025–2026)
| Option | What it is | Notes |
|:--|:--|:--|
| **`scratch`** | Empty image | For static binaries (Go/Rust `CGO_ENABLED=0`). No shell, no libc. |
| **Distroless** (`gcr.io/distroless/*`) | Google's runtime-only images | Variants: `static`, `base`, `cc`, language-specific (`java`, `nodejs`, `python3`); `:nonroot` (uid 65532) and `:debug` (adds busybox) tags. No shell/package manager. |
| **Chainguard / Wolfi** | "Undistro" minimal images built with `apko`/`melange` | Near-zero CVEs, daily rebuilds, SBOM + provenance built in, **700+ FIPS variants**. Wolfi is the community base. |
| **Docker Hardened Images (DHI)** | Docker's hardened catalog | **Free & open-source (Apache 2.0) since Dec 17 2025**; non-root by default, SLSA provenance, signed **VEX** attestations. |
| **Alpine** | musl + busybox, ~5 MB | Tiny but has a shell/apk; musl can cause glibc-compat issues (DNS, some binaries). |
| **`-slim` (Debian/Ubuntu)** | Trimmed glibc distro | Good compatibility, larger than Alpine. |

### Language-native image builders (no Dockerfile, reproducible by design)
- **`ko`** (Go) — builds distroless Go images without a Dockerfile or Docker daemon; produces SBOMs.
- **`jib`** (Java, Maven/Gradle) — daemonless, reproducible, layered Java images.
- **Cloud Native Buildpacks / Paketo** — turn source → OCI image with automatic rebase for OS patches.
- **`apko`/`melange`** — declarative apk-based image assembly (the Chainguard/Wolfi toolchain).

### Pin by digest, never `latest`
`latest` is mutable and non-reproducible. Pin **tag + digest** so the build is deterministic and
tamper-evident:
```dockerfile
FROM python:3.12-slim@sha256:<digest>
```
Automate digest bumps with **Renovate** or **Dependabot** (Dockerfile support) so pinning doesn't
mean stale/unpatched bases — the CVE-vs-reproducibility tension is solved by *automated* updates.

---

## 2. Multi-Stage & Dockerfile Hardening

**Multi-stage builds** keep compilers, SDKs, and build secrets out of the final image. Golden Go
example (build → distroless):
```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.22@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/app","healthcheck"]
ENTRYPOINT ["/app"]
```

### Dockerfile anti-patterns to eliminate
| Anti-pattern | Why it's bad | Fix |
|:--|:--|:--|
| `ADD` for local files / remote URLs | `ADD` auto-extracts tars and fetches URLs (SSRF/tamper risk) | Use `COPY`; fetch with a verified `RUN curl … && sha256sum -c` |
| `ONBUILD` triggers | Hidden instructions run in *downstream* builds | Avoid in shared bases |
| Unpinned `apt/apk/pip/npm` | Non-reproducible, cache-poisonable | Pin versions/hashes; `pip install --require-hashes`, `npm ci` w/ lockfile |
| Secrets in `ENV`/`ARG`/`COPY` | Persist in layers & `docker history`; leak in `mode=max` provenance | BuildKit secret mounts (§3) |
| Package cache left in layer | Bloat | `--no-install-recommends` + `rm -rf /var/lib/apt/lists/*` **same** `RUN` |
| Running as root | Escalation on escape | Create user + `USER` down |
| Missing `.dockerignore` | Leaks `.git`, `.env`, keys into context | Maintain a strict `.dockerignore` |

Combine cleanup in one layer (Debian):
```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
```

---

## 3. BuildKit Advanced (Mounts & Attestations)

All `RUN --mount` types need `# syntax=docker/dockerfile:1` and BuildKit (default in Engine 23.0+).
The frontend is a sandboxed image pulled per build, so **Dockerfile features ship independently of
the daemon** — `:1` gives automatic bugfixes; pin a digest for reproducibility.

### `--mount=type=cache` — build cache (perf, not correctness)
Persistent scratch dir kept on the **builder host**; reattached across builds even when the RUN layer
is rebuilt. **Not part of the image layer cache and not exported by `--cache-to`** → needs a
persistent builder (or a build service) to survive ephemeral CI runners. Never rely on its contents.
- `sharing` modes: `shared` (default, concurrent), `private` (per-writer copy), `locked` (serialize —
  use for apt/dpkg locks). `id` scopes cache identity; set `uid`/`gid` so a non-root `USER` can write.
```dockerfile
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && apt-get update && apt-get install -y gcc
```

### `--mount=type=secret` — build secrets (never in layers)
Exposed only for one `RUN`; default path `/run/secrets/<id>`, mode `0400`. `required=true` hard-fails
if absent. `env=` form (frontend v1.10+) exposes as env var. Predefined `GIT_AUTH_TOKEN`/`HTTP_AUTH_*`
for private contexts.
```dockerfile
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```
```bash
docker build --secret id=npmtoken,src=$HOME/.npmtoken .
```

### `--mount=type=ssh` — forward the agent for private git deps
```dockerfile
RUN --mount=type=ssh git clone git@gitlab.com:org/private.git
```
`docker buildx build --ssh default=$SSH_AUTH_SOCK .` (default id, socket mode `0600`).

### `--mount=type=bind` / `type=tmpfs`
`bind` is read-only by default (`from=<stage>` to pull artifacts without a `COPY` layer; `rw` writes
are discarded). `tmpfs` is in-memory scratch (`size=`) for sensitive intermediates.

### Selective cache bust & heredoc
- `docker buildx build --no-cache-filter builder,test .` busts only named stages (vs `--no-cache` all).
- HEREDOC (stable in `dockerfile:1.4`) collapses multi-line `RUN` into one layer without `&& \`.

### Attestations — provenance & SBOM
BuildKit attaches **in-toto JSON attestations** into the image index. **Requires the
`docker-container` buildx driver and pushing to a registry** — the default `docker` driver/exporter
adds none and can't load attested indexes.
- **Provenance (SLSA):** `mode=min` is default-on (container driver). `mode=max` adds the full LLB +
  **base64 Dockerfile** — but **exposes build-ARG values**, so never pass secrets as ARGs.
- **SBOM:** `--sbom=true` (Syft, SPDX). Expand scope with `ARG BUILDKIT_SBOM_SCAN_CONTEXT=true` /
  `..._SCAN_STAGE=true`.
```bash
docker buildx create --driver docker-container --use
docker buildx build --provenance=mode=max --sbom=true -t org/app:1.0 --push .
docker buildx imagetools inspect org/app:1.0 --format "{{ json .Provenance.SLSA }}"
```

---

## 4. Reproducible & Multi-Arch Builds

- **Reproducibility** makes provenance meaningful: same source → same digest, so a tampered build is
  detectable. Levers: pinned base digests, lockfiles/hash-pinned deps, `SOURCE_DATE_EPOCH` to
  normalize timestamps, `-trimpath`/`-ldflags="-s -w"` (Go), avoiding build-time nondeterminism.
- **Multi-arch:** `docker buildx build --platform linux/amd64,linux/arm64 --push` builds a manifest
  list (OCI image index) via QEMU emulation or native build nodes. Enterprises run **native build
  farms** (arm64 + amd64 nodes) to avoid slow emulation and keep provenance per-arch.

---

# Part II — SHIP

## 5. Supply Chain: SBOM & SLSA Provenance

Modern attackers poison the *pipeline*, not just prod. Controls form a chain of custody:

| Control | Tool | Gives you |
|:--|:--|:--|
| **SBOM** | Syft, `docker sbom`, Trivy | Every package in the image (SPDX or CycloneDX) |
| **Provenance** | BuildKit `--provenance`, SLSA | Tamper-evident record of source + builder |
| **Signing** | Cosign / Notation | Cryptographic proof of origin |
| **VEX** | OpenVEX + Scout/Trivy/Grype | Declares CVEs *not exploitable in context* → cuts noise |

### SLSA v1.0 Build Levels (know these cold)
| Level | Requirement | Guarantee |
|:--|:--|:--|
| **Build L1** | Provenance exists (builder id, source, artifact digest) | Auditability only — **forgeable** by anyone controlling the build env |
| **Build L2** | Hosted build platform + **signed** provenance | Tampering requires an explicit attack; deters unsophisticated adversaries |
| **Build L3** | Platform isolation; **signing keys inaccessible to build steps**; builds isolated | Strong tamper-resistance; forged provenance is hard |
Cumulative (L3 ⊇ L2 ⊇ L1). Docker Hardened Images and GitHub Actions OIDC builds can reach **L3**.
SBOM formats: **SPDX** (ISO standard, common in gov) vs **CycloneDX** (OWASP, security-focused).

---

## 6. Signing & Verification

### Sigstore / Cosign — keyless signing (the modern default)
No long-lived keys to leak. Flow: signer authenticates via **OIDC** → **Fulcio** issues a
short-lived (~10 min) cert binding an ephemeral key to that identity → sign → record in **Rekor**
(append-only transparency log). The private key lives in memory only, then is discarded.
```bash
# sign (keyless, in CI with the workflow's OIDC identity)
COSIGN_EXPERIMENTAL=1 cosign sign <registry>/app@sha256:<digest>
# attach an SBOM attestation
syft <image> -o spdx-json > sbom.spdx.json
cosign attest --predicate sbom.spdx.json --type spdxjson <image>
# verify (enforce identity + issuer)
cosign verify <image> \
  --certificate-identity-regexp 'https://github.com/org/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Forging a signature requires compromising the OIDC provider **and** Fulcio **and** Rekor at once.

### Notation (Notary Project / "Notary v2")
Spec-driven signing built on **X.509 cert chains** (existing enterprise PKI, not TUF). Supports
**multiple signatures** per image (e.g. vendor + internal approval), OCI-standard signatures stored
in the registry. Choose Notation when you need PKI integration / multi-party approval; Cosign for
developer-friendly keyless.

### Docker Content Trust is retired — migrate off
DCT deprecation began **Mar 31 2025**; signing certs expired **Aug 8 2025**; can't enable on new
registries after **Sep 30 2025**; data deleted **Mar 31 2028**. (<0.05% of pulls used it; old Notary
unmaintained.) **Migrate to Cosign or Notation.**

---

## 7. Registry Hardening

The registry is where enterprise container trust is enforced. Whether **Harbor** (CNCF, self-hosted)
or a cloud registry (**ECR / Google Artifact Registry / ACR**):

- **RBAC & robot/service accounts** — CI/CD uses scoped, **expiring** robot tokens per project, never
  human creds or long-lived keys. Cloud: least-privilege IAM pull roles, short-lived tokens (OIDC).
- **Tag immutability** — forbid overwriting a pushed tag; **deploy by digest** for true reproducibility.
- **Retention & GC** — e.g. "keep last 5 `prod-*`, delete anything not pulled in 30 days"; run garbage
  collection to reclaim storage.
- **Built-in scanning** — Harbor ships **Trivy** on by default; ECR/GAR/ACR have native scanning.
  **Quarantine** images above a CVE threshold.
- **Content-trust policy** — configure the project so **only signed artifacts** (Cosign/Notation) can
  be pulled.
- **Network** — private endpoints/VPC only; TLS; replication for DR; no anonymous pull for private repos.

---

## 8. Vulnerability Management

Scan **continuously** — in dev, in CI (gate), and in the registry (new CVEs appear for images you
already shipped).

| Scanner | Notes |
|:--|:--|
| **Docker Scout** | Native to Docker CLI/Desktop; applies **VEX** from DHI with zero config |
| **Trivy** | Ubiquitous OSS; images, IaC, SBOM; VEX via VEX Hub; default scanner in Harbor |
| **Grype** | Fast, SBOM-driven; `--vex` flag |

```bash
docker scout cves myapp:1.2.3
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 myapp:1.2.3   # CI gate
```
**Policy:** fail CI on **fixable** HIGH/CRITICAL. Use **VEX/OpenVEX/CSAF** to suppress CVEs assessed
not-exploitable-in-context so teams fix real risk instead of chasing noise.

---

## 9. Admission Control & Deploy-Time Enforcement

Enforce policy *before* a workload runs (this is the enforcement point for everything above).

| Engine | Language | Strengths |
|:--|:--|:--|
| **Pod Security Admission** | built-in labels | Baseline/Restricted profiles; zero-install, coarse |
| **OPA Gatekeeper** | **Rego** | Powerful, portable OPA ecosystem; validation-focused |
| **Kyverno** | **YAML** (K8s-native) | Validate + **mutate** + **generate** + **verifyImages** (Cosign); lightweight |
| **ValidatingAdmissionPolicy** | **CEL** (in-tree) | **GA in v1.30**; no external controller; `Deny`/`Warn`/`Audit` |

**Common enforced policies:** block `:latest`; block `runAsNonRoot: false`; block `privileged`,
`hostPath`, `hostNetwork`, `hostPID`; require dropped caps + `readOnlyRootFilesystem`; require resource
limits; **require a valid Cosign signature** and allow images only from an approved registry allowlist.

**Signature verification at admission:** Kyverno `verifyImages`, sigstore **policy-controller**,
**Connaisseur**, or **Ratify** — each checks the Cosign signature/attestations before admitting.
Pair with **zero-trust workload identity** (SPIFFE/SPIRE, IRSA / GKE Workload Identity) so pods
authenticate to registries/secret stores without static creds.

---

# Part III — RUN

## 10. Runtime Least Privilege

Where most real-world containers fail. Baseline:

| Control | Flag / setting | Why |
|:--|:--|:--|
| Non-root user | `USER 65532` / `--user` | Never run the app as root |
| Drop all caps | `--cap-drop=ALL` + minimal `--cap-add` | Removes Docker's ~14 default caps |
| No new privileges | `--security-opt=no-new-privileges` | Blocks setuid escalation (`PR_SET_NO_NEW_PRIVS`) |
| Read-only rootfs | `--read-only` + `--tmpfs /tmp` | Immutable runtime; write only to volumes |
| Seccomp | default profile / custom | Shrinks syscall attack surface |
| AppArmor / SELinux | `docker-default` / custom | MAC confinement of files/net/caps |
| Limits | `--cpus`, `--memory`, `--pids-limit` | Contain fork bombs / noisy-neighbor DoS |
| No `--privileged` | *never in prod* | All caps + device access = trivial escape |
| No socket mount | avoid `-v /var/run/docker.sock` | = root on the host |

### Dangerous capabilities — never grant casually
| Capability | Risk |
|:--|:--|
| **CAP_SYS_ADMIN** | "the new root" — mount, namespaces, huge surface; common escape primitive |
| **CAP_SYS_MODULE** | Load kernel modules → trivial host takeover |
| **CAP_SYS_PTRACE** | `ptrace`/`process_vm_readv`; can bypass seccomp; lethal with shared host PID ns |
| **CAP_DAC_READ_SEARCH** | Bypass file read perms (Shocker / `open_by_handle_at` escape) |
| **CAP_NET_RAW** | Raw packets → ARP/DNS spoofing, lateral movement |
| **CAP_NET_ADMIN**, **CAP_SETUID/SETGID**, **CAP_SYS_BOOT**, **CAP_SYS_TIME** | Various escalation/host-impact |
Safe common add-back: **`NET_BIND_SERVICE`** (ports <1024).

### Hardened `docker run`
```bash
docker run -d --user 65532:65532 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/etc/docker/seccomp/app.json \
  --pids-limit=200 --cpus=1 --memory=512m --memory-swap=512m \
  --restart=on-failure:3 myapp:1.2.3
```

### seccomp / AppArmor / SELinux
- **seccomp:** Docker's default profile blocks ~44 of 300+ syscalls (e.g. `kexec_load`,
  `perf_event_open`, `add_key`, namespace-creation). `--security-opt seccomp=unconfined` disables it —
  avoid. Author custom profiles to allow-list only what the workload needs.
- **AppArmor** (`docker-default`) and **SELinux** (svirt, `--security-opt label=…`, MCS categories)
  provide mandatory access control; use custom profiles for sensitive workloads.

---

## 11. Rootless & userns-remap Deep Dive

Common interview trap — know the difference:

- **userns-remap:** the *daemon still runs as root*, but container UID 0 maps to an unprivileged host
  UID (via `/etc/subuid`/`/etc/subgid`). Keeps full Docker features; mitigates container-root =
  host-root.
- **Rootless mode:** the *daemon itself* runs as a non-root user inside a user namespace. Strongest
  posture. Real trade-offs:
  - **Networking:** uses `slirp4netns` (5–10% overhead, NAT); the newer **`pasta`** driver avoids NAT
    for better throughput.
  - **Ports <1024:** blocked by default (needs `net.ipv4.ip_unprivileged_port_start` or `setcap`).
  - **Resource limits:** need **cgroup v2 with delegation**; by default only `memory`+`pids` are
    delegated to non-root — without full delegation Docker runs but **can't enforce cpu limits**.
  - Some storage drivers / volume-permission quirks with ACLs.

Prefer **rootless** for multi-tenant / untrusted workloads; userns-remap as a lighter middle ground.

---

## 12. Sandboxed Runtimes

When container isolation isn't enough (untrusted code, hostile multi-tenancy), swap the OCI runtime:

| Runtime | Mechanism | Isolation | Cost | Use when |
|:--|:--|:--|:--|:--|
| **runc** | Namespaces/cgroups | Baseline | None | Trusted internal workloads |
| **gVisor** (`runsc`) | Userspace kernel (**Sentry**, Go) intercepts syscalls | Strong, no VM | ~34% network hit; syscall-compat gaps | Medium-threat multi-tenant SaaS |
| **Kata Containers** | Lightweight **VM per pod**, own kernel (K8s `RuntimeClass`) | Hardware-level | ~6% network hit | High-threat, strong isolation, production-ready |
| **Firecracker** | Minimal Rust **microVM** (~5 MiB, ~125 ms cold start) | Hardware-level | Needs orchestration | Serverless/FaaS (Lambda/Fargate); usually via Kata |
| **Sysbox** | Extends runc; run Docker/K8s/systemd **inside** containers | Enhanced, no `--privileged` | Low | Rootless DinD, CI runners |

Threat-model guidance: **low/internal → runc; medium multi-tenant → gVisor; high/untrusted →
Kata or Firecracker.**

---

## 13. Secrets Management

**Never in an image layer or `docker history`.** `ENV`, `ARG`, `COPY .env` all persist.

| Need | Do | Don't |
|:--|:--|:--|
| Build-time | BuildKit `--mount=type=secret` (§3) | `ARG TOKEN=` / `ENV TOKEN=` |
| Runtime | Injected from a secret store | Baked into the image |

### Kubernetes/runtime secret stores (2025–2026)
| Tool | Model | Notes |
|:--|:--|:--|
| **HashiCorp Vault — Agent Injector** | Sidecar renders secrets to a shared memory volume | App stays Vault-unaware; supports dynamic secrets |
| **Vault CSI / Vault Secrets Operator** | Mount via CSI (no sidecar) | **CSI keeps secrets out of etcd**; recommended for new deploys |
| **External Secrets Operator (ESO)** | Syncs cloud secret managers → K8s Secrets | 40+ providers; easiest if you already use AWS/GCP/Azure secret managers |
| **SOPS** (CNCF) | File-level encryption with KMS/`age` | GitOps-native (Flux/ArgoCD); encrypted files portable |
| **Sealed Secrets** | Controller decrypts cluster-side | Simple GitOps; cluster-scoped key |
| **SPIFFE/SPIRE** | Workload identity (SVIDs) | Keyless auth to Vault/cloud without static creds |

Detect leaked secrets in images/history with **TruffleHog** (verifies creds against live APIs, peels
image layers) and **gitleaks** (fast regex, git-focused).

---

## 14. Network Security

- **Segment** with user-defined bridge networks; don't share the default bridge across unrelated apps.
- **Publish narrowly** — bind to `127.0.0.1` for local-only: `-p 127.0.0.1:8080:8080`.
- **Daemon socket:** never expose `tcp://0.0.0.0:2375` (unauthenticated = instant host compromise);
  require **TLS mutual auth** (`--tlsverify`) for remote access.
- **Kubernetes:** apply a **default-deny** NetworkPolicy per namespace on day one, then allow-list.
  Remember NetworkPolicies are **additive** — egress from sender *and* ingress to receiver must both
  allow. CNI matters: **Cilium** (eBPF) adds **FQDN-based egress**, DNS-aware and **L7** (HTTP
  method/path) policies; **Calico** offers global/namespaced default-deny.
- **Service mesh mTLS** (Istio/Linkerd) — transparent mutual TLS + identity between services;
  zero-trust east-west traffic.
- **Egress control** — default-deny outbound; a compromised container shouldn't beacon/exfiltrate.

---

## 15. Host & Daemon Hardening

Audit against **CIS Docker Benchmark v1.8.0** (7 sections, 100+ recs, Docker v28) using
**docker-bench-security** or the InSpec `dev-sec/cis-docker-benchmark` profile. Kubernetes:
**CIS Kubernetes Benchmark** + **kube-bench**.

High-value items:
- Run daemon **rootless** or **userns-remap**; restrict the **`docker` group** (root-equivalent).
- Use a **minimal / container-specific host OS** (NIST 800-190): Bottlerocket, Flatcar, RHEL CoreOS —
  read-only rootfs, minimal packages, auto-updates.
- Harden `/etc/docker/daemon.json`:
  ```json
  {
    "icc": false,
    "userns-remap": "default",
    "no-new-privileges": true,
    "live-restore": true,
    "userland-proxy": false,
    "log-driver": "json-file",
    "log-opts": { "max-size": "10m", "max-file": "3" }
  }
  ```
- **Audit** the daemon/files with `auditd` (CIS §1): `/usr/bin/dockerd`, `/etc/docker`,
  `/var/lib/docker`. Correct socket/cert perms (CIS §3).
- **Patch runc/BuildKit/Docker** promptly — container-escape CVEs live here (§21).
```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc:/etc:ro docker/docker-bench-security
```

---

# Part IV — OBSERVE

## 16. Runtime Threat Detection

Prevention leaks — you need eyes at runtime. The three eBPF-based OSS leaders:

| Tool | Origin | Model | Distinctive |
|:--|:--|:--|:--|
| **Falco** | CNCF (graduated) | Detect & alert | 70+ Falcosidekick integrations; the detection standard |
| **Tetragon** | Cilium/Isovalent | Detect **+ enforce** | In-kernel enforcement via **LSM/eBPF** — can kill a process / block a syscall *before* it completes |
| **Tracee** | Aqua | Detect **+ forensics** | Deep event capture for investigation |

They detect: shells spawned in containers, unexpected egress, writes to sensitive paths, privilege
escalation, cryptominers, container-escape behavior. **Pick Falco** for mature detection/alerting;
**Tetragon** when you need in-kernel *prevention* or already run Cilium; **Tracee** for
detection + forensic depth. Defense-in-depth trio: **Trivy** (scan) + **Kyverno/OPA** (admission) +
**Falco/Tetragon** (runtime).

---

## 17. Logging & Drift Detection

- **Centralize** logs to a SIEM (fluentd/fluent-bit → Elastic/Loki/Splunk); avoid logging secrets/PII.
- **Rotate** logs (`max-size`/`max-file`) to prevent disk-fill DoS.
- **Image drift detection** — alert when a running container's filesystem diverges from its image
  (sign of live tampering / injected payloads). `docker diff <ctr>` shows changed files.

---

## 18. Incident Response & Forensics

- **Preserve evidence before killing:** `docker inspect`, `docker diff`, `docker logs`; capture the
  filesystem (`docker export`) and, for memory, **CRIU checkpoint** (`docker checkpoint create`) to
  snapshot a running container's full state for offline memory forensics.
- **Debug without shipping tools:** ephemeral debug containers (`kubectl debug`) attach a toolbox to a
  distroless pod without rebuilding it.
- **Immutable infrastructure:** *redeploy, don't patch* a compromised container — kill & quarantine
  (cordon the node / NetworkPolicy isolate), then rebuild from a clean, signed image.
- **Post-incident:** scan the offending image/layers with TruffleHog/gitleaks for leaked creds; rotate
  anything exposed; feed findings back into admission policy.

---

# Part V — GOVERNANCE

## 19. Compliance & Standards

### NIST SP 800-190 — the five container risk areas (+ countermeasures)
| Area | Key risks | Countermeasures |
|:--|:--|:--|
| **Image** | Vulnerabilities, config defects, embedded malware, **clear-text secrets**, untrusted images | Scan + sign; secrets out of images; trusted base images |
| **Registry** | Insecure connections, stale images, weak authN/authZ | TLS, RBAC, prune stale tags, signed content-trust |
| **Orchestrator** | Unbounded admin access, poor network separation, mixed workload sensitivity, node trust | RBAC least-privilege, network segmentation, sensitivity-based scheduling |
| **Container** | Runtime vulns, unbounded privilege, escape | cap-drop, seccomp/MAC, read-only, resource limits |
| **Host OS** | Large attack surface, shared kernel | **Container-specific minimal OS**, patching, host hardening |
800-190 maps to **NIST 800-53**, **FedRAMP**, and **DoD cATO**.

### Other regimes you must name correctly
- **CIS Docker/Kubernetes Benchmarks** — prescriptive config baselines (§15). Automated: docker-bench,
  kube-bench, InSpec.
- **DISA STIG / Container Platform SRG** — DoD hardening; images via DoD Cyber Exchange /
  Iron Bank. Evidence via OpenSCAP/OSCAP scans + STIG checklists.
- **PCI-DSS 4.0.1** — the only active version since **Mar 31 2024**; future-dated 4.0 reqs became
  **mandatory Mar 31 2025**. Containers: segment CDE from non-CDE (NetworkPolicy/namespaces), scan
  images pre-deploy, no `privileged`, least-privilege RBAC + security contexts, read-only rootfs,
  logging.
- **FIPS 140-3** — validated crypto for regulated industries. Use FIPS base images (RHEL UBI FIPS,
  **Chainguard FIPS** — OpenSSL FIPS provider CMVP #4282, Bouncy Castle FIPS; 700+ variants, STIG-
  hardened, OSCAP reports). FIPS validation ≠ STIG-hardened ≠ CVE-free — they're distinct claims.
- **SOC 2 / ISO 27001** — pipeline controls, change management, evidence retention.
- **Frameworks:** OpenSSF **Scorecard**, **S2C2F**, CNCF Software Supply Chain Best Practices.

### Governance mechanics
Policy-as-code (§9) is how compliance is *enforced continuously*, not audited annually. Collect
evidence: signed provenance, SBOMs, scan reports, admission-policy logs, benchmark results.

---

## 20. CI/CD DevSecOps Pipeline

End-to-end hardened flow:
```
1. Lint            hadolint (Dockerfile), conftest (policy)
2. Build           BuildKit multi-stage, docker-container driver,
                   --provenance=mode=max --sbom=true, secrets via --mount, no AR%G secrets
3. Scan            trivy/scout — fail on fixable HIGH/CRITICAL (VEX-filtered)
4. SBOM            syft → SPDX/CycloneDX, attach as attestation
5. Sign            cosign (keyless OIDC) or notation (PKI)
6. Push            immutable tag + digest → trusted registry (Harbor/ECR/GAR/ACR)
7. Verify          admission: cosign verify + Kyverno/Gatekeeper/VAP
                   (no root, no latest, signed-only, limits, drop caps)
8. Run             non-root, cap-drop, seccomp, read-only; sandboxed runtime if untrusted;
                   Falco/Tetragon watching
9. Continuously    re-scan registry images; Renovate base bumps → rebuild on new CVEs
```
**Senior differentiators:** central **golden images** rebuilt on cadence; **ephemeral, isolated build
runners** (a poisoned build shouldn't reach shared infra); native multi-arch build farms; SLSA L3
provenance; continuous compliance scanning.

---

## 21. Incident Case Studies

### Leaky Vessels (Jan 2024) — container escape
| CVE | Component | Impact |
|:--|:--|:--|
| **CVE-2024-21626** | runc | FD leak → escape to host filesystem |
| **CVE-2024-23651** | BuildKit | Race condition → breakout during build |
| **CVE-2024-23652** | BuildKit | Arbitrary host file deletion during build |
| **CVE-2024-23653** | BuildKit | Breakout during image build |
Fix: **runc ≥ 1.1.12**, **BuildKit ≥ 0.12.5**. Lesson: the escape lived in the *core runtime*, not
your app — hence patch runc/BuildKit, don't rely on the container as your only boundary, and run
runtime detection.

### xz-utils backdoor (CVE-2024-3094, Mar 2024) — supply chain
A multi-year social-engineering campaign planted a backdoor in the `xz`/`liblzma` upstream tarball
(differing from the git source). Lesson: **reproducible builds + SBOM + provenance** would surface a
tarball that doesn't match source; pin and verify dependencies.

### GhostAction (early 2025) — CI compromise
Attackers compromised a widely-used GitHub Action to exfiltrate secrets. Lesson: pin Actions by
commit SHA, least-privilege `GITHUB_TOKEN`, OIDC over long-lived secrets, isolate build runners.

---

## 22. Audit Checklist

**Build**
- [ ] Minimal/distroless/Chainguard/DHI base, pinned by digest (no `latest`); auto-bumped (Renovate)
- [ ] Multi-stage; no build tools/secrets in final image; `.dockerignore` excludes `.git`/`.env`/keys
- [ ] BuildKit secret mounts for build-time creds; `mode=max` provenance only if no ARG secrets
- [ ] SBOM generated; image scanned; CI gated on fixable HIGH/CRITICAL (VEX-filtered)

**Ship**
- [ ] Signed (Cosign keyless or Notation) + SLSA provenance attached
- [ ] Immutable tags; trusted registry with RBAC + expiring robot accounts; deploy by digest

**Run**
- [ ] Non-root `USER`; `--cap-drop=ALL` (+ minimal); `no-new-privileges`; read-only rootfs + tmpfs
- [ ] seccomp + AppArmor/SELinux; resource + PID limits; **no** `--privileged`, **no** socket mount
- [ ] Rootless / userns-remap daemon; sandboxed runtime (gVisor/Kata) for untrusted workloads
- [ ] Secrets from Vault/CSI/ESO/SOPS — never in image/env
- [ ] Default-deny NetworkPolicy; mesh mTLS; daemon not exposed unauthenticated

**Observe / Govern**
- [ ] Falco/Tetragon runtime detection; centralized logging + rotation; drift detection
- [ ] Admission control (signed-only, no-root, limits) via Kyverno/Gatekeeper/VAP
- [ ] runc/BuildKit/Docker patched; host on minimal OS; docker-bench + kube-bench passing
- [ ] Compliance evidence collected (provenance, SBOM, scans, policy logs)

---

## 23. Interview Q&A

- **Why isn't a container a security boundary?** Shares the host kernel; isolation is
  namespaces/cgroups/caps/seccomp, not virtualization. A kernel/runc bug (Leaky Vessels) breaks out →
  defense-in-depth; use gVisor/Kata for untrusted code.
- **Secrets out of an image?** BuildKit `--mount=type=secret` at build; Vault/CSI/ESO at runtime.
  Never `ENV`/`ARG` — persist in layers, `docker history`, and `mode=max` provenance.
- **`--cap-drop=ALL` then what?** Add back only what's needed (e.g. `NET_BIND_SERVICE`). Never
  `CAP_SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`.
- **Rootless vs userns-remap?** Rootless = the *daemon* runs unprivileged (strongest, slirp4netns/pasta
  + cgroup-delegation trade-offs); userns-remap = daemon stays root, container UID 0 maps to
  unprivileged host UID.
- **How do you trust an image in prod?** SBOM + SLSA provenance + Cosign signature verified at
  admission (Kyverno/policy-controller); deploy by digest; SLSA L3 build.
- **SLSA levels?** L1 provenance exists (forgeable); L2 hosted + signed; L3 isolated builds, keys
  unreachable by build steps.
- **Distroless vs Alpine vs Chainguard?** Distroless: no shell/pkg-mgr (small surface, harder debug).
  Alpine: tiny but has shell + musl quirks. Chainguard/Wolfi: near-zero-CVE, daily rebuilds, SBOM +
  FIPS variants.
- **Cosign vs Notation?** Cosign keyless (OIDC/Fulcio/Rekor, dev-friendly); Notation X.509/PKI,
  multi-signature approval. DCT is retired (2025).
- **Falco vs Tetragon?** Falco detects/alerts (CNCF standard); Tetragon can *enforce* in-kernel
  (kill/block) via eBPF/LSM.
- **NIST 800-190 areas?** Image, registry, orchestrator, container, host OS.

---

## References & Standards

**Frameworks & benchmarks**
- CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker · v1.8.0 (Aug 2025): https://www.cisecurity.org/insights/blog/cis-benchmarks-august-2025-update
- NIST SP 800-190 — https://csrc.nist.gov/pubs/sp/800/190/final
- OWASP Docker Top 10 — https://owasp.org/www-project-docker-top-10/ · Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- SLSA v1.0 levels — https://slsa.dev/spec/v1.0/levels
- PCI-DSS 4.0.1 — https://www.pcisecuritystandards.org/ · DISA STIGs — https://public.cyber.mil/stigs/
- FIPS 140-3 — https://www.chainguard.dev/supply-chain-security-101/fips-140-3-everything-you-need-to-know

**Build & supply chain**
- BuildKit / Dockerfile reference — https://docs.docker.com/reference/dockerfile/ · Build secrets — https://docs.docker.com/build/building/secrets/ · Attestations — https://docs.docker.com/build/metadata/attestations/
- Docker Hardened Images — https://www.docker.com/blog/hardened-images-free-now-what/ · Chainguard — https://edu.chainguard.dev/
- Sigstore/Cosign — https://docs.sigstore.dev/ · Notation — https://notaryproject.dev/ · DCT retirement — https://www.docker.com/blog/retiring-docker-content-trust/
- Syft/SBOM — https://github.com/anchore/syft · Docker Scout — https://docs.docker.com/scout/ · Trivy — https://trivy.dev/

**Runtime & platform**
- Docker seccomp — https://docs.docker.com/engine/security/seccomp/ · Rootless — https://docs.docker.com/engine/security/rootless/ · capabilities(7) — https://man7.org/linux/man-pages/man7/capabilities.7.html
- gVisor — https://gvisor.dev/ · Kata — https://katacontainers.io/ · Firecracker — https://firecracker-microvm.github.io/ · Sysbox — https://github.com/nestybox/sysbox
- Harbor — https://goharbor.io/ · Kyverno — https://kyverno.io/ · OPA Gatekeeper — https://open-policy-agent.github.io/gatekeeper/ · ValidatingAdmissionPolicy — https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/

**Detection, secrets, network, IR**
- Falco — https://falco.org/ · Tetragon — https://tetragon.io/ · Tracee — https://aquasecurity.github.io/tracee/
- Vault on K8s — https://developer.hashicorp.com/vault/docs/platform/k8s · External Secrets Operator — https://external-secrets.io/ · SOPS — https://github.com/getsops/sops · SPIFFE/SPIRE — https://spiffe.io/
- Cilium — https://cilium.io/ · Calico — https://docs.tigera.io/ · TruffleHog — https://github.com/trufflesecurity/trufflehog · gitleaks — https://github.com/gitleaks/gitleaks
- Leaky Vessels — https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities · xz-utils CVE-2024-3094 — https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094

---

*Derived and expanded from the [Docker Professional Cheatsheet](./README.md). Living documentation —
revisit when CIS/NIST/OWASP/SLSA publish updates or when new container-escape CVEs land.*
