# 🛡️ Enterprise Docker DevSecOps — Best Practices & Security Guide

> A staff-engineer reference for building, shipping, running, observing, and governing containers
> securely at MNC scale. Written from a 10+ year Docker/DevSecOps perspective, optimized as an
> operational playbook **and** deep interview-prep material.
>
> **Version 3** · Last reviewed **July 2026** · Standards baseline: CIS Docker Benchmark **v1.8.0**
> (Aug 2025, Docker v28), NIST **SP 800-190**, OWASP **Docker Top 10**, SLSA **v1.0/1.1**,
> PCI-DSS **4.0.1**, CISA **BOD 26-04**.
>
> ⚠️ **On dates/versions:** this guide cites fast-moving facts (CVE fix versions, regulatory
> deadlines, tool GA states). Every such claim is flagged where it needs confirmation. Treat
> standards-body facts (NIST/CIS/SLSA/CVEs) as solid; verify vendor/tooling specifics against current
> docs before quoting in an audit or interview.

---

## Table of Contents

0. [Mental Model & Threat Model](#0-mental-model--threat-model)
- **I — BUILD:** [1 Base images](#1-base-image-selection) · [2 Dockerfile hardening](#2-dockerfile-hardening--anti-patterns) · [3 BuildKit internals](#3-buildkit-advanced-mounts--attestations) · [4 Reproducible/multi-arch](#4-reproducible--multi-arch-builds)
- **II — SHIP:** [5 SBOM & SLSA](#5-supply-chain-sbom--slsa) · [6 Signing](#6-signing--verification) · [7 SBOM ops](#7-sbom--attestation-operations-at-scale) · [8 Registry](#8-registry-hardening) · [9 Vuln mgmt](#9-vulnerability-management-program) · [10 Admission](#10-admission-control--deploy-time-gating)
- **III — RUN:** [11 Least privilege](#11-runtime-least-privilege) · [12 Kernel/LSM internals](#12-kernel--lsm-hardening-internals) · [13 Rootless](#13-rootless--user-namespaces) · [14 Sandboxed runtimes](#14-sandboxed-runtimes) · [15 Secrets](#15-secrets-management) · [16 Networking](#16-network-security) · [17 Host/daemon](#17-host--daemon-hardening)
- **IV — OBSERVE:** [18 Detection](#18-runtime-threat-detection) · [19 Enforcement](#19-runtime-enforcement--drift-prevention) · [20 IR/forensics](#20-incident-response--forensics)
- **V — ORCHESTRATE:** [21 Compose & Swarm](#21-docker-compose--swarm-security) · [22 Kubernetes](#22-kubernetes-workload-security)
- **VI — GOVERN:** [23 Compliance](#23-compliance--standards) · [24 CI/CD & SLSA L3](#24-cicd-hardening--slsa-l3) · [25 Cloud services](#25-cloud-provider-container-security)
26. [Incident case studies](#26-incident-case-studies) · 27. [Audit checklist](#27-audit-checklist) · 28. [Interview Q&A](#28-interview-qa) · [References](#references)

---

## 0. Mental Model & Threat Model

Containers are **not** a security boundary by default — they are process isolation via Linux
**namespaces + cgroups + capabilities + seccomp/LSM**, all sharing **one host kernel**. A container
escape is a kernel/`runc` problem, not a hypervisor one. Security is *defense in depth* across five
planes:

| Plane | You defend | Primary controls |
|:--|:--|:--|
| **Build** | The image & how it's produced | Minimal base, multi-stage, no secrets in layers, SBOM, reproducibility |
| **Ship** | Integrity in transit & at rest | Signing, provenance (SLSA), trusted registry, vuln gating, admission |
| **Run** | The live container & host | Non-root, cap-drop, seccomp/LSM, read-only FS, sandboxed runtimes, kernel hardening |
| **Observe** | The breach you didn't prevent | Falco/Tetragon, drift detection, forensics, IR |
| **Govern** | Provable, repeatable assurance | CIS/NIST/STIG/PCI/FIPS, policy-as-code, evidence |

**Golden rule:** *shift left, but don't trust left.* Prevent at build/admission time **and** watch at
runtime — prevention always leaks (Leaky Vessels; the Nov-2025 runc trio — §26).

> 💬 **Soundbite:** "A container shares the host kernel, so I treat isolation as defense-in-depth.
> I harden the build, sign and verify the supply chain, drop privileges and sandbox at runtime, and
> run eBPF detection + enforcement to catch what slips through."

---

# Part I — BUILD

## 1. Base Image Selection

Attack surface scales with package count. Preference order:
**`scratch` → distroless → Chainguard/Wolfi → `alpine` → `-slim` → full OS.**

| Option | What it is | Notes |
|:--|:--|:--|
| **`scratch`** | Empty image | Static binaries (Go/Rust `CGO_ENABLED=0`). No shell/libc. |
| **Distroless** (`gcr.io/distroless/*`) | Runtime-only | Variants `static`/`base`/`cc`/language; `:nonroot` (uid 65532), `:debug` (busybox). No shell/pkg-mgr. |
| **Chainguard / Wolfi** | Minimal "undistro" (built via `apko`/`melange`) | Near-zero CVE, **rebuilt within ~hours** of upstream fixes, SBOM+provenance built in, **700+ FIPS variants** (STIG-hardened, OSCAP reports, OpenSSL FIPS CMVP #4282). |
| **Docker Hardened Images (DHI)** | Docker's hardened catalog | Free/OSS (Apache-2.0) since **Dec 17 2025**; non-root default, SLSA provenance, signed **VEX** attestations. |
| **Alpine** | musl+busybox ~5 MB | Tiny but has shell/apk; musl glibc-compat quirks (DNS). |
| **`-slim`** | Trimmed glibc distro | Best compatibility, larger. |

**Language-native, daemonless, reproducible builders (no Dockerfile):** `ko` (Go), `jib` (Java),
Cloud Native Buildpacks/Paketo, `apko`/`melange` (Wolfi).

**Pin by digest, never `latest`** (`python:3.12-slim@sha256:…`). Solve the CVE-vs-reproducibility
tension with **automated** digest bumps: **Renovate** / **Dependabot** / **Digestabot** open PRs →
CI validates → rebuild → rescan → merge on green.

---

## 2. Dockerfile Hardening & Anti-Patterns

Golden multi-stage Go image (build tooling never reaches the final image):
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

| Anti-pattern | Why | Fix |
|:--|:--|:--|
| `ADD` for local/remote | Auto-extracts tars, fetches URLs (SSRF/tamper) | `COPY`; fetch with `curl … && sha256sum -c` |
| `ONBUILD` triggers | Hidden downstream execution | Avoid in shared bases |
| Unpinned apt/apk/pip/npm | Non-reproducible, cache-poisonable | Pin + hash: `pip --require-hashes`, `npm ci`, `go mod verify` |
| Secrets in `ENV`/`ARG`/`COPY` | Persist in layers & `docker history`; leak in `mode=max` provenance | BuildKit secret mounts (§3) |
| Cache left in layer | Bloat | `--no-install-recommends` + `rm -rf /var/lib/apt/lists/*` same `RUN` |
| Root at runtime | Escalation on escape | Create user + `USER` |
| No `.dockerignore` | Leaks `.git`/`.env`/keys into context | Strict `.dockerignore` |
| Shell-form `CMD`/`ENTRYPOINT` | Bad signal handling | Exec form `["…"]` |

---

## 3. BuildKit Advanced (Mounts & Attestations)

All `RUN --mount` types need `# syntax=docker/dockerfile:1` (BuildKit default in Engine 23.0+). The
frontend is a sandboxed image pulled per build → **Dockerfile features ship independently of the
daemon**; `:1` auto-gets bugfixes, pin a digest for reproducibility.

**`--mount=type=cache`** — persistent scratch on the **builder host**; reattached across builds even
when the RUN layer rebuilds. **Not part of the layer cache, not exported by `--cache-to`** → needs a
persistent builder (or a build service) to survive ephemeral CI. Never rely on its contents.
`sharing`: `shared`(default)/`private`/`locked` (use `locked` for apt/dpkg). Set `uid`/`gid` for
non-root writers.
```dockerfile
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && apt-get update && apt-get install -y gcc
```

**`--mount=type=secret`** — exposed only for one `RUN`; default `/run/secrets/<id>`, mode `0400`;
`required=true`; `env=` form (frontend v1.10+). Predefined `GIT_AUTH_TOKEN`/`HTTP_AUTH_*` for private
contexts.
```dockerfile
RUN --mount=type=secret,id=npmtoken NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```
`docker build --secret id=npmtoken,src=$HOME/.npmtoken .`

**`--mount=type=ssh`** (default id, socket mode `0600`) for private git deps:
`docker buildx build --ssh default=$SSH_AUTH_SOCK .`
**`--mount=type=bind`** (read-only default, `from=<stage>`, `rw` discarded) · **`type=tmpfs`** (`size=`).

**Selective bust:** `--no-cache-filter builder,test` (vs `--no-cache` all). **HEREDOC** (stable in
`dockerfile:1.4`) collapses multi-line `RUN` into one layer.

**Attestations** — in-toto JSON in the image index. **Requires the `docker-container` buildx driver +
push to a registry**; the default `docker` driver/exporter adds none and can't load attested indexes.
- **Provenance (SLSA):** `mode=min` default-on (container driver); **`mode=max` exposes build-ARG
  values + base64 Dockerfile** — never pass secrets as ARGs. Disable globally with
  `BUILDX_NO_DEFAULT_ATTESTATIONS=1`.
- **SBOM:** `--sbom=true` (Syft, SPDX); expand with `ARG BUILDKIT_SBOM_SCAN_CONTEXT/STAGE=true`.
```bash
docker buildx create --driver docker-container --use
docker buildx build --provenance=mode=max --sbom=true -t org/app:1.0 --push .
```

---

## 4. Reproducible & Multi-Arch Builds

- **Reproducibility** makes provenance meaningful: pin base digests, lockfile+hash-pin deps,
  `SOURCE_DATE_EPOCH` to normalize timestamps, `-trimpath`/`-ldflags="-s -w"`, avoid nondeterminism →
  byte-identical rebuilds enable independent verification.
- **Multi-arch:** `docker buildx build --platform linux/amd64,linux/arm64 --push` produces an OCI
  image index via QEMU or native build nodes. Enterprises run **native build farms** (avoid slow
  emulation; per-arch provenance).

---

# Part II — SHIP

## 5. Supply Chain: SBOM & SLSA

| Control | Tool | Gives you |
|:--|:--|:--|
| **SBOM** | Syft, `docker sbom`, Trivy | Every package (SPDX or CycloneDX) |
| **Provenance** | BuildKit `--provenance`, SLSA | Tamper-evident source+builder record |
| **Signing** | Cosign / Notation | Cryptographic proof of origin |
| **VEX** | OpenVEX + scanners | CVEs *not exploitable in context* → cuts noise |

### SLSA v1.0 Build Levels (memorize)
| Level | Requirement | Guarantee |
|:--|:--|:--|
| **L1** | Provenance exists | Auditability only — **forgeable** |
| **L2** | Hosted platform + **signed** provenance | Deters unsophisticated attackers |
| **L3** | **Isolated** build; **signing key unreachable by build steps**; ephemeral per-build env; no cross-build cache poisoning | Non-forgeable provenance |
Cumulative. **SLSA v1.1 approved Apr 2025** (clarifications, non-breaking). GitHub Artifact
Attestations, `slsa-github-generator`, and Google Cloud Build reach **L3**.

**SBOM formats:** **SPDX** (ISO/IEC 5962; 3.0 graph-based/profiles, Apr 2024) favored for
license/regulatory; **CycloneDX** (OWASP → now Ecma TC54; 1.6 Apr 2024, adds CBOM + native VEX +
attestations) favored for security. Tooling (Syft/Trivy) emits both. **SPDX↔CycloneDX conversion is
lossy** (protobom/`sbom-convert`/`cyclonedx-cli`) — never assert round-trip fidelity.

---

## 6. Signing & Verification

### Sigstore / Cosign — keyless (modern default)
No long-lived keys. **Fulcio** issues a short-lived (~10 min) cert binding an ephemeral key to an
**OIDC** identity → sign → record in **Rekor** (append-only transparency log; **Rekor v2 GA 2025**,
tile-based). Private key lives in memory only. Roots of trust for Fulcio/Rekor distributed via **TUF**
(supports private/air-gapped roots). Monitor with **rekor-monitor** (consistency proofs + alert on
unexpected use of *your* signing identity).
```bash
cosign sign <registry>/app@sha256:<digest>          # keyless (CI OIDC)
cosign verify <image> \
  --certificate-identity-regexp 'https://github.com/org/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Forging requires compromising OIDC **and** Fulcio **and** Rekor simultaneously.

### Notation (Notary Project / "Notary v2")
Spec-driven, built on **X.509 cert chains** (enterprise PKI, not TUF); supports **multiple signatures**
(vendor + internal approval); OCI-standard signatures in the registry. Choose for PKI/multi-party;
Cosign for dev-friendly keyless.

### Docker Content Trust is retired — migrate off
Deprecation began **Mar 31 2025**; certs expired **Aug 8 2025**; no new registries after
**Sep 30 2025**; data deleted **Mar 31 2028**. Azure ACR: DCT can't be enabled on new registries from
**May 31 2026**, removed **Mar 31 2028**. Migrate to **Cosign or Notation**.

---

## 7. SBOM & Attestation Operations at Scale

- **in-toto / DSSE:** DSSE Envelope → Statement (`_type: https://in-toto.io/Statement/v1`, `subject`
  digests, `predicateType`) → Predicate. PAE signs both payload + type (anti type-confusion).
- **Predicate types:** SLSA provenance `https://slsa.dev/provenance/v1`, **VSA**
  `https://slsa.dev/verification_summary/v1`, SPDX, CycloneDX, VEX, test results.
- **VSA (Verification Summary Attestation):** a trusted verifier records a prior verification (incl.
  transitive `dependencyLevels`) so consumers skip re-verifying.
- **OCI Referrers API (Image/Distribution 1.1):** attach SBOMs/signatures/attestations to an image via
  `/v2/<name>/referrers/<digest>` — no extra tags. Attach with `oras attach`, list with
  `oras discover`. Supported by Quay, ACR, ECR (Harbor in progress).
- **Storage/query at scale:** **OWASP Dependency-Track** (ingest CycloneDX once, monitor continuously
  against NVD/OSV/GHSA — new CVEs surface against shipped images without rescanning) and **GUAC**
  (graph of SBOMs/provenance; `guacone query vuln/dependents` for blast-radius).
```bash
syft $IMG -o cyclonedx-json=sbom.cdx.json
cosign attest --type cyclonedx --predicate sbom.cdx.json --new-bundle-format $IMG
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github.com/ORG/repo/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $IMG
```
> ⚠️ `cosign attach sbom` is deprecated → use attestations. cosign **v3** split `spdx` (tagvalue) vs
> `spdxjson`; flags churn — pin to your installed version.

**Regulatory drivers:** US **CISA 2025 Minimum Elements** (draft; adds component hash, license, tool
name, generation context, transitive coverage — *verify final publication*). EU **CRA** in force
Dec 2024; 24-h exploited-vuln reporting to ENISA from **Sep 11 2026**; full compliance (SBOM,
secure-by-design, CE) by **Dec 11 2027**; penalties up to €15M / 2.5% turnover.

---

## 8. Registry Hardening

Harbor (CNCF, self-hosted) or cloud (ECR/GAR/ACR):
- **RBAC + robot/service accounts** — CI uses scoped, **expiring** tokens per project; cloud uses
  least-privilege IAM + short-lived OIDC (no stored password).
- **Tag immutability** — forbid overwrite; **deploy by digest**. (ECR added immutability *exceptions*
  Jul 2025; ACR uses per-repo write-lock.)
- **Retention & GC** — e.g. "keep last 5 `prod-*`, delete unpulled >30 d".
- **Built-in scanning** — Harbor ships **Trivy** on by default; **quarantine** on CVE threshold.
- **Content-trust policy** — only signed (Cosign/Notation) artifacts pullable.
- **Network** — private endpoints/Private Link/VPC-SC; TLS; replication for DR.

---

## 9. Vulnerability Management Program

> **This is the section a shallow guide gets wrong.** Two 2026 shifts break the old "sort by CVSS,
> patch CRITICALs" playbook:

1. **NVD enrichment collapse (permanent).** From **Apr 15 2026**, NIST enriches only CVEs in **CISA
   KEV**, federal-gov software, and EO-14028 critical software (~15–20% of volume). Everything else:
   no CVSS/CPE/CWE. **You cannot depend on NVD** — pull from **OSV.dev** (fastest, PURL-precise),
   **GHSA**, and distro feeds (Alpine secdb, Debian, RHEL OVAL, Ubuntu USN — essential for
   *backport-patched* packages). Union of NVD+OSV+GHSA ≈ 98% coverage → **multi-feed scanners win**.
2. **CISA BOD 26-04 (Jun 10 2026)** retires CVSS-deadline SLAs for a **risk matrix**: 4 variables —
   (1) publicly exposed, (2) in KEV, (3) automatable, (4) total vs partial technical impact — → 16
   tiers (3 days for KEV+total-control, up to "next upgrade"). Mirror these variables internally
   instead of raw CVSS.

**Prioritize:** `KEV (act now) → EPSS (percentile/prob cut, e.g. ≥0.95 pctl) → reachability/exposure
→ CVSS-BTE`. **EPSS v4** (2025) = daily-refreshed exploitation probability; never a standalone risk
score. **CVSS v4.0** adds Attack Requirements + Supplemental group (only CVSS-B = half the picture).
**Reachability** (Endor/Snyk function-level; Wiz/Prisma runtime) deprioritizes CVEs your code never
calls — the biggest noise reducer.

**VEX** (OpenVEX): statuses `not_affected`/`affected`/`fixed`/`under_investigation`; `not_affected`
needs a justification enum (`vulnerable_code_not_in_execute_path`, etc.). Distribute via **VEX Hub**,
OCI attestation (`cosign attest --type openvex`), or internal repo; consume with
`trivy --vex` / `grype --vex` / Docker Scout (auto, zero-config). Prefer VEX over opaque
`.trivyignore` (govern residual ignores with **reason + expiry** in `.trivyignore.yaml`).

**Scanners:** run **two and reconcile** — **Trivy** (higher recall, more backport FPs) + **Grype**
(precise, lower FP). **Docker Scout** for Docker-centric + auto-VEX. **Wiz/Prisma (CNAPP)** correlate
image↔running↔exposure↔data for best noise reduction at scale.

**Remediate:** rebuild by default (clean provenance); **Project Copacetic (`copa patch`)** applies
OS-package fixes as one patch layer for **emergency KEV turnaround** without a rebuild (OS packages
only — app deps still need rebuild). Scan at **build (gate) + continuously in registry** (CVE data
changes even when the image doesn't).

---

## 10. Admission Control & Deploy-Time Gating

Enforce policy *before* a workload runs — the choke point for everything above.

| Engine | Language | Strengths |
|:--|:--|:--|
| **Pod Security Admission** | built-in labels | Baseline/Restricted; zero-install, coarse |
| **OPA Gatekeeper** | **Rego** | Powerful, portable; validation-focused |
| **Kyverno** | **YAML** | Validate + mutate + generate + **verifyImages** (Cosign/Notary); lightweight |
| **ValidatingAdmissionPolicy** | **CEL** (in-tree) | **GA v1.30**; no controller; Deny/Warn/Audit |

**Enforce:** block `:latest`, `runAsNonRoot:false`, `privileged`, `hostPath`/`hostNetwork`/`hostPID`;
require dropped caps + `readOnlyRootFilesystem` + resource limits; **require a valid signature +
SLSA-provenance attestation** and an approved-registry allowlist.

**Signature/provenance verification at admission:** Kyverno `verifyImages`/`ImageValidatingPolicy`,
sigstore **policy-controller** (`ClusterImagePolicy`, CUE/Rego), **Connaisseur**, **Ratify**. Pair
with **zero-trust workload identity** (SPIFFE/SPIRE, IRSA / GKE Workload Identity) so pods
authenticate without static creds. Gate **in-pipeline** (`slsa-verifier`/`cosign` non-zero fails the
deploy) **and** at admission — defense in depth.

---

# Part III — RUN

## 11. Runtime Least Privilege

| Control | Flag | Why |
|:--|:--|:--|
| Non-root | `--user 65532` | Never run app as root |
| Drop caps | `--cap-drop=ALL` + minimal add | Removes Docker's ~14 default caps |
| No new privs | `--security-opt=no-new-privileges` | Blocks setuid escalation (`PR_SET_NO_NEW_PRIVS`) |
| Read-only rootfs | `--read-only` + `--tmpfs /tmp` | Immutable runtime |
| seccomp | default / custom | Shrinks syscall surface |
| AppArmor/SELinux | `docker-default` / profile | MAC confinement |
| Limits | `--cpus`/`--memory`/`--pids-limit` | Fork-bomb & noisy-neighbor DoS |
| No `--privileged` | never in prod | All caps + devices = trivial escape (disables seccomp/AppArmor even if named) |
| No socket mount | avoid `-v /var/run/docker.sock` | = host root |

**Dangerous capabilities — never grant casually:** **CAP_SYS_ADMIN** ("the new root" — mount,
namespaces), **CAP_SYS_MODULE** (load kernel modules → escape), **CAP_SYS_PTRACE** (bypass seccomp,
lethal with shared host PID ns), **CAP_DAC_READ_SEARCH** (Shocker `open_by_handle_at`),
**CAP_NET_RAW** (ARP/DNS spoof), CAP_NET_ADMIN, CAP_SETUID/SETGID, CAP_SYS_BOOT/TIME. Safe common
add-back: **NET_BIND_SERVICE**.

```bash
docker run -d --user 65532:65532 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/etc/docker/seccomp/app.json \
  --pids-limit=200 --cpus=1 --memory=512m --memory-swap=512m myapp:1.2.3
```
Docker's **default seccomp** blocks ~44–50+ syscalls (`kexec_load`, `perf_event_open`, `add_key`,
`unshare`, `mount`, ns-creation). `seccomp=unconfined` disables it — avoid.

---

## 12. Kernel & LSM Hardening Internals

**Namespaces** (`clone`/`unshare`/`setns`; `/proc/PID/ns/`): mnt, pid, net, **user**, cgroup, uts,
ipc, time. Docker enables mnt/uts/ipc/pid/net by default; **user ns is opt-in**. Escape-relevant:
bind-mounting host paths (mnt), `--pid=host`/`--net=host`, and **nf_tables inside a netns** (the single
largest LPE surface behind userns).

**LSMs:** one *major/exclusive* (SELinux | AppArmor | Smack) + stackable *minor* (capability, YAMA,
LoadPin, SafeSetID, **BPF-LSM**, **Landlock**). SELinux (`container_t` + MCS) is strongest/complex;
AppArmor (`docker-default`) is path-based/simpler. **Landlock** = unprivileged self-sandboxing (ABI
1→8 across kernels 5.13→7.0).

**seccomp deep:** return actions high→low `KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF >
TRACE > LOG > ALLOW`. **User-notification** lets a supervisor emulate syscalls (runc/crun use it for
`mount`) — **TOCTOU caveat:** `seccomp_data` carries register values not deref'd pointers → re-read
`/proc/PID/mem` + `NOTIF_ID_VALID`. Generate profiles with **oci-seccomp-bpf-hook**, **Inspektor
Gadget**, or **Security Profiles Operator**.

**KSPP sysctls (container-relevant):**
```
kernel.kptr_restrict=2      kernel.dmesg_restrict=1     kernel.modules_disabled=1
kernel.kexec_load_disabled=1  kernel.yama.ptrace_scope=3  kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2   vm.unprivileged_userfaultfd=0  user.max_user_namespaces=0*
fs.protected_symlinks=1  fs.protected_hardlinks=1  fs.suid_dumpable=0
```
`*` disabling userns conflicts with rootless/K8s — see §13. **Kernel Lockdown LSM** (boot-set,
irreversible): `integrity` (block kernel modification) / `confidentiality` (+ block kernel-mem
readback → defeats KASLR leaks). Verify with **kernel-hardening-checker**.

**cgroups v2:** `memory.max`/`memory.high` (`--memory`), `pids.max` (`--pids-limit`, **fork-bomb
defense**), `cpu.max` (`--cpus`), `io.max`. **Device control is now eBPF** (`BPF_PROG_TYPE_CGROUP_DEVICE`;
v1 `devices.allow` gone). v2 removed `release_agent` from delegated subtrees → closed the classic v1
cgroup escape.

---

## 13. Rootless & User Namespaces

- **userns-remap:** *daemon still root*, container UID 0 → unprivileged host UID (`/etc/subuid`).
  Keeps full features; mitigates container-root = host-root.
- **Rootless:** *daemon itself* unprivileged. Strongest, with trade-offs: networking via
  `slirp4netns` (5–10% NAT overhead; newer **`pasta`** avoids NAT); **ports <1024 blocked** by
  default; **resource limits need cgroup v2 + delegation** (only memory+pids delegated by default —
  no CPU limit without full delegation); AppArmor/overlay-networks/`--privileged`/checkpoint
  unsupported (so **Swarm is effectively non-functional rootless**).

⚠️ **The userns tension:** unprivileged user namespaces are the rootless enabler **and** a major LPE
surface (Edera 2026: +262% reachable kernel ops; ~43% of userns-gated CVEs are nf_tables). KSPP/Edera
advise disabling them; K8s (2025) and rootless *depend* on them. Ubuntu 24.04 gates them per-binary
via AppArmor (Qualys disclosed 3 bypasses in 2025). **Present as an environment-dependent trade-off,
not a blanket "disable."** Two distinct knobs: `kernel.unprivileged_userns_clone=0` (Debian/Ubuntu
only) + `user.max_user_namespaces=0` (mainline/RHEL).

---

## 14. Sandboxed Runtimes

When container isolation isn't enough (untrusted/AI-generated code, hostile multi-tenancy), swap the
OCI runtime:

| Runtime | Mechanism | Isolation | Cost | Use when |
|:--|:--|:--|:--|:--|
| **runc** | namespaces/cgroups | baseline | none | Trusted internal |
| **gVisor** (`runsc`) | userspace kernel "Sentry" intercepts syscalls | strong, no VM | ~34% net hit; syscall-compat gaps | Medium-threat multi-tenant (GKE Sandbox, "Agent Sandbox" for AI code) |
| **Kata** | lightweight VM per pod, own kernel (`RuntimeClass`) | hardware | ~6% net hit | High-threat, production-ready |
| **Firecracker** | minimal Rust microVM (~5 MiB, ~125 ms cold start) | hardware | needs orchestration | Serverless/FaaS (Lambda/Fargate); usually via Kata |
| **Sysbox** | extends runc | enhanced, no `--privileged` | low | Rootless DinD, CI runners, systemd-in-container |

Guidance: **low/internal → runc; medium multi-tenant → gVisor; high/untrusted → Kata or Firecracker.**

---

## 15. Secrets Management

**Never in a layer/`docker history`.** Build-time → BuildKit `--mount=type=secret`. Runtime → a store.

| Tool | Model | Notes |
|:--|:--|:--|
| **Vault Agent Injector** | sidecar renders to shared-mem volume | App stays Vault-unaware; best for **dynamic secrets** + lease renewal |
| **Vault CSI / Secrets Operator** | CSI mount / CRD sync | **CSI keeps secrets out of etcd**; HashiCorp now recommends **VSO** as default |
| **External Secrets Operator** | syncs cloud managers → K8s Secrets | 40+ providers; easiest with cloud secret managers |
| **SOPS** (CNCF) | file encryption (KMS/`age`) | GitOps-native (Flux/ArgoCD); portable |
| **SPIFFE/SPIRE** | workload identity (SVIDs) | Keyless auth; solves secret-zero |

**Dynamic secrets (Vault):** DB engine mints a fresh per-request user (TTL 15–30 m), PKI issues
short-lived certs, cloud engines mint STS creds. `database/rotate-root` so no human holds the
bootstrap password. Auth via **Kubernetes auth** (TokenReview — catches revocation) over
JWT/OIDC/AppRole (AppRole reintroduces secret-zero).

**The secret-zero problem** → **workload identity**: derive the first credential from platform
attestation, not a stored key. **SPIFFE/SPIRE** (node + workload attestation → auto-rotated SVIDs);
cloud federation (**AWS IRSA / EKS Pod Identity**, **GKE Workload Identity**, **Azure Workload
Identity**); **GitHub Actions OIDC → cloud** (`permissions: id-token: write`, lock the trust-policy
`sub` to `repo:ORG/REPO:ref:…`).

**Leaked-secret playbook (order matters):** **REVOKE/ROTATE FIRST**, then scrub history — deleting the
commit is *not* enough (earlier commits, clones, CI caches, and **forks** persist). Detect with
**TruffleHog** (verifies creds against live APIs) + **gitleaks** + GitHub push-protection; purge with
`git-filter-repo`/BFG + force-push; contact GitHub Support for cached/fork refs; audit usage.

**etcd encryption:** base64 ≠ encryption. Enable `EncryptionConfiguration` with a **KMS v2** provider
(envelope; v1 deprecated v1.28, off by default v1.29+); re-encrypt existing Secrets
(`kubectl get secrets -A -o json | kubectl replace -f -`); verify `k8s:enc:kms:v2:` prefix.

---

## 16. Network Security

- **Segment** with user-defined bridge networks (isolate by default) over the blunt `--icc=false`.
  Bind local-only ports to `127.0.0.1`. **Published ports bypass `ufw`** (DNAT in `nat` before
  `INPUT`) → put custom rules in the **`DOCKER-USER`** chain. Docker **29.0.0** adds an experimental
  **nftables** backend.
- **Daemon:** never `2375` plaintext; `2376` with **TLS mutual auth** (`--tlsverify`). Unauth API =
  host root. Prefer rootless + socket over SSH.
- **Kubernetes:** apply a **default-deny** NetworkPolicy per namespace day one, then allow-list
  (additive; both egress-of-sender and ingress-of-receiver must allow; `namespaceSelector`+`podSelector`
  in one `from` = AND). Vanilla NetworkPolicy can't do L7/FQDN/deny/logging.
  - **Cilium** (eBPF): FQDN/DNS-aware egress (`toFQDNs`), **L7 HTTP** rules (node-local Envoy),
    cluster-wide/host policies, Hubble. **Calico** v3.31 (late 2025): eBPF default, nftables GA,
    `GlobalNetworkPolicy` + `destination.domains`, HostEndpoint for node firewalling.
  - **In-cluster encryption:** WireGuard (preferred) / IPsec (FIPS). Caveat: traffic to
    not-yet-discovered endpoints may go unencrypted; same-node pod-to-pod is not encrypted.
  - **Service-mesh mTLS:** identity via **SPIFFE** SVIDs. **Istio Ambient** (GA; ztunnel L4 + waypoint
    L7, HBONE) or **Linkerd** (lighter, 24-h cert rotation, 2.19 post-quantum ML-KEM-768).
  - **Egress control / DNS anti-exfil:** egress gateways (static source IPs for external allow-listing);
    restrict which domains pods may *resolve* to kill DNS-tunnel C2.
- **Ingress:** terminate TLS (cert-manager); WAF (ModSecurity CRS / cloud) + rate limit.
  ⚠️ **`ingress-nginx` reached EOL Mar 24 2026** (no more CVE patches) — **migrate to Gateway API**
  (`ingress2gateway`) or kgateway/Envoy Gateway. Security-critical.

---

## 17. Host & Daemon Hardening

Audit against **CIS Docker Benchmark v1.8.0** (7 sections, 100+ recs) with **docker-bench-security**
or InSpec `dev-sec/cis-docker-benchmark`; K8s → **CIS Kubernetes Benchmark** + **kube-bench**.
- Run daemon **rootless/userns-remap**; restrict the root-equivalent **`docker` group**.
- **Minimal/container-specific host OS** (NIST 800-190): Bottlerocket, Flatcar, RHEL CoreOS.
- Harden `/etc/docker/daemon.json`:
  ```json
  { "icc": false, "userns-remap": "default", "no-new-privileges": true, "live-restore": true,
    "userland-proxy": false, "log-driver": "json-file", "log-opts": {"max-size":"10m","max-file":"3"} }
  ```
- **auditd** on `/usr/bin/dockerd`, `/etc/docker`, `/var/lib/docker` (CIS §1); correct socket/cert
  perms (§3). **Patch runc/BuildKit/Docker** promptly — escape CVEs live here (§26).

---

# Part IV — OBSERVE

## 18. Runtime Threat Detection

| Tool | Origin | Model | Distinctive |
|:--|:--|:--|:--|
| **Falco** | CNCF (graduated) | **detect/alert** | 70+ Falcosidekick integrations; the detection standard; *does not block* |
| **Tetragon** | Cilium (1.0 GA) | **detect + enforce** | In-kernel enforcement via eBPF/**LSM hooks** — kill/block *before* completion |
| **Tracee** | Aqua | **detect + forensics** | Deep event capture |

Falco rules = rules/macros/lists (YAML); custom rules in `/etc/falco/rules.d/` with `override`
(append/replace); plugins for `k8saudit`, `cloudtrail`, etc. Detect: shell-in-container, unexpected
egress, sensitive-file writes, privilege escalation, cryptominers, container-escape behavior.
Defense-in-depth trio: **Trivy** (scan) + **Kyverno/OPA** (admission) + **Falco/Tetragon** (runtime).

---

## 19. Runtime Enforcement & Drift Prevention

Falco is detection-only → route response downstream or enforce in-kernel:
- **Falco → Falcosidekick → Falco Talon** (response engine, reacts in ms): actionners
  `kubernetes:terminate`, `:networkpolicy` (quarantine isolate), `:label`, `:exec`,
  `:tcpdump`/`:sysdig` (forensics to S3). ⚠️ Talon is **pre-1.0** (v0.3.0) — validate before standardizing.
- **Tetragon enforcement** (`TracingPolicy` `matchActions`): **`Sigkill`** (kill process) + **`Override`**
  (`argError` — syscall never executes). **Combine both** — a `SIGKILL` alone doesn't guarantee the
  op didn't commit; `Override` needs `CONFIG_BPF_KPROBE_OVERRIDE`. Enforcement survives daemon restart
  (in-kernel). LSM hooks avoid the kprobe TOCTOU race.
- **KubeArmor** (CNCF sandbox): LSM inline policy (AppArmor/BPF-LSM/SELinux) — allow/audit/block
  process/file/network/caps; `defaultPosture` Audit by default, flip to **block** for zero-trust
  whitelist mode. Prefer BPF-LSM (kernel ≥5.7) over AppArmor backend.
- **Auto profile generation:** Inspektor Gadget / oci-seccomp-bpf-hook / **Security Profiles Operator**
  (record with `SCMP_ACT_LOG` → review → enforce `SCMP_ACT_ERRNO` → attach via `securityContext`).

**Drift prevention:** `readOnlyRootFilesystem: true` (enforce fleet-wide via Kyverno/PSA);
**distroless can't spawn a shell** (structurally blocks exec-based post-exploitation); Falco
container-drift rule (new executable in a running container). Escalation ladder: **Audit → Block
(KubeArmor) → in-kernel Override (Tetragon)**; feed findings back to admission-policy tightening.

---

## 20. Incident Response & Forensics

- **Preserve before killing:** `docker inspect` / `docker diff` / `docker logs`; `docker export`
  (filesystem); **CRIU checkpoint** (`docker checkpoint create`) to snapshot running state for memory
  forensics.
- **Debug distroless without shipping tools:** ephemeral debug containers (`kubectl debug`).
- **Immutable infra:** *redeploy, don't patch* — kill & quarantine (cordon node / NetworkPolicy
  isolate; Talon can automate), then rebuild from a clean, signed image.
- **Post-incident:** scan offending image/layers with TruffleHog/gitleaks; rotate exposed creds; feed
  back into admission policy. Ship logs to a SIEM (fluentd/fluent-bit); rotate to prevent disk-fill DoS.

---

# Part V — ORCHESTRATE

## 21. Docker Compose & Swarm Security

Hardened Compose service:
```yaml
services:
  web:
    image: nginx@sha256:<digest>
    user: "10001:10001"
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true", "seccomp=/etc/docker/seccomp-nginx.json"]
    pids_limit: 100
    ulimits: { nofile: {soft: 1024, hard: 2048} }
    tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]
    mem_limit: 256m
    cpus: 0.5
    healthcheck: { test: ["CMD","curl","-f","http://localhost/healthz"], interval: 30s, retries: 3 }
    secrets: [db_password]
secrets:
  db_password: { file: ./db_password.txt }
```
- ⚠️ Gotcha: modern Compose v2 honors `deploy.resources.limits`, but `deploy.restart_policy`/
  `placement`/`replicas` are **Swarm-only** (ignored by `compose up`). Use top-level
  `mem_limit`/`cpus`/`pids_limit` for non-Swarm certainty.
- Compose secrets mount as **files at `/run/secrets/<name>`**, per-service; **plain Compose does NOT
  encrypt at rest** (just bind-mounts) — real encryption needs Swarm or Vault. `configs:` = same but
  no tmpfs (non-sensitive only). Env vars leak (visible to all procs, logs, `docker inspect`).
- **Swarm:** `docker secret` → sent to manager over **mTLS**, stored in the **encrypted Raft log**,
  mounted on tmpfs, never env. mTLS between nodes (node certs rotate 90 d default; tighten with
  `--cert-expiry`). Rotate join tokens (`docker swarm join-token --rotate`); managers are crown jewels
  (odd number 3/5, no untrusted workloads). **`--autolock`** encrypts the Raft KEK at rest (manual
  `docker swarm unlock` per restart). Overlay data-plane is **not encrypted by default** →
  `--opt encrypted` (IPsec, ~12-h key rotation, CPU cost).
- ⚠️ **CVE-2025-62725**: path traversal in Compose `include` with OCI artifacts → upgrade Compose
  ≥ v2.40.2. Engine **v29** has breaking changes (min API 1.44; broke some Swarm DNS/legacy volume
  plugins) — pin/validate before upgrading a prod Swarm.
- **Swarm status:** Mirantis supports it through ~2030; little innovation since 2022 ("deprecated in
  spirit"). Keep existing Swarm; build new on **Kubernetes**.

---

## 22. Kubernetes Workload Security

**Restricted-compliant `securityContext`:**
```yaml
spec:
  automountServiceAccountToken: false
  securityContext:                 # pod-level
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    fsGroupChangePolicy: OnRootMismatch
    supplementalGroupsPolicy: Strict     # GA v1.35
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: app
      securityContext:             # container-level
        allowPrivilegeEscalation: false   # sets no_new_privs; forced true if privileged/CAP_SYS_ADMIN
        privileged: false
        readOnlyRootFilesystem: true      # best practice (beyond PSS)
        capabilities: { drop: ["ALL"] }   # add back only NET_BIND_SERVICE under Restricted
        seccompProfile: { type: RuntimeDefault }
      volumeMounts: [{ name: tmp, mountPath: /tmp }]
  volumes: [{ name: tmp, emptyDir: {} }]
```
- **Pod Security Standards:** Privileged ⊂ Baseline ⊂ Restricted. **Pod Security Admission** (GA v1.25,
  replaced PodSecurityPolicy removed v1.25) via namespace labels
  `pod-security.kubernetes.io/{enforce|audit|warn}: {…}` — **pin `-version`** so upgrades don't tighten
  silently; roll out warn/audit → enforce.
- **Version state:** seccomp `SeccompDefault` GA v1.27; AppArmor `appArmorProfile` field GA v1.30; user
  namespaces (`hostUsers: false`) beta/on-by-default v1.33 (verify GA per cluster);
  `supplementalGroupsPolicy` GA v1.35.
- **ServiceAccount tokens:** `automountServiceAccountToken: false`; bound/projected tokens (default
  v1.22, audience-scoped, auto-rotated, pod-bound); legacy long-lived secret tokens off since v1.24.
- **RBAC least-privilege:** namespaced Role+RoleBinding to a dedicated SA (never `default`); no
  wildcards; withhold danger verbs (`escalate`, `bind`, `impersonate`, `pods/exec`,
  `secrets get/list`, `nodes/proxy`); never `cluster-admin` to workloads.

---

# Part VI — GOVERN

## 23. Compliance & Standards

**NIST SP 800-190 — five risk areas + countermeasures:**
| Area | Risks | Countermeasures |
|:--|:--|:--|
| **Image** | vulns, config defects, embedded malware, **clear-text secrets**, untrusted images | scan+sign, secrets out of images, trusted bases |
| **Registry** | insecure connections, stale images, weak authN/Z | TLS, RBAC, prune, signed content-trust |
| **Orchestrator** | unbounded admin, poor net separation, mixed sensitivity, node trust | RBAC, segmentation, sensitivity-based scheduling |
| **Container** | runtime vulns, unbounded privilege, escape | cap-drop, seccomp/MAC, read-only, limits |
| **Host OS** | large surface, shared kernel | minimal container-specific OS, patching |
Maps to NIST 800-53, FedRAMP, DoD cATO.

**Other regimes:** **CIS Docker/K8s Benchmarks** (§17). **DISA STIG / Container Platform SRG** (DoD;
Iron Bank images; OSCAP evidence). **PCI-DSS 4.0.1** — only active version since Mar 31 2024,
future-dated 4.0 reqs mandatory **Mar 31 2025**: segment CDE (NetworkPolicy/namespaces), scan
pre-deploy, no `privileged`, least-privilege RBAC + security contexts, read-only rootfs, logging.
**FIPS 140-3** — validated crypto (RHEL UBI FIPS, **Chainguard FIPS** — OpenSSL FIPS provider
CMVP #4282; note FIPS-validated ≠ STIG-hardened ≠ CVE-free). **SOC 2 / ISO 27001** — pipeline
controls + evidence. **OpenSSF Scorecard / S2C2F**. **OWASP Docker Top 10** (D01–D10) & **Docker
Security Cheat Sheet** (Rules 0–13) as design/ops checklists. **NSA/CISA Kubernetes Hardening Guide
v1.2** (2022, still current).

Governance mechanics: policy-as-code enforces compliance **continuously**; collect evidence (signed
provenance, SBOMs, scan reports, admission logs, benchmark results).

---

## 24. CI/CD Hardening & SLSA L3

**Threat model — OWASP CICD-SEC Top 10:** **Poisoned Pipeline Execution** (D-PPE edits CI config;
I-PPE poisons referenced build scripts; 3PE = fork-PR code in shared CI), dependency confusion, cache
poisoning, compromised actions/runners. A build node inherits every secret it can reach. Real 2025
incidents: **`tj-actions/changed-files`** compromise, **Shai-Hulud** npm worm, GhostAction.

**GitHub Actions hardening:** **pin actions by full commit SHA** (org policy can enforce since
Aug 15 2025); least-privilege `permissions: {}` default + per-job grants; **OIDC to cloud** (no
long-lived secrets, lock trust-policy `sub`); avoid `pull_request_target` with untrusted checkout;
pass `github.event.*` via `env:` (anti script-injection); Environment protection rules for approvals;
pin reusable workflows by SHA. Native **`actions/attest-build-provenance`** = keyless SLSA provenance
→ **L3** when signing runs in GitHub's isolated control plane.

**SLSA Build L3 requires:** signed **non-forgeable** provenance + **isolated ephemeral** build env
where **the signing key is unreachable by build steps** + no cross-build cache poisoning. Achieve via
**`slsa-github-generator`** (⚠️ pinned by `@vX.Y.Z` tag, not SHA — intentional exception),
**Tekton Chains** (out-of-band signing), **Google Cloud Build** (platform-generated provenance).
GitLab SLSA L2 is GA; **L3 is Experiment-only** (18.3, flag off) — not production-ready.

**Verify:** `slsa-verifier verify-image` / `cosign verify-attestation` in-pipeline **and** Kyverno/
policy-controller at admission. **Ephemeral single-use runners** (JIT/ARC) are required for L3
isolation — standard self-hosted runners are not guaranteed clean.

**Source-side:** branch protection, signed commits, 2-person review, lockfiles + hash-pinned deps,
and a **private proxy/pull-through cache** (Artifactory/Nexus/CodeArtifact) + reserved org scope to
defeat dependency confusion.

---

## 25. Cloud Provider Container Security

| | **AWS** | **GCP** | **Azure** |
|:--|:--|:--|:--|
| Registry scan | ECR basic (OS) vs **Enhanced/Inspector** (OS+lang, continuous) | Artifact Analysis (on-push + continuous) | Defender for Containers (agentless MDVM, daily, multicloud incl. ECR/GAR) |
| Deploy gating | **Kyverno/Ratify** (EKS) or Lambda hook (ECS) — *no native gate* | **Binary Authorization** (native; attestation/Sigstore/SLSA/freshness; **CV every ≥24 h**, GKE) | `defender-admission-controller` (vuln gating) + **Azure Policy/Gatekeeper** |
| Workload identity | **IRSA** / **EKS Pod Identity** (no OIDC-provider limit, cross-cluster reuse) | **GKE Workload Identity** | **Entra Workload ID** (federated) |
| Signing | **AWS Signer + Notation**; **ECR managed signing** GA Nov 2025 (auto-sign on push) | Cosign/attestations + Binary Authorization | Notation (DCT deprecated) |
| Runtime | **GuardDuty Runtime Monitoring** (eBPF agent; Fargate sidecar) | GKE Sandbox (gVisor), Autopilot PSS-Baseline default | **Defender sensor** (eBPF, MITRE ATT&CK, drift block) |
| Hardening | Fargate: no `privileged`, read-only rootfs, distinct task vs execution roles | Autopilot: Shielded Nodes + Workload Identity + PSS-Baseline by default | Azure Policy built-in PSS initiatives |

All three: private endpoints (VPC/Private Link/VPC-SC), immutable tags, least-privilege pull, OIDC
federation from CI. Only **GCP Binary Authorization** is a first-class native admission gate;
AWS/Azure lean on Kyverno/Gatekeeper.

---

## 26. Incident Case Studies

### Leaky Vessels (Jan 2024) — container escape
| CVE | Component | Impact | Fix |
|:--|:--|:--|:--|
| **CVE-2024-21626** | runc ≤1.1.11 | FD leak / `process.cwd` → host access (CVSS 8.6) | **runc 1.1.12** |
| CVE-2024-23651/52/53 | BuildKit ≤0.12.4 | build-time breakout / host file deletion | **BuildKit 0.12.5** |
Aggregate: **Moby/Engine v25.0.2**, Docker Desktop 4.27.1.

### Nov 2025 runc trio (disclosed Nov 5 2025) — newest escape class
| CVE | Mechanism |
|:--|:--|
| **CVE-2025-31133** | `/dev/null`→symlink → runc bind-mounts attacker target RW → `/proc` write escape |
| **CVE-2025-52565** | `/dev/pts/$n`→`/dev/console` mount **before** maskedPaths applied |
| **CVE-2025-52881** | redirect `/proc` writes, bypass LSM relabel |
Fixed in **runc 1.2.8 / 1.3.3 / 1.4.0-rc.3**. **runc 1.1.x is EOL/unpatched — upgrade.** Same
mount-race/procfs-write family as Leaky Vessels; rootless + userns + no-new-privileges + read-only
rootfs + mandatory seccomp/AppArmor materially reduce impact.

### Supply-chain: **xz-utils (CVE-2024-3094, Mar 2024)** — multi-year backdoor in `liblzma` (tarball ≠
git source) → reproducible builds + SBOM + provenance would surface it. **GhostAction / tj-actions
(2025)** — compromised GitHub Action exfiltrating secrets → pin by SHA, least-priv token, OIDC.
**Shai-Hulud (2025)** — self-propagating npm worm → lockfiles, private proxy, scoped packages.

---

## 27. Audit Checklist

**Build** — minimal/distroless/Chainguard/DHI base pinned by digest, auto-bumped · multi-stage, no
build tools/secrets in final image · `.dockerignore` · BuildKit secret mounts · SBOM + scan gated on
fixable HIGH/CRITICAL (VEX-filtered).
**Ship** — signed (Cosign/Notation) + SLSA provenance · immutable tags + digest deploy · trusted
registry with RBAC + expiring robot accounts · two-scanner reconcile + continuous registry rescan.
**Run** — non-root `USER` · `--cap-drop=ALL` (+minimal) · `no-new-privileges` · read-only rootfs +
tmpfs · seccomp + AppArmor/SELinux · resource+PID limits · **no** `--privileged`/socket mount ·
rootless/userns · sandboxed runtime for untrusted · secrets from Vault/CSI/ESO/SOPS · default-deny
NetworkPolicy + mesh mTLS · daemon not exposed unauthenticated.
**Observe/Govern** — Falco/Tetragon + Talon/KubeArmor enforcement · centralized logging + rotation +
drift detection · admission (signed-only, no-root, limits) via Kyverno/Gatekeeper/VAP ·
runc/BuildKit/Docker patched (≥ Nov-2025 fixes) · host on minimal OS · docker-bench + kube-bench ·
compliance evidence collected.

---

## 28. Interview Q&A

- **Why isn't a container a security boundary?** Shares the host kernel; isolation is
  namespaces/cgroups/caps/seccomp/LSM. A kernel/runc bug (Leaky Vessels, Nov-2025 trio) breaks out →
  defense-in-depth; gVisor/Kata for untrusted code.
- **Secrets out of an image?** BuildKit `--mount=type=secret` at build; Vault/CSI/ESO at runtime.
  Never `ENV`/`ARG` (persist in layers, `docker history`, `mode=max` provenance).
- **`--cap-drop=ALL` then what?** Add back only what's needed (`NET_BIND_SERVICE`); never
  `CAP_SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`.
- **Rootless vs userns-remap?** Rootless = the *daemon* runs unprivileged (strongest;
  slirp4netns/pasta + cgroup-delegation trade-offs); userns-remap = daemon root, container UID 0 →
  unprivileged host UID.
- **SLSA levels?** L1 provenance exists (forgeable); L2 hosted+signed; L3 isolated builds + keys
  unreachable by build steps.
- **How do you trust an image in prod?** SBOM + SLSA provenance + Cosign signature verified at
  admission (Kyverno/policy-controller); deploy by digest; SLSA L3 build.
- **Cosign vs Notation?** Cosign keyless (OIDC/Fulcio/Rekor); Notation X.509/PKI, multi-signature.
  DCT retired 2025.
- **Falco vs Tetragon?** Falco detects/alerts; Tetragon enforces in-kernel (Sigkill+Override) via
  eBPF/LSM.
- **How do you prioritize CVEs now that NVD is gutted?** Multi-feed (OSV/GHSA/distro), KEV first, EPSS,
  reachability/exposure, BOD-26-04 risk variables — not raw CVSS.
- **Distroless vs Alpine vs Chainguard?** Distroless: no shell/pkg-mgr. Alpine: tiny, musl quirks.
  Chainguard/Wolfi: near-zero-CVE, daily rebuilds, SBOM + FIPS.
- **NIST 800-190 areas?** Image, registry, orchestrator, container, host OS.

---

## References

**Standards:** CIS Docker Benchmark https://www.cisecurity.org/benchmark/docker · NIST SP 800-190
https://csrc.nist.gov/pubs/sp/800/190/final · OWASP Docker Top 10 https://owasp.org/www-project-docker-top-10/
· OWASP Docker Cheat Sheet https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
· SLSA https://slsa.dev/spec/v1.0/levels · NSA/CISA K8s Hardening https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
· PCI-DSS https://www.pcisecuritystandards.org/ · DISA STIGs https://public.cyber.mil/stigs/ · KSPP https://kspp.github.io/Recommended_Settings.html

**Supply chain:** Sigstore https://docs.sigstore.dev/ · Notation https://notaryproject.dev/ · in-toto
https://github.com/in-toto/attestation · CycloneDX https://cyclonedx.org/ · SPDX https://spdx.dev/ ·
GUAC https://guac.sh/ · Dependency-Track https://dependencytrack.org/ · OpenVEX https://github.com/openvex/spec
· EPSS https://www.first.org/epss/ · CISA KEV https://www.cisa.gov/known-exploited-vulnerabilities-catalog
· BOD 26-04 https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk

**Build/runtime:** BuildKit https://docs.docker.com/build/ · Docker seccomp https://docs.docker.com/engine/security/seccomp/
· Rootless https://docs.docker.com/engine/security/rootless/ · capabilities(7) https://man7.org/linux/man-pages/man7/capabilities.7.html
· gVisor https://gvisor.dev/ · Kata https://katacontainers.io/ · Firecracker https://firecracker-microvm.github.io/
· Copacetic https://github.com/project-copacetic/copacetic · kernel-hardening-checker https://github.com/a13xp0p0v/kernel-hardening-checker

**Platform/detection:** Harbor https://goharbor.io/ · Kyverno https://kyverno.io/ · OPA Gatekeeper https://open-policy-agent.github.io/gatekeeper/
· Falco https://falco.org/ · Tetragon https://tetragon.io/ · KubeArmor https://kubearmor.io/ · Cilium https://cilium.io/
· Calico https://docs.tigera.io/ · Vault K8s https://developer.hashicorp.com/vault/docs/platform/k8s ·
External Secrets https://external-secrets.io/ · SPIFFE/SPIRE https://spiffe.io/ · slsa-github-generator https://github.com/slsa-framework/slsa-github-generator
· TruffleHog https://github.com/trufflesecurity/trufflehog · gitleaks https://github.com/gitleaks/gitleaks

**Incidents:** Leaky Vessels https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities ·
Nov-2025 runc trio https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/
· xz-utils CVE-2024-3094 https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094

---

*Derived and expanded from the [Docker Professional Cheatsheet](./README.md). Living documentation —
revisit when CIS/NIST/OWASP/SLSA update, when regulatory deadlines (EU CRA, PCI, CISA) shift, or when
new container-escape CVEs land.*
