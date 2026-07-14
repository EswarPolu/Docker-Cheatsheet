# 🛡️ Enterprise Docker DevSecOps — Best Practices & Security Guide

> A senior-engineer reference for building, shipping, and running containers securely at MNC scale.
> Written from the perspective of a 10+ year Docker/DevSecOps engineer. Optimized both as an
> operational checklist **and** as interview-prep material.
>
> Last reviewed: **July 2026** · Standards baseline: CIS Docker Benchmark **v1.8.0** (Aug 2025),
> NIST **SP 800-190**, OWASP **Docker Top 10** & Docker Security Cheat Sheet.

---

## 0. Mental Model & Threat Model

Containers are **not** a security boundary by default — they are process isolation using Linux
namespaces + cgroups + capabilities, all sharing **one host kernel**. A container escape is a
kernel/`runc` problem, not a hypervisor problem. Security is therefore *defense in depth* across
four planes:

| Plane | What you defend | Primary controls |
|:--|:--|:--|
| **Build** | The image and how it's produced | Minimal base, multi-stage, no secrets in layers, SBOM |
| **Ship** | Integrity in transit & at rest | Signing (Cosign), provenance (SLSA), trusted registry |
| **Run** | The live container & host | Non-root, cap-drop, seccomp/AppArmor, read-only FS |
| **Observe** | Detecting the breach you didn't prevent | Falco, audit logs, drift detection |

**The golden rule:** *shift left, but don't trust left.* Prevent at build/admission time, and still
watch at runtime — because prevention always leaks (see Leaky Vessels, §11).

> 💬 **Interview soundbite:** "A container shares the host kernel, so I treat isolation as
> defense-in-depth, not a wall. I harden the build, sign and verify the supply chain, drop
> privileges at runtime, and run Falco to catch what slips through."

---

## 1. Image & Build Security

### Principles
1. **Smallest viable base.** Attack surface scales with package count. Prefer, in order:
   `scratch` → `distroless` → `alpine` → `-slim` → full OS. Fewer packages = fewer CVEs = smaller
   blast radius and faster pulls.
2. **Pin by digest, never `latest`.** `latest` is mutable and non-reproducible.
   ```dockerfile
   FROM python:3.12-slim@sha256:<digest>
   ```
3. **Multi-stage builds** so compilers, SDKs, and build secrets never reach the final image.
4. **Non-root at runtime** — create a dedicated user and `USER` down (see §3).
5. **Layer & cache hygiene** — order instructions least-changing-first; clean caches *in the same layer*.
6. **`.dockerignore` always** — keeps `.git`, `.env`, keys, and `node_modules` out of the build context.

### Golden production Dockerfile (Go → distroless)
```dockerfile
# syntax=docker/dockerfile:1.7
# --- build stage ---
FROM golang:1.22@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER 65532:65532                      # nonroot, no shell, no package manager
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/app","healthcheck"]
ENTRYPOINT ["/app"]
```

### apt/apk cleanup pattern (Debian)
```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
```

### Docker Hardened Images (DHI) — 2025/2026 shift
Docker made its **1,000+ Hardened Image catalog free and open source (Apache 2.0) on Dec 17, 2025.**
DHIs ship near-zero-CVE, minimal, **non-root by default**, with built-in **SLSA provenance** and
signed **VEX attestations**. For enterprise work, prefer DHI or an internally-curated "golden image"
over pulling arbitrary community images.

> 💬 **Interview soundbite:** "I default to distroless or Docker Hardened Images, pin by digest,
> and use multi-stage builds so the final image contains only the binary and its runtime — no shell,
> no package manager, nothing for an attacker to pivot with."

---

## 2. Supply Chain Security (SLSA, SBOM, Signing)

The 2020s threat has moved *left* — attackers poison the build pipeline, not just prod (e.g. the
**GhostAction** GitHub Actions compromise, early 2025). Controls:

| Control | Tool | What it gives you |
|:--|:--|:--|
| **SBOM** (bill of materials) | `docker sbom`, Syft | Know every package in the image; feed scanners & audits |
| **Provenance** (how it was built) | BuildKit `--provenance`, SLSA | Tamper-evident record of source + builder (aim for **SLSA L3**) |
| **Signing** | Cosign / Sigstore | Cryptographic proof of origin; verify before deploy |
| **VEX** | OpenVEX + Docker Scout | Declares which CVEs are *not exploitable* in context, cutting noise |

### Keyless signing with Cosign (Sigstore)
Modern practice is **keyless** — no long-lived keys to leak. Authenticate via OIDC, get a
short-lived certificate, sign, and log to the transparency log:
```bash
# sign (keyless, in CI with OIDC identity)
COSIGN_EXPERIMENTAL=1 cosign sign <registry>/app@sha256:<digest>

# generate SBOM + attach as attestation
syft <image> -o spdx-json > sbom.spdx.json
cosign attest --predicate sbom.spdx.json --type spdxjson <image>

# verify at deploy / admission time
cosign verify <image> --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Build with provenance + SBOM in one shot
```bash
docker buildx build --sbom=true --provenance=mode=max -t <registry>/app:1.2.3 --push .
```

> 💬 **Interview soundbite:** "Supply chain security is SBOM + provenance + signing. I build with
> BuildKit provenance, generate a Syft SBOM, sign keylessly with Cosign, and enforce
> `cosign verify` at admission so unsigned or tampered images never deploy."

---

## 3. Runtime Hardening (Least Privilege)

This is where most real-world containers fail. The runtime checklist:

| Control | Flag / setting | Why |
|:--|:--|:--|
| **Non-root user** | `USER 65532` / `--user` | Container-root ≠ host-root only *with* userns; still, never run app as root |
| **Drop all caps** | `--cap-drop=ALL` then `--cap-add=` only needed | Removes ~default 14 caps; most apps need none |
| **No privilege escalation** | `--security-opt=no-new-privileges` | Blocks setuid escalation inside the container |
| **Read-only root FS** | `--read-only` + `--tmpfs /tmp` | Immutable runtime; write only to explicit volumes |
| **Seccomp** | default profile (blocks ~50 syscalls) or custom | Shrinks kernel attack surface |
| **AppArmor / SELinux** | `docker-default` or custom profile | MAC confinement of files/network/caps |
| **PID / resource limits** | `--pids-limit`, `--cpus`, `--memory` | Contain fork bombs & noisy-neighbor DoS |
| **No `--privileged`** | *never in prod* | Grants all caps + device access = trivial escape |
| **No Docker socket mount** | avoid `-v /var/run/docker.sock` | Mounting the socket = root on the host |

### Hardened `docker run`
```bash
docker run -d \
  --user 65532:65532 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/etc/docker/seccomp/app.json \
  --pids-limit=200 --cpus=1 --memory=512m --memory-swap=512m \
  --restart=on-failure:3 \
  myapp:1.2.3
```

### Rootless Docker vs userns-remap (know the difference — common interview trap)
- **userns-remap**: the *daemon still runs as root*, but container UID 0 maps to an unprivileged host
  UID. Keeps full Docker features; mitigates container-root = host-root.
- **Rootless mode**: the *daemon itself* runs as a non-root user inside a user namespace. Strongest
  posture, but has trade-offs (networking via slirp is slower, some storage drivers/ports <1024,
  cgroup limits need delegation). Prefer rootless for multi-tenant / untrusted workloads.

> 💬 **Interview soundbite:** "My runtime baseline is: non-root, `--cap-drop=ALL`,
> `no-new-privileges`, read-only rootfs with a tmpfs, a seccomp profile, and resource limits.
> `--privileged` and mounting the Docker socket are hard no's — both are effectively host root."

---

## 4. Secrets Management

**Secrets must never land in an image layer or `docker history`.** `ENV`, `ARG`, and `COPY .env`
all persist and are trivially extractable.

| Need | Do | Don't |
|:--|:--|:--|
| Build-time (private repo token, npmrc) | BuildKit `RUN --mount=type=secret` | `ARG TOKEN=` / `ENV TOKEN=` |
| Runtime config | Injected env / mounted file from orchestrator | Baked into image |
| Enterprise secrets | HashiCorp Vault, AWS/GCP/Azure KMS, External Secrets | Committing to git / registry |

### BuildKit build secret (not persisted to layers)
```dockerfile
# syntax=docker/dockerfile:1.7
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```
```bash
docker build --secret id=npmtoken,src=$HOME/.npmtoken .
```

> 💬 **Interview soundbite:** "Secrets never go in `ENV`/`ARG` — they persist in layers and
> `docker history`. Build-time secrets use BuildKit `--mount=type=secret`; runtime secrets come from
> Vault or the platform's secret store, mounted at runtime."

---

## 5. Networking Security

- **Segment with user-defined bridge networks**; don't put unrelated services on the default bridge.
  User-defined networks give embedded DNS *and* isolation.
- **Prefer granular per-network isolation over the blunt `--icc=false`.** OWASP now recommends
  designing explicit networks and attaching only the containers that must talk, rather than globally
  disabling inter-container comms.
- **Publish ports explicitly and narrowly** — bind to `127.0.0.1` when only local access is needed:
  `-p 127.0.0.1:8080:8080`.
- **Encrypt the Docker daemon socket** if remote access is required: TLS **mutual auth**
  (`--tlsverify`), never expose `tcp://0.0.0.0:2375` (unauthenticated = instant host compromise).
- **Control egress** — default-deny outbound where possible; a compromised container shouldn't be
  able to exfiltrate or beacon out.

---

## 6. Host & Daemon Hardening (CIS Docker Benchmark)

The **CIS Docker Benchmark v1.8.0** (Aug 2025, covers Docker Server **v28**) is the authoritative
config baseline — 7 sections, 100+ recommendations. Audit with **docker-bench-security**.

**High-value host/daemon items:**
- Run the daemon **rootless** or with **userns-remap**; restrict membership of the `docker` group
  (it's root-equivalent — anyone in it can mount `/` into a container).
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
- Use a **container-specific / minimal host OS** (NIST SP 800-190 recommendation) — Bottlerocket,
  Flatcar, RHEL CoreOS — read-only rootfs, minimal packages.
- **Audit the Docker daemon & files** with `auditd` (CIS §1): watch `/usr/bin/dockerd`,
  `/etc/docker`, `/var/lib/docker`.
- **Keep Docker/runc/BuildKit patched** — container-escape CVEs land here (see §11).
- Set correct **file permissions/ownership** on daemon socket, config, TLS certs (CIS §3).

```bash
# quick self-audit
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc:/etc:ro docker/docker-bench-security
```

---

## 7. Vulnerability Management (Shift-Left Scanning)

Scan **continuously**: in dev, in CI (gate the build), and continuously in the registry (new CVEs
appear for images you already shipped).

| Scanner | Notes |
|:--|:--|
| **Docker Scout** | Native to Docker CLI/Desktop; applies VEX from DHI with zero config |
| **Trivy** | Ubiquitous OSS; images, IaC, SBOM; VEX via VEX Hub |
| **Grype** | Fast OSS SBOM-driven scanning; `--vex` flag |

```bash
docker scout cves myapp:1.2.3                 # CVEs with fixable/exploitable context
docker scout recommendations myapp:1.2.3      # base-image upgrade advice
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:1.2.3   # CI gate
```

**Policy:** fail CI on `HIGH`/`CRITICAL` **fixable** CVEs. Use **VEX/OpenVEX** attestations to
suppress CVEs assessed *not exploitable in context* so teams fix real risk instead of chasing noise.

> 💬 **Interview soundbite:** "I gate CI on fixable HIGH/CRITICAL CVEs and re-scan images in the
> registry continuously, because an image that was clean at build time isn't clean forever. VEX
> attestations keep the signal-to-noise sane."

---

## 8. Compliance, Governance & Policy-as-Code

- **Frameworks to name-drop correctly:**
  - **CIS Docker Benchmark** — prescriptive host/daemon/container config.
  - **NIST SP 800-190** — the container security guide; maps to FedRAMP, NIST 800-53, DoD cATO.
  - **OWASP Docker Top 10** — ten *security controls* (not risks) for a secure container env.
- **Policy-as-code / admission control** — enforce rules *before* workloads run:
  - **OPA / Gatekeeper** and **Kyverno** block non-compliant images (unsigned, `latest` tag,
    running as root, `privileged`) at Kubernetes admission time.
  - Registry-level policy: only allow signed images from approved namespaces.
- **Tag immutability** — configure the registry so a pushed tag can't be overwritten; deploy by
  **digest** for true reproducibility.

---

## 9. Observability & Runtime Threat Detection

Prevention leaks; you need eyes at runtime.

- **Falco** (CNCF) — kernel-event-based runtime detection: alerts on shells spawned in containers,
  unexpected outbound connections, writes to sensitive paths, privilege escalations.
- **Defense-in-depth trio** (the "three pillars"): **Trivy** (scan) + **Kyverno/OPA** (admission)
  + **Falco** (runtime). Admission prevents; Falco detects what slips through; a controller can
  auto-respond (e.g. kill the pod).
- **Centralized logging** — ship container logs to a SIEM; set log rotation to prevent disk-fill DoS.
- **Image drift detection** — alert if a running container's filesystem diverges from its image
  (a sign of live tampering / injected payloads).

---

## 10. CI/CD DevSecOps Pipeline (putting it together)

A hardened build-to-deploy flow:

```
1. Lint Dockerfile        → hadolint
2. Build (BuildKit)       → multi-stage, --provenance=max, --sbom=true, no secrets in layers
3. Scan                   → trivy/scout, fail on fixable HIGH/CRITICAL
4. Generate SBOM          → syft → attach as attestation
5. Sign                   → cosign (keyless, OIDC)
6. Push                   → immutable tag + digest to trusted registry
7. Verify at admission    → cosign verify + Kyverno/OPA policy (no root, no latest, signed only)
8. Runtime               → non-root, cap-drop, seccomp, read-only; Falco watching
9. Continuous            → re-scan registry images; patch base + rebuild on new CVEs
```

**Operational excellence extras (senior differentiators):**
- **Golden base images** maintained centrally, rebuilt on a cadence to absorb upstream patches.
- **`docker buildx`** for reproducible **multi-arch** (amd64/arm64) builds.
- **Ephemeral, isolated build runners** — a poisoned build shouldn't reach shared infra.
- **Build cache hygiene** — `docker builder prune --all` to reclaim BuildKit cache; monitor with
  `docker system df`.

---

## 11. Know Your Incidents — Leaky Vessels (case study)

In Jan 2024, Snyk disclosed **"Leaky Vessels"** — four container-escape CVEs:

| CVE | Component | Impact |
|:--|:--|:--|
| **CVE-2024-21626** | runc | File-descriptor leak → escape to host filesystem |
| **CVE-2024-23651** | BuildKit | Race condition → container breakout during build |
| **CVE-2024-23652** | BuildKit | Arbitrary host file deletion during build |
| **CVE-2024-23653** | BuildKit | Breakout during image build |

**Fix:** runc **≥ 1.1.12** (released Jan 31, 2024), BuildKit **≥ 0.12.5**.
**Lesson (and the interview point):** the escape lived in the *core runtime*, not your app — which is
exactly why you (a) keep runc/BuildKit patched, (b) don't rely on the container as your only boundary,
and (c) run Falco to detect escape behavior. This is the concrete justification for defense-in-depth.

---

## 12. The 60-Second Audit Checklist

**Build**
- [ ] Minimal/distroless/DHI base, pinned by digest (no `latest`)
- [ ] Multi-stage; no build tools or secrets in the final image
- [ ] `.dockerignore` excludes `.git`, `.env`, keys
- [ ] SBOM generated; image scanned; CI gated on fixable HIGH/CRITICAL

**Ship**
- [ ] Image signed (Cosign keyless) + provenance (SLSA) attached
- [ ] Immutable tags; trusted registry; deploy by digest

**Run**
- [ ] Non-root `USER`; `--cap-drop=ALL` (+ minimal add-back)
- [ ] `no-new-privileges`; read-only rootfs + tmpfs
- [ ] seccomp + AppArmor/SELinux profile applied
- [ ] Resource + PID limits set; **no** `--privileged`, **no** docker socket mount
- [ ] Rootless or userns-remap daemon

**Observe**
- [ ] Falco (or equivalent) runtime detection
- [ ] Centralized logging + rotation; drift detection
- [ ] runc/BuildKit/Docker patched; host on minimal OS; docker-bench-security passing

---

## 13. Rapid-Fire Interview Q&A

- **Q: Why isn't a container a security boundary?**
  A: It shares the host kernel; isolation is namespaces/cgroups/caps, not virtualization. A kernel or
  runc bug (Leaky Vessels) breaks out. Hence defense-in-depth.
- **Q: How do you keep secrets out of an image?**
  A: BuildKit `--mount=type=secret` for build-time; Vault/KMS injected at runtime. Never `ENV`/`ARG` —
  they persist in layers and `docker history`.
- **Q: `--cap-drop=ALL` — then what?**
  A: Add back only what's required (e.g. `NET_BIND_SERVICE` for ports <1024). Most apps need none.
- **Q: Rootless vs userns-remap?**
  A: Rootless = the *daemon* runs unprivileged; userns-remap = daemon stays root but container UID 0
  maps to an unprivileged host UID. Rootless is stronger, with networking/perf trade-offs.
- **Q: How do you trust an image in prod?**
  A: SBOM + SLSA provenance + Cosign signature, verified at admission via Kyverno/OPA; deploy by
  digest, not tag.
- **Q: Distroless vs Alpine?**
  A: Distroless has no shell/package manager (smaller attack surface, harder to debug); Alpine is tiny
  but has a shell + apk and uses musl (occasional glibc-compat issues). Pick per risk/debuggability.

---

## References & Standards

- CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker
- CIS Benchmarks Aug 2025 update (v1.8.0 / Docker v28) — https://www.cisecurity.org/insights/blog/cis-benchmarks-august-2025-update
- NIST SP 800-190, Application Container Security Guide — https://csrc.nist.gov/pubs/sp/800/190/final
- OWASP Docker Top 10 — https://owasp.org/www-project-docker-top-10/
- OWASP Docker Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- Docker Hardened Images — https://www.docker.com/blog/hardened-images-free-now-what/
- Docker Scout CVEs — https://docs.docker.com/reference/cli/docker/scout/cves/
- Docker rootless mode — https://docs.docker.com/engine/security/rootless/
- Sigstore / Cosign — https://www.sigstore.dev/
- SLSA framework — https://slsa.dev/
- Falco (CNCF) — https://falco.org/
- Leaky Vessels (CVE-2024-21626 et al.) — https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities
- docker-bench-security — https://github.com/docker/docker-bench-security

---

*Derived and expanded from the [Docker Professional Cheatsheet](./README.md). Maintained as living
documentation — revisit when CIS/NIST/OWASP publish updates or when new container-escape CVEs land.*
