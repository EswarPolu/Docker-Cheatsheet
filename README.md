# 01 Jan 2026 Docker Professional Cheatsheet 
a full reference for professional and beginners
# 🐳 The Definitive Docker Professional Cheatsheet

## 1. Core Concepts & Architecture

- **Containers vs. Virtual Machines**: Each VM uses its own guest OS, whereas **all Docker containers share a single host OS kernel**, making them more lightweight
- **Images vs. Containers**: An **image** is a read-only package (blueprint); a **container** is a running instance of that package.
- **The Docker Engine**: Consists of a background service (**Docker Daemon**), a **REST API** for communication, and the **Docker CLI** used for commands.
- **Layered Architecture**: Images are built in stacked **read-only layers**; once a container runs, it adds a thin **read-write layer** on top.
- **Copy-On-Write (CoW)**: When a container modifies a file from the image, it copies the file to the top read-write layer before making changes, leaving the original image layer untouched.

---
## 9. The Dockerfile Reference

|Instruction|Purpose|
|:--|:--|
|`FROM`|Defines the **base image** (e.g., Ubuntu, Python).|
|`RUN`|Executes commands during the **build process** to install dependencies.|
|`COPY`|Copies files/folders from the host to the image.|
|`WORKDIR`|Sets the **working directory** for subsequent instructions.|
|`ENV`|Sets environment variables within the image.|
|`EXPOSE`|Informs Docker that the container listens on specific ports.|
|`ENTRYPOINT`|Specifies the **command that will always run** at startup.|
|`CMD`|Provides **default arguments** for the entrypoint (can be overridden).|
___

## 2. Essential Commands Reference

### Lifecycle & Operations

|Command|Description|Optimization Tip|
|:--|:--|:--|
|`docker run`|Create and start a container.|Use `--rm` to auto-delete containers on exit.|
|`docker stop`|Gracefully shut down a container.|Use `docker kill` for immediate, forceful stops.|
|`docker ps -a`|List **all** containers (running and stopped).|Crucial for finding "ghost" containers taking up space.|
|`docker exec -it`|Run an interactive command inside a running container.|Best for debugging live environments.|
|`docker logs -f`|Stream container output/logs in real-time.|Use to monitor application startup errors.|

### System Maintenance

- **`docker system df`**: Show real-time disk usage by Docker objects.
- **`docker system prune`**: Remove all unused containers, networks, and dangling images.
- **`docker system prune -a --volumes`**: **High Danger.** Clears everything, including all unused images and all volumes.

---

## 3. Storage: Volumes & Bind Mounts

Docker data is non-persistent unless mapped to the host system. By default, data is stored in `/var/lib/docker` on Linux.

- **Named Volumes**: Managed by Docker. Best for database persistence.
    - `docker volume create <name>`
    - `docker run -v my_vol:/app/data`
- **Bind Mounts**: Maps a specific host directory to a container. Best for source code sharing during dev.
    - `docker run -v /host/path:/container/path`
- **Modern Optmized Syntax**: Use `--mount` for better readability and explicit control.
    - `docker run --mount type=bind,source=/data,target=/var/lib/mysql`

---

## 4. Networking Drivers

|Driver|Behavior|Use Case|
|:--|:--|:--|
|**Bridge**|Default network; containers get internal IPs.|Standard isolated app communication.|
|**Host**|Removes isolation between container and host network.|Maximum performance; no port mapping needed.|
|**None**|No external or internal network connectivity.|Highly secure, offline batch processing.|
|**User-defined**|Custom bridge network with **Embedded DNS**.|Allows containers to talk via **Container Name**.|

---

## 5. Dockerfile Optimization Patterns

### CMD vs. ENTRYPOINT

- **`ENTRYPOINT ["executable"]`**: Defines the command that **always runs** at startup.
- **`CMD ["param"]`**: Provides **default arguments** for the entrypoint; easily overridden by CLI arguments.
    - _Pattern_: `ENTRYPOINT ["sleep"]` + `CMD ["5"]` allows `docker run img` to sleep for 5s, while `docker run img 10` sleeps for 10s.

### Best Practices for Seniors

- **Minimize Layers**: Combine `RUN` commands (e.g., `RUN apt-get update && apt-get install...`) to reduce image size.
- **Security**: Always define a **non-root user** in the Dockerfile to prevent container-breakout vulnerabilities.
- **Resource Constraints**: Prevent one container from crashing the host by limiting CPU and RAM.
    - `docker run --cpus=".5" --memory="100m" ubuntu`

---
## 6. Resource Management & Constraints

To prevent a single container from crashing the entire host, always define resource limits.

• **Limit CPU**: `docker run --cpus=0.5 ubuntu` (Limits container to 50% of one CPU core).

• **Limit Memory**: `docker run --memory=500m ubuntu` (Restricts memory usage to 500 MB).

• **Real-time Monitoring**: Use `docker stats` to view live CPU and memory utilization across all containers.
___

## 7. Common Mistakes & Fixes

### Junior Mistakes

1. **Port Mapping Confusion**: Forgetting that the mapping is `-p <HostPort>:<ContainerPort>`. Mapping a host port already in use results in a "Bind failure" error.
2. **Dangling Data**: Using `docker rm` but forgetting that **volumes remain** on the disk, slowly filling up storage.
3. **Dependent Images**: Attempting to `docker rmi` an image while a container (even a stopped one) is still using it.

### Senior/Optimization Failures

1. **Hardcoding IPs**: Using internal container IPs instead of **User-defined Bridge networks** with DNS resolution.
2. **Missing Healthchecks**: Not using the `HEALTHCHECK` instruction, leading to "running" containers that are actually dead inside.
3. **Thick Images**: Using a full OS (Ubuntu) as a base instead of **Alpine** or **Hardened Images** for production.

---

## 8. Docker Compose & Swarm (Orchestration)

- **Docker Compose**: Used to run multi-container applications (Services, Networks, Volumes) via a `.yml` file.
    - `docker compose up -d`
- **Docker Swarm**: A cluster of Docker Engines. Use `docker swarm init` to create a manager and `docker swarm join` for workers.
    - **Services**: In Swarm, you create **Services** instead of individual containers to allow for scaling.
    - `docker service create --replicas=3 my-app`

---

## 10. Multi-Stage Builds

Multi-stage builds let you use **multiple `FROM` statements in a single Dockerfile**. Each `FROM` begins a new **stage**, and you selectively copy only the artifacts you need from one stage into the next. This keeps heavy build tooling (compilers, SDKs, dev dependencies) out of the **final image**, producing a small, secure production artifact.

### Why Use Them

- **Smaller Images**: The final image contains only the runtime and the compiled output — not the full build toolchain. Images can shrink from ~1 GB to tens of MB.
- **Better Security**: Fewer packages in the final image means a smaller **attack surface** (no compilers, package managers, or build secrets left behind).
- **Single Dockerfile**: Replaces the old "builder pattern" of maintaining two Dockerfiles plus shell scripts to copy artifacts between them.
- **Better Layer Caching**: Dependency-install stages are cached and reused unless their inputs change, speeding up rebuilds.

### How It Works

- Each `FROM` starts a fresh stage; stages are numbered from `0` by default.
- Name a stage with `AS <name>` so it can be referenced clearly.
- Use `COPY --from=<stage>` to pull built artifacts from an earlier stage into the current one.
- Only the **last stage** becomes the final image; earlier stages are discarded.

### Example: Go Application

```dockerfile
# --- Stage 1: Build ---
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download          # Cached unless dependencies change
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/server

# --- Stage 2: Runtime ---
FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/server /app/server   # Copy ONLY the binary
EXPOSE 8080
USER nobody                  # Run as non-root
ENTRYPOINT ["/app/server"]
```

The `golang` image (~800 MB with the full toolchain) is used only to compile the binary. The final image is based on tiny `alpine` and carries just the compiled `server` binary.

### Key Instructions & Commands

|Syntax|Purpose|
|:--|:--|
|`FROM <img> AS <name>`|Start a named build stage.|
|`COPY --from=<name> src dst`|Copy files from a previous stage into the current one.|
|`COPY --from=<img> src dst`|Copy directly from an external image (e.g. `nginx:latest`).|
|`docker build --target <name> .`|Build and stop at a specific stage (great for a **debug/test** stage).|
|`FROM scratch`|Empty base image for statically-compiled binaries — the smallest possible image.|

### Best Practices

- **Order stages by change frequency**: install dependencies before copying source code so the dependency layer stays cached.
- **Use minimal final bases**: `alpine`, `distroless`, or `scratch` for the runtime stage.
- **Name every stage** (`AS builder`) instead of relying on numeric indexes — it is more readable and refactor-safe.
- **Use `--target`** to build a dedicated `test` stage in CI without shipping test tooling to production.
- **Keep secrets out of the final image**: build-time credentials used in an early stage never leak into the final layers.

---


**Analogy for Recall**: Imagine a **Shipping Port**. 
An **Image** is a standardized blueprint for a crate; 
a **Registry** is the global warehouse of blueprints; a **Container** is the physical crate being moved by the crane (**Docker Engine**). 
If you don't use a **Volume**, it's like a crate that is incinerated the moment you unpack it—anything inside that wasn't written down on the **Host Dock** is lost forever.

### Resources Links
1. https://docs.docker.com/engine/containers/resource_constraints/
