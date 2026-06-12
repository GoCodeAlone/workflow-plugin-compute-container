# workflow-plugin-compute-container

Public command and container-build runtime adapter plugin for Workflow Compute.

This plugin owns reusable runtime adapter contracts and conformance helpers for
`command` and `container-build` workload execution. The Workflow Compute host
continues to own task admission, leases, authorization, credential resolution,
registry allowlists, proof/reward mutation, and worker binding.

## Packages

- `container`: sandbox runtime adapter interfaces, command/container-build
  invocation builders, env ref resolution, artifact hashing, digest marker
  validation, and Docker-compatible runtime backend probes.

Runtime adapter metadata is published in `runtime-adapters.json` and referenced
from `plugin.json` through `runtimeAdaptersRef`.

Managed runtime bundle metadata is published in `managed-runtime-bundles.json`
and referenced from `plugin.json` through `managedRuntimeBundlesRef`.

## Runtime Backend Probes

The `container` package can probe Docker-compatible runtimes through
`DockerCompatibleRuntimeProbes`. Probe results use
`compute-core/protocol.RuntimeBackendReport` so Workflow Compute agents can
advertise executor capabilities from evidence-backed backend reports instead of
assuming Docker is present.

The default probe set covers Podman, Docker, and nerdctl/containerd. Supported
reports are only emitted after the runtime executable is found, version probing
works, and the conformance command succeeds. Degraded and unsupported reports do
not advertise executor providers or executor refs.

The `ManagedContainerdRuntimeProbes` helper builds target-aware probes from the
managed runtime bundle catalog and an explicit agent-managed install root. The
initial managed bundle target is Linux amd64 and is pinned to
`containerd/nerdctl` `v2.3.1` `nerdctl-full-2.3.1-linux-amd64.tar.gz`. Agents
must only advertise this backend after the bundle descriptor validates for the
current OS/architecture, the pinned runtime has been downloaded and extracted
into the agent-managed install root, the helper resolves an absolute
`bin/nerdctl` path inside that root, and the same conformance checks pass. The
managed backend uses an opaque nerdctl namespace so workloads run outside the
host's default container namespace.

Managed runtime release packaging verifies the upstream `SHA256SUMS` and
`SHA256SUMS.asc` digests and emits a source manifest in the plugin release
archive. The public `ManagedRuntimeBundleInstaller` helper and
`managed-runtime` subcommands provide the reusable agent-side lifecycle contract:
download pinned artifact/checksum/signature objects from catalog metadata,
extract the bundle into an agent-owned scoped install root, write an install
manifest, doctor the scoped install, remove only the scoped bundle root, and
reinstall from the same pinned metadata. Workflow Compute hosts consume this
contract instead of implementing private host-only bundle lifecycle behavior.

The default conformance image reference is the Debian 13 distroless static index:

```text
gcr.io/distroless/static-debian13@sha256:3592aa8171c77482f62bbc4164e6a2d141c6122554ace66e5cc910cadb961ff0
```

By default the probe invokes `/usr/local/bin/wfcompute-sandbox-probe` inside the
image, matching the compute-agent direct probe command convention for distroless
probe images. A raw upstream distroless base image will usually return a
degraded report until a purpose-built probe binary image is supplied.

Conformance commands run with `--network none`, a temporary workspace mounted at
`/workspace`, `WFCOMPUTE_RUNTIME_PROBE=1`, and a read-only root filesystem. The
probe image must emit a `RuntimeBackendEvidence` JSON payload proving workspace,
network, env, proof, and cleanup behavior under those constraints.

## Verification

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
```

Run installed runtime smoke probes explicitly:

```sh
WORKFLOW_COMPUTE_RUNTIME_PROBE_REAL=1 GOWORK=off go test ./container -run TestDockerCompatibleRuntimeProbeRealBackends -count=1 -v
```

Install and verify a managed bundle from catalog metadata:

```sh
workflow-plugin-compute-container managed-runtime install \
  --catalog managed-runtime-bundles.json \
  --install-root "$HOME/.local/share/workflow-compute/managed-runtime" \
  --bundle-id managed-containerd-linux-amd64 \
  --target-os linux \
  --target-arch amd64

workflow-plugin-compute-container managed-runtime doctor \
  --catalog managed-runtime-bundles.json \
  --install-root "$HOME/.local/share/workflow-compute/managed-runtime" \
  --bundle-id managed-containerd-linux-amd64 \
  --target-os linux \
  --target-arch amd64
```
