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
verify the detached OpenPGP signature against the catalog-pinned trust root,
extract the bundle into an agent-owned scoped install root, write an install
manifest with extracted file digests, doctor the scoped install, remove only the
scoped bundle root, and reinstall from the same pinned metadata without removing
the old install before the replacement has been staged. Workflow Compute hosts
consume this contract instead of implementing private host-only bundle lifecycle
behavior.

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

### Native execution bounds

Protected workload and conformance runs explicitly use `--pull never`. Approved
images must already be cached; execution never falls back to pulling an image.
Availability has a ten-second ceiling, conformance has thirty seconds, and direct
command execution defaults to one minute. Explicit request/runtime limits and
earlier caller deadlines take precedence. Owned cancellation cleanup gets a
separate ten-second opportunity shared by ownership inspection and removal.
Cleanup requires the independent per-attempt owner label and a full verified
container ID before removing that ID in the same runtime scope. Name collisions,
missing/malformed inspection and unknown creation remain unresolved errors; no
foreign name is removed and generic inspection failure never proves absence.

`ExecDockerCommandRunner.MaxOutputBytes` bounds aggregate stdout/stderr. A positive
limit is used exactly; the implementation default is 1 MiB when no positive limit
is supplied. Writers continue draining through EOF and retain each stream's final
rolling tail before deterministic aggregate rebalancing. `OutputLimitError`
implements `OutputCaptureMetadataProvider`, carrying original per-stream counts
and final truncation flags without putting output into its error text. Adapters
preserve that typed error across timeout wrapping. Consumers must copy this
metadata into their run-log provenance before preserving bounded streams.
`CaptureIncompleteError` has `Complete:false`; its partial streams are withheld.
Observed bytes from forced pipe closure must never be labeled complete original
stream sizes. Control-process output is not exposed as workload provenance.

`ReadOnlyWorkspace` is an opt-in policy on `DockerSandboxRuntime`,
`SandboxRuntimeCommandAdapter` and `SandboxRunRequest`; defaults remain false.
It keeps the same workspace bind mounted read-only, requires a successful strict
initial byte-limit walk, rejects writable/shadowing mounts, special files,
symlinks, writable rootfs/tmpfs/capability overrides and artifact output requests.
The shared `ValidateReadOnlyPolicy` preflight also rejects image-declared writable
volumes and checks Docker's advertised memory/swap/CPU/PID controls. The opt-in
command policy caps memory plus swap at the declared memory limit. Unsupported runtime
evidence fails closed; read-only control verification currently supports Docker
with a Linux daemon. A native smoke test must still demonstrate actual configured
limits and write denial on the selected runtime. No daemon or cgroup settings are
changed by this policy.

An exclusively owned empty workspace then has zero workload growth; read-only
mounting cannot stop concurrent host writes. `/tmp` is separately bounded to
64 MiB. Read-only commands and all conformance containers use `--log-driver none`;
bounded attached output is distinct from daemon log storage. Legacy writable
workspace/artifact behavior remains available. Its `WorkspaceBytes` describes
measurement/reservation, not a portable hard quota on a writable bind mount.

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
