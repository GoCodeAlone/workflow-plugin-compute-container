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

The default conformance image reference is the Debian 13 distroless static index:

```text
gcr.io/distroless/static-debian13@sha256:3592aa8171c77482f62bbc4164e6a2d141c6122554ace66e5cc910cadb961ff0
```

By default the probe invokes `/usr/local/bin/wfcompute-sandbox-probe` inside the
image, matching the compute-agent direct probe command convention for distroless
probe images. A raw upstream distroless base image will usually return a
degraded report until a purpose-built probe binary image is supplied.

## Verification

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
```

Run installed runtime smoke probes explicitly:

```sh
WORKFLOW_COMPUTE_RUNTIME_PROBE_REAL=1 GOWORK=off go test ./container -run TestDockerCompatibleRuntimeProbeRealBackends -count=1 -v
```
