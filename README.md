# workflow-plugin-compute-container

Public command and container-build runtime adapter plugin for Workflow Compute.

This plugin owns reusable runtime adapter contracts and conformance helpers for
`command` and `container-build` workload execution. The Workflow Compute host
continues to own task admission, leases, authorization, credential resolution,
registry allowlists, proof/reward mutation, and worker binding.

## Packages

- `container`: sandbox runtime adapter interfaces, command/container-build
  invocation builders, env ref resolution, artifact hashing, and digest marker
  validation.

## Verification

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
```
