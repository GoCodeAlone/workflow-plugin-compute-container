package container

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestSandboxedCommandInvocationResolvesEnvRefsAndStripsPayloadRefs(t *testing.T) {
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{
		TaskID:    "task-1",
		LeaseID:   "lease-1",
		Image:     "ghcr.io/gocodealone/command@sha256:abc",
		Workspace: t.TempDir(),
		Network:   SandboxNetworkNone,
		Timeout:   45 * time.Second,
		Workload: core.CommandWorkload{
			Args:             []string{"sh", "-c", "printf ok > out.txt"},
			WorkingDirectory: "work",
			Env: []core.EnvRef{
				{Name: "TOKEN", SecretRef: "secret://token"},
			},
			ArtifactAllowlist: []string{"out.txt"},
		},
		ResolvedEnv: map[string]string{"secret://token": "redacted-token"},
	})
	if err != nil {
		t.Fatalf("build invocation: %v", err)
	}
	if invocation.Request.ProtocolVersion != core.Version {
		t.Fatalf("protocol version = %q, want %q", invocation.Request.ProtocolVersion, core.Version)
	}
	if invocation.Request.Operation != SandboxedCommandOperationRun {
		t.Fatalf("operation = %q, want %q", invocation.Request.Operation, SandboxedCommandOperationRun)
	}
	if got := invocation.Request.Env["TOKEN"]; got != "redacted-token" {
		t.Fatalf("resolved env TOKEN = %q", got)
	}
	var payload core.CommandWorkload
	if err := json.Unmarshal(invocation.Request.Input, &payload); err != nil {
		t.Fatalf("decode input payload: %v", err)
	}
	if len(payload.Env) != 0 {
		t.Fatalf("runtime payload leaked env refs: %+v", payload.Env)
	}
}

func TestSandboxRuntimeCommandAdapterRunsHardenedSandboxAndHashesArtifacts(t *testing.T) {
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "work", "out.txt"), []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &recordingSandboxRuntime{
		result: SandboxRunResult{
			Stdout: []byte("ok"),
		},
	}
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{
		TaskID:    "task-1",
		LeaseID:   "lease-1",
		Image:     "sandbox-image",
		Workspace: workspace,
		Network:   SandboxNetworkNone,
		Timeout:   time.Minute,
		Workload: core.CommandWorkload{
			Args:              []string{"sh", "-c", "true"},
			WorkingDirectory:  "work",
			Env:               []core.EnvRef{{Name: "TOKEN", SecretRef: "secret://token"}},
			ArtifactAllowlist: []string{"out.txt"},
		},
		ResolvedEnv: map[string]string{"secret://token": "resolved"},
	})
	if err != nil {
		t.Fatalf("build invocation: %v", err)
	}
	result, err := (SandboxRuntimeCommandAdapter{Runtime: runtime}).RunSandboxedCommand(context.Background(), invocation)
	if err != nil {
		t.Fatalf("run sandboxed command: %v", err)
	}
	if got, want := runtime.request.Image, "sandbox-image"; got != want {
		t.Fatalf("image = %q, want %q", got, want)
	}
	if got := strings.Join(runtime.request.Command, " "); got != "sh -c true" {
		t.Fatalf("command = %q", got)
	}
	if runtime.request.Network != SandboxNetworkNone {
		t.Fatalf("network = %q", runtime.request.Network)
	}
	if runtime.request.Env["TOKEN"] != "resolved" {
		t.Fatalf("sandbox env TOKEN = %q", runtime.request.Env["TOKEN"])
	}
	if result.ArtifactHash == "" || !strings.HasPrefix(result.ArtifactHash, "sha256:") {
		t.Fatalf("artifact hash = %q", result.ArtifactHash)
	}
	if !slices.Equal(result.Artifacts, []string{"out.txt"}) {
		t.Fatalf("artifacts = %+v", result.Artifacts)
	}
}

func TestSandboxRuntimeContainerBuildAdapterUsesStrictBuildSandboxAndDigestMarker(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	runtime := &recordingSandboxRuntime{
		result: SandboxRunResult{
			Stdout: []byte("log\n" + SandboxedContainerBuildDigestMarker + digest + "\n"),
		},
	}
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invocation, err := NewSandboxedContainerBuildInvocation(SandboxedContainerBuildInvocationOptions{
		TaskID:    "task-2",
		LeaseID:   "lease-2",
		Image:     "builder-image",
		Workspace: workspace,
		Network:   SandboxNetworkNone,
		Timeout:   time.Hour,
		Workload: core.ContainerBuildWorkload{
			ContextDirectory: ".",
			Dockerfile:       "Dockerfile",
			Tags:             []string{"example:test"},
			Env: []core.EnvRef{
				{Name: "DOCKER_CONFIG_JSON", SecretRef: "secret://docker-config"},
			},
		},
		ResolvedEnv: map[string]string{"secret://docker-config": "{}"},
	})
	if err != nil {
		t.Fatalf("build invocation: %v", err)
	}
	result, err := (SandboxRuntimeContainerBuildAdapter{Runtime: runtime}).BuildSandboxedContainer(context.Background(), invocation)
	if err != nil {
		t.Fatalf("run sandboxed container build: %v", err)
	}
	if result.ArtifactHash != digest {
		t.Fatalf("artifact hash = %q, want %q", result.ArtifactHash, digest)
	}
	if !runtime.request.RunAsRoot {
		t.Fatal("container-build sandbox must run as root for builder compatibility")
	}
	if !runtime.request.WritableRootFS {
		t.Fatal("container-build sandbox must use writable rootfs for builder compatibility")
	}
	if !slices.Contains(runtime.request.AddCapabilities, "CHOWN") || !slices.Contains(runtime.request.AddCapabilities, "FOWNER") {
		t.Fatalf("missing strict builder capabilities: %+v", runtime.request.AddCapabilities)
	}
	if runtime.request.Network != SandboxNetworkNone {
		t.Fatalf("network = %q", runtime.request.Network)
	}
	if runtime.request.Env["DOCKER_CONFIG_JSON"] != "{}" {
		t.Fatalf("docker config env = %q", runtime.request.Env["DOCKER_CONFIG_JSON"])
	}
	if runtime.request.Env["WORKFLOW_COMPUTE_BUILD_DOCKERFILE"] != "Dockerfile" {
		t.Fatalf("dockerfile env = %q", runtime.request.Env["WORKFLOW_COMPUTE_BUILD_DOCKERFILE"])
	}
	if runtime.request.Env["WORKFLOW_COMPUTE_BUILD_TAGS"] != `["example:test"]` {
		t.Fatalf("tags env = %q", runtime.request.Env["WORKFLOW_COMPUTE_BUILD_TAGS"])
	}
}

func TestContainerBuildRejectsReservedControlEnvOverride(t *testing.T) {
	_, err := NewSandboxedContainerBuildInvocation(SandboxedContainerBuildInvocationOptions{
		TaskID:    "task-2",
		LeaseID:   "lease-2",
		Image:     "builder-image",
		Workspace: t.TempDir(),
		Workload: core.ContainerBuildWorkload{
			ContextDirectory: ".",
			Tags:             []string{"example:test"},
			Env: []core.EnvRef{
				{Name: "WORKFLOW_COMPUTE_BUILD_DIGEST_FILE", SecretRef: "secret://override"},
			},
		},
		ResolvedEnv: map[string]string{"secret://override": "/outside"},
	})
	if err == nil || !strings.Contains(err.Error(), "reserved workflow-compute build env") {
		t.Fatalf("expected reserved env rejection, got %v", err)
	}
}

func TestContainerBuildPassesAllTagsAsJSON(t *testing.T) {
	runtime := &recordingSandboxRuntime{
		result: SandboxRunResult{ArtifactHash: "sha256:" + strings.Repeat("a", 64)},
	}
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invocation, err := NewSandboxedContainerBuildInvocation(SandboxedContainerBuildInvocationOptions{
		TaskID:    "task-2",
		LeaseID:   "lease-2",
		Image:     "builder-image",
		Workspace: workspace,
		Workload: core.ContainerBuildWorkload{
			ContextDirectory: ".",
			Tags:             []string{"example:one", "example:two"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (SandboxRuntimeContainerBuildAdapter{Runtime: runtime}).BuildSandboxedContainer(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if got := runtime.request.Env["WORKFLOW_COMPUTE_BUILD_TAGS"]; got != `["example:one","example:two"]` {
		t.Fatalf("WORKFLOW_COMPUTE_BUILD_TAGS = %q", got)
	}
}

func TestCommandArtifactHashRejectsSymlinkPathComponents(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "out.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runtime := &recordingSandboxRuntime{result: SandboxRunResult{Stdout: []byte("ok")}}
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{
		TaskID:    "task-1",
		LeaseID:   "lease-1",
		Image:     "sandbox-image",
		Workspace: workspace,
		Workload: core.CommandWorkload{
			Args:              []string{"true"},
			ArtifactAllowlist: []string{"link/out.txt"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (SandboxRuntimeCommandAdapter{Runtime: runtime}).RunSandboxedCommand(context.Background(), invocation)
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("expected symlink component rejection, got %v", err)
	}
}

func TestRuntimeAdapterContractsDescribePublicCommandAndContainerBuildAdapters(t *testing.T) {
	command := SandboxedCommandContract(core.RuntimeDescriptor{
		Name:                  SandboxedCommandProviderName,
		Version:               "v1.0.0",
		ExecutionSecurityTier: core.ExecutionSandboxedContainer,
		ProofTier:             core.ProofArtifactHash,
		ImageDigest:           "sha256:" + strings.Repeat("b", 64),
		RootFSDigest:          "sha256:" + strings.Repeat("c", 64),
	})
	if command.AdapterID != SandboxedCommandProviderName {
		t.Fatalf("command adapter id = %q", command.AdapterID)
	}
	if !slices.Equal(command.WorkloadKinds, []core.WorkloadKind{core.WorkloadCommand}) {
		t.Fatalf("command workload kinds = %+v", command.WorkloadKinds)
	}
	if !slices.Equal(command.RuntimeProfiles, []core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}) {
		t.Fatalf("command runtime profiles = %+v", command.RuntimeProfiles)
	}
	if command.WorkspacePolicy != core.RuntimeWorkspaceRequired {
		t.Fatalf("command workspace policy = %q", command.WorkspacePolicy)
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("command contract invalid: %v", err)
	}

	build := SandboxedContainerBuildContract(core.RuntimeDescriptor{
		Name:                  SandboxedContainerBuildProviderName,
		Version:               "v1.0.0",
		ExecutionSecurityTier: core.ExecutionSandboxedContainer,
		ProofTier:             core.ProofArtifactHash,
		ImageDigest:           "sha256:" + strings.Repeat("d", 64),
		RootFSDigest:          "sha256:" + strings.Repeat("e", 64),
	})
	if build.AdapterID != SandboxedContainerBuildProviderName {
		t.Fatalf("container-build adapter id = %q", build.AdapterID)
	}
	if !slices.Equal(build.WorkloadKinds, []core.WorkloadKind{core.WorkloadContainerBuild}) {
		t.Fatalf("container-build workload kinds = %+v", build.WorkloadKinds)
	}
	if !slices.Equal(build.RuntimeProfiles, []core.RuntimeProfile{core.RuntimeProfileContainerBuild}) {
		t.Fatalf("container-build runtime profiles = %+v", build.RuntimeProfiles)
	}
	if !slices.Equal(build.ConformanceProfiles, []string{"container-build-v1"}) {
		t.Fatalf("container-build conformance profiles = %+v", build.ConformanceProfiles)
	}
	if err := build.Validate(); err != nil {
		t.Fatalf("container-build contract invalid: %v", err)
	}
}

type recordingSandboxRuntime struct {
	request SandboxRunRequest
	result  SandboxRunResult
}

func (r *recordingSandboxRuntime) Available(context.Context) error {
	return nil
}

func (r *recordingSandboxRuntime) Run(_ context.Context, req SandboxRunRequest) (SandboxRunResult, error) {
	r.request = req
	return r.result, nil
}
