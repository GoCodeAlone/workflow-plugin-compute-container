package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestDockerCompatibleRuntimeBuildsBreakoutResistantArgs(t *testing.T) {
	workspace := t.TempDir()
	spec, cleanup, err := (DockerSandboxRuntime{RuntimeName: "runsc"}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/workload:latest",
		Command:   []string{"./build.sh"},
		Workspace: workspace,
		Network:   SandboxNetworkNone,
		Limits: core.ResourceLimits{
			MemoryBytes: 268435456,
			CPUPercent:  50,
		},
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	for _, want := range []string{
		"--network\x00none",
		"--read-only",
		"--cap-drop\x00ALL",
		"--security-opt\x00no-new-privileges",
		"--pids-limit\x00256",
		"--tmpfs\x00/tmp:rw,noexec,nosuid,nodev,size=64m",
		fmt.Sprintf("--user\x00%d:%d", os.Getuid(), os.Getgid()),
		"--runtime\x00runsc",
		"--memory\x00268435456",
		"--cpus\x000.50",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("docker args missing %q in %q", want, args)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network\x00host", "--pid\x00host", "--ipc\x00host", "/var/run/docker.sock"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("docker args contain breakout primitive %q in %q", forbidden, args)
		}
	}
	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		t.Fatalf("abs workspace: %v", err)
	}
	if !strings.Contains(args, "-v\x00"+absWorkspace+":/workspace:rw") {
		t.Fatalf("docker args must mount exact workspace, args=%q", args)
	}
}

func TestDockerCompatibleRuntimeClearsImageEntrypointForExplicitCommand(t *testing.T) {
	image := "ghcr.io/gocodealone/workload-with-entrypoint@sha256:" + strings.Repeat("a", 64)
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:                      image,
		Command:                    []string{"/workspace/provider/dynamic-provider"},
		CommandOverridesEntrypoint: true,
		Workspace:                  t.TempDir(),
		Network:                    SandboxNetworkBridge,
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	entrypointAt := strings.Index(args, "--entrypoint\x00\x00")
	if entrypointAt < 0 {
		t.Fatalf("docker args must clear image entrypoint for explicit command: %q", args)
	}
	imageAt := strings.Index(args, image)
	if imageAt < 0 {
		t.Fatalf("image arg missing: %q", args)
	}
	if entrypointAt > imageAt {
		t.Fatalf("--entrypoint must appear before image arg: %q", args)
	}
	if !strings.Contains(args, image+"\x00/workspace/provider/dynamic-provider") {
		t.Fatalf("explicit command must remain after image arg: %q", args)
	}
}

func TestDockerCompatibleRuntimePreservesImageEntrypointForCommandArgsByDefault(t *testing.T) {
	image := "ghcr.io/gocodealone/workload-with-entrypoint@sha256:" + strings.Repeat("a", 64)
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     image,
		Command:   []string{"serve", "--port", "8080"},
		Workspace: t.TempDir(),
		Network:   SandboxNetworkBridge,
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	if strings.Contains(args, "--entrypoint\x00\x00") {
		t.Fatalf("docker args must preserve image entrypoint unless command override is explicit: %q", args)
	}
	if !strings.Contains(args, image+"\x00serve\x00--port\x008080") {
		t.Fatalf("command args must remain after image arg: %q", args)
	}
}

func TestDockerCompatibleRuntimeRequiresCommandForEntrypointOverride(t *testing.T) {
	for _, command := range [][]string{nil, []string{""}} {
		_, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
			Image:                      "ghcr.io/gocodealone/workload-with-entrypoint:latest",
			Command:                    command,
			CommandOverridesEntrypoint: true,
			Workspace:                  t.TempDir(),
			Network:                    SandboxNetworkBridge,
		})
		cleanup()
		if err == nil || !strings.Contains(err.Error(), "entrypoint override requires a command") {
			t.Fatalf("entrypoint override accepted command %#v: %v", command, err)
		}
	}
}

func TestDockerCompatibleRuntimeUsesDefaultDenyNetwork(t *testing.T) {
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/workload:latest",
		Command:   []string{"true"},
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	if !strings.Contains(strings.Join(spec.Args, "\x00"), "--network\x00none") {
		t.Fatalf("default network must be none: %+v", spec.Args)
	}
}

func TestDockerCompatibleRuntimeAllowsOnlyExplicitBridgeNetwork(t *testing.T) {
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/container-builder:latest",
		Command:   []string{"sh", "-c", "true"},
		Workspace: t.TempDir(),
		Network:   SandboxNetworkBridge,
	})
	if err != nil {
		t.Fatalf("prepare bridge run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	if !strings.Contains(args, "--network\x00bridge") {
		t.Fatalf("bridge network not applied: %q", args)
	}
	if strings.Contains(args, "--network\x00host") {
		t.Fatalf("host network leaked into args: %q", args)
	}

	_, cleanup, err = (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/container-builder:latest",
		Command:   []string{"sh", "-c", "true"},
		Workspace: t.TempDir(),
		Network:   "host",
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "unsupported sandbox network") {
		t.Fatalf("unsupported network err: got %v", err)
	}
}

func TestDockerCompatibleRuntimeSupportsExplicitBuilderProfile(t *testing.T) {
	workspace := t.TempDir()
	contextDir := filepath.Join(workspace, "build-context", "nested")
	if err := os.MkdirAll(contextDir, 0o700); err != nil {
		t.Fatalf("mkdir build context: %v", err)
	}
	contextFile := filepath.Join(contextDir, "Dockerfile")
	if err := os.WriteFile(contextFile, []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("write build context: %v", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		t.Fatalf("chmod workspace: %v", err)
	}
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:           "ghcr.io/gocodealone/container-builder:latest",
		Command:         []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace:       workspace,
		RunAsRoot:       true,
		AddCapabilities: []string{"CHOWN", "FOWNER"},
		ExtraTmpfs:      []string{"/wfcompute-build:rw,noexec,nosuid,nodev,size=512m"},
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	info, err := os.Stat(workspace)
	if err != nil {
		t.Fatalf("stat workspace after prepare: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("builder workspace mode after prepare: got %o want 755", got)
	}
	defer func() {
		cleanup()
		info, err := os.Stat(workspace)
		if err != nil {
			t.Fatalf("stat workspace after cleanup: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("builder workspace mode after cleanup: got %o want 700", got)
		}
	}()
	args := strings.Join(spec.Args, "\x00")
	for _, want := range []string{
		"--network\x00none",
		"--read-only",
		"--cap-drop\x00ALL",
		"--cap-add\x00CHOWN",
		"--cap-add\x00FOWNER",
		"--security-opt\x00no-new-privileges",
		"--pids-limit\x00256",
		"--tmpfs\x00/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--tmpfs\x00/wfcompute-build:rw,noexec,nosuid,nodev,size=512m",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("builder sandbox args missing %q in %q", want, args)
		}
	}
	for _, forbidden := range []string{fmt.Sprintf("--user\x00%d:%d", os.Getuid(), os.Getgid()), "--privileged", "--network\x00host", "--cap-add\x00SYS_ADMIN", "/var/run/docker.sock"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("builder sandbox args contain forbidden %q in %q", forbidden, args)
		}
	}
}

func TestDockerCompatibleRuntimeRequiresExplicitWritableRootFS(t *testing.T) {
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:          "ghcr.io/gocodealone/container-builder:latest",
		Command:        []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace:      t.TempDir(),
		RunAsRoot:      true,
		WritableRootFS: true,
		ExtraTmpfs:     []string{"/wfcompute-build:rw,noexec,nosuid,nodev,size=512m"},
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	if strings.Contains(args, "--read-only") {
		t.Fatalf("writable rootfs must be explicit, got %q", args)
	}
	for _, forbidden := range []string{"--privileged", "--cap-add\x00SYS_ADMIN", "/var/run/docker.sock", "--network\x00host"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("writable-root sandbox args contain forbidden %q in %q", forbidden, args)
		}
	}
}

func TestDockerCompatibleRuntimeRejectsDisallowedCapabilitiesAndTmpfs(t *testing.T) {
	_, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:           "ghcr.io/gocodealone/container-builder:latest",
		Command:         []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace:       t.TempDir(),
		RunAsRoot:       true,
		AddCapabilities: []string{"SYS_ADMIN"},
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "capability") {
		t.Fatalf("expected disallowed capability rejection, got %v", err)
	}

	_, cleanup, err = (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:      "ghcr.io/gocodealone/container-builder:latest",
		Command:    []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace:  t.TempDir(),
		RunAsRoot:  true,
		ExtraTmpfs: []string{"/var/run:rw,size=1g"},
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "tmpfs") {
		t.Fatalf("expected disallowed tmpfs rejection, got %v", err)
	}
}

func TestDockerCompatibleRuntimeDoesNotLeakEnvValuesInArgsAndCleansEnvFile(t *testing.T) {
	value := "runtime-sensitive-value"
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/workload:latest",
		Command:   []string{"./build.sh"},
		Workspace: t.TempDir(),
		Env: map[string]string{
			"SAFE_VALUE": value,
		},
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	args := strings.Join(spec.Args, " ")
	if strings.Contains(args, value) {
		t.Fatalf("docker args leaked env value: %q", args)
	}
	if spec.EnvFile == "" {
		t.Fatal("expected env file for sandbox env")
	}
	info, err := os.Stat(spec.EnvFile)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode: got %o want 600", info.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(spec.EnvFile); !os.IsNotExist(err) {
		t.Fatalf("env file residual after cleanup: %v", err)
	}
}

func TestDockerCompatibleRuntimeHonorsWorkingDirInsideWorkspace(t *testing.T) {
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:      "ghcr.io/gocodealone/workload:latest",
		Command:    []string{"pwd"},
		Workspace:  workspace,
		WorkingDir: "work",
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	if !strings.Contains(strings.Join(spec.Args, "\x00"), "-w\x00/workspace/work") {
		t.Fatalf("working dir not applied: %+v", spec.Args)
	}

	_, cleanup, err = (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:      "ghcr.io/gocodealone/workload:latest",
		Command:    []string{"pwd"},
		Workspace:  workspace,
		WorkingDir: "../outside",
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "working_dir") {
		t.Fatalf("expected working dir escape rejection, got %v", err)
	}
}

func TestPodmanSandboxRuntimeKeepsHostUserNamespace(t *testing.T) {
	spec, cleanup, err := (DockerSandboxRuntime{Tool: "podman"}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/workload:latest",
		Command:   []string{"./build.sh"},
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	args := strings.Join(spec.Args, "\x00")
	for _, want := range []string{"--userns\x00keep-id", fmt.Sprintf("--user\x00%d:%d", os.Getuid(), os.Getgid())} {
		if !strings.Contains(args, want) {
			t.Fatalf("podman args missing %q in %q", want, args)
		}
	}
}

func TestNerdctlSandboxRuntimePrefixesScopedRuntimeArgs(t *testing.T) {
	scope := ContainerRuntimeScope{Args: []string{"--namespace", "wfcompute-private-image"}}
	spec, cleanup, err := (DockerSandboxRuntime{Tool: "nerdctl"}).prepareRun(SandboxRunRequest{
		Image:        "localhost/private-provider:v1",
		Command:      []string{"run"},
		RuntimeScope: scope,
		Workspace:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	defer cleanup()
	if !slices.Equal(spec.RuntimeArgs, scope.Args) {
		t.Fatalf("runtime args = %+v want %+v", spec.RuntimeArgs, scope.Args)
	}
	if got := strings.Join(spec.CommandArgs(), " "); !strings.HasPrefix(got, strings.Join(scope.Args, " ")+" run ") {
		t.Fatalf("scoped runtime args not prefixed: %q", got)
	}
}

func TestDockerCompatibleRuntimeRejectsUnsafeRuntimeScopeArgs(t *testing.T) {
	_, cleanup, err := (DockerSandboxRuntime{Tool: "nerdctl"}).prepareRun(SandboxRunRequest{
		Image:        "localhost/private-provider:v1",
		Command:      []string{"run"},
		RuntimeScope: ContainerRuntimeScope{Args: []string{"--address", "/var/run/containerd/containerd.sock"}},
		Workspace:    t.TempDir(),
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "runtime scope") {
		t.Fatalf("expected unsafe runtime scope rejection, got %v", err)
	}
}

func TestDockerCompatibleRuntimeAllowsMountAtRequiredPrefix(t *testing.T) {
	dir := t.TempDir()
	hostPath, containerPath, err := validateSandboxMount(SandboxMount{
		HostPath:       dir,
		ContainerPath:  "/data",
		RequiredPrefix: dir,
	})
	if err != nil {
		t.Fatalf("mount at required prefix rejected: %v", err)
	}
	if hostPath != filepath.Clean(dir) || containerPath != "/data" {
		t.Fatalf("mount normalized to host=%q container=%q", hostPath, containerPath)
	}
}

func TestDockerCompatibleRuntimeRestoresRecursiveWorkspacePermissions(t *testing.T) {
	workspace := t.TempDir()
	nested := filepath.Join(workspace, "nested")
	file := filepath.Join(nested, "script.sh")
	if err := os.Chmod(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{
		Image:     "ghcr.io/gocodealone/container-builder:latest",
		Command:   []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace: workspace,
		RunAsRoot: true,
	})
	if err != nil {
		t.Fatalf("prepare run: %v", err)
	}
	_ = spec
	cleanup()
	for path, want := range map[string]os.FileMode{
		workspace: 0o700,
		nested:    0o700,
		file:      0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode after cleanup: got %o want %o", path, got, want)
		}
	}
}

func TestDockerCompatibleRuntimeReturnsExitCode(t *testing.T) {
	result, err := (DockerSandboxRuntime{Runner: fakeDockerCommandRunner{err: fakeExitError(17)}}).Run(t.Context(), SandboxRunRequest{
		Image:     "image",
		Command:   []string{"cmd"},
		Workspace: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected runtime error")
	}
	if result.ExitCode != 17 {
		t.Fatalf("exit code not populated on runtime failure: %+v err=%v", result, err)
	}
}

func TestDockerCompatibleRuntimeAvailableIncludesStderr(t *testing.T) {
	err := (DockerSandboxRuntime{Runner: fakeDockerCommandRunner{
		stderr: []byte("Cannot connect to runtime socket"),
		err:    fakeExitError(125),
	}}).Available(t.Context())
	if err == nil {
		t.Fatal("expected availability error")
	}
	if !strings.Contains(err.Error(), "Cannot connect to runtime socket") {
		t.Fatalf("availability error omitted stderr: %v", err)
	}
}

func TestDockerCompatibleRuntimeAvailableFallsBackWhenStderrIsBlank(t *testing.T) {
	err := (DockerSandboxRuntime{Runner: fakeDockerCommandRunner{
		stdout: []byte("runtime daemon is unavailable"),
		stderr: []byte(" \n\t"),
		err:    fakeExitError(125),
	}}).Available(t.Context())
	if err == nil {
		t.Fatal("expected availability error")
	}
	if !strings.Contains(err.Error(), "runtime daemon is unavailable") {
		t.Fatalf("availability error did not fall back to stdout: %v", err)
	}
	if strings.HasSuffix(err.Error(), ":") {
		t.Fatalf("availability error ended with empty message separator: %v", err)
	}
}

type fakeDockerCommandRunner struct {
	stdout []byte
	stderr []byte
	err    error
}

func (r fakeDockerCommandRunner) CombinedOutput(context.Context, []byte, string, ...string) ([]byte, []byte, error) {
	return r.stdout, r.stderr, r.err
}

type fakeExitError int

func (e fakeExitError) Error() string {
	return fmt.Sprintf("exit status %d", e)
}

func (e fakeExitError) ExitCode() int {
	return int(e)
}
