package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

type disappearingWorkspaceRuntime struct{}

func (disappearingWorkspaceRuntime) Available(context.Context) error { return nil }
func (disappearingWorkspaceRuntime) Run(_ context.Context, req SandboxRunRequest) (SandboxRunResult, error) {
	if err := os.RemoveAll(req.Workspace); err != nil {
		return SandboxRunResult{}, err
	}
	return SandboxRunResult{Stdout: []byte("known-output"), ArtifactHash: "sha256:" + strings.Repeat("a", 64)}, nil
}

type disappearingWorkspaceRunner struct{ workspace string }

func (r disappearingWorkspaceRunner) CombinedOutput(context.Context, []byte, string, ...string) ([]byte, []byte, error) {
	if err := os.RemoveAll(r.workspace); err != nil {
		return nil, nil, err
	}
	return []byte("known-output"), nil, nil
}

// The real runtime and both adapters must not turn an incomplete accounting
// walk into a successfully measured zero-byte workspace.
func TestNativeAccountingIncompleteWalkIsNotSuccessfulZero(t *testing.T) {
	for _, kind := range []string{"direct", "command", "build"} {
		t.Run(kind, func(t *testing.T) {
			workspace := t.TempDir()
			var size int64
			var err error
			switch kind {
			case "direct":
				result, runErr := (DockerSandboxRuntime{Runner: disappearingWorkspaceRunner{workspace}}).Run(t.Context(), SandboxRunRequest{Image: "fixture", Command: []string{"true"}, Workspace: workspace, Timeout: time.Second})
				size, err = result.ResourceUsage.WorkspaceBytes, runErr
			case "command":
				invocation, makeErr := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "fixture", Workspace: workspace, Workload: core.CommandWorkload{Args: []string{"true"}}})
				if makeErr != nil {
					t.Fatal(makeErr)
				}
				result, runErr := (SandboxRuntimeCommandAdapter{Runtime: disappearingWorkspaceRuntime{}}).RunSandboxedCommand(t.Context(), invocation)
				size, err = result.ResourceUsage.WorkspaceBytes, runErr
			case "build":
				if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
					t.Fatal(err)
				}
				invocation, makeErr := NewSandboxedContainerBuildInvocation(SandboxedContainerBuildInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "fixture", Workspace: workspace, Workload: core.ContainerBuildWorkload{ContextDirectory: ".", Dockerfile: "Dockerfile", Tags: []string{"fixture:local"}}})
				if makeErr != nil {
					t.Fatal(makeErr)
				}
				result, runErr := (SandboxRuntimeContainerBuildAdapter{Runtime: disappearingWorkspaceRuntime{}}).BuildSandboxedContainer(t.Context(), invocation)
				size, err = result.ResourceUsage.WorkspaceBytes, runErr
			}
			if !errors.Is(err, os.ErrNotExist) || size != 0 {
				t.Fatalf("incomplete workspace walk reported success or partial usage: size=%d err=%v", size, err)
			}
			if strings.Contains(err.Error(), "known-output") {
				t.Fatal("accounting error echoed successful process output")
			}
		})
	}
}

// Cancellation is triggered on a real context at deterministic accounting
// checkpoints, avoiding timing-sensitive sleeps or a large filesystem fixture.
type accountingCheckpointContext struct {
	context.Context
	cancel           context.CancelFunc
	cancelAt, checks int
}

func (c *accountingCheckpointContext) Err() error {
	c.checks++
	if c.checks == c.cancelAt {
		c.cancel()
	}
	return c.Context.Err()
}
func TestNativeAccountingContextCancellationDiscardsPartialMeasurement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b"), []byte("1234567"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   int
	}{{"before_io", 1}, {"after_first_file", 4}, {"after_last_file", 5}} {
		t.Run(tc.name, func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &accountingCheckpointContext{Context: base, cancel: cancel, cancelAt: tc.at}
			size, err := directorySizeContext(ctx, root)
			if !errors.Is(err, context.Canceled) || size != 0 || ctx.checks != tc.at {
				t.Fatalf("canceled walk retained bytes or continued: size=%d err=%v checks=%d", size, err, ctx.checks)
			}
		})
	}
	size, err := directorySizeContext(t.Context(), root)
	if err != nil || size != 10 || DirectorySize(root) != 10 {
		t.Fatalf("complete accounting changed: size=%d err=%v", size, err)
	}
	expired, cancel := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer cancel()
	if size, err := directorySizeContext(expired, filepath.Join(root, "missing")); !errors.Is(err, context.DeadlineExceeded) || size != 0 {
		t.Fatalf("expired accounting began I/O: size=%d err=%v", size, err)
	}
}
