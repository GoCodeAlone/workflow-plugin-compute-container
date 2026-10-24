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

type policyFixtureRunner struct {
	info, volumes string
	calls         [][]string
}

func (r *policyFixtureRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, errors.New("unbounded preflight")
	}
	r.calls = append(r.calls, append([]string(nil), args...))
	switch args[0] {
	case "info":
		return []byte(r.info), nil, nil
	case "image":
		return []byte(r.volumes), nil, nil
	case "run":
		return []byte("marker"), nil, nil
	}
	return nil, nil, nil
}

const supportedDockerControls = `{"OSType":"linux","MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true,"PidsLimit":true}`

func TestNativeReadOnlyPreflightRejectsMissingControlEvidenceAndImageVolumes(t *testing.T) {
	req := SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 16, MemoryBytes: 64 << 20, CPUPercent: 25}}
	for _, mode := range []string{"valid", "missing_memory", "missing_cpu", "missing_pid", "image_volumes", "malformed_info", "malformed_image", "unsupported_backend"} {
		t.Run(mode, func(t *testing.T) {
			runner := &policyFixtureRunner{info: supportedDockerControls, volumes: "null"}
			r := DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: runner}
			switch mode {
			case "missing_memory":
				runner.info = strings.Replace(runner.info, `"MemoryLimit":true`, `"MemoryLimit":false`, 1)
			case "missing_cpu":
				runner.info = strings.Replace(runner.info, `"CPUCfsQuota":true`, `"CPUCfsQuota":false`, 1)
			case "missing_pid":
				runner.info = strings.Replace(runner.info, `"PidsLimit":true`, `"PidsLimit":false`, 1)
			case "image_volumes":
				runner.volumes = `{"/unbounded":{}}`
			case "malformed_info":
				runner.info = `{}`
			case "malformed_image":
				runner.volumes = `[]`
			case "unsupported_backend":
				r.Tool = "podman"
			}
			err := r.ValidateReadOnlyPolicy(t.Context(), req)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode %s err=%v", mode, err)
			}
		})
	}
}

type timeoutMetadataRuntime struct{ availableDeadline bool }

func (r *timeoutMetadataRuntime) Available(ctx context.Context) error {
	_, r.availableDeadline = ctx.Deadline()
	return nil
}
func (*timeoutMetadataRuntime) Run(ctx context.Context, _ SandboxRunRequest) (SandboxRunResult, error) {
	<-ctx.Done()
	return SandboxRunResult{Stdout: []byte("tail")}, &OutputLimitError{Metadata: OutputCaptureMetadata{Complete: true, StdoutOriginalSizeBytes: 20, StdoutTruncated: true}}
}
func TestNativeAdapterDeadlineIncludesAvailabilityAndPreservesCaptureError(t *testing.T) {
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: t.TempDir(), Timeout: time.Millisecond, Workload: core.CommandWorkload{Args: []string{"true"}}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &timeoutMetadataRuntime{}
	_, err = (SandboxRuntimeCommandAdapter{Runtime: runtime}).RunSandboxedCommand(t.Context(), invocation)
	var capture *OutputLimitError
	if !runtime.availableDeadline || !errors.As(err, &capture) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout lost metadata/deadline: %v", err)
	}
}

func TestNativeReadOnlyAdapterRejectsArtifactsBeforeAvailability(t *testing.T) {
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: t.TempDir(), Workload: core.CommandWorkload{Args: []string{"true"}, ArtifactAllowlist: []string{"out.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &recordingSandboxRuntime{}
	_, err = (SandboxRuntimeCommandAdapter{Runtime: runtime, ReadOnlyWorkspace: true}).RunSandboxedCommand(t.Context(), invocation)
	if err == nil || runtime.request.Image != "" {
		t.Fatal("read-only artifact task reached execution")
	}
}

func TestNativeConfiguredRuntimeReadOnlyCannotBeDisabledAtAdapter(t *testing.T) {
	invocation, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: t.TempDir(), Workload: core.CommandWorkload{Args: []string{"true"}, ArtifactAllowlist: []string{"out.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &policyFixtureRunner{}
	for _, runtime := range []SandboxRuntime{DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: runner}, &DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: runner}} {
		_, err = (SandboxRuntimeCommandAdapter{Runtime: runtime}).RunSandboxedCommand(t.Context(), invocation)
		if err == nil || !strings.Contains(err.Error(), "artifacts") || len(runner.calls) != 0 {
			t.Fatalf("configured policy lost at adapter: %v calls=%v", err, runner.calls)
		}
	}
}

type runtimeLimitProbe struct{ bounded bool }

func (r *runtimeLimitProbe) Available(ctx context.Context) error {
	d, ok := ctx.Deadline()
	r.bounded = ok && time.Until(d) < 1500*time.Millisecond
	return nil
}
func (*runtimeLimitProbe) Run(context.Context, SandboxRunRequest) (SandboxRunResult, error) {
	return SandboxRunResult{}, nil
}
func TestNativeAdapterRuntimeLimitIncludesAvailability(t *testing.T) {
	inv, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: t.TempDir(), Timeout: 10 * time.Second, Limits: core.ResourceLimits{RuntimeSeconds: 1}, Workload: core.CommandWorkload{Args: []string{"true"}}})
	if err != nil {
		t.Fatal(err)
	}
	r := &runtimeLimitProbe{}
	_, err = (SandboxRuntimeCommandAdapter{Runtime: r}).RunSandboxedCommand(t.Context(), inv)
	if err != nil || !r.bounded {
		t.Fatalf("runtime limit omitted availability: %v bounded=%t", err, r.bounded)
	}
}

type controlCaptureRunner struct{}

func (controlCaptureRunner) CombinedOutput(context.Context, []byte, string, ...string) ([]byte, []byte, error) {
	return []byte("tail"), nil, &OutputLimitError{Metadata: OutputCaptureMetadata{Complete: true, StdoutOriginalSizeBytes: 999, StdoutTruncated: true}}
}
func TestNativeControlCaptureCannotMasqueradeAsWorkloadProvenance(t *testing.T) {
	r := DockerSandboxRuntime{Runner: controlCaptureRunner{}}
	var metadata OutputCaptureMetadataProvider
	if err := r.Available(t.Context()); err == nil || errors.As(err, &metadata) {
		t.Fatalf("availability output presented as workload: %v", err)
	}
	r.ReadOnlyWorkspace = true
	req := SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 16, MemoryBytes: 64 << 20, CPUPercent: 25}}
	if err := r.ValidateReadOnlyPolicy(t.Context(), req); err == nil || errors.As(err, &metadata) {
		t.Fatalf("preflight output presented as workload: %v", err)
	}
}

type cleanupFailureRunner struct {
	cancel context.CancelFunc
	calls  [][]string
	fresh  bool
}

func (r *cleanupFailureRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(r.calls) == 1 {
		r.cancel()
		return []byte("partial"), nil, context.Canceled
	}
	_, r.fresh = ctx.Deadline()
	r.fresh = r.fresh && ctx.Err() == nil
	return nil, nil, &OutputLimitError{Metadata: OutputCaptureMetadata{Complete: true, StdoutOriginalSizeBytes: 999, StdoutTruncated: true}}
}
func TestNativeCancellationCleanupIsScopedFreshVisibleAndNotTaskOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runner := &cleanupFailureRunner{cancel: cancel}
	result, err := (DockerSandboxRuntime{Tool: "nerdctl", Runner: runner}).Run(ctx, SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), RuntimeScope: ContainerRuntimeScope{Args: []string{"--namespace", "owned"}}})
	if len(runner.calls) != 2 || !runner.fresh || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("cleanup not fresh/visible: %v %v", runner.calls, err)
	}
	if got := strings.Join(runner.calls[1][:4], " "); got != "--namespace owned inspect --type" {
		t.Fatalf("lost cleanup scope %v", runner.calls[1])
	}
	var capture OutputCaptureMetadataProvider
	if !errors.As(err, &capture) || capture.CaptureMetadata().Complete || len(result.Stdout) != 0 || result.ResourceUsage.OutputBytes != 0 {
		t.Fatalf("partial/control bytes claimed as complete task output: result=%+v err=%v", result, err)
	}
}

func TestNativeReadOnlyCanceledPreflightStopsBeforeEngineCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runner := &policyFixtureRunner{info: supportedDockerControls, volumes: "null"}
	r := DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: runner}
	err := r.ValidateReadOnlyPolicy(ctx, SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 16, MemoryBytes: 64 << 20, CPUPercent: 25}})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("canceled preflight kept running: %v calls=%v", err, runner.calls)
	}
}

type accountingRunner struct{}

func (accountingRunner) CombinedOutput(_ context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	if len(args) > 0 && args[0] == "version" {
		return []byte("1"), nil, nil
	}
	return []byte("0123456789"), []byte("abcdefghij"), nil
}
func TestNativeRuntimeAdapterCountsCompleteOriginalOutputNotRetainedTails(t *testing.T) {
	inv, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{OutputBytes: 8}, Workload: core.CommandWorkload{Args: []string{"true"}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (SandboxRuntimeCommandAdapter{Runtime: DockerSandboxRuntime{Runner: accountingRunner{}}}).RunSandboxedCommand(t.Context(), inv)
	var capture *OutputLimitError
	if !errors.As(err, &capture) || result.ResourceUsage.OutputBytes != 20 || len(result.Stdout)+len(result.Stderr) != 8 {
		t.Fatalf("original output accounting lost: %+v err=%v", result, err)
	}
}

type collisionRunner struct {
	cancel  context.CancelFunc
	removed bool
}

func (r *collisionRunner) CombinedOutput(_ context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	switch args[0] {
	case "run":
		r.cancel()
		return nil, nil, errors.New("name collision")
	case "inspect":
		return []byte(`{"id":"` + strings.Repeat("b", 64) + `","owner":"foreign"}`), nil, nil
	case "rm":
		r.removed = true
		return nil, nil, nil
	}
	return nil, nil, nil
}
func TestNativeCommandCollisionNeverRemovesForeignContainer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runner := &collisionRunner{cancel: cancel}
	_, err := (DockerSandboxRuntime{Runner: runner}).Run(ctx, SandboxRunRequest{Image: "cached", Workspace: t.TempDir()})
	if err == nil || runner.removed {
		t.Fatalf("foreign collision target removed: removed=%t err=%v", runner.removed, err)
	}
}

type collisionProbeRunner struct{ removed bool }

func (*collisionProbeRunner) LookPath(name string) (string, error) { return name, nil }
func (r *collisionProbeRunner) Run(_ context.Context, _ string, args ...string) (RuntimeCommandResult, error) {
	switch args[0] {
	case "version":
		return RuntimeCommandResult{Stdout: []byte("1")}, nil
	case "run":
		return RuntimeCommandResult{}, errors.New("name collision")
	case "inspect":
		return RuntimeCommandResult{Stdout: []byte(`{"id":"` + strings.Repeat("b", 64) + `","owner":"foreign"}`)}, nil
	case "rm":
		r.removed = true
		return RuntimeCommandResult{}, nil
	}
	return RuntimeCommandResult{}, nil
}
func TestNativeProbeCollisionNeverRemovesForeignContainer(t *testing.T) {
	runner := &collisionProbeRunner{}
	report := (RuntimeBackendProbe{Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}), Runner: runner}).Probe(t.Context())
	if report.Status != core.RuntimeBackendDegraded || runner.removed {
		t.Fatalf("foreign probe target removed: removed=%t report=%+v", runner.removed, report)
	}
}

type adapterCaptureRuntime struct{ complete, availableError bool }

func (r adapterCaptureRuntime) Available(context.Context) error {
	if r.availableError {
		return &OutputLimitError{Metadata: OutputCaptureMetadata{Complete: true, StdoutOriginalSizeBytes: 999}}
	}
	return nil
}
func (r adapterCaptureRuntime) Run(ctx context.Context, _ SandboxRunRequest) (SandboxRunResult, error) {
	<-ctx.Done()
	metadata := OutputCaptureMetadata{Complete: r.complete, StdoutOriginalSizeBytes: 20, StdoutTruncated: true}
	if !r.complete {
		return SandboxRunResult{}, &CaptureIncompleteError{Metadata: metadata, Cause: ctx.Err()}
	}
	return SandboxRunResult{Stdout: []byte("tail")}, &OutputLimitError{Metadata: metadata, Cause: ctx.Err()}
}
func nativeAdapterCall(t *testing.T, name string, runtime SandboxRuntime) (core.RuntimeExecutionResult, error) {
	t.Helper()
	workspace := t.TempDir()
	if name == "command" {
		inv, err := NewSandboxedCommandInvocation(SandboxedCommandInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "cached", Workspace: workspace, Timeout: time.Millisecond, Workload: core.CommandWorkload{Args: []string{"true"}}})
		if err != nil {
			t.Fatal(err)
		}
		return (SandboxRuntimeCommandAdapter{Runtime: runtime}).RunSandboxedCommand(t.Context(), inv)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inv, err := NewSandboxedContainerBuildInvocation(SandboxedContainerBuildInvocationOptions{TaskID: "task", LeaseID: "lease", Image: "builder", Workspace: workspace, Timeout: time.Millisecond, Workload: core.ContainerBuildWorkload{ContextDirectory: ".", Dockerfile: "Dockerfile", Tags: []string{"example:test"}}})
	if err != nil {
		t.Fatal(err)
	}
	return (SandboxRuntimeContainerBuildAdapter{Runtime: runtime}).BuildSandboxedContainer(t.Context(), inv)
}
func TestNativeAllAdaptersPreserveCaptureMetadataAcrossTimeout(t *testing.T) {
	for _, name := range []string{"command", "build"} {
		for _, complete := range []bool{true, false} {
			t.Run(name+map[bool]string{true: "_overflow", false: "_incomplete"}[complete], func(t *testing.T) {
				_, err := nativeAdapterCall(t, name, adapterCaptureRuntime{complete: complete})
				var capture OutputCaptureMetadataProvider
				if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &capture) || capture.CaptureMetadata().Complete != complete {
					t.Fatalf("adapter lost capture provenance: %v", err)
				}
			})
		}
	}
}
func TestNativeAllAdaptersDoNotProjectAvailabilityOutputAsTask(t *testing.T) {
	for _, name := range []string{"command", "build"} {
		t.Run(name, func(t *testing.T) {
			_, err := nativeAdapterCall(t, name, adapterCaptureRuntime{availableError: true})
			var capture OutputCaptureMetadataProvider
			if err == nil || errors.As(err, &capture) {
				t.Fatalf("control output claimed as workload: %v", err)
			}
		})
	}
}
