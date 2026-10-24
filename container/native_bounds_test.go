package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestNativeProcessFixture(t *testing.T) {
	if os.Getenv("WFC_PLUGIN_NATIVE_FIXTURE") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "flood" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("o", 1100000)+"stdout-final-tail")
		_, _ = io.WriteString(os.Stderr, strings.Repeat("e", 1100000)+"stderr-final-tail")
	} else if mode == "sleep" {
		time.Sleep(10 * time.Second)
	} else if mode == "inherited-pipe" || mode == "inherited-pipe-exit" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeProcessFixture$", "--", "sleep")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(os.Getenv("WFC_PLUGIN_PID_FILE"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
			os.Exit(4)
		}
		if err := cmd.Process.Release(); err != nil {
			os.Exit(5)
		}
		if mode == "inherited-pipe-exit" {
			os.Exit(7)
		}
	}
	os.Exit(0)
}

func TestNativeExactPositiveOutputLimitAndTruthfulProvenance(t *testing.T) {
	t.Setenv("WFC_PLUGIN_NATIVE_FIXTURE", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{8, 3 << 20} {
		r := ExecDockerCommandRunner{MaxOutputBytes: limit}
		out, stderr, err := r.CombinedOutput(t.Context(), nil, binary, "-test.run=^TestNativeProcessFixture$", "--", "flood")
		if limit == 8 {
			var capture *OutputLimitError
			if !errors.As(err, &capture) {
				t.Fatalf("missing typed output provenance: %v", err)
			}
			m := capture.Metadata
			if !m.Complete || m.StdoutOriginalSizeBytes != 1100017 || m.StderrOriginalSizeBytes != 1100017 || !m.StdoutTruncated || !m.StderrTruncated {
				t.Fatalf("false original metadata: %+v", m)
			}
			if string(out) != "tail" || string(stderr) != "tail" {
				t.Fatalf("wrong aggregate final tails %q/%q", out, stderr)
			}
			if strings.Contains(err.Error(), "tail") {
				t.Fatal("error copied output")
			}
		} else if err != nil || len(out)+len(stderr) != 2200034 {
			t.Fatalf("positive limit replaced by smaller default: %d %v", len(out)+len(stderr), err)
		}
	}
}

func TestNativeIncompleteCaptureDoesNotInventCompleteOriginalSizes(t *testing.T) {
	for _, mode := range []string{"inherited-pipe", "inherited-pipe-exit"} {
		t.Run(mode, func(t *testing.T) { testNativeIncompleteCapture(t, mode) })
	}
}

func testNativeIncompleteCapture(t *testing.T, mode string) {
	t.Setenv("WFC_PLUGIN_NATIVE_FIXTURE", "1")
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("WFC_PLUGIN_PID_FILE", pidFile)
	t.Cleanup(func() {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			}
		}
	})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, stderr, err := (ExecDockerCommandRunner{}).CombinedOutput(t.Context(), nil, binary, "-test.run=^TestNativeProcessFixture$", "--", mode)
	var capture *CaptureIncompleteError
	if !errors.As(err, &capture) || capture.Metadata.Complete || len(out)+len(stderr) != 0 {
		t.Fatalf("incomplete capture represented as complete: %v out=%d stderr=%d", err, len(out), len(stderr))
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("pipe wait was unbounded")
	}
}

func TestNativeDefaultOutputContinuesDrainingAndRetainsAggregateTail(t *testing.T) {
	t.Setenv("WFC_PLUGIN_NATIVE_FIXTURE", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	out, stderr, err := splitOutputContextWithStdin(ctx, nil, binary, "-test.run=^TestNativeProcessFixture$", "--", "flood")
	if len(out)+len(stderr) > 1<<20 {
		t.Fatalf("unbounded aggregate output: %d", len(out)+len(stderr))
	}
	if !bytes.HasSuffix(out, []byte("stdout-final-tail")) || !bytes.HasSuffix(stderr, []byte("stderr-final-tail")) {
		t.Fatal("did not drain final stream tails")
	}
	if err == nil {
		t.Fatal("effective default output limit violation not reported")
	}
}

func TestNativeProtectedRunNeverPulls(t *testing.T) {
	spec, cleanup, err := (DockerSandboxRuntime{}).prepareRun(SandboxRunRequest{Image: "local-pinned-image", Workspace: t.TempDir()})
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if dockerArgValue(spec.Args, "--pull") != "never" {
		t.Fatalf("implicit image pull remains possible: %v", spec.Args)
	}
}

type nativeDeadlineRunner struct{ bounded bool }

func (r *nativeDeadlineRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	if len(args) > 0 && args[0] == "run" {
		deadline, ok := ctx.Deadline()
		r.bounded = ok && time.Until(deadline) <= 100*time.Millisecond
		return nil, nil, errors.New("fixture completed")
	}
	return nil, nil, nil
}
func TestNativeDirectRunHonorsRequestTimeout(t *testing.T) {
	r := &nativeDeadlineRunner{}
	_, _ = (DockerSandboxRuntime{Runner: r}).Run(t.Context(), SandboxRunRequest{Image: "local-image", Workspace: t.TempDir(), Timeout: 25 * time.Millisecond})
	if !r.bounded {
		t.Fatal("direct runtime ignored requested timeout")
	}
}

func TestNativeAvailabilityHasFiniteDefaultDeadline(t *testing.T) {
	r := nativeAvailabilityRunner{}
	if err := (DockerSandboxRuntime{Runner: r}).Available(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type nativeAvailabilityRunner struct{}

func (nativeAvailabilityRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, _ ...string) ([]byte, []byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, fmt.Errorf("availability deadline missing")
	}
	return nil, nil, nil
}

func TestNativeReadOnlyWorkspacePolicyAndLegacyMount(t *testing.T) {
	r := DockerSandboxRuntime{}
	field := reflect.ValueOf(&r).Elem().FieldByName("ReadOnlyWorkspace")
	if !field.IsValid() {
		t.Fatal("read-only workspace policy missing")
	}
	field.SetBool(true)
	workspace := t.TempDir()
	req := SandboxRunRequest{Workspace: workspace, Image: "local", Limits: core.ResourceLimits{WorkspaceBytes: 16, MemoryBytes: 64 << 20, CPUPercent: 25}}
	spec, cleanup, err := r.prepareRun(req)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(spec.Args, "\x00")
	if !strings.Contains(args, workspace+":/workspace:ro") || dockerArgValue(spec.Args, "--log-driver") != "none" {
		t.Fatalf("missing enforced read-only/log policy: %v", spec.Args)
	}
	for _, mode := range []string{"root", "tmpfs", "writable_mount", "shadow_mount", "oversize", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			bad := req
			switch mode {
			case "root":
				bad.WritableRootFS = true
			case "tmpfs":
				bad.ExtraTmpfs = []string{"/wfcompute-build:rw,noexec,nosuid,nodev,size=512m"}
			case "writable_mount":
				bad.DataMounts = []SandboxMount{{HostPath: t.TempDir(), ContainerPath: "/data"}}
			case "shadow_mount":
				bad.DataMounts = []SandboxMount{{HostPath: t.TempDir(), ContainerPath: "/workspace/nested", ReadOnly: true}}
			case "oversize":
				bad.Workspace = t.TempDir()
				if err := os.WriteFile(filepath.Join(bad.Workspace, "big"), make([]byte, 17), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				bad.Workspace = t.TempDir()
				if err := os.Symlink(workspace, filepath.Join(bad.Workspace, "link")); err != nil {
					t.Skip(err)
				}
			}
			_, c, err := r.prepareRun(bad)
			c()
			if err == nil {
				t.Fatal("unsafe read-only request accepted")
			}
		})
	}
	legacy, c, err := (DockerSandboxRuntime{}).prepareRun(req)
	defer c()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(legacy.Args, "\x00"), workspace+":/workspace:rw") {
		t.Fatal("legacy writable semantics changed")
	}
}

func TestNativeProbeHasNoPullLogStorageOrUnboundedLifetime(t *testing.T) {
	runner := &nativeProbeRunner{}
	probe := RuntimeBackendProbe{Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}), Runner: runner}
	report := probe.Probe(t.Context())
	if report.Status != core.RuntimeBackendSupported {
		t.Fatalf("probe: %+v", report)
	}
	if !runner.bounded {
		t.Fatal("probe deadline missing")
	}
	for _, key := range []string{"--name", "--memory", "--cpus", "--pids-limit"} {
		if dockerArgValue(runner.args, key) == "" {
			t.Fatalf("probe missing %s", key)
		}
	}
	if dockerArgValue(runner.args, "--pull") != "never" || dockerArgValue(runner.args, "--log-driver") != "none" {
		t.Fatalf("probe may pull/store logs: %v", runner.args)
	}
}

type nativeProbeRunner struct {
	args    []string
	bounded bool
}

func (*nativeProbeRunner) LookPath(name string) (string, error) { return name, nil }
func (r *nativeProbeRunner) Run(ctx context.Context, _ string, args ...string) (RuntimeCommandResult, error) {
	_, ok := ctx.Deadline()
	r.bounded = ok
	if len(args) > 0 && args[0] == "version" {
		return RuntimeCommandResult{Stdout: []byte("1")}, nil
	}
	r.args = append([]string(nil), args...)
	return RuntimeCommandResult{Stdout: []byte(validRuntimeEvidenceJSON())}, nil
}
