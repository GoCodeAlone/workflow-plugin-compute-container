package container

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type cliErrorCleanupRunner struct {
	runErr, inspectErr, removeErr error
	foreign                       bool
	cancel                        context.CancelFunc
	owner, removed                string
	calls                         []string
	fresh                         bool
}

func (r *cliErrorCleanupRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, args[0])
	switch args[0] {
	case "run":
		r.owner = strings.TrimPrefix(dockerArgValue(args, "--label"), sandboxOwnerLabel+"=")
		if r.cancel != nil {
			r.cancel()
		}
		return nil, nil, r.runErr
	case "inspect":
		deadline, ok := ctx.Deadline()
		r.fresh = ok && ctx.Err() == nil && time.Until(deadline) <= 10*time.Second
		owner := r.owner
		if r.foreign {
			owner = "foreign"
		}
		return []byte(`{"id":"` + strings.Repeat("a", 64) + `","owner":"` + owner + `"}`), nil, r.inspectErr
	case "rm":
		r.removed = args[len(args)-1]
		return nil, nil, r.removeErr
	}
	return nil, nil, errors.New("unexpected fixture operation")
}
func TestNativeCLIErrorRequiresOwnedCleanup(t *testing.T) {
	runFailure := errors.New("synthetic CLI transport failure")
	inspectFailure := errors.New("synthetic uncertain inspection")
	removeFailure := errors.New("synthetic uncertain removal")
	for _, mode := range []string{"ordinary", "foreign", "inspect_failure", "remove_failure", "canceled", "success"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			runner := &cliErrorCleanupRunner{runErr: runFailure}
			switch mode {
			case "foreign":
				runner.foreign = true
			case "inspect_failure":
				runner.inspectErr = inspectFailure
			case "remove_failure":
				runner.removeErr = removeFailure
			case "canceled":
				runner.runErr = context.Canceled
				runner.cancel = cancel
			case "success":
				runner.runErr = nil
			}
			_, err := (DockerSandboxRuntime{Runner: runner}).Run(ctx, SandboxRunRequest{Image: "fixture", Command: []string{"true"}, Workspace: t.TempDir(), Timeout: time.Second})
			if mode == "success" {
				if err != nil || len(runner.calls) != 1 {
					t.Fatalf("successful run acquired cleanup: err=%v calls=%v", err, runner.calls)
				}
				return
			}
			if !errors.Is(err, runner.runErr) {
				t.Fatalf("original execution failure lost: %v", err)
			}
			if !runner.fresh || len(runner.owner) != 32 {
				t.Fatalf("owned inspection missing or cleanup context expired: calls=%v fresh=%t", runner.calls, runner.fresh)
			}
			wantRemove := mode != "foreign" && mode != "inspect_failure"
			if wantRemove {
				if runner.removed != strings.Repeat("a", 64) || strings.Join(runner.calls, ",") != "run,inspect,rm" {
					t.Fatalf("exact owned removal missing: calls=%v", runner.calls)
				}
			} else if runner.removed != "" || strings.Join(runner.calls, ",") != "run,inspect" {
				t.Fatalf("unproved identity authorized removal: calls=%v", runner.calls)
			}
			if mode == "inspect_failure" && !errors.Is(err, inspectFailure) {
				t.Fatal("inspection uncertainty lost")
			}
			if mode == "remove_failure" && !errors.Is(err, removeFailure) {
				t.Fatal("removal uncertainty lost")
			}
		})
	}
}
