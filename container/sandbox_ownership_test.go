package container

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type ownershipRunner struct {
	inspection []byte
	inspectErr error
	calls      [][]string
	fresh      bool
}

func (r *ownershipRunner) CombinedOutput(ctx context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	_, r.fresh = ctx.Deadline()
	r.fresh = r.fresh && ctx.Err() == nil
	if len(args) > 2 && args[2] == "inspect" {
		return r.inspection, nil, r.inspectErr
	}
	return nil, nil, nil
}
func TestNativeOwnedCleanupRequiresExactClosedProofAndFullID(t *testing.T) {
	id := strings.Repeat("a", 64)
	owner := strings.Repeat("c", 32)
	for _, row := range []struct {
		name, payload string
		valid         bool
	}{
		{"valid", `{"id":"` + id + `","owner":"` + owner + `"}`, true},
		{"foreign", `{"id":"` + id + `","owner":"foreign"}`, false},
		{"short_id", `{"id":"aaaa","owner":"` + owner + `"}`, false},
		{"duplicate", `{"id":"` + id + `","id":"` + id + `","owner":"` + owner + `"}`, false},
		{"unknown", `{"id":"` + id + `","owner":"` + owner + `","extra":true}`, false},
		{"missing", `{"id":"` + id + `"}`, false},
		{"null_owner", `{"id":"` + id + `","owner":null}`, false},
		{"extra_document", `{"id":"` + id + `","owner":"` + owner + `"}{}`, false},
		{"malformed", `[]`, false},
		{"absent", "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := &ownershipRunner{inspection: []byte(row.payload)}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := removeOwnedSandbox(ctx, r, "/scoped/bin/nerdctl", ContainerRuntimeScope{Args: []string{"--namespace", "owned"}}, "attempt-name", owner)
			if (err == nil) != row.valid || !r.fresh {
				t.Fatalf("proof err=%v fresh=%t", err, r.fresh)
			}
			if !row.valid && len(r.calls) != 1 {
				t.Fatalf("unverified proof allowed removal: %v", r.calls)
			}
			if row.valid && (len(r.calls) != 2 || strings.Join(r.calls[1], " ") != "--namespace owned rm -f "+id) {
				t.Fatalf("removed by name/wrong scope: %v", r.calls)
			}
		})
	}
	r := &ownershipRunner{inspectErr: errors.New("engine unavailable")}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := removeOwnedSandbox(ctx, r, "nerdctl", ContainerRuntimeScope{Args: []string{"--namespace", "owned"}}, "attempt-name", owner); err == nil || len(r.calls) != 1 {
		t.Fatalf("inspection failure inferred absence: err=%v calls=%v", err, r.calls)
	}
}

type ownedProbeCleanupRunner struct {
	cancel  context.CancelFunc
	owner   string
	removed string
	fresh   bool
}

func (*ownedProbeCleanupRunner) LookPath(name string) (string, error) { return name, nil }
func (r *ownedProbeCleanupRunner) Run(ctx context.Context, _ string, args ...string) (RuntimeCommandResult, error) {
	switch args[0] {
	case "version":
		return RuntimeCommandResult{Stdout: []byte("1")}, nil
	case "run":
		r.owner = strings.TrimPrefix(dockerArgValue(args, "--label"), sandboxOwnerLabel+"=")
		r.cancel()
		return RuntimeCommandResult{}, context.Canceled
	case "inspect":
		_, r.fresh = ctx.Deadline()
		r.fresh = r.fresh && ctx.Err() == nil
		return RuntimeCommandResult{Stdout: []byte(`{"id":"` + strings.Repeat("a", 64) + `","owner":"` + r.owner + `"}`)}, nil
	case "rm":
		r.removed = args[len(args)-1]
		return RuntimeCommandResult{}, nil
	}
	return RuntimeCommandResult{}, errors.New("unexpected fixture operation")
}
func TestNativeProbeCancellationRemovesOnlyVerifiedOwnedID(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runner := &ownedProbeCleanupRunner{cancel: cancel}
	_ = (RuntimeBackendProbe{Options: podmanProbeOptions(nil), Runner: runner}).Probe(ctx)
	if len(runner.owner) != 32 || !runner.fresh || runner.removed != strings.Repeat("a", 64) {
		t.Fatalf("owned probe cleanup unproved: owner=%q fresh=%t removed=%q", runner.owner, runner.fresh, runner.removed)
	}
}
