//go:build unix

package container

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPodmanRuntimeScopeOwnerRequiresEffectiveUser(t *testing.T) {
	uid := uint32(os.Geteuid())
	if err := validatePodmanRuntimeScopeOwner("/tmp/wfcompute-podman-scope-test/root", fakePodmanScopeOwnerInfo{uid: uid}); err != nil {
		t.Fatalf("current uid rejected: %v", err)
	}

	other := uid + 1
	if other == 0 {
		other = uid - 1
	}
	err := validatePodmanRuntimeScopeOwner("/tmp/wfcompute-podman-scope-test/root", fakePodmanScopeOwnerInfo{uid: other})
	if err == nil {
		t.Fatal("mismatched uid accepted")
	}
}

type fakePodmanScopeOwnerInfo struct {
	uid uint32
}

func (f fakePodmanScopeOwnerInfo) Name() string       { return "root" }
func (f fakePodmanScopeOwnerInfo) Size() int64        { return 0 }
func (f fakePodmanScopeOwnerInfo) Mode() os.FileMode  { return 0o700 }
func (f fakePodmanScopeOwnerInfo) ModTime() time.Time { return time.Time{} }
func (f fakePodmanScopeOwnerInfo) IsDir() bool        { return true }
func (f fakePodmanScopeOwnerInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }
