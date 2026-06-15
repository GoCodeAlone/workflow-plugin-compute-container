//go:build unix

package container

import (
	"fmt"
	"os"
	"syscall"
)

func validatePodmanRuntimeScopeOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("podman runtime scope path %q owner metadata is unavailable", path)
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != uid {
		return fmt.Errorf("podman runtime scope path %q must be owned by the current user", path)
	}
	return nil
}
