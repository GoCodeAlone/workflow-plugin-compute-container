//go:build !unix

package container

import (
	"errors"
	"os"
)

func validatePodmanRuntimeScopeOwner(_ string, _ os.FileInfo) error {
	return errors.New("podman runtime scope owner validation is not supported on this platform")
}
