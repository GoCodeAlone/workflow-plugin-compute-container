package container

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

const sandboxOwnerLabel = "com.gocodealone.workflow-compute.sandbox-owner"

func newSandboxOwner() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", errors.New("sandbox ownership unavailable")
	}
	return hex.EncodeToString(token[:]), nil
}

// Inspect only two fields, require exact attempt ownership, and remove by full
// immutable ID. Failed/absent/ambiguous inspection never authorizes deletion.
func removeOwnedSandbox(ctx context.Context, runner DockerCommandRunner, tool string, scope ContainerRuntimeScope, name, owner string) error {
	if name == "" || owner == "" {
		return errors.New("sandbox cleanup ownership unresolved")
	}
	validated, err := validateRuntimeScope(filepath.Base(tool), scope)
	if err != nil {
		return errors.New("sandbox cleanup scope unresolved")
	}
	format := `{"id":{{json .Id}},"owner":{{json (index .Config.Labels "` + sandboxOwnerLabel + `")}}}`
	out, stderr, err := runner.CombinedOutput(ctx, nil, tool, appendRuntimeScopeArgs(validated, "inspect", "--type", "container", "--format", format, name)...)
	out, _, err = boundRunnerOutput(out, stderr, err, 0)
	if err != nil {
		return errors.Join(errors.New("sandbox cleanup inspection unresolved"), controlProcessError(err, "sandbox cleanup inspection output unavailable"))
	}
	id, err := ownedSandboxID(out, owner)
	if err != nil {
		return err
	}
	_, _, err = runner.CombinedOutput(ctx, nil, tool, appendRuntimeScopeArgs(validated, "rm", "-f", id)...)
	if err != nil {
		return errors.Join(errors.New("owned sandbox removal failed"), controlProcessError(err, "sandbox cleanup removal output unavailable"))
	}
	return nil
}

func ownedSandboxID(raw []byte, owner string) (string, error) {
	invalid := errors.New("sandbox cleanup identity or owner unresolved")
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", invalid
	}
	fields := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", invalid
		}
		key, ok := token.(string)
		if !ok || (key != "id" && key != "owner") {
			return "", invalid
		}
		if _, duplicate := fields[key]; duplicate {
			return "", invalid
		}
		var value string
		if decoder.Decode(&value) != nil {
			return "", invalid
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return "", invalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", invalid
	}
	id := fields["id"]
	if len(fields) != 2 || fields["owner"] != owner || owner == "" || len(id) != 64 || strings.ToLower(id) != id {
		return "", invalid
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 32 {
		return "", invalid
	}
	return id, nil
}

type probeCleanupRunner struct{ runner RuntimeCommandRunner }

func (r probeCleanupRunner) CombinedOutput(ctx context.Context, _ []byte, tool string, args ...string) ([]byte, []byte, error) {
	result, err := r.runner.Run(ctx, tool, args...)
	return result.Stdout, result.Stderr, err
}
