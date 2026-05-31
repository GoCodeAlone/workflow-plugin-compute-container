package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	container "github.com/GoCodeAlone/workflow-plugin-compute-container/container"
	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestManifest(t *testing.T) {
	plugin := NewPlugin()
	manifest := plugin.Manifest()
	if manifest.Name != "workflow-plugin-compute-container" {
		t.Fatalf("name = %q", manifest.Name)
	}
	if manifest.Version != Version {
		t.Fatalf("version = %q, want %q", manifest.Version, Version)
	}
	if manifest.Description == "" {
		t.Fatal("description is required")
	}
}

func TestPluginJSONReferencesRuntimeAdapters(t *testing.T) {
	root := filepath.Clean("..")
	data, err := os.ReadFile(filepath.Join(root, "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RuntimeAdaptersRef string `json:"runtimeAdaptersRef"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.RuntimeAdaptersRef != "runtime-adapters.json" {
		t.Fatalf("runtimeAdaptersRef = %q", manifest.RuntimeAdaptersRef)
	}
	adapters, err := os.ReadFile(filepath.Join(root, manifest.RuntimeAdaptersRef))
	if err != nil {
		t.Fatal(err)
	}
	var catalog container.RuntimeAdapterCatalogDocument
	if err := json.Unmarshal(adapters, &catalog); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("runtime adapter catalog invalid: %v", err)
	}
	if len(catalog.Adapters) != 2 {
		t.Fatalf("runtime adapter catalog incomplete: %+v", catalog)
	}
	for _, adapter := range catalog.Adapters {
		contract := adapter.Contract(core.RuntimeDescriptor{
			Name:                  adapter.AdapterID,
			Version:               "v1.0.0",
			ExecutionSecurityTier: core.ExecutionSandboxedContainer,
			ProofTier:             core.ProofArtifactHash,
			ImageDigest:           "sha256:" + strings.Repeat("a", 64),
			RootFSDigest:          "sha256:" + strings.Repeat("b", 64),
		})
		if err := contract.Validate(); err != nil {
			t.Fatalf("runtime adapter contract for %s invalid: %v", adapter.AdapterID, err)
		}
	}
}
