package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
	var catalog struct {
		ProtocolVersion           string `json:"protocolVersion"`
		Adapters                  []any  `json:"adapters"`
		HostOwnedResponsibilities []any  `json:"hostOwnedResponsibilities"`
	}
	if err := json.Unmarshal(adapters, &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.ProtocolVersion == "" || len(catalog.Adapters) != 2 || len(catalog.HostOwnedResponsibilities) == 0 {
		t.Fatalf("runtime adapter catalog incomplete: %+v", catalog)
	}
}
