package internal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-container/container"
	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestManagedRuntimeCLIInstallDoctorUninstallLifecycle(t *testing.T) {
	catalog, objects := testManagedRuntimeCLICatalogAndObjects(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		object, ok := objects[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(object)
	}))
	defer server.Close()
	catalog.SourceBaseURL = server.URL
	catalogPath := filepath.Join(t.TempDir(), "managed-runtime-bundles.json")
	content, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	if err := os.WriteFile(catalogPath, content, 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	installRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve install root: %v", err)
	}
	args := []string{
		"--catalog", catalogPath,
		"--install-root", installRoot,
		"--bundle-id", catalog.Bundles[0].BundleID,
		"--target-os", "linux",
		"--target-arch", "amd64",
	}

	var stdout, stderr bytes.Buffer
	if code := RunManagedRuntimeCLI(context.Background(), append([]string{"managed-runtime", "install"}, args...), &stdout, &stderr); code != 0 {
		t.Fatalf("install exit code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var install container.ManagedRuntimeInstallResult
	if err := json.Unmarshal(stdout.Bytes(), &install); err != nil {
		t.Fatalf("decode install JSON: %v", err)
	}
	if install.CommandPath == "" {
		t.Fatalf("install command path is empty: %#v", install)
	}

	stdout.Reset()
	if code := RunManagedRuntimeCLI(context.Background(), append([]string{"managed-runtime", "doctor"}, args...), &stdout, io.Discard); code != 0 {
		t.Fatalf("doctor exit code = %d stdout=%s", code, stdout.String())
	}
	var doctor container.ManagedRuntimeDoctorResult
	if err := json.Unmarshal(stdout.Bytes(), &doctor); err != nil {
		t.Fatalf("decode doctor JSON: %v", err)
	}
	if doctor.Status != container.ManagedRuntimeLifecycleStatusOK {
		t.Fatalf("doctor status = %q, want ok: %#v", doctor.Status, doctor)
	}

	stdout.Reset()
	if code := RunManagedRuntimeCLI(context.Background(), append([]string{"managed-runtime", "uninstall"}, args...), &stdout, io.Discard); code != 0 {
		t.Fatalf("uninstall exit code = %d stdout=%s", code, stdout.String())
	}
	var uninstall container.ManagedRuntimeUninstallResult
	if err := json.Unmarshal(stdout.Bytes(), &uninstall); err != nil {
		t.Fatalf("decode uninstall JSON: %v", err)
	}
	if !uninstall.Removed || !uninstall.ScopedOnly {
		t.Fatalf("uninstall result = %#v, want scoped removal", uninstall)
	}
}

func testManagedRuntimeCLICatalogAndObjects(t *testing.T) (container.ManagedRuntimeBundleCatalog, map[string][]byte) {
	t.Helper()
	entity, publicKey := testManagedRuntimeCLISigningEntity(t)
	artifact := testManagedRuntimeCLITarGzip(t)
	artifactDigest := "sha256:" + testManagedRuntimeCLISHA256(artifact)
	artifactName := "nerdctl-full-test-linux-amd64.tar.gz"
	checksum := []byte(testManagedRuntimeCLISHA256(artifact) + "  " + artifactName + "\n")
	signature := testManagedRuntimeCLIDetachedSignature(t, entity, checksum)
	checksumDigest := "sha256:" + testManagedRuntimeCLISHA256(checksum)
	signatureDigest := "sha256:" + testManagedRuntimeCLISHA256(signature)
	trustRootName := "test-release-key.asc"
	trustRootDigest := "sha256:" + testManagedRuntimeCLISHA256(publicKey)
	keyID := entity.PrimaryKey.KeyIdString()
	bundle := core.ManagedRuntimeBundleDescriptor{
		ProtocolVersion: core.Version,
		BundleID:        "managed-containerd-linux-amd64",
		Family:          core.RuntimeBackendFamilyContainerd,
		Tool:            core.ContainerRuntimeNerdctl,
		Version:         "v2.3.1",
		OS:              "linux",
		Arch:            "amd64",
		ArtifactName:    artifactName,
		ArtifactDigest:  artifactDigest,
		ChecksumName:    "SHA256SUMS",
		ChecksumDigest:  checksumDigest,
		SignatureName:   "SHA256SUMS.asc",
		SignatureDigest: signatureDigest,
		SignatureIssuer: "containerd/nerdctl release",
		SignatureKeyID:  keyID,
		TrustRootDigest: trustRootDigest,
		SignatureSubject: core.ManagedRuntimeSignatureSubject{
			ArtifactDigest:          artifactDigest,
			RuntimeFamily:           core.RuntimeBackendFamilyContainerd,
			OS:                      "linux",
			Arch:                    "amd64",
			Version:                 "v2.3.1",
			Channel:                 "stable",
			ConformanceProfile:      "distroless-static-v1",
			ScopedStorePolicyDigest: "sha256:311ab6244d878cf7280a5927f5af6063337ec262e35fd7c84c6579d07591337e",
		},
		ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		UpdatePolicy: core.ManagedRuntimeUpdatePolicy{
			Channel:             "stable",
			MinSupportedVersion: "v2.3.1",
		},
		CVEPolicy: core.ManagedRuntimeCVEPolicy{
			PolicyDigest:     "sha256:5bc9d3baf40fe716e68bfc469c53040351288caaaa048650aeadd6320ca6d7c1",
			UpdatedByVersion: "v2.3.1",
		},
		ScopedStore: core.ManagedRuntimeScopedStorePolicy{
			Required:                      true,
			NamespaceStrategy:             "opaque-worker-pool-scope",
			StoreStrategy:                 "workflow-owned-content-store",
			PolicyDigest:                  "sha256:311ab6244d878cf7280a5927f5af6063337ec262e35fd7c84c6579d07591337e",
			CleanupRequired:               true,
			HostGlobalVisibilityForbidden: true,
		},
		SupportedTargets:   []core.ManagedRuntimeTarget{{OS: "linux", Arch: "amd64"}},
		ConformanceProfile: "distroless-static-v1",
		InstallBurden:      core.RuntimeInstallBundled,
	}
	return container.ManagedRuntimeBundleCatalog{
			ReleaseTag:       "v2.3.1",
			GeneratedAt:      time.Unix(1_700_000_000, 0).UTC(),
			MinimumVersion:   "v2.3.1",
			StableSigningKey: keyID,
			Bundles:          []core.ManagedRuntimeBundleDescriptor{bundle},
			TrustRoots: []container.ManagedRuntimeTrustRoot{{
				KeyID:  keyID,
				Name:   trustRootName,
				Digest: trustRootDigest,
				Issuer: "test release key",
			}},
		}, map[string][]byte{
			artifactName:     artifact,
			"SHA256SUMS":     checksum,
			"SHA256SUMS.asc": signature,
			trustRootName:    publicKey,
		}
}

func testManagedRuntimeCLISigningEntity(t *testing.T) (*openpgp.Entity, []byte) {
	t.Helper()
	entity, err := openpgp.NewEntity("Workflow Compute Runtime Test", "managed-runtime", "runtime@example.invalid", &packet.Config{
		RSABits: 1024,
		Time:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("create signing entity: %v", err)
	}
	var public bytes.Buffer
	block, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor public key: %v", err)
	}
	if err := entity.Serialize(block); err != nil {
		t.Fatalf("serialize public key: %v", err)
	}
	if err := block.Close(); err != nil {
		t.Fatalf("close public key armor: %v", err)
	}
	return entity, public.Bytes()
}

func testManagedRuntimeCLIDetachedSignature(t *testing.T, entity *openpgp.Entity, content []byte) []byte {
	t.Helper()
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(content), &packet.Config{
		Time: func() time.Time { return time.Unix(1_700_000_001, 0).UTC() },
	}); err != nil {
		t.Fatalf("sign checksum: %v", err)
	}
	return signature.Bytes()
}

func testManagedRuntimeCLITarGzip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\nprintf nerdctl-test\n")
	if err := tw.WriteHeader(&tar.Header{Name: "bin/nerdctl", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func testManagedRuntimeCLISHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}
