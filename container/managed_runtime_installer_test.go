package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestManagedRuntimeBundleInstallerLifecycleUsesScopedRootAndPinnedObjects(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	bundle := catalog.Bundles[0]
	installRoot := realManagedRuntimeTestDir(t)
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: installRoot,
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	installed, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   bundle.BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("install managed runtime bundle: %v", err)
	}
	if installed.BundleID != bundle.BundleID {
		t.Fatalf("installed bundle id = %q, want %q", installed.BundleID, bundle.BundleID)
	}
	if !strings.HasPrefix(installed.Root, installRoot+string(os.PathSeparator)) {
		t.Fatalf("installed root %q escaped install root %q", installed.Root, installRoot)
	}
	wantCommand := filepath.Join(installed.Root, "bin", "nerdctl")
	if installed.CommandPath != wantCommand {
		t.Fatalf("command path = %q, want %q", installed.CommandPath, wantCommand)
	}
	if _, err := os.Stat(installed.CommandPath); err != nil {
		t.Fatalf("installed command missing: %v", err)
	}
	if _, err := os.Stat(installed.ManifestPath); err != nil {
		t.Fatalf("install manifest missing: %v", err)
	}

	doctor, err := installer.Doctor(ctx, ManagedRuntimeDoctorRequest{
		BundleID:   bundle.BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("doctor managed runtime bundle: %v", err)
	}
	if doctor.Status != ManagedRuntimeLifecycleStatusOK {
		t.Fatalf("doctor status = %q, want ok: %#v", doctor.Status, doctor)
	}
	if !doctor.ScopedStoreEnforced {
		t.Fatalf("doctor did not preserve scoped store evidence: %#v", doctor)
	}

	sibling := filepath.Join(installRoot, "sibling.txt")
	if err := os.WriteFile(sibling, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	uninstalled, err := installer.Uninstall(ctx, ManagedRuntimeUninstallRequest{
		BundleID: bundle.BundleID,
	})
	if err != nil {
		t.Fatalf("uninstall managed runtime bundle: %v", err)
	}
	if !uninstalled.Removed {
		t.Fatalf("uninstall removed = false, want true")
	}
	if _, err := os.Stat(installed.Root); !os.IsNotExist(err) {
		t.Fatalf("installed root still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("uninstall removed install-root sibling: %v", err)
	}

	reinstalled, err := installer.Reinstall(ctx, ManagedRuntimeInstallRequest{
		BundleID:   bundle.BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("reinstall managed runtime bundle: %v", err)
	}
	if reinstalled.Install.CommandPath == "" || reinstalled.Doctor.Status != ManagedRuntimeLifecycleStatusOK {
		t.Fatalf("reinstall did not finish with healthy doctor result: %#v", reinstalled)
	}
}

func TestManagedRuntimeBundleInstallerRejectsUnpinnedSignatureObject(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	objects[catalog.Bundles[0].SignatureName] = []byte("tampered signature")
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: realManagedRuntimeTestDir(t),
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	_, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "signature digest") {
		t.Fatalf("install error = %v, want signature digest failure", err)
	}
}

func TestManagedRuntimeBundleInstallerRejectsDigestPinnedInvalidSignature(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	tampered := []byte("not a valid detached signature")
	objects[catalog.Bundles[0].SignatureName] = tampered
	catalog.Bundles[0].SignatureDigest = "sha256:" + testManagedRuntimeSHA256(tampered)
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: realManagedRuntimeTestDir(t),
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	_, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "signature verification") {
		t.Fatalf("install error = %v, want signature verification failure", err)
	}
}

func TestManagedRuntimeBundleInstallerRejectsArchivePathEscape(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"../escape":   "bad",
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	installRoot := realManagedRuntimeTestDir(t)
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: installRoot,
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	_, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("install error = %v, want unsafe archive path failure", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "..", "escape")); !os.IsNotExist(err) {
		t.Fatalf("archive escape was written or unexpected stat error: %v", err)
	}
}

func TestManagedRuntimeBundleInstallerRejectsSymlinkedInstallRoot(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	linkRoot := filepath.Join(t.TempDir(), "managed-runtime")
	if err := os.Symlink(t.TempDir(), linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: linkRoot,
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	_, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("install error = %v, want symlink install root failure", err)
	}
}

func TestManagedRuntimeBundleInstallerRejectsSymlinkedInstallRootParent(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	base := t.TempDir()
	parentLink := filepath.Join(base, "linked-parent")
	if err := os.Symlink(t.TempDir(), parentLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: filepath.Join(parentLink, "managed-runtime"),
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}

	_, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("install error = %v, want parent symlink install root failure", err)
	}
}

func TestManagedRuntimeBundleInstallerDoctorRejectsCommandSymlink(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: realManagedRuntimeTestDir(t),
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}
	installed, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("install managed runtime bundle: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "nerdctl")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write outside runtime: %v", err)
	}
	if err := os.Remove(installed.CommandPath); err != nil {
		t.Fatalf("remove command: %v", err)
	}
	if err := os.Symlink(outside, installed.CommandPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	doctor, err := installer.Doctor(ctx, ManagedRuntimeDoctorRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("doctor managed runtime bundle: %v", err)
	}
	if doctor.Status != ManagedRuntimeLifecycleStatusDegraded || !strings.Contains(doctor.Reason, "symlink") {
		t.Fatalf("doctor = %#v, want degraded symlink result", doctor)
	}
}

func TestHTTPManagedRuntimeBundleObjectSourceDefaultClientHasTimeout(t *testing.T) {
	source := HTTPManagedRuntimeBundleObjectSource{}

	client := source.httpClient()

	if client.Timeout <= 0 {
		t.Fatalf("default managed runtime HTTP client timeout = %s, want positive timeout", client.Timeout)
	}
}

func TestManagedRuntimeBundleInstallerDoctorRejectsTamperedInstalledContent(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: realManagedRuntimeTestDir(t),
		Source:      managedRuntimeTestSource(objects),
		Now:         func() time.Time { return catalog.GeneratedAt },
	}
	installed, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("install managed runtime bundle: %v", err)
	}
	if err := os.WriteFile(installed.CommandPath, []byte("#!/bin/sh\nprintf tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper command: %v", err)
	}

	doctor, err := installer.Doctor(ctx, ManagedRuntimeDoctorRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("doctor managed runtime bundle: %v", err)
	}
	if doctor.Status == ManagedRuntimeLifecycleStatusOK || !strings.Contains(doctor.Reason, "file digest") {
		t.Fatalf("doctor = %#v, want file digest degradation", doctor)
	}
}

func TestManagedRuntimeBundleInstallerReinstallKeepsOldRuntimeWhenReplacementFetchFails(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	source := managedRuntimeTestSource(objects)
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: realManagedRuntimeTestDir(t),
		Source:      source,
		Now:         func() time.Time { return catalog.GeneratedAt },
	}
	installed, err := installer.Install(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("install managed runtime bundle: %v", err)
	}
	objects[catalog.Bundles[0].ArtifactName] = []byte("bad replacement")

	_, err = installer.Reinstall(ctx, ManagedRuntimeInstallRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err == nil {
		t.Fatalf("reinstall error = nil, want replacement failure")
	}
	if _, statErr := os.Stat(installed.CommandPath); statErr != nil {
		t.Fatalf("old command missing after failed reinstall: %v", statErr)
	}
	doctor, err := installer.Doctor(ctx, ManagedRuntimeDoctorRequest{
		BundleID:   catalog.Bundles[0].BundleID,
		TargetOS:   "linux",
		TargetArch: "amd64",
	})
	if err != nil {
		t.Fatalf("doctor old runtime: %v", err)
	}
	if doctor.Status != ManagedRuntimeLifecycleStatusOK {
		t.Fatalf("old runtime doctor = %#v, want ok", doctor)
	}
}

func managedRuntimeTestSource(objects map[string][]byte) ManagedRuntimeBundleObjectSource {
	return ManagedRuntimeBundleObjectSourceFunc(func(_ context.Context, request ManagedRuntimeBundleObjectRequest) ([]byte, error) {
		object, ok := objects[request.Name]
		if !ok {
			return nil, fmt.Errorf("missing object %q", request.Name)
		}
		return bytes.Clone(object), nil
	})
}

func realManagedRuntimeTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

func testManagedRuntimeCatalogAndObjects(t *testing.T, archiveFiles map[string]string) (ManagedRuntimeBundleCatalog, map[string][]byte) {
	t.Helper()
	entity, publicKey := testManagedRuntimeSigningEntity(t)
	artifact := testManagedRuntimeTarGzip(t, archiveFiles)
	artifactDigest := "sha256:" + testManagedRuntimeSHA256(artifact)
	artifactName := "nerdctl-full-test-linux-amd64.tar.gz"
	checksum := []byte(strings.TrimPrefix(artifactDigest, "sha256:") + "  " + artifactName + "\n")
	signature := testManagedRuntimeDetachedSignature(t, entity, checksum)
	checksumDigest := "sha256:" + testManagedRuntimeSHA256(checksum)
	signatureDigest := "sha256:" + testManagedRuntimeSHA256(signature)
	trustRootName := "test-release-key.asc"
	trustRootDigest := "sha256:" + testManagedRuntimeSHA256(publicKey)
	keyID := entity.PrimaryKey.KeyIdString()

	catalog := validManagedRuntimeBundleCatalog()
	catalog.SourceBaseURL = "memory://managed-runtime-test"
	catalog.StableSigningKey = keyID
	catalog.TrustRoots = []ManagedRuntimeTrustRoot{{
		KeyID:  keyID,
		Name:   trustRootName,
		Digest: trustRootDigest,
		Issuer: "test release key",
	}}
	catalog.Bundles[0].ArtifactName = artifactName
	catalog.Bundles[0].ArtifactDigest = artifactDigest
	catalog.Bundles[0].ChecksumDigest = checksumDigest
	catalog.Bundles[0].SignatureDigest = signatureDigest
	catalog.Bundles[0].SignatureKeyID = keyID
	catalog.Bundles[0].TrustRootDigest = trustRootDigest
	catalog.Bundles[0].SignatureSubject.ArtifactDigest = artifactDigest
	return catalog, map[string][]byte{
		artifactName:                     artifact,
		catalog.Bundles[0].ChecksumName:  checksum,
		catalog.Bundles[0].SignatureName: signature,
		trustRootName:                    publicKey,
	}
}

func testManagedRuntimeSigningEntity(t *testing.T) (*openpgp.Entity, []byte) {
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

func testManagedRuntimeDetachedSignature(t *testing.T, entity *openpgp.Entity, content []byte) []byte {
	t.Helper()
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(content), &packet.Config{
		Time: func() time.Time { return time.Unix(1_700_000_001, 0).UTC() },
	}); err != nil {
		t.Fatalf("sign checksum: %v", err)
	}
	return signature.Bytes()
}

func testManagedRuntimeTarGzip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		body := []byte(content)
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(body)),
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func testManagedRuntimeSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}
