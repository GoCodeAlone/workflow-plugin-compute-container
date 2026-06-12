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
)

func TestManagedRuntimeBundleInstallerLifecycleUsesScopedRootAndPinnedObjects(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	bundle := catalog.Bundles[0]
	installRoot := t.TempDir()
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
		InstallRoot: t.TempDir(),
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

func TestManagedRuntimeBundleInstallerRejectsArchivePathEscape(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"../escape":   "bad",
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	installRoot := t.TempDir()
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

func TestManagedRuntimeBundleInstallerDoctorRejectsCommandSymlink(t *testing.T) {
	ctx := context.Background()
	catalog, objects := testManagedRuntimeCatalogAndObjects(t, map[string]string{
		"bin/nerdctl": "#!/bin/sh\nprintf nerdctl-test\n",
	})
	installer := ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: t.TempDir(),
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
	if doctor.Status == ManagedRuntimeLifecycleStatusOK || !strings.Contains(doctor.Reason, "symlink") {
		t.Fatalf("doctor = %#v, want degraded symlink result", doctor)
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

func testManagedRuntimeCatalogAndObjects(t *testing.T, archiveFiles map[string]string) (ManagedRuntimeBundleCatalog, map[string][]byte) {
	t.Helper()
	artifact := testManagedRuntimeTarGzip(t, archiveFiles)
	artifactDigest := "sha256:" + testManagedRuntimeSHA256(artifact)
	artifactName := "nerdctl-full-test-linux-amd64.tar.gz"
	checksum := []byte(strings.TrimPrefix(artifactDigest, "sha256:") + "  " + artifactName + "\n")
	signature := []byte("test signature over " + artifactName + "\n")
	checksumDigest := "sha256:" + testManagedRuntimeSHA256(checksum)
	signatureDigest := "sha256:" + testManagedRuntimeSHA256(signature)

	catalog := validManagedRuntimeBundleCatalog()
	catalog.SourceBaseURL = "memory://managed-runtime-test"
	catalog.Bundles[0].ArtifactName = artifactName
	catalog.Bundles[0].ArtifactDigest = artifactDigest
	catalog.Bundles[0].ChecksumDigest = checksumDigest
	catalog.Bundles[0].SignatureDigest = signatureDigest
	catalog.Bundles[0].SignatureSubject.ArtifactDigest = artifactDigest
	return catalog, map[string][]byte{
		artifactName:                     artifact,
		catalog.Bundles[0].ChecksumName:  checksum,
		catalog.Bundles[0].SignatureName: signature,
	}
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
