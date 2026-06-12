package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/ProtonMail/go-crypto/openpgp"
)

const managedRuntimeInstallManifestName = "wfcompute-managed-runtime-install.json"
const defaultManagedRuntimeHTTPTimeout = 15 * time.Minute
const defaultManagedRuntimeHTTPMaxBytes = 512 << 20

type ManagedRuntimeLifecycleStatus string

const (
	ManagedRuntimeLifecycleStatusOK       ManagedRuntimeLifecycleStatus = "ok"
	ManagedRuntimeLifecycleStatusMissing  ManagedRuntimeLifecycleStatus = "missing"
	ManagedRuntimeLifecycleStatusDegraded ManagedRuntimeLifecycleStatus = "degraded"
)

type ManagedRuntimeBundleInstaller struct {
	Catalog     ManagedRuntimeBundleCatalog
	InstallRoot string
	Source      ManagedRuntimeBundleObjectSource
	Now         func() time.Time
	HTTPClient  *http.Client
}

type ManagedRuntimeInstallRequest struct {
	BundleID   string
	TargetOS   string
	TargetArch string
}

type ManagedRuntimeDoctorRequest struct {
	BundleID   string
	TargetOS   string
	TargetArch string
}

type ManagedRuntimeUninstallRequest struct {
	BundleID string
}

type ManagedRuntimeBundleObjectRequest struct {
	BundleID string
	Kind     string
	Name     string
	URL      string
}

type ManagedRuntimeBundleObjectSource interface {
	FetchManagedRuntimeBundleObject(context.Context, ManagedRuntimeBundleObjectRequest) ([]byte, error)
}

type ManagedRuntimeBundleObjectSourceFunc func(context.Context, ManagedRuntimeBundleObjectRequest) ([]byte, error)

func (f ManagedRuntimeBundleObjectSourceFunc) FetchManagedRuntimeBundleObject(ctx context.Context, request ManagedRuntimeBundleObjectRequest) ([]byte, error) {
	return f(ctx, request)
}

type HTTPManagedRuntimeBundleObjectSource struct {
	Client *http.Client
}

func (s HTTPManagedRuntimeBundleObjectSource) FetchManagedRuntimeBundleObject(ctx context.Context, request ManagedRuntimeBundleObjectRequest) ([]byte, error) {
	if strings.TrimSpace(request.URL) == "" {
		return nil, errors.New("managed runtime object URL is required")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient().Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch managed runtime object %q: %s", request.Name, resp.Status)
	}
	limited := io.LimitReader(resp.Body, defaultManagedRuntimeHTTPMaxBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > defaultManagedRuntimeHTTPMaxBytes {
		return nil, fmt.Errorf("managed runtime object %q is too large", request.Name)
	}
	return content, nil
}

func (s HTTPManagedRuntimeBundleObjectSource) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: defaultManagedRuntimeHTTPTimeout}
}

type ManagedRuntimeInstallResult struct {
	BundleID                string            `json:"bundle_id"`
	Version                 string            `json:"version"`
	Root                    string            `json:"root"`
	CommandPath             string            `json:"command_path"`
	ManifestPath            string            `json:"manifest_path"`
	ArtifactDigest          string            `json:"artifact_digest"`
	ChecksumDigest          string            `json:"checksum_digest"`
	SignatureDigest         string            `json:"signature_digest"`
	TrustRootDigest         string            `json:"trust_root_digest"`
	ScopedStoreEnforced     bool              `json:"scoped_store_enforced"`
	HostGlobalStoreExcluded bool              `json:"host_global_store_excluded"`
	FileDigests             map[string]string `json:"file_digests"`
	InstalledAt             time.Time         `json:"installed_at"`
}

type ManagedRuntimeDoctorResult struct {
	Status                  ManagedRuntimeLifecycleStatus `json:"status"`
	BundleID                string                        `json:"bundle_id"`
	Version                 string                        `json:"version,omitempty"`
	Root                    string                        `json:"root,omitempty"`
	CommandPath             string                        `json:"command_path,omitempty"`
	ManifestPath            string                        `json:"manifest_path,omitempty"`
	ArtifactDigest          string                        `json:"artifact_digest,omitempty"`
	SignatureDigest         string                        `json:"signature_digest,omitempty"`
	ScopedStoreEnforced     bool                          `json:"scoped_store_enforced,omitempty"`
	HostGlobalStoreExcluded bool                          `json:"host_global_store_excluded,omitempty"`
	Reason                  string                        `json:"reason,omitempty"`
}

type ManagedRuntimeUninstallResult struct {
	BundleID     string `json:"bundle_id"`
	Root         string `json:"root"`
	Removed      bool   `json:"removed"`
	ScopedOnly   bool   `json:"scoped_only"`
	ManifestPath string `json:"manifest_path"`
}

type ManagedRuntimeReinstallResult struct {
	Uninstall ManagedRuntimeUninstallResult `json:"uninstall"`
	Install   ManagedRuntimeInstallResult   `json:"install"`
	Doctor    ManagedRuntimeDoctorResult    `json:"doctor"`
}

type managedRuntimeInstallManifest struct {
	ProtocolVersion         string            `json:"protocol_version"`
	BundleID                string            `json:"bundle_id"`
	Version                 string            `json:"version"`
	OS                      string            `json:"os"`
	Arch                    string            `json:"arch"`
	Root                    string            `json:"root"`
	CommandPath             string            `json:"command_path"`
	ArtifactName            string            `json:"artifact_name"`
	ArtifactDigest          string            `json:"artifact_digest"`
	ChecksumName            string            `json:"checksum_name"`
	ChecksumDigest          string            `json:"checksum_digest"`
	SignatureName           string            `json:"signature_name"`
	SignatureDigest         string            `json:"signature_digest"`
	SignatureKeyID          string            `json:"signature_key_id"`
	TrustRootDigest         string            `json:"trust_root_digest"`
	ScopedStoreEnforced     bool              `json:"scoped_store_enforced"`
	HostGlobalStoreExcluded bool              `json:"host_global_store_excluded"`
	FileDigests             map[string]string `json:"file_digests"`
	InstalledAt             time.Time         `json:"installed_at"`
}

func (i ManagedRuntimeBundleInstaller) Install(ctx context.Context, request ManagedRuntimeInstallRequest) (ManagedRuntimeInstallResult, error) {
	if err := ctx.Err(); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	now := i.now()
	bundle, err := i.Catalog.BundleForTarget(request.BundleID, request.TargetOS, request.TargetArch, now)
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	installRoot, bundleRoot, err := managedRuntimeBundleRoot(i.InstallRoot, bundle.BundleID)
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	unlock, err := managedRuntimeAcquireBundleLock(installRoot, bundle.BundleID)
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	defer unlock()
	if err := i.validateManagedRuntimeExistingRootForReplacement(bundleRoot, bundle.BundleID); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	source := i.source()
	artifact, checksum, signature, trustRoot, err := i.fetchPinnedObjects(ctx, source, bundle)
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	if err := verifyManagedRuntimeChecksum(bundle, checksum); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	if err := verifyManagedRuntimeSignature(bundle, checksum, signature, trustRoot); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	stagingParent := filepath.Join(installRoot, ".staging")
	if err := os.MkdirAll(stagingParent, 0o700); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingParent, bundle.BundleID+"-")
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	removeStage := true
	defer func() {
		if removeStage {
			_ = os.RemoveAll(stageRoot)
		}
	}()
	if err := extractManagedRuntimeTarGzip(artifact, stageRoot); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	commandPath := filepath.Join(stageRoot, "bin", "nerdctl")
	if err := managedRuntimeRequireFileUnderRoot(stageRoot, commandPath); err != nil {
		return ManagedRuntimeInstallResult{}, fmt.Errorf("managed runtime command: %w", err)
	}
	fileDigests, err := managedRuntimeFileDigests(stageRoot, "")
	if err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	result := ManagedRuntimeInstallResult{
		BundleID:                bundle.BundleID,
		Version:                 bundle.Version,
		Root:                    bundleRoot,
		CommandPath:             filepath.Join(bundleRoot, "bin", "nerdctl"),
		ManifestPath:            filepath.Join(bundleRoot, managedRuntimeInstallManifestName),
		ArtifactDigest:          bundle.ArtifactDigest,
		ChecksumDigest:          bundle.ChecksumDigest,
		SignatureDigest:         bundle.SignatureDigest,
		TrustRootDigest:         bundle.TrustRootDigest,
		ScopedStoreEnforced:     bundle.ScopedStore.Required,
		HostGlobalStoreExcluded: bundle.ScopedStore.HostGlobalVisibilityForbidden,
		FileDigests:             fileDigests,
		InstalledAt:             now,
	}
	manifest := managedRuntimeInstallManifest{
		ProtocolVersion:         core.Version,
		BundleID:                bundle.BundleID,
		Version:                 bundle.Version,
		OS:                      bundle.OS,
		Arch:                    bundle.Arch,
		Root:                    result.Root,
		CommandPath:             result.CommandPath,
		ArtifactName:            bundle.ArtifactName,
		ArtifactDigest:          bundle.ArtifactDigest,
		ChecksumName:            bundle.ChecksumName,
		ChecksumDigest:          bundle.ChecksumDigest,
		SignatureName:           bundle.SignatureName,
		SignatureDigest:         bundle.SignatureDigest,
		SignatureKeyID:          bundle.SignatureKeyID,
		TrustRootDigest:         bundle.TrustRootDigest,
		ScopedStoreEnforced:     result.ScopedStoreEnforced,
		HostGlobalStoreExcluded: result.HostGlobalStoreExcluded,
		FileDigests:             fileDigests,
		InstalledAt:             now,
	}
	if err := writeManagedRuntimeManifest(filepath.Join(stageRoot, managedRuntimeInstallManifestName), manifest); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	if err := managedRuntimePromoteStage(stageRoot, bundleRoot); err != nil {
		return ManagedRuntimeInstallResult{}, err
	}
	removeStage = false
	return result, nil
}

func (i ManagedRuntimeBundleInstaller) Doctor(ctx context.Context, request ManagedRuntimeDoctorRequest) (ManagedRuntimeDoctorResult, error) {
	if err := ctx.Err(); err != nil {
		return ManagedRuntimeDoctorResult{}, err
	}
	now := i.now()
	bundle, err := i.Catalog.BundleForTarget(request.BundleID, request.TargetOS, request.TargetArch, now)
	if err != nil {
		return ManagedRuntimeDoctorResult{}, err
	}
	_, bundleRoot, err := managedRuntimeBundleRoot(i.InstallRoot, bundle.BundleID)
	if err != nil {
		return ManagedRuntimeDoctorResult{}, err
	}
	manifestPath := filepath.Join(bundleRoot, managedRuntimeInstallManifestName)
	manifest, err := readManagedRuntimeManifest(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ManagedRuntimeDoctorResult{
				Status:       ManagedRuntimeLifecycleStatusMissing,
				BundleID:     bundle.BundleID,
				Root:         bundleRoot,
				ManifestPath: manifestPath,
				Reason:       "install manifest is missing",
			}, nil
		}
		return ManagedRuntimeDoctorResult{}, err
	}
	result := ManagedRuntimeDoctorResult{
		Status:                  ManagedRuntimeLifecycleStatusOK,
		BundleID:                bundle.BundleID,
		Version:                 manifest.Version,
		Root:                    bundleRoot,
		CommandPath:             filepath.Join(bundleRoot, "bin", "nerdctl"),
		ManifestPath:            manifestPath,
		ArtifactDigest:          manifest.ArtifactDigest,
		SignatureDigest:         manifest.SignatureDigest,
		ScopedStoreEnforced:     manifest.ScopedStoreEnforced,
		HostGlobalStoreExcluded: manifest.HostGlobalStoreExcluded,
	}
	if manifest.BundleID != bundle.BundleID ||
		manifest.ArtifactDigest != bundle.ArtifactDigest ||
		manifest.SignatureDigest != bundle.SignatureDigest ||
		manifest.TrustRootDigest != bundle.TrustRootDigest {
		result.Status = ManagedRuntimeLifecycleStatusDegraded
		result.Reason = "install manifest does not match pinned bundle metadata"
		return result, nil
	}
	if manifest.CommandPath != result.CommandPath || manifest.Root != bundleRoot {
		result.Status = ManagedRuntimeLifecycleStatusDegraded
		result.Reason = "install manifest path scope does not match scoped root"
		return result, nil
	}
	if !manifest.ScopedStoreEnforced || !manifest.HostGlobalStoreExcluded {
		result.Status = ManagedRuntimeLifecycleStatusDegraded
		result.Reason = "scoped store policy is not enforced"
		return result, nil
	}
	if err := managedRuntimeRequireFileUnderRoot(bundleRoot, result.CommandPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result.Status = ManagedRuntimeLifecycleStatusMissing
		} else {
			result.Status = ManagedRuntimeLifecycleStatusDegraded
		}
		result.Reason = err.Error()
		return result, nil
	}
	if err := verifyManagedRuntimeInstalledFileDigests(bundleRoot, manifest.FileDigests); err != nil {
		result.Status = ManagedRuntimeLifecycleStatusDegraded
		result.Reason = err.Error()
		return result, nil
	}
	return result, nil
}

func (i ManagedRuntimeBundleInstaller) Uninstall(ctx context.Context, request ManagedRuntimeUninstallRequest) (ManagedRuntimeUninstallResult, error) {
	if err := ctx.Err(); err != nil {
		return ManagedRuntimeUninstallResult{}, err
	}
	_, bundleRoot, err := managedRuntimeBundleRoot(i.InstallRoot, request.BundleID)
	if err != nil {
		return ManagedRuntimeUninstallResult{}, err
	}
	installRoot := filepath.Dir(bundleRoot)
	unlock, err := managedRuntimeAcquireBundleLock(installRoot, request.BundleID)
	if err != nil {
		return ManagedRuntimeUninstallResult{}, err
	}
	defer unlock()
	_, statErr := os.Stat(bundleRoot)
	removed := false
	if statErr == nil {
		if err := i.validateManagedRuntimeManifestForRemoval(bundleRoot, request.BundleID); err != nil {
			return ManagedRuntimeUninstallResult{}, err
		}
		if err := os.RemoveAll(bundleRoot); err != nil {
			return ManagedRuntimeUninstallResult{}, err
		}
		removed = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ManagedRuntimeUninstallResult{}, statErr
	}
	return ManagedRuntimeUninstallResult{
		BundleID:     request.BundleID,
		Root:         bundleRoot,
		Removed:      removed,
		ScopedOnly:   true,
		ManifestPath: filepath.Join(bundleRoot, managedRuntimeInstallManifestName),
	}, nil
}

func (i ManagedRuntimeBundleInstaller) Reinstall(ctx context.Context, request ManagedRuntimeInstallRequest) (ManagedRuntimeReinstallResult, error) {
	_, bundleRoot, err := managedRuntimeBundleRoot(i.InstallRoot, request.BundleID)
	if err != nil {
		return ManagedRuntimeReinstallResult{}, err
	}
	replaced := false
	if _, err := os.Stat(bundleRoot); err == nil {
		replaced = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ManagedRuntimeReinstallResult{}, err
	}
	install, err := i.Install(ctx, request)
	if err != nil {
		return ManagedRuntimeReinstallResult{}, err
	}
	doctor, err := i.Doctor(ctx, ManagedRuntimeDoctorRequest{
		BundleID:   request.BundleID,
		TargetOS:   request.TargetOS,
		TargetArch: request.TargetArch,
	})
	if err != nil {
		return ManagedRuntimeReinstallResult{}, err
	}
	return ManagedRuntimeReinstallResult{
		Uninstall: ManagedRuntimeUninstallResult{
			BundleID:     request.BundleID,
			Root:         install.Root,
			Removed:      replaced,
			ScopedOnly:   true,
			ManifestPath: install.ManifestPath,
		},
		Install: install,
		Doctor:  doctor,
	}, nil
}

func (i ManagedRuntimeBundleInstaller) validateManagedRuntimeManifestForRemoval(bundleRoot, bundleID string) error {
	manifestPath := filepath.Join(bundleRoot, managedRuntimeInstallManifestName)
	manifest, err := readManagedRuntimeManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("managed runtime install manifest is required before uninstall: %w", err)
	}
	if manifest.BundleID != bundleID || manifest.Root != bundleRoot || manifest.CommandPath != filepath.Join(bundleRoot, "bin", "nerdctl") {
		return errors.New("managed runtime install manifest does not match scoped bundle root")
	}
	return nil
}

func (i ManagedRuntimeBundleInstaller) validateManagedRuntimeExistingRootForReplacement(bundleRoot, bundleID string) error {
	_, err := os.Stat(bundleRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := i.validateManagedRuntimeManifestForRemoval(bundleRoot, bundleID); err != nil {
		return fmt.Errorf("managed runtime install manifest is required before replacement: %w", err)
	}
	return nil
}

func (i ManagedRuntimeBundleInstaller) fetchPinnedObjects(ctx context.Context, source ManagedRuntimeBundleObjectSource, bundle core.ManagedRuntimeBundleDescriptor) ([]byte, []byte, []byte, []byte, error) {
	artifact, err := fetchManagedRuntimePinnedObject(ctx, i.Catalog, source, bundle, "artifact", bundle.ArtifactName, bundle.ArtifactDigest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	checksum, err := fetchManagedRuntimePinnedObject(ctx, i.Catalog, source, bundle, "checksum", bundle.ChecksumName, bundle.ChecksumDigest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signature, err := fetchManagedRuntimePinnedObject(ctx, i.Catalog, source, bundle, "signature", bundle.SignatureName, bundle.SignatureDigest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	trustRoot, err := i.Catalog.TrustRootForBundle(bundle)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	trustRootObject, err := fetchManagedRuntimePinnedObjectWithURL(ctx, source, bundle.BundleID, "trust root", trustRoot.Name, managedRuntimeTrustRootURL(i.Catalog, trustRoot), trustRoot.Digest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return artifact, checksum, signature, trustRootObject, nil
}

func (i ManagedRuntimeBundleInstaller) source() ManagedRuntimeBundleObjectSource {
	if i.Source != nil {
		return i.Source
	}
	return HTTPManagedRuntimeBundleObjectSource{Client: i.HTTPClient}
}

func (i ManagedRuntimeBundleInstaller) now() time.Time {
	if i.Now != nil {
		if now := i.Now(); !now.IsZero() {
			return now.UTC()
		}
	}
	return time.Now().UTC()
}

func fetchManagedRuntimePinnedObject(ctx context.Context, catalog ManagedRuntimeBundleCatalog, source ManagedRuntimeBundleObjectSource, bundle core.ManagedRuntimeBundleDescriptor, kind, name, wantDigest string) ([]byte, error) {
	return fetchManagedRuntimePinnedObjectWithURL(ctx, source, bundle.BundleID, kind, name, managedRuntimeObjectURL(catalog.SourceBaseURL, name), wantDigest)
}

func fetchManagedRuntimePinnedObjectWithURL(ctx context.Context, source ManagedRuntimeBundleObjectSource, bundleID, kind, name, url, wantDigest string) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("managed runtime %s object name is required", kind)
	}
	if strings.TrimSpace(wantDigest) == "" {
		return nil, fmt.Errorf("managed runtime %s digest is required", kind)
	}
	object, err := source.FetchManagedRuntimeBundleObject(ctx, ManagedRuntimeBundleObjectRequest{
		BundleID: bundleID,
		Kind:     kind,
		Name:     name,
		URL:      url,
	})
	if err != nil {
		return nil, fmt.Errorf("fetch managed runtime %s object: %w", kind, err)
	}
	if err := verifyManagedRuntimeDigest(kind, object, wantDigest); err != nil {
		return nil, err
	}
	return object, nil
}

func managedRuntimeTrustRootURL(catalog ManagedRuntimeBundleCatalog, root ManagedRuntimeTrustRoot) string {
	if strings.TrimSpace(root.URL) != "" {
		return strings.TrimSpace(root.URL)
	}
	return managedRuntimeObjectURL(catalog.SourceBaseURL, root.Name)
}

func managedRuntimeObjectURL(base, name string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return name
	}
	return base + "/" + name
}

func verifyManagedRuntimeDigest(kind string, content []byte, want string) error {
	want = strings.TrimSpace(want)
	got := "sha256:" + managedRuntimeDigestHex(content)
	if got != want {
		return fmt.Errorf("managed runtime %s digest mismatch: got %s want %s", kind, got, want)
	}
	return nil
}

func verifyManagedRuntimeChecksum(bundle core.ManagedRuntimeBundleDescriptor, checksum []byte) error {
	wantDigest := strings.TrimPrefix(bundle.ArtifactDigest, "sha256:")
	lines := bytes.Split(checksum, []byte{'\n'})
	for _, line := range lines {
		fields := strings.Fields(string(line))
		if len(fields) < 2 {
			continue
		}
		if fields[0] == wantDigest && fields[len(fields)-1] == bundle.ArtifactName {
			return nil
		}
	}
	return fmt.Errorf("managed runtime checksum object does not pin artifact %q to %s", bundle.ArtifactName, bundle.ArtifactDigest)
}

func verifyManagedRuntimeSignature(bundle core.ManagedRuntimeBundleDescriptor, checksum, signature, trustRoot []byte) error {
	if len(signature) == 0 {
		return errors.New("managed runtime signature object is empty")
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(trustRoot))
	if err != nil {
		return fmt.Errorf("managed runtime signature verification trust root: %w", err)
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(checksum), bytes.NewReader(signature), nil)
	if err != nil {
		return fmt.Errorf("managed runtime signature verification failed: %w", err)
	}
	if signer == nil || signer.PrimaryKey == nil {
		return errors.New("managed runtime signature verification did not identify a signer")
	}
	if !strings.EqualFold(signer.PrimaryKey.KeyIdString(), bundle.SignatureKeyID) {
		return fmt.Errorf("managed runtime signature signer %q does not match pinned key %q", signer.PrimaryKey.KeyIdString(), bundle.SignatureKeyID)
	}
	return nil
}

func managedRuntimeDigestHex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func managedRuntimeBundleRoot(installRoot, bundleID string) (string, string, error) {
	if strings.TrimSpace(installRoot) == "" {
		return "", "", errors.New("managed runtime install root is required")
	}
	if !managedRuntimeSafePathPart(bundleID) {
		return "", "", fmt.Errorf("unsafe managed runtime bundle id %q", bundleID)
	}
	root, err := filepath.Abs(installRoot)
	if err != nil {
		return "", "", err
	}
	if err := managedRuntimeRejectSymlinkedInstallRootPath(root); err != nil {
		return "", "", err
	}
	bundleRoot := filepath.Join(root, bundleID)
	if err := managedRuntimeRequirePathUnderRoot(root, bundleRoot); err != nil {
		return "", "", err
	}
	return root, bundleRoot, nil
}

func managedRuntimeRejectSymlinkedInstallRootPath(root string) error {
	root = filepath.Clean(root)
	volume := filepath.VolumeName(root)
	rest := strings.TrimPrefix(root, volume)
	current := volume
	if strings.HasPrefix(rest, string(os.PathSeparator)) {
		current += string(os.PathSeparator)
		rest = strings.TrimPrefix(rest, string(os.PathSeparator))
	}
	for _, part := range strings.Split(rest, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if current == "" || current == string(os.PathSeparator) || strings.HasSuffix(current, string(os.PathSeparator)) {
			current = filepath.Join(current, part)
		} else {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed runtime install root path %q contains symlink %q", root, current)
		}
	}
	return nil
}

func managedRuntimeAcquireBundleLock(installRoot, bundleID string) (func(), error) {
	lockRoot := filepath.Join(installRoot, ".locks")
	if err := os.MkdirAll(lockRoot, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(lockRoot, bundleID+".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("managed runtime bundle %q is already locked", bundleID)
		}
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Close()
	return func() {
		_ = os.Remove(lockPath)
	}, nil
}

func managedRuntimePromoteStage(stageRoot, bundleRoot string) error {
	backupRoot := bundleRoot + ".previous"
	_ = os.RemoveAll(backupRoot)
	hadExisting := false
	if _, err := os.Stat(bundleRoot); err == nil {
		hadExisting = true
		if err := os.Rename(bundleRoot, backupRoot); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stageRoot, bundleRoot); err != nil {
		if hadExisting {
			_ = os.Rename(backupRoot, bundleRoot)
		}
		return err
	}
	if hadExisting {
		_ = os.RemoveAll(backupRoot)
	}
	return nil
}

func managedRuntimeSafePathPart(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." {
		return false
	}
	if filepath.IsAbs(value) || path.IsAbs(value) || filepath.VolumeName(value) != "" {
		return false
	}
	if strings.Contains(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	return filepath.Clean(value) == value
}

func managedRuntimeRequirePathUnderRoot(root, candidate string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("managed runtime path %q escapes root %q", candidate, root)
	}
	return nil
}

func managedRuntimeRequireFileUnderRoot(root, candidate string) error {
	if err := managedRuntimeRequirePathUnderRoot(root, candidate); err != nil {
		return err
	}
	if err := managedRuntimeRejectSymlinkPath(root, candidate); err != nil {
		return err
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory", candidate)
	}
	return nil
}

func managedRuntimeFileDigests(root, skipRel string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(pathValue string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if pathValue == root {
			return nil
		}
		rel, err := filepath.Rel(root, pathValue)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == skipRel {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(pathValue)
			if err != nil {
				return err
			}
			digestTarget, err := managedRuntimeSymlinkDigestTarget(rel, target)
			if err != nil {
				return err
			}
			out[rel] = "sha256:" + managedRuntimeDigestHex([]byte("symlink:"+digestTarget))
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("managed runtime path %q is not a regular file", pathValue)
		}
		content, err := os.ReadFile(pathValue)
		if err != nil {
			return err
		}
		out[rel] = "sha256:" + managedRuntimeDigestHex(content)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func verifyManagedRuntimeInstalledFileDigests(root string, want map[string]string) error {
	if len(want) == 0 {
		return errors.New("managed runtime install manifest has no file digests")
	}
	got, err := managedRuntimeFileDigests(root, managedRuntimeInstallManifestName)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("managed runtime file digest set changed: got %d want %d", len(got), len(want))
	}
	for rel, wantDigest := range want {
		if got[rel] != wantDigest {
			return fmt.Errorf("managed runtime file digest mismatch for %s", rel)
		}
	}
	return nil
}

func managedRuntimeRejectSymlinkPath(root, candidate string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed runtime path %q contains symlink %q", candidate, current)
		}
	}
	return nil
}

func extractManagedRuntimeTarGzip(content []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return err
	}
	defer gz.Close()
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(gz)
	seen := map[string]struct{}{}
	symlinkEntries := map[string]struct{}{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := managedRuntimeArchiveLocalPath(header.Name)
		if err != nil {
			return err
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate archive entry %q", header.Name)
		}
		if managedRuntimeArchiveHasSymlinkAncestor(name, symlinkEntries) {
			return fmt.Errorf("unsafe archive path %q is under symlink", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, modePerm(header.FileInfo().Mode())|0o700); err != nil {
				return err
			}
			seen[name] = struct{}{}
		case tar.TypeReg, tar.TypeRegA:
			if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
				return err
			}
			mode := modePerm(header.FileInfo().Mode())
			if mode == 0 {
				mode = 0o600
			}
			file, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(file, tr)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			seen[name] = struct{}{}
		case tar.TypeSymlink:
			linkTarget, err := managedRuntimeArchiveSymlinkTarget(name, header.Linkname)
			if err != nil {
				return err
			}
			if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
				return err
			}
			if err := root.Symlink(linkTarget, name); err != nil {
				return err
			}
			seen[name] = struct{}{}
			symlinkEntries[name] = struct{}{}
		default:
			return fmt.Errorf("unsafe archive entry type %d for %q", header.Typeflag, header.Name)
		}
	}
}

func managedRuntimeArchiveLocalPath(name string) (string, error) {
	if strings.TrimSpace(name) == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	if !fs.ValidPath(clean) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func managedRuntimeArchiveHasSymlinkAncestor(name string, symlinkEntries map[string]struct{}) bool {
	for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
		if _, ok := symlinkEntries[dir]; ok {
			return true
		}
	}
	return false
}

func managedRuntimeArchiveSymlinkTarget(entryName, target string) (string, error) {
	if _, err := managedRuntimeSymlinkDigestTarget(entryName, target); err != nil {
		return "", err
	}
	return path.Clean(target), nil
}

func managedRuntimeSymlinkDigestTarget(entryName, target string) (string, error) {
	if strings.TrimSpace(target) == "" || strings.Contains(target, "\\") || path.IsAbs(target) {
		return "", fmt.Errorf("unsafe archive symlink target %q", target)
	}
	entryClean, err := managedRuntimeArchiveLocalPath(entryName)
	if err != nil {
		return "", err
	}
	targetClean := path.Clean(target)
	if targetClean == "." {
		return "", fmt.Errorf("unsafe archive symlink target %q", target)
	}
	resolved := path.Clean(path.Join(path.Dir(entryClean), targetClean))
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", fmt.Errorf("unsafe archive symlink target %q", target)
	}
	return targetClean, nil
}

func modePerm(mode os.FileMode) os.FileMode {
	return mode.Perm()
}

func writeManagedRuntimeManifest(path string, manifest managedRuntimeInstallManifest) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	return os.WriteFile(path, content, 0o600)
}

func readManagedRuntimeManifest(path string) (managedRuntimeInstallManifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return managedRuntimeInstallManifest{}, err
	}
	var manifest managedRuntimeInstallManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return managedRuntimeInstallManifest{}, err
	}
	return manifest, nil
}
