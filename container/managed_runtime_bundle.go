package container

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

type ManagedRuntimeBundleCatalog struct {
	ReleaseTag       string                                `json:"release_tag,omitempty"`
	SourceBaseURL    string                                `json:"source_base_url,omitempty"`
	GeneratedAt      time.Time                             `json:"generated_at"`
	Bundles          []core.ManagedRuntimeBundleDescriptor `json:"bundles"`
	TrustRoots       []ManagedRuntimeTrustRoot             `json:"trust_roots,omitempty"`
	BlockedVersions  []string                              `json:"blocked_versions,omitempty"`
	RevokedKeyIDs    []string                              `json:"revoked_key_ids,omitempty"`
	MinimumVersion   string                                `json:"minimum_version,omitempty"`
	StableSigningKey string                                `json:"stable_signing_key,omitempty"`
}

type ManagedRuntimeTrustRoot struct {
	KeyID  string `json:"key_id"`
	Name   string `json:"name"`
	URL    string `json:"url,omitempty"`
	Digest string `json:"digest"`
	Issuer string `json:"issuer,omitempty"`
}

func (c ManagedRuntimeBundleCatalog) Bundle(bundleID string, now time.Time) (core.ManagedRuntimeBundleDescriptor, error) {
	if strings.TrimSpace(bundleID) == "" {
		return core.ManagedRuntimeBundleDescriptor{}, errors.New("bundle_id is required")
	}
	if now.IsZero() {
		return core.ManagedRuntimeBundleDescriptor{}, errors.New("validation time is required")
	}
	for _, bundle := range c.Bundles {
		if bundle.BundleID != bundleID {
			continue
		}
		if err := validateManagedRuntimeBundlePolicy(c, bundle, now); err != nil {
			return core.ManagedRuntimeBundleDescriptor{}, err
		}
		return bundle, nil
	}
	return core.ManagedRuntimeBundleDescriptor{}, fmt.Errorf("managed runtime bundle %q not found", bundleID)
}

func (c ManagedRuntimeBundleCatalog) BundleForTarget(bundleID, targetOS, targetArch string, now time.Time) (core.ManagedRuntimeBundleDescriptor, error) {
	bundle, err := c.Bundle(bundleID, now)
	if err != nil {
		return core.ManagedRuntimeBundleDescriptor{}, err
	}
	if !managedRuntimeBundleSupportsTarget(bundle, targetOS, targetArch) {
		return core.ManagedRuntimeBundleDescriptor{}, fmt.Errorf("managed runtime bundle %q does not support %s/%s", bundleID, targetOS, targetArch)
	}
	return bundle, nil
}

func (c ManagedRuntimeBundleCatalog) TrustRootForBundle(bundle core.ManagedRuntimeBundleDescriptor) (ManagedRuntimeTrustRoot, error) {
	for _, root := range c.TrustRoots {
		if root.KeyID == bundle.SignatureKeyID && root.Digest == bundle.TrustRootDigest {
			if strings.TrimSpace(root.Name) == "" {
				return ManagedRuntimeTrustRoot{}, fmt.Errorf("managed runtime trust root for key %q has no object name", bundle.SignatureKeyID)
			}
			return root, nil
		}
	}
	return ManagedRuntimeTrustRoot{}, fmt.Errorf("managed runtime trust root for signing key %q and digest %q not found", bundle.SignatureKeyID, bundle.TrustRootDigest)
}

func validateManagedRuntimeBundlePolicy(c ManagedRuntimeBundleCatalog, bundle core.ManagedRuntimeBundleDescriptor, now time.Time) error {
	if err := bundle.ValidateAt(now); err != nil {
		return err
	}
	if slices.Contains(c.BlockedVersions, bundle.Version) ||
		slices.Contains(bundle.UpdatePolicy.BlockedVersions, bundle.Version) ||
		slices.Contains(bundle.CVEPolicy.BlockedVersions, bundle.Version) {
		return fmt.Errorf("managed runtime bundle version %q is blocked", bundle.Version)
	}
	if slices.Contains(c.RevokedKeyIDs, bundle.SignatureKeyID) ||
		slices.Contains(bundle.CVEPolicy.RevokedKeyIDs, bundle.SignatureKeyID) {
		return fmt.Errorf("managed runtime bundle signing key %q is revoked", bundle.SignatureKeyID)
	}
	minVersion := firstNonEmpty(c.MinimumVersion, bundle.UpdatePolicy.MinSupportedVersion)
	if minVersion != "" && semverLess(bundle.Version, minVersion) {
		return fmt.Errorf("managed runtime bundle version %q is below minimum %q", bundle.Version, minVersion)
	}
	if c.StableSigningKey != "" && bundle.SignatureKeyID != c.StableSigningKey {
		return fmt.Errorf("managed runtime bundle signing key %q does not match stable signing key", bundle.SignatureKeyID)
	}
	return nil
}

func managedRuntimeBundleSupportsTarget(bundle core.ManagedRuntimeBundleDescriptor, targetOS, targetArch string) bool {
	targetOS = strings.TrimSpace(targetOS)
	targetArch = strings.TrimSpace(targetArch)
	if targetOS == "" || targetArch == "" {
		return false
	}
	for _, target := range bundle.SupportedTargets {
		if target.OS == targetOS && target.Arch == targetArch {
			return true
		}
	}
	return false
}

func semverLess(left, right string) bool {
	l := parseVersionParts(left)
	r := parseVersionParts(right)
	for i := range 3 {
		if l[i] != r[i] {
			return l[i] < r[i]
		}
	}
	return false
}

func parseVersionParts(version string) [3]int {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		value, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}
		}
		out[i] = value
	}
	return out
}
