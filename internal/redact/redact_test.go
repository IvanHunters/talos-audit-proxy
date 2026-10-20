package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigMasksAllSecrets(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "machineconfig.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	masked, sha, err := Config(raw)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	out := string(masked)

	// Every secret marker must be gone. publicKey is masked too: the fail-safe
	// over-masks a public key rather than risk leaking a private one.
	secretMarkers := []string{
		"MARKER-machine-token",
		"MARKER-machine-ca-key",
		"MARKER-cluster-id",
		"MARKER-cluster-secret",
		"MARKER-cluster-token",
		"MARKER-cluster-ca-key",
		"MARKER-cluster-aggregatorca-key",
		"MARKER-cluster-sa-key",
		"MARKER-cluster-etcd-ca-key",
		"MARKER-wg-privatekey",
		"MARKER-wg-publickey",
		"MARKER-wg-preshared",
	}
	for _, m := range secretMarkers {
		if strings.Contains(out, m) {
			t.Errorf("secret marker %q leaked into masked output", m)
		}
	}

	// Public and plain values must stay, so the audit diff shows what changed.
	publicRemain := []string{
		"v1alpha1",
		"PUBLIC-machine-ca-crt",
		"PUBLIC-cluster-ca-crt",
		"PUBLIC-cluster-aggregatorca-crt",
		"PUBLIC-cluster-etcd-ca-crt",
		"/dev/sda",
		"cp-01",
		"10.0.0.2:51820",
	}
	for _, p := range publicRemain {
		if !strings.Contains(out, p) {
			t.Errorf("public value %q should remain visible but was removed", p)
		}
	}

	if !strings.Contains(out, "***REDACTED***") {
		t.Error("expected redaction placeholder in output")
	}
	if len(sha) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(sha))
	}
}

// TestConfigHashTracksOriginalNotMasked proves the SHA is over the input: two
// configs that differ only in a secret value mask to the same bytes yet must
// hash differently, so the audit record can still tell two applies apart.
func TestConfigHashTracksOriginalNotMasked(t *testing.T) {
	a := []byte("machine:\n  token: abc\n")
	b := []byte("machine:\n  token: xyz\n")

	maskedA, shaA, err := Config(a)
	if err != nil {
		t.Fatal(err)
	}
	maskedB, shaB, err := Config(b)
	if err != nil {
		t.Fatal(err)
	}

	if string(maskedA) != string(maskedB) {
		t.Fatalf("expected identical masked output, got %q vs %q", maskedA, maskedB)
	}
	if shaA == shaB {
		t.Error("hash must differ when inputs differ, even though masked output is identical")
	}

	_, shaA2, err := Config(a)
	if err != nil {
		t.Fatal(err)
	}
	if shaA != shaA2 {
		t.Error("hash must be stable for identical input")
	}
}

func TestConfigInvalidYAML(t *testing.T) {
	if _, _, err := Config([]byte("key: value\n  bad: indent: :")); err == nil {
		t.Error("expected error on invalid YAML")
	}
}
