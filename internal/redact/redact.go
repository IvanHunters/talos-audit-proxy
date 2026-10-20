// Package redact masks secret-bearing fields in a Talos machine config before
// it is written to the audit trail, so the "what changed" view is legible
// without leaking credentials into the log.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// placeholder replaces every masked value.
const placeholder = "***REDACTED***"

// Config returns the machine config with secret-bearing fields masked, and the
// hex SHA-256 of the original un-redacted bytes. The hash is taken over the
// input, so two applies can be compared even when the masked views are
// identical.
//
// Masking is intentionally over-broad (fail-safe): a field whose key names a
// token, secret, password, or key is masked, so a newly introduced secret
// scalar is hidden rather than leaked. Public certificate bodies (the `crt`
// key) are left visible on purpose, to surface CA and certificate changes in
// the audit diff.
//
// Known limitation: secrets nested inside an inline manifest body
// (cluster.inlineManifests[].contents is a YAML string holding Kubernetes
// objects, e.g. a Secret's data) are not parsed and masked by this version.
// Masking there needs a second pass that decodes the embedded YAML; until then
// such a manifest must not be relied on to be redacted.
func Config(raw []byte) (masked []byte, sha256hex string, err error) {
	sum := sha256.Sum256(raw)
	sha256hex = hex.EncodeToString(sum[:])

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	for {
		var doc yaml.Node
		if e := dec.Decode(&doc); e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return nil, sha256hex, fmt.Errorf("parse machine config: %w", e)
		}
		redactNode(&doc, nil)
		if e := enc.Encode(&doc); e != nil {
			return nil, sha256hex, fmt.Errorf("encode redacted config: %w", e)
		}
	}
	if e := enc.Close(); e != nil {
		return nil, sha256hex, fmt.Errorf("close encoder: %w", e)
	}
	return out.Bytes(), sha256hex, nil
}

// redactNode walks the YAML tree, masking the value of any mapping key that
// names a secret. path is the chain of mapping keys from the document root,
// used for the few secrets whose key name alone is too generic to match on.
func redactNode(n *yaml.Node, path []string) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			redactNode(c, path)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]
			child := append(append([]string{}, path...), key.Value)
			if isSecretKey(key.Value, child) {
				maskValue(val)
			} else {
				redactNode(val, child)
			}
		}
	}
}

// maskValue replaces a node (scalar, mapping, or sequence) with the redaction
// placeholder, keeping any descriptive comment attached to it.
func maskValue(n *yaml.Node) {
	n.Kind = yaml.ScalarNode
	n.Tag = "!!str"
	n.Style = 0
	n.Value = placeholder
	n.Content = nil
	n.Anchor = ""
	n.Alias = nil
}

// isSecretKey reports whether a field's value must be masked.
func isSecretKey(key string, path []string) bool {
	lk := strings.ToLower(key)
	switch {
	case strings.Contains(lk, "token"),
		strings.Contains(lk, "secret"),
		strings.Contains(lk, "password"),
		strings.Contains(lk, "passwd"):
		return true
	case lk == "key" || strings.HasSuffix(lk, "key"):
		return true
	}
	// cluster.id is a shared secret but "id" alone is too generic to match on.
	if pathIs(path, "cluster", "id") {
		return true
	}
	return false
}

// pathIs reports whether path equals want, case-insensitively.
func pathIs(path []string, want ...string) bool {
	if len(path) != len(want) {
		return false
	}
	for i := range want {
		if !strings.EqualFold(path[i], want[i]) {
			return false
		}
	}
	return true
}
