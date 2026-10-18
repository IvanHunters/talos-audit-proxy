package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Record is one audited Talos Machine API call. It answers "who changed what
// on which node, when". It is written as a single JSON line to the audit log.
type Record struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`            // CN of the operator's client cert
	Roles  []string  `json:"roles,omitempty"`  // Talos roles (cert Organization), e.g. os:admin
	Source string    `json:"source"`           // operator's remote address
	Method string    `json:"method"`           // gRPC full-method path
	Class  string    `json:"class"`            // Class.String(): mutating/sensitive/read-only/unclassified
	Nodes  []string  `json:"nodes,omitempty"`  // target nodes from request metadata
	DryRun bool      `json:"dry_run,omitempty"`

	// ConfigSHA256 and Config describe an ApplyConfiguration body. Config is
	// the submitted machine config with secret-bearing fields redacted; the
	// SHA is over the un-redacted bytes so two applies can be compared even
	// when the redacted view hides the difference. Both are empty for methods
	// that carry no config body.
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	Config       string `json:"config,omitempty"`

	// Error is the upstream forwarding error, if the call to apid failed.
	// An audited attempt is recorded whether or not it succeeded.
	Error string `json:"error,omitempty"`
}

// Sink receives audit records. Implementations must be safe for concurrent use
// by multiple proxied streams.
type Sink interface {
	Write(Record) error
	Close() error
}

// FileSink appends audit records as JSON lines to a file and fsyncs each one,
// so a crash cannot lose an already-returned record. Mutating-call volume is
// low (operators, not machines), so a sync per record is affordable and buys
// durability the audit trail needs.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink opens path for appending, creating it if absent. The file is
// owner read/write, group read: an audit log is not world-readable.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &FileSink{f: f}, nil
}

// Write marshals the record to one JSON line and fsyncs it to disk.
func (s *FileSink) Write(r Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return err
	}
	return s.f.Sync()
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
