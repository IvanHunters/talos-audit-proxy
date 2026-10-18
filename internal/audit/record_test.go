package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileSinkWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}

	recs := []Record{
		{
			Time:   time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
			Actor:  "ivan.okhotnikov@aenix.io",
			Roles:  []string{"os:admin"},
			Source: "10.0.0.5:51000",
			Method: "/machine.MachineService/ApplyConfiguration",
			Class:  ClassMutating.String(),
			Nodes:  []string{"10.0.0.11"},
		},
		{
			Time:   time.Date(2026, 10, 18, 12, 1, 0, 0, time.UTC),
			Actor:  "ivan.okhotnikov@aenix.io",
			Source: "10.0.0.5:51002",
			Method: "/machine.MachineService/Reboot",
			Class:  ClassMutating.String(),
			Nodes:  []string{"10.0.0.11"},
		},
	}
	for _, r := range recs {
		if err := sink.Write(r); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var got []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("unmarshal line %q: %v", sc.Text(), err)
		}
		got = append(got, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(got) != len(recs) {
		t.Fatalf("read back %d records, wrote %d", len(got), len(recs))
	}
	if got[0].Actor != recs[0].Actor || got[0].Method != recs[0].Method {
		t.Errorf("record 0 mismatch: got %+v", got[0])
	}
	if !got[0].Time.Equal(recs[0].Time) {
		t.Errorf("record 0 time: got %v want %v", got[0].Time, recs[0].Time)
	}
	if len(got[0].Roles) != 1 || got[0].Roles[0] != "os:admin" {
		t.Errorf("record 0 roles: got %v", got[0].Roles)
	}
}

// TestFileSinkOmitsEmptyOptionalFields guards that a read-only-style record
// does not emit noisy empty keys (roles, config, nodes) that would bloat the
// log and confuse downstream parsers.
func TestFileSinkOmitsEmptyOptionalFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Write(Record{
		Time:   time.Now(),
		Actor:  "svc",
		Source: "10.0.0.5:1",
		Method: "/machine.MachineService/Version",
		Class:  ClassReadOnly.String(),
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"roles", "nodes", "config", "config_sha256", "dry_run", "error"} {
		if _, present := m[k]; present {
			t.Errorf("empty optional field %q should be omitted, got %v", k, m[k])
		}
	}
}

// TestFileSinkConcurrentWrites checks that parallel proxied streams do not
// interleave into corrupt lines: every line must parse as one record.
func TestFileSinkConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sink.Write(Record{
				Time:   time.Now(),
				Actor:  "ivan.okhotnikov@aenix.io",
				Source: "10.0.0.5:1",
				Method: "/machine.MachineService/ApplyConfiguration",
				Class:  ClassMutating.String(),
			})
		}()
	}
	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("corrupt line %d: %q: %v", lines, sc.Text(), err)
		}
		lines++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines != n {
		t.Fatalf("got %d lines, want %d", lines, n)
	}
}
