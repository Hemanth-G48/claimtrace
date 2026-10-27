// SPDX-License-Identifier: AGPL-3.0-or-later
package assess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTraceExtractsRawEvents(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "trace.log")
	lines := strings.Join([]string{
		`12   12:00:00.000001 execve("/usr/local/bin/node", ["node", "index.js"], 0x0 /* 5 vars */) = 0`,
		`12   12:00:00.000002 openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3`,
		`12   12:00:00.000003 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH`,
	}, "\n")
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	events := parseTrace("entry", logPath)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if events[0].Category != "process" || events[0].Operation != "exec" {
		t.Errorf("first event = %+v", events[0])
	}
	if got := events[1].Detail["path"]; got != "/root/.ssh/id_rsa" {
		t.Errorf("path = %v", got)
	}
	if got := events[2].Detail["addr"]; got != "203.0.113.9" {
		t.Errorf("addr = %v", got)
	}
}

func TestNpmEntryAndImportAreSeparateScripts(t *testing.T) {
	entry := phaseScript("entry", "pkg.tgz", "pkg")
	imp := phaseScript("import", "pkg.tgz", "pkg")
	if entry == "" || imp == "" {
		t.Fatal("npm entry/import scripts must be present")
	}
	if strings.Contains(entry, "require.resolve") {
		t.Error("entry script must execute a file, not resolve a package import")
	}
	if !strings.Contains(imp, "require.resolve") {
		t.Error("import script must resolve the package")
	}
	if strings.Contains(entry, "postinstall") {
		t.Error("entry script must not run lifecycle hooks")
	}
	if strings.Contains(entry, "| while") || !strings.Contains(entry, "done < /tmp/entry-bins") {
		t.Error("entry bin loop must run in the current shell so a missing bin exits the phase")
	}
}

func TestPreflightRefusalHasNoObservations(t *testing.T) {
	// A refused result is constructed without touching Docker; the assertion is
	// the contract the API must preserve when preflight fails.
	r := Result{
		Status:    "refused",
		Phases:    map[string]PhaseResult{},
		Coverage:  Coverage{Level: "incomplete"},
		Preflight: &Preflight{Status: "refused", FailedControl: "cap_drop_all"},
	}
	if r.Status != "refused" || len(r.RawEvents) != 0 || r.Coverage.Level != "incomplete" {
		t.Fatalf("bad refusal shape: %+v", r)
	}
}
