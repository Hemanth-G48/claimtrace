// SPDX-License-Identifier: AGPL-3.0-or-later
package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["max_concurrent"] != float64(2) {
		t.Errorf("max_concurrent = %v, want 2", body["max_concurrent"])
	}
}

func TestDetonateValidation(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})

	body := `{"ecosystem": "pypi", "name": "test-pkg"}`
	req := httptest.NewRequest("POST", "/api/v1/detonate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (missing fields)", w.Code)
	}
}

func TestDetonateUnsupportedEcosystem(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})

	body := `{"ecosystem": "unknown", "name": "pkg", "version": "1.0", "archive_path": "/tmp/pkg.tar.gz", "archive_kind": "sdist"}`
	req := httptest.NewRequest("POST", "/api/v1/detonate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (unsupported ecosystem)", w.Code)
	}
}

func TestAssessValidation(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})

	body := `{"ecosystem":"npm","name":"pkg","version":"1.0.0","archive_path":"relative.tgz","archive_kind":"npm"}`
	req := httptest.NewRequest("POST", "/api/v1/assess", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (relative archive_path)", w.Code)
	}
}

func TestAssessRejectsInvalidPackageName(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})
	body := `{"ecosystem":"npm","name":"bad'; touch /tmp/pwned; '","version":"1.0.0","archive_path":"/tmp/pkg.tgz","archive_kind":"npm"}`
	req := httptest.NewRequest("POST", "/api/v1/assess", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (invalid package name)", w.Code)
	}
}

func TestAssessRejectsDirectoryArchive(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})
	dir := t.TempDir()
	body := `{"ecosystem":"npm","name":"pkg","version":"1.0.0","archive_path":"` + dir + `","archive_kind":"npm"}`
	req := httptest.NewRequest("POST", "/api/v1/assess", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (directory archive_path)", w.Code)
	}
}

func TestNotFound(t *testing.T) {
	srv := NewServer(Config{MaxConcurrent: 2, BaseDir: "/tmp/detonation-test"})

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
