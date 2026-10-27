// SPDX-License-Identifier: AGPL-3.0-or-later
// Package assess implements the Stage 0 local-artifact assessment sandbox.
//
// It is deliberately separate from the registry detonation path. The API receives
// a staged archive path, starts one hardened container, and runs install, entry,
// and import as separate captured phases. Tetragon is the production collector;
// this package's local fallback uses ptrace (strace) inside the container and
// labels telemetry unverified. It never fetches a registry release.
package assess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"detonation/internal/honeytokens"
	"detonation/internal/trace"
)

type Request struct {
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	ArchivePath    string `json:"archive_path"`
	ArchiveKind    string `json:"archive_kind"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	// Test-only fault injection; accepted only when ASSESS_TEST_FAULTS=1.
	FaultDropRaw     string `json:"fault_drop_raw,omitempty"`
	FaultIndependent bool   `json:"fault_independent,omitempty"`
}

type PhaseResult struct {
	Status     string `json:"status"` // started_completed | failed | timed_out
	ExitCode   int    `json:"exit_code"`
	DurationMS int    `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	Detail     string `json:"detail,omitempty"`
}

type RawEvent struct {
	RawEventID   string                 `json:"raw_event_id"`
	Phase        string                 `json:"phase"`
	Category     string                 `json:"category"`
	Operation    string                 `json:"operation"`
	PID          int                    `json:"pid,omitempty"`
	Timestamp    string                 `json:"timestamp,omitempty"`
	Docker       string                 `json:"docker,omitempty"`
	Detail       map[string]interface{} `json:"detail"`
	FilterReason string                 `json:"filter_reason,omitempty"`
}

type Preflight struct {
	Status               string            `json:"status"`
	FailedControl        string            `json:"failed_control,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	EffectiveProfile     map[string]string `json:"effective_profile,omitempty"`
	EffectiveProfileHash string            `json:"effective_profile_hash,omitempty"`
	ProfileSource        string            `json:"profile_source,omitempty"`
}

type Coverage struct {
	Level              string                 `json:"level"`
	CaptureMode        string                 `json:"capture_mode"`
	TelemetryLevel     string                 `json:"telemetry_level"`
	Egress             string                 `json:"egress"`
	DNSMode            string                 `json:"dns_mode"`
	SinkholeMode       string                 `json:"sinkhole_mode"`
	SinkholePorts      []int                  `json:"sinkhole_ports"`
	CaptureHealth      map[string]interface{} `json:"capture_health,omitempty"`
	SettleWindowSec    int                    `json:"settle_window_seconds"`
	InstallMode        string                 `json:"install_mode"`
	CaptureProfileHash string                 `json:"capture_profile_hash"`
	DecoySetHash       string                 `json:"decoy_set_hash"`
	CapturedPaths      []string               `json:"captured_paths"`
	Phases             map[string]PhaseResult `json:"phases"`
}

type Result struct {
	Status            string                 `json:"status"`
	Request           Request                `json:"request"`
	Phases            map[string]PhaseResult `json:"phases"`
	RawEvents         []RawEvent             `json:"raw_events"`
	Findings          []interface{}          `json:"findings"`
	Coverage          Coverage               `json:"coverage"`
	EvidenceIntegrity map[string]interface{} `json:"evidence_integrity"`
	Preflight         *Preflight             `json:"preflight,omitempty"`
	Error             string                 `json:"error,omitempty"`
}

var imageOnce = syncMap{}

var packageNameRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// ValidPackageName rejects names that could escape the package path or be
// interpreted by the phase shell. npm's registry names are lowercase.
func ValidPackageName(name string) bool {
	return len(name) > 0 && len(name) <= 214 && packageNameRE.MatchString(name)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

type syncMap struct {
	m map[string]string
}

func (s *syncMap) load(k string) (string, bool) {
	if s.m == nil {
		return "", false
	}
	v, ok := s.m[k]
	return v, ok
}
func (s *syncMap) store(k, v string) {
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
}

func jsonHash(v interface{}) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func docker(args ...string) *exec.Cmd {
	return exec.Command("docker", args...)
}

func execDocker(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "docker", args...).Run()
}

func timeNowNano() int64 { return time.Now().UnixNano() }

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	c := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.String(), err
}

func resolveImage() string {
	if v := os.Getenv("ASSESS_IMAGE"); v != "" {
		return v
	}
	for _, candidate := range []string{"claimtrace-det-npm", "claimtrace-m2-node:latest", "node:22-trixie-slim"} {
		if _, err := dockerOutput(context.Background(), "image", "inspect", candidate); err == nil {
			return candidate
		}
	}
	return "node:22-trixie-slim"
}

func preflight(ctx context.Context, image string, requireStrace bool) (*Preflight, error) {
	sec, err := dockerOutput(ctx, "info", "--format", "{{json .SecurityOptions}}")
	if err != nil {
		return &Preflight{Status: "refused", FailedControl: "docker_rootless", Reason: "docker info failed: " + err.Error(), ProfileSource: "docker"}, nil
	}
	if !strings.Contains(sec, "rootless") {
		return &Preflight{Status: "refused", FailedControl: "docker_rootless", Reason: "Docker daemon is not rootless", ProfileSource: "docker"}, nil
	}

	probe := `set -eu
CAP=$(awk '/^CapEff:/{print $2}' /proc/self/status)
NNP=$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status)
PIDS=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unavailable)
RO=yes; touch /probe-write >/dev/null 2>&1 && RO=no || true
TMP=$(df -Pk /tmp 2>/dev/null | awk 'NR==2{print $2}')
DISK=$(df -Pk /sandbox 2>/dev/null | awk 'NR==2{print $2}')
NET=$(ls /sys/class/net 2>/dev/null | sort | tr '\n' ',' || true)
STRACE=no; command -v strace >/dev/null 2>&1 && STRACE=yes
printf 'CAP=%s\nNNP=%s\nPIDS=%s\nRO=%s\nTMP=%s\nDISK=%s\nNET=%s\nSTRACE=%s\n' "$CAP" "$NNP" "$PIDS" "$RO" "$TMP" "$DISK" "$NET" "$STRACE"`

	args := []string{
		"run", "--rm", "--network=none",
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=64", "--memory=512m", "--read-only",
		"--tmpfs", "/tmp:rw,size=16m",
		"--tmpfs", "/sandbox:rw,size=64m",
		image, "sh", "-c", probe,
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return &Preflight{
			Status: "refused", FailedControl: "docker_probe",
			Reason:           "preflight probe failed: " + strings.TrimSpace(out) + " " + err.Error(),
			ProfileSource:    "assess-probe-v1",
			EffectiveProfile: map[string]string{"probe": strings.Join(args, " ")},
		}, nil
	}
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	failed := ""
	switch {
	case vals["CAP"] != "0000000000000000":
		failed = "cap_drop_all"
	case vals["NNP"] != "1":
		failed = "no_new_privileges"
	case vals["PIDS"] == "" || vals["PIDS"] == "unavailable" || vals["PIDS"] == "max":
		failed = "pid_limit"
	case vals["RO"] != "yes":
		failed = "read_only_rootfs"
	case vals["TMP"] == "" || vals["TMP"] == "0":
		failed = "disk_limit"
	case vals["DISK"] == "" || vals["DISK"] == "0":
		failed = "workspace_disk_limit"
	case strings.Trim(vals["NET"], ",") != "lo":
		failed = "network_isolation"
	case requireStrace && vals["STRACE"] != "yes":
		failed = "ptrace_capture"
	}
	if failed != "" {
		return &Preflight{Status: "refused", FailedControl: failed,
			Reason:           "effective probe did not verify " + failed,
			EffectiveProfile: vals, ProfileSource: "assess-probe-v1",
			EffectiveProfileHash: jsonHash(vals)}, nil
	}
	captureLabel := "strace"
	if !requireStrace {
		captureLabel = "tetragon"
	}
	profile := map[string]string{
		"cap_drop": "ALL", "no_new_privileges": vals["NNP"], "pids_limit": "64",
		"memory_limit_mb": "512", "rootfs": "read-only", "tmpfs_size_kb": vals["TMP"],
		"workspace_size_kb": vals["DISK"], "network": "isolated_bridge", "dns": "fake_nonforwarding", "capture": captureLabel,
	}
	return &Preflight{Status: "ok", EffectiveProfile: profile,
		EffectiveProfileHash: jsonHash(profile), ProfileSource: "assess-probe-v1"}, nil
}

func containerName(id string) string { return "assess-" + id }

func hashDecoyHome(root string) string {
	h := sha256.New()
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		fmt.Fprintf(h, "%s\x00", rel)
		b, _ := os.ReadFile(path)
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

func applyFault(raw []RawEvent, req Request) ([]string, []string) {
	if os.Getenv("ASSESS_TEST_FAULTS") != "1" || req.FaultDropRaw == "" {
		return nil, nil
	}
	var missing, independent []string
	for i := range raw {
		match := false
		switch req.FaultDropRaw {
		case "network":
			match = raw[i].Category == "network" && raw[i].Operation == "connect"
		case "file":
			match = raw[i].Category == "file"
		case "sensitive":
			if raw[i].Category == "network" && raw[i].Operation == "connect" {
				match = true
			}
			if raw[i].Category == "file" {
				if path, _ := raw[i].Detail["path"].(string); strings.Contains(path, ".ssh") || strings.Contains(path, ".aws") {
					match = true
				}
			}
		}
		if !match {
			continue
		}
		missing = append(missing, raw[i].RawEventID)
		raw[i].FilterReason = "fault_injected_missing_raw"
		if req.FaultIndependent && raw[i].Category == "network" && raw[i].Operation == "connect" {
			independent = append(independent, raw[i].RawEventID)
			for j := range raw {
				if j != i && raw[j].Phase == raw[i].Phase && raw[j].Category == "network" && raw[j].Operation == "sinkhole_accept" {
					independent = append(independent, raw[j].RawEventID)
					break
				}
			}
		}
	}
	return missing, independent
}

func startContainer(ctx context.Context, image, archive, name string, timeoutSec int, network, dnsIP string) (string, string, string, error) {
	base, err := os.MkdirTemp("", "claimtrace-assess-")
	if err != nil {
		return "", "", "", err
	}
	cleanup := func() { _ = os.RemoveAll(base) }
	_ = os.MkdirAll(filepath.Join(base, "decoy-home"), 0o755)
	decoyHome := filepath.Join(base, "decoy-home")
	if err := honeytokens.MaterializeHome(decoyHome); err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("materialize decoys: %w", err)
	}
	decoyHash := hashDecoyHome(decoyHome)
	archiveAbs, err := filepath.Abs(archive)
	if err != nil {
		cleanup()
		return "", "", "", err
	}
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", archiveAbs, name, time.Now().UnixNano()))))[:12]
	args := []string{
		"run", "-d", "--rm", "--name", containerName(id),
		"--network", network, "--dns", dnsIP, "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=64", "--memory=512m", "--read-only",
		"--tmpfs", "/sandbox:rw,size=64m", "--tmpfs", "/tmp:rw,size=16m",
		"--workdir", "/sandbox",
		"-v", archiveAbs + ":/input/" + filepath.Base(archiveAbs) + ":ro",
		"-e", "HOME=/root", "-e", "DET_SETTLE_SEC=10",
	}
	args = append(args, honeytokens.EnvArgs()...)
	args = append(args, honeytokens.FileMounts(decoyHome, "/sandbox")...)
	args = append(args, image, "sleep", "3600")
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("start sandbox: %s: %w", strings.TrimSpace(out), err)
	}
	return strings.TrimSpace(out), decoyHash, base, nil
}

func stopContainer(ctx context.Context, name string) {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
}

func execPhase(ctx context.Context, container, phase, archiveBase, name string, timeoutSec int, usePtrace bool) (PhaseResult, string) {
	script := phaseScript(phase, archiveBase, name)
	if script == "" {
		return PhaseResult{Status: "not_requested", ExitCode: 0}, ""
	}
	logPath := ""
	traceArgs := []string{"exec", container, "sh", "-c", script}
	if usePtrace {
		logPath = "/sandbox/trace-" + phase + ".log"
		traceArgs = []string{
			"exec", container, "strace", "-f", "-tt", "-qq", "-o", logPath,
			"-e", "trace=execve,execveat,openat,open,connect,ptrace,process_vm_writev,memfd_create",
			"sh", "-c", script,
		}
	}
	start := time.Now()
	c := exec.CommandContext(ctx, "docker", traceArgs...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	elapsed := int(time.Since(start).Milliseconds())
	res := PhaseResult{Status: "started_completed", DurationMS: elapsed, Detail: strings.TrimSpace(out.String())}
	if ctx.Err() == context.DeadlineExceeded {
		res.Status, res.TimedOut, res.ExitCode = "timed_out", true, -1
		return res, logPath
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
		res.Status = "failed"
	}
	return res, logPath
}

func phaseScript(phase, archiveBase, name string) string {
	pkg := shellQuote("/sandbox/app/node_modules/" + name)
	archive := shellQuote("/input/" + archiveBase)
	switch phase {
	case "install":
		return `set -u
mkdir -p /sandbox/app
cd /sandbox/app
[ -f package.json ] || printf '{"name":"assess-app","version":"1.0.0","private":true}\n' > package.json
export npm_config_cache=/tmp/npm-cache
npm install --ignore-scripts --offline --no-audit --no-fund ` + archive + ` || exit 10
cd ` + pkg + ` || exit 11
for h in preinstall install postinstall; do
  s=$(node -e "try{var x=(require('./package.json').scripts||{})['$h']||'';process.stdout.write(x)}catch(e){}")
  if [ -n "$s" ]; then
    echo "SCRIPT_START $h"
    sh -c "$s"
    rc=$?
    echo "SCRIPT_EXIT $h $rc"
    [ $rc -eq 0 ] || exit 20
  fi
done`
	case "entry":
		return `set -u
cd ` + pkg + ` || exit 12
echo "ENTRY_ROOT=$PWD"
main=$(node -e "var p=require('./package.json');process.stdout.write(typeof p.main==='string'?p.main:'')")
if [ -n "$main" ]; then
  [ -f "$main" ] || exit 30
  echo "ENTRY_METHOD=main ENTRY_PATH=$main"
  timeout 15 node "$main" || { rc=$?; [ $rc -eq 124 ] || exit $rc; echo ENTRY_TIMEOUT; }
elif [ -f index.js ]; then
  echo "ENTRY_METHOD=index_default ENTRY_PATH=index.js"
  timeout 15 node index.js || { rc=$?; [ $rc -eq 124 ] || exit $rc; echo ENTRY_TIMEOUT; }
else
  echo "ENTRY_METHOD=none"
fi
node -e "var b=require('./package.json').bin;if(typeof b==='string')console.log(b);else if(b)Object.keys(b).forEach(function(k){console.log(b[k])})" > /tmp/entry-bins || exit 32
while IFS= read -r bp; do
  [ -n "$bp" ] || continue
  [ -f "$bp" ] || exit 31
  echo "ENTRY_BIN=$bp"
  timeout 15 node "$bp" || { rc=$?; [ $rc -eq 124 ] || exit $rc; echo BIN_TIMEOUT; }
done < /tmp/entry-bins
sleep "${DET_SETTLE_SEC:-10}"`
	case "import":
		return `set -u
cd /sandbox/app || exit 13
echo "IMPORT_ROOT=$PWD"
if node -e "process.exit(require('./node_modules/` + name + `/package.json').type==='module'?0:1)"; then
  node --input-type=module -e "console.log('IMPORT_METHOD=import');console.log('IMPORT_FORMAT=esm');try{console.log('IMPORT_PATH='+import.meta.resolve('` + name + `'))}catch(e){};await import('` + name + `')" || exit 40
else
  node -e "var path=require.resolve('` + name + `');console.log('IMPORT_METHOD=require');console.log('IMPORT_PATH='+path);console.log('IMPORT_FORMAT=commonjs');require('` + name + `')" || exit 40
fi`
	}
	return ""
}

var (
	reExec    = regexp.MustCompile(`(?:execve|execveat)\("([^"]+)"`)
	reOpen    = regexp.MustCompile(`(?:openat|open)\([^,]*, "([^"]+)"`)
	reConnect = regexp.MustCompile(`connect\([^,]*, \{sa_family=([^,]+), sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)`)
	reTime    = regexp.MustCompile(`^(\d+)\s+([0-9:.]+)\s+`)
)

func parseTrace(phase, path string) []RawEvent {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []RawEvent
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		m := reTime.FindStringSubmatch(line)
		ts := ""
		if len(m) == 3 {
			ts = m[2]
		}
		if mm := reExec.FindStringSubmatch(line); mm != nil {
			out = append(out, RawEvent{RawEventID: fmt.Sprintf("raw-%s-%d", phase, len(out)), Phase: phase,
				Category: "process", Operation: "exec", Timestamp: ts,
				Detail: map[string]interface{}{"binary": mm[1], "arguments": line}})
			continue
		}
		if mm := reConnect.FindStringSubmatch(line); mm != nil {
			out = append(out, RawEvent{RawEventID: fmt.Sprintf("raw-%s-%d", phase, len(out)), Phase: phase,
				Category: "network", Operation: "connect", Timestamp: ts,
				Detail: map[string]interface{}{"addr": mm[3], "port": mm[2], "family": mm[1]}})
			continue
		}
		if mm := reOpen.FindStringSubmatch(line); mm != nil {
			out = append(out, RawEvent{RawEventID: fmt.Sprintf("raw-%s-%d", phase, len(out)), Phase: phase,
				Category: "file", Operation: "open", Timestamp: ts,
				Detail: map[string]interface{}{"path": mm[1]}})
		}
	}
	return out
}

func tetragonLogPath() string {
	if v := os.Getenv("TETRAGON_LOG"); v != "" {
		return v
	}
	return "/var/log/tetragon/tetragon.log"
}

func selectCapture() string {
	if v := os.Getenv("ASSESS_CAPTURE"); v != "" {
		return v
	}
	if _, err := os.Stat(tetragonLogPath()); err == nil {
		return "tetragon"
	}
	return "ptrace"
}

func tetragonRaw(phase string, events []trace.TraceEvent) []RawEvent {
	out := make([]RawEvent, 0, len(events))
	for _, e := range events {
		detail := map[string]interface{}{}
		for k, v := range e.Detail {
			detail[k] = v
		}
		out = append(out, RawEvent{
			Phase: phase, Category: e.Category, Operation: e.Operation,
			PID: e.PID, Timestamp: e.Timestamp, Docker: e.Docker, Detail: detail,
		})
	}
	return out
}

func captureHealth(raw []RawEvent) map[string]interface{} {
	tetragonConnect, sinkholeAccept, dnsQueries := 0, 0, 0
	for _, e := range raw {
		if e.Category == "network" && e.Operation == "connect" {
			tetragonConnect++
		}
		if e.Category == "network" && e.Operation == "sinkhole_accept" {
			sinkholeAccept++
		}
		if e.Category == "dns" && e.Operation == "query" {
			dnsQueries++
		}
	}
	loss := sinkholeAccept > tetragonConnect
	status := "no_observed_loss"
	if loss {
		status = "loss_detected"
	}
	return map[string]interface{}{
		"method": "cross_stream_network", "scope": "network_connect_only",
		"tetragon_connect": tetragonConnect, "sinkhole_accept": sinkholeAccept,
		"dns_queries": dnsQueries, "loss_detected": loss, "status": status,
		"note": "network-only cross-stream check; file/process event loss is not measured",
	}
}

func enrichSinkholeHostnames(raw []RawEvent, sinkIP string) {
	for i := range raw {
		if raw[i].Category != "network" || raw[i].Operation != "connect" {
			continue
		}
		addr, _ := raw[i].Detail["addr"].(string)
		if addr != sinkIP {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if raw[j].Phase != raw[i].Phase {
				continue
			}
			if raw[j].Category == "dns" && raw[j].Operation == "query" {
				if host, _ := raw[j].Detail["hostname"].(string); host != "" {
					raw[i].Detail["hostname"] = host
				}
				break
			}
		}
	}
}

func tetragonOffset() int64 {
	fi, err := os.Stat(tetragonLogPath())
	if err != nil {
		return 0
	}
	return fi.Size()
}

func collectTetragonFromOffset(path string, offset int64, container, phase string) []RawEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && offset > fi.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return nil
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var raw []RawEvent
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		events, err := trace.ParseTetragonLine(line, []string{container})
		if err != nil {
			continue
		}
		raw = append(raw, tetragonRaw(phase, events)...)
	}
	return raw
}

// Run executes one local assessment. It returns a refused result rather than
// starting package code if any mandatory control cannot be verified.
func Run(ctx context.Context, req Request) Result {
	if !ValidPackageName(req.Name) {
		return Result{Status: "error", Request: req, Error: "invalid npm package name"}
	}
	image := resolveImage()
	capture := selectCapture()
	if capture == "tetragon" {
		if _, err := os.Stat(tetragonLogPath()); err != nil {
			return Result{Status: "refused", Request: req,
				Preflight: &Preflight{Status: "refused", FailedControl: "tetragon_log",
					Reason: "Tetragon log unavailable: " + err.Error(), ProfileSource: "tetragon"},
				Phases: map[string]PhaseResult{},
				Coverage: Coverage{Level: "incomplete", CaptureMode: "tetragon", TelemetryLevel: "unavailable",
					Egress: "network_none", InstallMode: "controlled", Phases: map[string]PhaseResult{}},
				EvidenceIntegrity: map[string]interface{}{"status": "ok", "missing_raw_event_ids": []string{}}}
		}
	}
	pf, err := preflight(ctx, image, capture == "ptrace")
	if err != nil {
		return Result{Status: "error", Request: req, Error: err.Error(), Preflight: pf}
	}
	if pf.Status != "ok" {
		return Result{Status: "refused", Request: req, Preflight: pf, Phases: map[string]PhaseResult{},
			Coverage: Coverage{Level: "incomplete", CaptureMode: capture, TelemetryLevel: "unavailable",
				Egress: "network_none", InstallMode: "controlled", Phases: map[string]PhaseResult{}},
			EvidenceIntegrity: map[string]interface{}{"status": "ok", "missing_raw_event_ids": []string{}}}
	}
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 180
	}
	network, sinkIP, err := createAssessNetwork(ctx)
	if err != nil {
		return Result{Status: "refused", Request: req, Phases: map[string]PhaseResult{},
			Preflight: &Preflight{Status: "refused", FailedControl: "sinkhole_network", Reason: err.Error(), ProfileSource: "assess-sinkhole-v1"},
			Coverage: Coverage{Level: "incomplete", CaptureMode: capture, TelemetryLevel: "unavailable",
				Egress: "recording_sinkhole", DNSMode: "fake_nonforwarding", SinkholeMode: "tcp_accept_common_ports", SinkholePorts: []int{80, 443, 8080, 8443}, InstallMode: "controlled", Phases: map[string]PhaseResult{}},
			EvidenceIntegrity: map[string]interface{}{"status": "ok", "missing_raw_event_ids": []string{}}}
	}
	sinkDir, err := os.MkdirTemp("", "claimtrace-sinkhole-")
	if err != nil {
		stopSinkhole(ctx, "", network)
		return Result{Status: "error", Request: req, Error: err.Error(), Preflight: pf}
	}
	defer os.RemoveAll(sinkDir)
	sinkName, sinkLog, err := startSinkhole(ctx, image, network, sinkIP, sinkDir)
	if err != nil {
		stopSinkhole(ctx, "", network)
		return Result{Status: "refused", Request: req, Phases: map[string]PhaseResult{},
			Preflight: &Preflight{Status: "refused", FailedControl: "sinkhole_setup", Reason: err.Error(), ProfileSource: "assess-sinkhole-v1"},
			Coverage: Coverage{Level: "incomplete", CaptureMode: capture, TelemetryLevel: "unavailable",
				Egress: "recording_sinkhole", DNSMode: "fake_nonforwarding", SinkholeMode: "tcp_accept_common_ports", SinkholePorts: []int{80, 443, 8080, 8443}, InstallMode: "controlled", Phases: map[string]PhaseResult{}},
			EvidenceIntegrity: map[string]interface{}{"status": "ok", "missing_raw_event_ids": []string{}}}
	}
	defer stopSinkhole(ctx, sinkName, network)
	container, decoyHash, sandboxBase, err := startContainer(ctx, image, req.ArchivePath, req.Name, timeout, network, sinkIP)
	if err != nil {
		return Result{Status: "error", Request: req, Error: err.Error(), Preflight: pf}
	}
	defer os.RemoveAll(sandboxBase)
	defer stopContainer(ctx, container)
	phases := map[string]PhaseResult{}
	var raw []RawEvent
	captureFailures := []string{}
	for _, phase := range []string{"install", "entry", "import"} {
		if phase == "import" && req.Ecosystem != "npm" {
			phases[phase] = PhaseResult{Status: "not_requested"}
			continue
		}
		phaseCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		offset := int64(0)
		if capture == "tetragon" {
			offset = tetragonOffset()
		}
		sinkOffset := int64(0)
		if sinkLog != "" {
			sinkOffset = sinkholeOffset(sinkLog)
		}
		res, logPath := execPhase(phaseCtx, container, phase, filepath.Base(req.ArchivePath), req.Name, timeout, capture == "ptrace")
		cancel()
		phases[phase] = res
		if sinkLog != "" {
			raw = append(raw, collectSinkholeFromOffset(sinkLog, sinkOffset, phase)...)
		}
		if capture == "tetragon" {
			var phaseEvents []RawEvent
			for attempt := 0; attempt < 4; attempt++ {
				time.Sleep(300 * time.Millisecond)
				phaseEvents = collectTetragonFromOffset(tetragonLogPath(), offset, container, phase)
				if len(phaseEvents) > 0 {
					break
				}
			}
			if len(phaseEvents) == 0 {
				captureFailures = append(captureFailures, phase+"_no_tetragon_events")
			}
			raw = append(raw, phaseEvents...)
			continue
		}
		hostLog := filepath.Join(os.TempDir(), fmt.Sprintf("assess-%s-%s.log", container[:8], phase))
		// Rootless Docker's `docker cp` does not see files in a tmpfs mount in
		// this environment; `docker exec cat` reads the same path reliably.
		logData, logErr := dockerOutput(ctx, "exec", container, "cat", logPath)
		if logErr != nil || strings.TrimSpace(logData) == "" {
			captureFailures = append(captureFailures, phase)
		}
		_ = os.WriteFile(hostLog, []byte(logData), 0o600)
		raw = append(raw, parseTrace(phase, hostLog)...)
		_ = os.Remove(hostLog)
	}
	// Stable raw IDs across phases and unique within the assessment.
	enrichSinkholeHostnames(raw, sinkIP)
	for i := range raw {
		raw[i].RawEventID = fmt.Sprintf("raw-%s-%03d", raw[i].Phase, i)
	}
	missingFault, independentFault := applyFault(raw, req)
	health := captureHealth(raw)
	level := "unverified"
	if anyFailed(phases) {
		level = "incomplete"
	}
	if ok, _ := health["loss_detected"].(bool); ok {
		level = "incomplete"
	}
	evidence := map[string]interface{}{"status": "ok", "missing_raw_event_ids": []string{}}
	if len(captureFailures) > 0 {
		level = "incomplete"
		evidence["status"] = "failed"
		evidence["capture_failures"] = captureFailures
	}
	if len(missingFault) > 0 {
		level = "incomplete"
		evidence["status"] = "failed"
		evidence["missing_raw_event_ids"] = missingFault
		evidence["independent_evidence_ids"] = independentFault
	}
	if decoyHash == "" && pf.EffectiveProfile != nil {
		decoyHash = jsonHash(pf.EffectiveProfile)
	}
	return Result{
		Status: "completed", Request: req, Phases: phases, RawEvents: raw,
		Findings: []interface{}{},
		Coverage: Coverage{
			Level: level, CaptureMode: capture, TelemetryLevel: "unverified",
			Egress: "recording_sinkhole", DNSMode: "fake_nonforwarding", SinkholeMode: "tcp_accept_common_ports", SinkholePorts: []int{80, 443, 8080, 8443}, CaptureHealth: health, SettleWindowSec: 10, InstallMode: "controlled",
			CaptureProfileHash: pf.EffectiveProfileHash, DecoySetHash: decoyHash,
			CapturedPaths: []string{"process.exec", "file.open", "dns.query", "network.connect", "network.sinkhole_accept", "process.ptrace", "process.fileless_exec"}, Phases: phases,
		},
		EvidenceIntegrity: evidence,
		Preflight:         pf,
	}
}

func anyFailed(phases map[string]PhaseResult) bool {
	for _, p := range phases {
		if p.Status == "failed" || p.Status == "timed_out" || p.Status == "requested_not_started" {
			return true
		}
	}
	return false
}

// sortStrings is kept local so the package has no mutable global ordering.
func sortStrings(in []string) []string { sort.Strings(in); return in }

var _ = strconv.Itoa
