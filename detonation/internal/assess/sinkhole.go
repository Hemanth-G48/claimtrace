// SPDX-License-Identifier: AGPL-3.0-or-later
package assess

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sinkholeJS = `'use strict';
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const ip = process.argv[2] || '10.88.0.2';
const logPath = process.argv[3] || '/logs/sinkhole.jsonl';
function log(obj) { try { fs.appendFileSync(logPath, JSON.stringify(Object.assign({ts: new Date().toISOString()}, obj)) + '\n'); } catch (_) {} }
function qname(buf) {
  let i = 12, labels = [];
  while (i < buf.length) {
    const n = buf[i++];
    if (n === 0) break;
    if (n > 63 || i + n > buf.length) return '';
    labels.push(buf.slice(i, i + n).toString('ascii'));
    i += n;
  }
  return labels.join('.').toLowerCase();
}
const dns = dgram.createSocket('udp4');
let ready = 0;
function markReady() {
  ready += 1;
  if (ready === 5) {
    try { fs.writeFileSync('/logs/ready', '1'); } catch (_) {}
  }
}
dns.on('message', (msg, rinfo) => {
  if (msg.length < 12) return;
  const name = qname(msg);
  log({kind: 'dns', name: name, client: rinfo.address});
  const qtype = msg.readUInt16BE(msg.length - 4);
  const question = msg.slice(12);
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0); answer.writeUInt16BE(1, 2);
  answer.writeUInt16BE(1, 4); answer.writeUInt32BE(30, 6);
  answer.writeUInt16BE(4, 10);
  ip.split('.').forEach((b, i) => answer.writeUInt8(parseInt(b, 10), 12 + i));
  const h = Buffer.alloc(12);
  msg.copy(h, 0, 0, 2); h.writeUInt16BE(0x8180, 2);
  h.writeUInt16BE(1, 4); h.writeUInt16BE(qtype === 1 ? 1 : 0, 6);
  h.writeUInt16BE(0, 8); h.writeUInt16BE(0, 10);
  dns.send(Buffer.concat([h, question, answer]), rinfo.port, rinfo.address);
});
dns.bind(53, '0.0.0.0', markReady);
for (const port of [80, 443, 8080, 8443]) {
  net.createServer((sock) => {
    log({kind: 'tcp', port: port, client: sock.remoteAddress, remote_port: sock.remotePort});
    sock.end();
  }).listen(port, '0.0.0.0', markReady);
}
process.on('SIGTERM', () => process.exit(0));
`

type sinkEvent struct {
	TS         string `json:"ts"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Client     string `json:"client"`
	Port       int    `json:"port"`
	RemotePort int    `json:"remote_port"`
}

func createAssessNetwork(ctx context.Context) (string, string, error) {
	id := fmt.Sprintf("%x", timeNowNano())
	name := "assess-net-" + id
	// A per-assessment /24 avoids collisions between concurrent assessments.
	third := int(timeNowNano()%200) + 10
	subnet := fmt.Sprintf("10.88.%d.0/24", third)
	out, err := dockerOutput(ctx, "network", "create", "--internal", "--subnet", subnet, name)
	if err != nil {
		return "", "", fmt.Errorf("create assessment network: %s: %w", strings.TrimSpace(out), err)
	}
	return name, fmt.Sprintf("10.88.%d.2", third), nil
}

func startSinkhole(ctx context.Context, image, network, ip, logDir string) (string, string, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return "", "", err
	}
	script := filepath.Join(logDir, "sinkhole.js")
	if err := os.WriteFile(script, []byte(sinkholeJS), 0o644); err != nil {
		return "", "", err
	}
	name := "sinkhole-" + fmt.Sprintf("%x", timeNowNano())
	logPath := filepath.Join(logDir, "sinkhole.jsonl")
	_ = os.WriteFile(logPath, nil, 0o644)
	readyPath := filepath.Join(logDir, "ready")
	_ = os.Remove(readyPath)
	args := []string{
		"run", "-d", "--name", name,
		"--network", network, "--ip", ip,
		"--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE",
		"--security-opt=no-new-privileges", "--read-only",
		"--tmpfs", "/tmp:rw,size=8m",
		"-v", script + ":/sinkhole.js:ro",
		"-v", logDir + ":/logs:rw",
		image, "node", "/sinkhole.js", ip, "/logs/sinkhole.jsonl",
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return "", "", fmt.Errorf("start sinkhole: %s: %w", strings.TrimSpace(out), err)
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(readyPath); err == nil {
			return strings.TrimSpace(out), logPath, nil
		}
		select {
		case <-ctx.Done():
			_ = execDocker(ctx, "rm", "-f", name)
			return "", "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_ = execDocker(ctx, "rm", "-f", name)
	return "", "", fmt.Errorf("sinkhole did not become ready within 5s")
}

func stopSinkhole(ctx context.Context, name, network string) {
	if name != "" {
		_ = execDocker(ctx, "rm", "-f", name)
	}
	if network != "" {
		_ = execDocker(ctx, "network", "rm", network)
	}
}

func sinkholeOffset(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func collectSinkholeFromOffset(path string, offset int64, phase string) []RawEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	if offset > fi.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return nil
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var out []RawEvent
	for scanner.Scan() {
		var e sinkEvent
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		switch e.Kind {
		case "dns":
			out = append(out, RawEvent{
				Phase: phase, Category: "dns", Operation: "query", Timestamp: e.TS,
				Detail: map[string]interface{}{"hostname": e.Name, "client": e.Client},
			})
		case "tcp":
			out = append(out, RawEvent{
				Phase: phase, Category: "network", Operation: "sinkhole_accept", Timestamp: e.TS,
				Detail: map[string]interface{}{"client": e.Client, "port": e.Port, "remote_port": e.RemotePort},
			})
		}
	}
	return out
}
