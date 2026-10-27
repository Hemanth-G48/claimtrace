package assess

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureHealthNoLoss(t *testing.T) {
	raw := []RawEvent{
		{Category: "network", Operation: "connect"},
		{Category: "network", Operation: "sinkhole_accept"},
		{Category: "dns", Operation: "query"},
	}
	h := captureHealth(raw)
	if h["loss_detected"] != false || h["status"] != "no_observed_loss" {
		t.Fatalf("unexpected health: %#v", h)
	}
}

func TestCaptureHealthDetectsNetworkLoss(t *testing.T) {
	raw := []RawEvent{
		{Category: "network", Operation: "sinkhole_accept"},
		{Category: "network", Operation: "sinkhole_accept"},
	}
	h := captureHealth(raw)
	if h["loss_detected"] != true || h["status"] != "loss_detected" {
		t.Fatalf("unexpected health: %#v", h)
	}
}

func TestCollectSinkholeFromOffset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sinkhole.jsonl")
	if err := os.WriteFile(p, []byte(`{"ts":"t1","kind":"dns","name":"evil.example","client":"10.88.0.3"}`+"\n"+`{"ts":"t2","kind":"tcp","port":443,"client":"10.88.0.3","remote_port":50123}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := collectSinkholeFromOffset(p, 0, "entry")
	if len(events) != 2 {
		t.Fatalf("got %d events", len(events))
	}
	if events[0].Category != "dns" || events[0].Detail["hostname"] != "evil.example" {
		t.Fatalf("bad dns event: %#v", events[0])
	}
	if events[1].Operation != "sinkhole_accept" || events[1].Detail["port"] != 443 {
		t.Fatalf("bad tcp event: %#v", events[1])
	}
}

func TestEnrichSinkholeHostnames(t *testing.T) {
	raw := []RawEvent{
		{Phase: "entry", Category: "dns", Operation: "query", Detail: map[string]interface{}{"hostname": "evil.example"}},
		{Phase: "entry", Category: "network", Operation: "connect", Detail: map[string]interface{}{"addr": "10.88.0.2"}},
		{Phase: "install", Category: "network", Operation: "connect", Detail: map[string]interface{}{"addr": "10.88.0.2"}},
	}
	enrichSinkholeHostnames(raw, "10.88.0.2")
	if raw[1].Detail["hostname"] != "evil.example" {
		t.Fatalf("entry hostname not attributed: %#v", raw[1])
	}
	if _, ok := raw[2].Detail["hostname"]; ok {
		t.Fatalf("install event must not borrow entry DNS: %#v", raw[2])
	}
}
