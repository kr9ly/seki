package main

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakeHerdr listens on a unix socket and forwards each received request
// line to the returned channel, replying with a minimal response.
func fakeHerdr(t *testing.T) (string, <-chan map[string]any) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "herdr.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	reqs := make(chan map[string]any, 10)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				var req map[string]any
				if err := json.Unmarshal([]byte(line), &req); err != nil {
					return
				}
				resp, _ := json.Marshal(map[string]any{"id": req["id"], "ok": true})
				c.Write(append(resp, '\n'))
				reqs <- req
			}(conn)
		}
	}()
	return sockPath, reqs
}

func recvReq(t *testing.T, reqs <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case req := <-reqs:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for herdr request")
		return nil
	}
}

func TestHerdrReporter(t *testing.T) {
	sockPath, reqs := fakeHerdr(t)
	h := &herdrReporter{paneID: "w1:p1", sockPath: sockPath}

	h.report("blocked", "api.github.com")
	req := recvReq(t, reqs)
	if req["method"] != "pane.report_agent" {
		t.Errorf("method = %v, want pane.report_agent", req["method"])
	}
	params, _ := req["params"].(map[string]any)
	if params == nil {
		t.Fatalf("params missing: %v", req)
	}
	if params["pane_id"] != "w1:p1" || params["source"] != "custom:seki" || params["agent"] != "seki" {
		t.Errorf("unexpected identity params: %v", params)
	}
	if params["state"] != "blocked" || params["message"] != "api.github.com" {
		t.Errorf("unexpected state params: %v", params)
	}

	// Duplicate state+message is suppressed; the next distinct report
	// must arrive with a higher seq.
	h.report("blocked", "api.github.com")
	h.report("idle", "")
	req2 := recvReq(t, reqs)
	params2, _ := req2["params"].(map[string]any)
	if params2["state"] != "idle" {
		t.Errorf("state = %v, want idle (duplicate should be suppressed)", params2["state"])
	}
	if s1, s2 := params["seq"].(float64), params2["seq"].(float64); s2 <= s1 {
		t.Errorf("seq %v → %v, want strictly increasing", s1, s2)
	}

	select {
	case extra := <-reqs:
		t.Errorf("unexpected extra request: %v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHerdrReporterNil(t *testing.T) {
	t.Setenv("HERDR_PANE_ID", "")
	t.Setenv("HERDR_SOCKET_PATH", "")
	h := newHerdrReporter()
	if h != nil {
		t.Fatal("reporter should be nil outside herdr")
	}
	h.report("idle", "") // must not panic on nil receiver
}
