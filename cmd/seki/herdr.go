package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// herdrReporter pushes seki watch's approval-queue state to herdr's agents
// pane via the herdr socket API (pane.report_agent). It reports the pane
// watch itself runs in, so it never conflicts with herdr's own agent
// detection for Claude panes.
//
// Inactive (nil) unless HERDR_PANE_ID and HERDR_SOCKET_PATH are set, i.e.
// watch runs inside a herdr-managed pane. All methods are nil-safe.
type herdrReporter struct {
	paneID   string
	sockPath string

	mu        sync.Mutex
	seq       int64
	lastState string
	lastMsg   string
}

func newHerdrReporter() *herdrReporter {
	paneID := os.Getenv("HERDR_PANE_ID")
	sockPath := os.Getenv("HERDR_SOCKET_PATH")
	if paneID == "" || sockPath == "" {
		return nil
	}
	return &herdrReporter{paneID: paneID, sockPath: sockPath}
}

// report sends the given state to herdr if it differs from the last report.
// The send runs in a goroutine so callers holding the queue mutex never
// block on herdr I/O; herdr drops out-of-order updates via seq.
func (h *herdrReporter) report(state, message string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if state == h.lastState && message == h.lastMsg {
		h.mu.Unlock()
		return
	}
	h.lastState, h.lastMsg = state, message
	// herdr tracks seq per source and ignores reports at or below the last
	// accepted value — surviving watch restarts requires a clock, not a
	// process-local counter. Microseconds stay within float64-exact range
	// for JSON; the max() guards same-microsecond consecutive reports.
	seq := max(time.Now().UnixMicro(), h.seq+1)
	h.seq = seq
	h.mu.Unlock()

	req := map[string]any{
		"id":     fmt.Sprintf("seki_%d", seq),
		"method": "pane.report_agent",
		"params": map[string]any{
			"pane_id": h.paneID,
			"source":  "custom:seki",
			"agent":   "seki",
			"state":   state,
			"message": message,
			"seq":     seq,
		},
	}
	go h.send(req)
}

func (h *herdrReporter) send(req map[string]any) {
	const timeout = 2 * time.Second
	conn, err := net.DialTimeout("unix", h.sockPath, timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	b, err := json.Marshal(req)
	if err != nil {
		return
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return
	}
	// Drain the response line; herdr's protocol is request/response.
	bufio.NewReader(conn).ReadString('\n')
}
