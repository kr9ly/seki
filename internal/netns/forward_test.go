//go:build linux

package netns

import (
	"net"
	"path/filepath"
	"testing"
)

// fakeSlirpAPI serves the slirp4netns API protocol on a unix socket,
// returning incrementing forward ids and recording each add_hostfwd call.
func fakeSlirpAPI(t *testing.T) (path string, calls *int) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "slirp.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	calls = new(int)
	go func() {
		id := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			if _, err := conn.Read(buf); err == nil {
				*calls++
				id++
				conn.Write([]byte(`{"return":{"id":` + string(rune('0'+id)) + `}}`))
			}
			conn.Close()
		}
	}()
	return path, calls
}

func TestForwardTableIdempotent(t *testing.T) {
	apiSock, calls := fakeSlirpAPI(t)
	tbl := &forwardTable{fwds: make(map[int]fwdEntry)}

	first, created, err := tbl.resolve(apiSock, 4966)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if !created {
		t.Error("first resolve: created = false, want true")
	}
	if first.hostPort == 0 {
		t.Error("first resolve: hostPort = 0")
	}

	second, created, err := tbl.resolve(apiSock, 4966)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if created {
		t.Error("second resolve: created = true, want false")
	}
	if second != first {
		t.Errorf("second resolve: got %+v, want same mapping %+v", second, first)
	}
	if *calls != 1 {
		t.Errorf("slirp add_hostfwd calls = %d, want 1", *calls)
	}
}

func TestForwardTableDistinctPorts(t *testing.T) {
	apiSock, _ := fakeSlirpAPI(t)
	tbl := &forwardTable{fwds: make(map[int]fwdEntry)}

	a, _, err := tbl.resolve(apiSock, 3000)
	if err != nil {
		t.Fatalf("resolve 3000: %v", err)
	}
	b, created, err := tbl.resolve(apiSock, 4000)
	if err != nil {
		t.Fatalf("resolve 4000: %v", err)
	}
	if !created {
		t.Error("resolve 4000: created = false, want true")
	}
	if a.id == b.id {
		t.Errorf("distinct guest ports share forward id %d", a.id)
	}
}
