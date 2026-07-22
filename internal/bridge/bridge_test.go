package bridge

import (
	"bytes"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// echoServer accepts one connection, echoes everything back, then
// half-closes its write side after the client's FIN arrives.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

func TestForwardRoundTrip(t *testing.T) {
	backend := echoServer(t)
	defer backend.Close()

	b, err := Start("test", "127.0.0.1:0", backend.Addr().String())
	if err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	defer b.Close()

	c, err := net.Dial("tcp", b.Addr().String())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer c.Close()

	msg := []byte("000chost:version")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close the client side; the echo server should still deliver the
	// response and its FIN through the bridge.
	c.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round trip mismatch: got %q want %q", got, msg)
	}
}

func TestAddrInUseIsDetectable(t *testing.T) {
	backend := echoServer(t)
	defer backend.Close()

	b, err := Start("first", "127.0.0.1:0", backend.Addr().String())
	if err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	defer b.Close()

	_, err = Start("second", b.Addr().String(), backend.Addr().String())
	if err == nil {
		t.Fatal("expected address-in-use error")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("expected EADDRINUSE, got %v", err)
	}
}

func TestCloseStopsAccepting(t *testing.T) {
	backend := echoServer(t)
	defer backend.Close()

	b, err := Start("test", "127.0.0.1:0", backend.Addr().String())
	if err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	addr := b.Addr().String()
	b.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err != nil {
			return // listener gone — expected
		}
	}
	t.Fatal("bridge still accepting after Close")
}
