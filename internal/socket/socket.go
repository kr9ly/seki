package socket

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is a real-time notification from seki exec to seki watch.
type Event struct {
	Type    string `json:"type"`              // "dns", "tcp", "status"
	Time    string `json:"time,omitempty"`
	Domain  string `json:"domain,omitempty"`
	QType   string `json:"qtype,omitempty"`
	Dest    string `json:"dest,omitempty"`
	SNI     string `json:"sni,omitempty"`
	Action  string `json:"action,omitempty"`  // "allow", "deny"
	Tag     string `json:"tag,omitempty"`
	Learned bool   `json:"learned,omitempty"` // would deny in learning mode
	// Status event fields
	Session      string `json:"session,omitempty"`
	LearningMode bool   `json:"learning_mode,omitempty"`
}

// Server streams events to connected watch clients via a Unix socket.
type Server struct {
	path    string
	ln      net.Listener
	clients []net.Conn
	mu      sync.Mutex
}

// NewServer creates a socket server at ~/.config/seki/seki.sock.
func NewServer() (*Server, error) {
	path, err := sockPath()
	if err != nil {
		return nil, err
	}
	// Remove stale socket from previous run
	os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	os.Chmod(path, 0660)

	s := &Server{path: path, ln: ln}
	go s.accept()
	return s, nil
}

// Emit broadcasts an event to all connected watch clients.
func (s *Server) Emit(e Event) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	alive := s.clients[:0]
	for _, c := range s.clients {
		if _, err := c.Write(data); err != nil {
			c.Close()
			continue
		}
		alive = append(alive, c)
	}
	s.clients = alive
}

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	for _, c := range s.clients {
		c.Close()
	}
	s.clients = nil
	s.mu.Unlock()

	err := s.ln.Close()
	os.Remove(s.path)
	return err
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.clients = append(s.clients, conn)
		s.mu.Unlock()
	}
}

// Client connects to the seki exec socket and receives events.
type Client struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

// Connect connects to the seki exec socket.
// If wait is true, retries until the socket becomes available.
func Connect(wait bool) (*Client, error) {
	path, err := sockPath()
	if err != nil {
		return nil, err
	}

	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return &Client{conn: conn, scanner: bufio.NewScanner(conn)}, nil
		}
		if !wait {
			return nil, fmt.Errorf("connect %s: %w (is seki exec running?)", path, err)
		}
		fmt.Fprintf(os.Stderr, "waiting for seki exec...\n")
		time.Sleep(1 * time.Second)
	}
}

// Next reads the next event. Returns false when the connection is closed.
func (c *Client) Next() bool {
	return c.scanner.Scan()
}

// Event parses the current event.
func (c *Client) Event() (Event, error) {
	var e Event
	if err := json.Unmarshal(c.scanner.Bytes(), &e); err != nil {
		return e, err
	}
	return e, nil
}

// Emit sends an event to the server (used by child process to emit events).
func (c *Client) Emit(e Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.conn.Write(data)
	return err
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func sockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "seki")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "seki.sock"), nil
}
