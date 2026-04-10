package credential

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Request is the message sent from seki credential to the server.
type Request struct {
	Action   string `json:"action"`   // "get"
	Protocol string `json:"protocol"` // "https"
	Host     string `json:"host"`     // "github.com"
}

// Response is the message returned from the server to seki credential.
type Response struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Server listens on a Unix socket and handles credential requests.
type Server struct {
	path    string
	ln      net.Listener
	config  *Config
	hostEnv map[string]string
}

// NewServer creates and starts a credential socket server.
// The socket path is derived from SEKI_CRED_SOCK env var (via SockPath).
func NewServer(config *Config, hostEnv map[string]string) (*Server, error) {
	path, err := SockPath()
	if err != nil {
		return nil, err
	}
	// Remove stale socket from a previous run
	os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}

	s := &Server{
		path:    path,
		ln:      ln,
		config:  config,
		hostEnv: hostEnv,
	}
	go s.accept()
	return s, nil
}

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	err := s.ln.Close()
	os.Remove(s.path)
	return err
}

// SockPath returns the absolute path for the credential socket.
// It is based on ~/.config/seki/<SEKI_CRED_SOCK>, defaulting to "seki-cred.sock".
func SockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "seki")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := os.Getenv("SEKI_CRED_SOCK")
	if name == "" {
		name = "seki-cred.sock"
	}
	return filepath.Join(dir, name), nil
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// handle processes a single connection: read one JSON request, send one JSON response, close.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		resp := Response{Error: "invalid request: " + err.Error()}
		writeResponse(conn, resp)
		return
	}

	var resp Response
	if req.Action == "get" {
		username, password, ok := s.config.ResolveGitCredential(req.Host, s.hostEnv)
		if ok {
			resp.Username = username
			resp.Password = password
		} else {
			resp.Error = "no credential for host: " + req.Host
		}
	} else {
		resp.Error = "unsupported action: " + req.Action
	}

	writeResponse(conn, resp)
}

func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	data = append(data, '\n')
	conn.Write(data)
}
