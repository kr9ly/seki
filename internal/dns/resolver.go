package dns

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
)

// QueryEntry represents a logged DNS query.
type QueryEntry struct {
	Time   time.Time
	Domain string
	QType  string
}

// OnQueryFunc is called for each DNS query received by the resolver.
// Returns true to allow the query, false to return NXDOMAIN.
type OnQueryFunc func(QueryEntry) bool

// Resolver is a forwarding DNS server that logs all queries.
type Resolver struct {
	listenAddr string
	upstream   string
	onQuery    OnQueryFunc
	udp        *mdns.Server
	tcp        *mdns.Server
	ipCache    sync.Map // IP string -> domain string
}

// LookupIP returns the domain associated with an IP from DNS resolution cache.
func (r *Resolver) LookupIP(ip string) string {
	if v, ok := r.ipCache.Load(ip); ok {
		return v.(string)
	}
	return ""
}

// NewResolver creates a DNS resolver that listens on listenAddr,
// forwards queries to upstream, and calls onQuery for each query.
func NewResolver(listenAddr, upstream string, onQuery OnQueryFunc) *Resolver {
	return &Resolver{
		listenAddr: listenAddr,
		upstream:   upstream,
		onQuery:    onQuery,
	}
}

// Start begins listening for DNS queries on UDP and TCP.
// Blocks until both servers are ready to accept queries.
func (r *Resolver) Start() error {
	handler := mdns.HandlerFunc(r.handle)

	var wg sync.WaitGroup
	wg.Add(2)

	r.udp = &mdns.Server{
		Addr:              r.listenAddr,
		Net:               "udp",
		Handler:           handler,
		NotifyStartedFunc: wg.Done,
	}
	r.tcp = &mdns.Server{
		Addr:              r.listenAddr,
		Net:               "tcp",
		Handler:           handler,
		NotifyStartedFunc: wg.Done,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- r.udp.ListenAndServe() }()
	go func() { errCh <- r.tcp.ListenAndServe() }()

	// Wait for both servers to be ready, or fail fast on error
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server: %w", err)
	case <-done:
		return nil
	}
}

// Close shuts down the DNS servers.
func (r *Resolver) Close() error {
	var errs []error
	if r.udp != nil {
		if err := r.udp.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.tcp != nil {
		if err := r.tcp.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("dns shutdown: %v", errs)
	}
	return nil
}

func (r *Resolver) handle(w mdns.ResponseWriter, req *mdns.Msg) {
	// Evaluate each question — deny if any question is denied
	denied := false
	for _, q := range req.Question {
		if r.onQuery != nil {
			if !r.onQuery(QueryEntry{
				Time:   time.Now(),
				Domain: strings.TrimSuffix(q.Name, "."),
				QType:  mdns.TypeToString[q.Qtype],
			}) {
				denied = true
			}
		}
	}

	// Return NXDOMAIN for denied queries
	if denied {
		msg := new(mdns.Msg)
		msg.SetRcode(req, mdns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	// Forward to upstream
	proto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		proto = "tcp"
	}

	client := &mdns.Client{
		Net:     proto,
		Timeout: 5 * time.Second,
		Dialer: &net.Dialer{
			Control: setSOMarkControl,
		},
	}
	resp, _, err := client.Exchange(req, r.upstream)
	if err != nil {
		msg := new(mdns.Msg)
		msg.SetRcode(req, mdns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}

	// Cache IP→domain mapping from A/AAAA records
	for _, q := range req.Question {
		domain := strings.TrimSuffix(q.Name, ".")
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *mdns.A:
				r.ipCache.Store(v.A.String(), domain)
			case *mdns.AAAA:
				r.ipCache.Store(v.AAAA.String(), domain)
			}
		}
	}

	w.WriteMsg(resp)
}

// DetectUpstream reads the host's /etc/resolv.conf to find the upstream DNS server.
// Must be called before the child namespace overrides resolv.conf.
func DetectUpstream() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "nameserver ") {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
			return net.JoinHostPort(addr, "53"), nil
		}
	}
	return "", fmt.Errorf("no nameserver found in /etc/resolv.conf")
}

// setSOMarkControl sets SO_MARK=1 on a socket to bypass iptables REDIRECT rules.
func setSOMarkControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 1) // SO_MARK = 0x24 (36)
	})
}
