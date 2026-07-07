package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Default  string           `json:"default"`
	Projects []ProjectMapping `json:"projects"`
}

type ProjectMapping struct {
	Match   string `json:"match"`
	Profile string `json:"profile"`
}

// Service describes a daemon to spawn inside the sandbox when services are
// declared. It is started before the user command and stopped after it exits.
type Service struct {
	// Name is used as a log file stem and for diagnostic messages.
	Name string `json:"name"`
	// Match is an optional glob pattern matched against the sandbox's cwd.
	// When set, this service is only started when the cwd matches the pattern.
	// The same matching semantics as ProjectMapping.Match apply (filepath.Match
	// with ~ expansion). When omitted, the service applies to all sessions.
	Match string `json:"match,omitempty"`
	// Command is the argv to exec. No shell expansion — array only.
	Command []string `json:"command"`
	// ReadySocket is an optional unix socket path. seki will wait until the
	// socket accepts connections before starting the user command.
	// Environment variables are expanded via os.ExpandEnv.
	ReadySocket string `json:"ready_socket,omitempty"`
	// ReadyTimeoutSec is the maximum number of seconds to wait for ReadySocket.
	// Defaults to 15 if zero. On timeout, a warning is printed and execution
	// continues rather than blocking the user command.
	ReadyTimeoutSec int `json:"ready_timeout_sec,omitempty"`
	// StopCommand is an optional argv executed (with a 10s timeout) before
	// sending SIGTERM to the service process. Useful for clean shutdown
	// (e.g. "podman stop --all").
	StopCommand []string `json:"stop_command,omitempty"`
	// Env holds additional environment variables merged on top of os.Environ().
	Env map[string]string `json:"env,omitempty"`
}

type GlobalConfig struct {
	ClaudeProfiles *Config           `json:"claude_profiles"`
	SandboxEnv     map[string]string `json:"sandbox_env"`
	Services       []Service         `json:"services,omitempty"`
}

// LoadGlobalConfig reads ~/.config/seki/config.json.
// Returns a zero-value GlobalConfig (not nil) if the file doesn't exist.
func LoadGlobalConfig() (*GlobalConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return &GlobalConfig{}, nil
	}
	path := filepath.Join(home, ".config", "seki", "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &GlobalConfig{}, nil
		}
		return nil, err
	}
	var gc GlobalConfig
	if err := json.Unmarshal(data, &gc); err != nil {
		return nil, err
	}
	return &gc, nil
}

// LoadConfig reads the claude_profiles section from ~/.config/seki/config.json.
// Returns nil without error if the file or section doesn't exist.
func LoadConfig() (*Config, error) {
	gc, err := LoadGlobalConfig()
	if err != nil {
		return nil, err
	}
	return gc.ClaudeProfiles, nil
}

// Resolve returns the profile name for the given working directory.
// Matches projects globs in order, falls back to default.
// Returns empty string if no profile applies.
func (c *Config) Resolve(cwd string) string {
	if c == nil {
		return ""
	}
	for _, p := range c.Projects {
		matched, err := filepath.Match(p.Match, cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: bad glob pattern %q: %v\n", p.Match, err)
			continue
		}
		if matched {
			return p.Profile
		}
	}
	return c.Default
}

// expandHome replaces a leading "~" with the user's home directory.
// Returns the original string unchanged if HOME is not set or the string
// does not start with "~". This matches the expansion semantics used in
// ProjectMapping.Match.
func expandHome(pattern string) string {
	if !strings.HasPrefix(pattern, "~") {
		return pattern
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return pattern
	}
	return home + pattern[1:]
}

// MatchServices filters services to those that apply for the given working
// directory. A service without a Match field applies to all cwds. A service
// with a Match field applies only when the cwd matches the glob pattern
// (after ~ expansion, using the same semantics as Config.Resolve /
// ProjectMapping.Match).
//
// When the returned slice is empty the caller should treat this the same as
// no services being declared at all (the supervisor still runs as pid 1,
// just with no services to spawn).
func MatchServices(cwd string, services []Service) []Service {
	var matched []Service
	for _, svc := range services {
		if svc.Match == "" {
			matched = append(matched, svc)
			continue
		}
		pattern := expandHome(svc.Match)
		ok, err := filepath.Match(pattern, cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: bad service match pattern %q: %v\n", svc.Match, err)
			continue
		}
		if ok {
			matched = append(matched, svc)
		}
	}
	return matched
}

// CredentialsPath returns ~/.claude-profiles/<profile>/.credentials.json.
func CredentialsPath(profile string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude-profiles", profile, ".credentials.json"), nil
}
