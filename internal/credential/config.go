package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Config is the structure of ~/.config/seki/credentials.json.
type Config struct {
	Credentials     []Entry `json:"credentials"`
	SSHAgentForward bool    `json:"ssh_agent_forward"`
}

// Entry is a single credential entry.
type Entry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`              // "git-credential", "npmrc", "env"
	Host     string `json:"host,omitempty"`     // for git-credential
	Source   string `json:"source"`             // "env:VAR_NAME"
	Username string `json:"username,omitempty"` // defaults to "x-access-token"
}

// LoadConfig reads ~/.config/seki/credentials.json.
// If the file does not exist, an empty Config is returned without error.
func LoadConfig() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return &Config{}, nil
	}
	path := filepath.Join(home, ".config", "seki", "credentials.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ResolveGitCredential finds the first git-credential entry matching host and
// resolves the password from hostEnv. Returns ok=false if not found.
func (c *Config) ResolveGitCredential(host string, hostEnv map[string]string) (username, password string, ok bool) {
	for _, e := range c.Credentials {
		if e.Type != "git-credential" {
			continue
		}
		if e.Host != host {
			continue
		}
		pw := resolveSource(e.Source, hostEnv)
		if pw == "" {
			continue
		}
		uname := e.Username
		if uname == "" {
			uname = "x-access-token"
		}
		return uname, pw, true
	}
	return "", "", false
}

// SecretKeys returns the environment variable names referenced by "env:VAR" sources.
func (c *Config) SecretKeys() []string {
	var keys []string
	for _, e := range c.Credentials {
		if name, ok := envVarName(e.Source); ok {
			keys = append(keys, name)
		}
	}
	return keys
}

// resolveSource resolves an "env:VAR" source string to its value from env.
func resolveSource(source string, env map[string]string) string {
	if name, ok := envVarName(source); ok {
		return env[name]
	}
	return ""
}

// envVarName extracts the variable name from an "env:VAR" string.
func envVarName(source string) (string, bool) {
	if strings.HasPrefix(source, "env:") {
		return strings.TrimPrefix(source, "env:"), true
	}
	return "", false
}
