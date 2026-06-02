package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Default  string           `json:"default"`
	Projects []ProjectMapping `json:"projects"`
}

type ProjectMapping struct {
	Match   string `json:"match"`
	Profile string `json:"profile"`
}

type GlobalConfig struct {
	ClaudeProfiles *Config           `json:"claude_profiles"`
	SandboxEnv     map[string]string `json:"sandbox_env"`
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

// CredentialsPath returns ~/.claude-profiles/<profile>/.credentials.json.
func CredentialsPath(profile string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude-profiles", profile, ".credentials.json"), nil
}
