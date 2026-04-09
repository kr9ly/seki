package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Action constants.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Rule defines a single matching rule.
type Rule struct {
	Match  string `json:"match"`
	Action string `json:"action"`
	Tag    string `json:"tag,omitempty"`
}

// RuleSet is the complete rule configuration.
type RuleSet struct {
	Rules        []Rule `json:"rules"`
	LearningMode bool   `json:"learning_mode"`
}

// Result is the outcome of evaluating a domain/IP against the rule set.
type Result struct {
	Action  string
	Rule    *Rule
	Learned bool // true if denied but learning_mode is on (not actually blocked)
}

// Load reads rules from ~/.config/seki/rules.json.
// Returns a default ruleset if the file doesn't exist.
func Load() (*RuleSet, error) {
	path, err := rulesPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultRuleSet(), nil
		}
		return nil, fmt.Errorf("read rules: %w", err)
	}

	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	return &rs, nil
}

// Save writes the rule set to disk.
func (rs *RuleSet) Save() error {
	path, err := rulesPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Evaluate checks a domain and/or IP against the rules.
// First matching rule wins.
func (rs *RuleSet) Evaluate(domain, ip string) Result {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if matchRule(r.Match, domain, ip) {
			res := Result{Action: r.Action, Rule: r}
			if r.Action == Deny && rs.LearningMode {
				res.Learned = true
				res.Action = Allow // don't actually block in learning mode
			}
			return res
		}
	}
	// Default deny
	res := Result{Action: Deny}
	if rs.LearningMode {
		res.Learned = true
		res.Action = Allow
	}
	return res
}

// AddRule appends a rule. If a rule with the same match already exists, it's updated.
func (rs *RuleSet) AddRule(match, action, tag string) {
	for i, r := range rs.Rules {
		if r.Match == match {
			rs.Rules[i].Action = action
			rs.Rules[i].Tag = tag
			return
		}
	}
	// Insert before the default deny rule (last rule)
	newRule := Rule{Match: match, Action: action, Tag: tag}
	if len(rs.Rules) > 0 && rs.Rules[len(rs.Rules)-1].Match == "*" {
		rs.Rules = append(rs.Rules[:len(rs.Rules)-1], newRule, rs.Rules[len(rs.Rules)-1])
	} else {
		rs.Rules = append(rs.Rules, newRule)
	}
}

// RemoveRule removes a rule by match pattern.
func (rs *RuleSet) RemoveRule(match string) bool {
	for i, r := range rs.Rules {
		if r.Match == match {
			rs.Rules = append(rs.Rules[:i], rs.Rules[i+1:]...)
			return true
		}
	}
	return false
}

// DefaultRuleSet returns a minimal starting ruleset in learning mode.
func DefaultRuleSet() *RuleSet {
	return &RuleSet{
		LearningMode: true,
		Rules: []Rule{
			{Match: "127.0.0.0/8", Action: Allow, Tag: "loopback"},
			{Match: "::1/128", Action: Allow, Tag: "loopback"},
			{Match: "10.0.0.0/8", Action: Allow, Tag: "private"},
			{Match: "172.16.0.0/12", Action: Allow, Tag: "private"},
			{Match: "192.168.0.0/16", Action: Allow, Tag: "private"},
			{Match: "*", Action: Deny},
		},
	}
}

func matchRule(pattern, domain, ip string) bool {
	// Try CIDR match on IP
	if ip != "" && isCIDR(pattern) {
		_, cidr, err := net.ParseCIDR(pattern)
		if err == nil && cidr.Contains(net.ParseIP(ip)) {
			return true
		}
	}

	// Try domain glob match
	if domain != "" {
		return matchGlob(pattern, domain)
	}

	return false
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// matchGlob matches a domain against a glob pattern.
// Supports: "*" (match all), "*.example.com" (subdomains), "example.com" (exact).
func matchGlob(pattern, domain string) bool {
	if pattern == "*" {
		return true
	}

	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	return domain == pattern
}

func rulesPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "seki")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	return filepath.Join(dir, "rules.json"), nil
}
