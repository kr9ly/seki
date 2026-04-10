package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Action constants.
const (
	Allow  = "allow"
	Deny   = "deny"
	Prompt = "prompt"
)

// Kind constants.
const (
	KindNetwork = ""        // default: network rule (domain glob / CIDR)
	KindCommand = "command" // command rule (regex)
)

// Rule defines a single matching rule.
type Rule struct {
	Match  string `json:"match"`
	Action string `json:"action"`
	Tag    string `json:"tag,omitempty"`
	Kind   string `json:"kind,omitempty"` // "" = network, "command" = command
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

// Save normalizes (sort + merge) and writes the rule set to disk.
func (rs *RuleSet) Save() error {
	rs.normalize()
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

// normalize sorts network rules by specificity and merges redundant rules.
func (rs *RuleSet) normalize() {
	var network, command []Rule
	for _, r := range rs.Rules {
		if r.Kind == KindCommand {
			command = append(command, r)
		} else {
			network = append(network, r)
		}
	}

	sort.SliceStable(network, func(i, j int) bool {
		si, sj := ruleSpecificity(network[i]), ruleSpecificity(network[j])
		if si != sj {
			return si > sj
		}
		return network[i].Match < network[j].Match
	})

	network = mergeRedundant(network)
	rs.Rules = append(network, command...)
}

// ruleSpecificity returns a numeric score (higher = more specific).
func ruleSpecificity(r Rule) int {
	if r.Match == "*" {
		return 0
	}
	if isCIDR(r.Match) {
		_, cidr, _ := net.ParseCIDR(r.Match)
		ones, _ := cidr.Mask.Size()
		return 10 + ones
	}
	if strings.HasPrefix(r.Match, "*.") {
		return 200
	}
	return 300 // exact domain
}

// mergeRedundant removes exact domain rules covered by a wildcard with the same action and tag.
func mergeRedundant(rules []Rule) []Rule {
	var wildcards []Rule
	for _, r := range rules {
		if strings.HasPrefix(r.Match, "*.") {
			wildcards = append(wildcards, r)
		}
	}
	if len(wildcards) == 0 {
		return rules
	}

	var result []Rule
	for _, r := range rules {
		if r.Match != "*" && !isCIDR(r.Match) && !strings.HasPrefix(r.Match, "*.") {
			covered := false
			for _, w := range wildcards {
				if w.Action == r.Action && w.Tag == r.Tag && matchGlob(w.Match, r.Match) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
		}
		result = append(result, r)
	}
	return result
}

// Evaluate checks a domain and/or IP against network rules.
// First matching rule wins. Default: deny.
func (rs *RuleSet) Evaluate(domain, ip string) Result {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Kind == KindCommand {
			continue
		}
		if matchRule(r.Match, domain, ip) {
			res := Result{Action: r.Action, Rule: r}
			if (r.Action == Deny || r.Action == Prompt) && rs.LearningMode {
				res.Learned = true
				res.Action = Allow
			}
			return res
		}
	}
	// Default deny (whitelist)
	res := Result{Action: Deny}
	if rs.LearningMode {
		res.Learned = true
		res.Action = Allow
	}
	return res
}

// EvaluateCommand checks a command string against command rules.
// First matching rule wins. Default: allow (blacklist).
func (rs *RuleSet) EvaluateCommand(cmd string) Result {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Kind != KindCommand {
			continue
		}
		if matchCommand(r.Match, cmd) {
			return Result{Action: r.Action, Rule: r}
		}
	}
	// Default allow (blacklist)
	return Result{Action: Allow}
}

// AddRule appends or updates a rule. Ordering is handled by Save.
func (rs *RuleSet) AddRule(match, action, tag, kind string) {
	for i, r := range rs.Rules {
		if r.Match == match && r.Kind == kind {
			rs.Rules[i].Action = action
			rs.Rules[i].Tag = tag
			return
		}
	}
	rs.Rules = append(rs.Rules, Rule{Match: match, Action: action, Tag: tag, Kind: kind})
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

// matchCommand checks a command string against a regex pattern.
func matchCommand(pattern, cmd string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(cmd)
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
