package rules

import (
	"testing"
)

func TestMatchRule(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		domain  string
		ip      string
		want    bool
	}{
		// catch-all
		{"catch-all matches domain", "*", "example.com", "", true},
		{"catch-all matches ip", "*", "", "1.2.3.4", true},
		{"catch-all matches both", "*", "example.com", "1.2.3.4", true},
		{"catch-all matches empty", "*", "", "", true},

		// exact domain
		{"exact domain match", "example.com", "example.com", "", true},
		{"exact domain case insensitive", "Example.COM", "example.com", "", true},
		{"exact domain no match", "example.com", "other.com", "", false},
		{"exact domain ignores ip", "example.com", "", "1.2.3.4", false},

		// wildcard domain
		{"wildcard subdomain", "*.example.com", "sub.example.com", "", true},
		{"wildcard apex", "*.example.com", "example.com", "", true},
		{"wildcard deep sub", "*.example.com", "a.b.example.com", "", true},
		{"wildcard no match", "*.example.com", "other.com", "", false},

		// CIDR
		{"cidr /8 match", "10.0.0.0/8", "", "10.1.2.3", true},
		{"cidr /8 no match", "10.0.0.0/8", "", "11.0.0.1", false},
		{"cidr /32 match", "203.0.113.5/32", "", "203.0.113.5", true},
		{"cidr /32 no match", "203.0.113.5/32", "", "203.0.113.6", false},
		{"cidr ipv6", "::1/128", "", "::1", true},
		{"cidr ignores domain", "10.0.0.0/8", "example.com", "", false},

		// bare IP
		{"bare ip match", "203.0.113.5", "", "203.0.113.5", true},
		{"bare ip no match", "203.0.113.5", "", "203.0.113.6", false},
		{"bare ip ignores domain", "203.0.113.5", "example.com", "", false},
		{"bare ipv6 match", "::1", "", "::1", true},
		{"bare ipv6 no match", "::1", "", "::2", false},
		{"bare ip with domain and ip", "203.0.113.5", "example.com", "203.0.113.5", true},

		// empty inputs
		{"domain pattern no inputs", "example.com", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRule(tt.pattern, tt.domain, tt.ip)
			if got != tt.want {
				t.Errorf("matchRule(%q, %q, %q) = %v, want %v",
					tt.pattern, tt.domain, tt.ip, got, tt.want)
			}
		})
	}
}

func TestRuleSpecificity(t *testing.T) {
	tests := []struct {
		match string
		want  int
	}{
		{"*", 0},
		{"10.0.0.0/8", 18},    // 10 + 8
		{"192.168.1.0/24", 34}, // 10 + 24
		{"203.0.113.5/32", 42}, // 10 + 32
		{"*.example.com", 200},
		{"example.com", 300},
		{"203.0.113.5", 310},
	}

	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			got := ruleSpecificity(Rule{Match: tt.match})
			if got != tt.want {
				t.Errorf("ruleSpecificity(%q) = %d, want %d", tt.match, got, tt.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: "203.0.113.5", Action: Allow, Tag: "api-server"},
			{Match: "*.github.com", Action: Allow, Tag: "github"},
			{Match: "10.0.0.0/8", Action: Allow, Tag: "private"},
			{Match: "*", Action: Deny},
		},
	}

	tests := []struct {
		name   string
		domain string
		ip     string
		action string
		tag    string
	}{
		{"bare ip allow", "", "203.0.113.5", Allow, "api-server"},
		{"bare ip deny other", "", "203.0.113.6", Deny, ""},
		{"wildcard domain", "api.github.com", "", Allow, "github"},
		{"cidr private", "", "10.1.2.3", Allow, "private"},
		{"unknown domain", "evil.com", "", Deny, ""},
		{"unknown ip", "", "8.8.8.8", Deny, ""},
		// domain resolved via DNS + IP from connection
		{"domain with ip both match", "api.github.com", "10.0.0.1", Allow, "github"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := rs.Evaluate(tt.domain, tt.ip)
			if res.Action != tt.action {
				t.Errorf("Evaluate(%q, %q).Action = %q, want %q",
					tt.domain, tt.ip, res.Action, tt.action)
			}
			tag := ""
			if res.Rule != nil {
				tag = res.Rule.Tag
			}
			if tag != tt.tag {
				t.Errorf("Evaluate(%q, %q).Tag = %q, want %q",
					tt.domain, tt.ip, tag, tt.tag)
			}
		})
	}
}

func TestEvaluateLearningMode(t *testing.T) {
	rs := &RuleSet{
		LearningMode: true,
		Rules: []Rule{
			{Match: "10.0.0.0/8", Action: Allow, Tag: "private"},
			{Match: "*", Action: Deny},
		},
	}

	res := rs.Evaluate("", "10.0.0.1")
	if res.Action != Allow || res.Learned {
		t.Errorf("allowed rule: got action=%q learned=%v, want allow/false", res.Action, res.Learned)
	}

	res = rs.Evaluate("evil.com", "")
	if res.Action != Allow || !res.Learned {
		t.Errorf("denied rule in learning: got action=%q learned=%v, want allow/true", res.Action, res.Learned)
	}

	res = rs.Evaluate("", "8.8.8.8")
	if res.Action != Allow || !res.Learned {
		t.Errorf("denied ip in learning: got action=%q learned=%v, want allow/true", res.Action, res.Learned)
	}
}

func TestEvaluateCommand(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: `\bgit\s+push\b`, Action: Prompt, Tag: "git-push", Kind: KindCommand},
			{Match: "*.github.com", Action: Allow, Tag: "github"},
		},
	}

	res := rs.EvaluateCommand("git push origin main")
	if res.Action != Prompt {
		t.Errorf("git push: got %q, want prompt", res.Action)
	}

	res = rs.EvaluateCommand("git status")
	if res.Action != Allow {
		t.Errorf("git status: got %q, want allow (default)", res.Action)
	}
}

func TestAddRule(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: "*", Action: Deny},
		},
	}

	rs.AddRule("203.0.113.5", Allow, "api", KindNetwork)

	// bare IP should be sorted before catch-all
	if rs.Rules[0].Match != "203.0.113.5" {
		t.Errorf("first rule after add: got %q, want 203.0.113.5", rs.Rules[0].Match)
	}

	// update existing
	rs.AddRule("203.0.113.5", Deny, "blocked", KindNetwork)
	if rs.Rules[0].Action != Deny || rs.Rules[0].Tag != "blocked" {
		t.Errorf("updated rule: got action=%q tag=%q, want deny/blocked",
			rs.Rules[0].Action, rs.Rules[0].Tag)
	}
}

func TestNormalizeSortOrder(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: "*", Action: Deny},
			{Match: "*.example.com", Action: Allow},
			{Match: "10.0.0.0/8", Action: Allow},
			{Match: "203.0.113.5", Action: Allow},
			{Match: "example.com", Action: Deny, Tag: "block"},
		},
	}
	rs.normalize()

	// example.com has different action from *.example.com, so not merged
	want := []string{"203.0.113.5", "example.com", "*.example.com", "10.0.0.0/8", "*"}
	if len(rs.Rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %v", len(rs.Rules), len(want), rs.Rules)
	}
	for i, w := range want {
		if rs.Rules[i].Match != w {
			t.Errorf("rules[%d] = %q, want %q", i, rs.Rules[i].Match, w)
		}
	}
}

func TestBareIPPriorityCIDR(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: "203.0.113.0/24", Action: Deny, Tag: "block-range"},
			{Match: "203.0.113.5", Action: Allow, Tag: "exception"},
			{Match: "*", Action: Deny},
		},
	}
	rs.normalize()

	res := rs.Evaluate("", "203.0.113.5")
	if res.Action != Allow || res.Rule.Tag != "exception" {
		t.Errorf("bare IP should override CIDR: got action=%q tag=%q", res.Action, res.Rule.Tag)
	}

	res = rs.Evaluate("", "203.0.113.6")
	if res.Action != Deny || res.Rule.Tag != "block-range" {
		t.Errorf("other IP in range: got action=%q tag=%q", res.Action, res.Rule.Tag)
	}
}
