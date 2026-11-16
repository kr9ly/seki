package rules

import (
	"slices"
	"strings"
	"testing"
)

func TestCommandUnits(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string // units that must be present
		not  []string // units that must be absent
		ok   bool
	}{
		{"simple", "git push origin main", []string{"git push origin main"}, nil, true},
		{"and-list", "cd x && npm publish", []string{"cd x", "npm publish"}, nil, true},
		{"semicolon and pipe", "a; b | c", []string{"a", "b", "c"}, nil, true},
		{"assignment prefix", "FOO=1 terraform apply", []string{"terraform apply"}, nil, true},
		{"command substitution", "echo $(git push)", []string{"git push"}, nil, true},
		{"backquote substitution", "echo `nix build`", []string{"nix build"}, nil, true},
		{"subshell and function", "(nix build); f() { home-manager switch; }", []string{"nix build", "home-manager switch"}, nil, true},
		{"quotes removed", `git "push" 'origin'`, []string{"git push origin"}, nil, true},
		{"escaped name", `g\it push`, []string{"git push"}, nil, true},
		{"absolute path", "/usr/bin/git push", []string{"/usr/bin/git push", "git push"}, nil, true},
		{"heredoc body is data", "cat >> notes.md <<'EOF'\ngit push origin main\nEOF", []string{"cat"}, []string{"git push origin main"}, true},
		{"heredoc substitution runs", "cat <<EOF\n$(nix build)\nEOF", []string{"nix build"}, nil, true},
		{"ssh argument is data", "ssh host 'which nix home-manager'", []string{"ssh host which nix home-manager"}, []string{"which nix home-manager"}, true},
		{"bash -c", `bash -c "cd x && git push"`, []string{"cd x", "git push"}, nil, true},
		{"sh -lc", "sh -lc 'npm publish'", []string{"npm publish"}, nil, true},
		{"nested bash -c", `bash -c "sh -c 'nix build'"`, []string{"nix build"}, nil, true},
		{"eval", `eval "git push"`, []string{"git push"}, nil, true},
		{"env wrapper", "env FOO=1 terraform apply", []string{"terraform apply"}, nil, true},
		{"timeout wrapper", "timeout 10 git push", []string{"git push"}, nil, true},
		{"sudo wrapper with options", "sudo -u root nix-env -i foo", []string{"nix-env -i foo"}, nil, true},
		{"stacked wrappers", "nice -n 5 timeout 10 bash -c 'npm publish'", []string{"npm publish"}, nil, true},
		{"xargs", "ls | xargs -n1 git push", []string{"git push"}, nil, true},
		{"find -exec", `find . -name x -exec git push \;`, []string{"git push"}, nil, true},
		{"expansion in argument", "git push $REMOTE", []string{"git push $REMOTE"}, nil, true},
		{"expansion as command name", "$cmd push", nil, nil, false},
		{"syntax error", "git push '", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			units, ok := commandUnits(tt.cmd)
			if ok != tt.ok {
				t.Errorf("ok = %v, want %v (units %q)", ok, tt.ok, units)
			}
			for _, w := range tt.want {
				if !slices.Contains(units, w) {
					t.Errorf("missing unit %q in %q", w, units)
				}
			}
			for _, n := range tt.not {
				if slices.Contains(units, n) {
					t.Errorf("unexpected unit %q in %q", n, units)
				}
			}
		})
	}
}

func TestCommandUnitsDepthLimit(t *testing.T) {
	cmd := "git status"
	for i := 0; i < maxShellDepth+2; i++ {
		cmd = "eval " + strings.ReplaceAll(cmd, " ", `\ `)
	}
	if _, ok := commandUnits(cmd); ok {
		t.Errorf("nesting beyond the limit must report ok=false")
	}
}

func TestEvaluateCommandPerCommand(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: `^nix\s+develop\b`, Action: Allow, Tag: "nix", Kind: KindCommand},
			{Match: `^nix\s`, Action: Deny, Tag: "nix", Kind: KindCommand},
			{Match: `^home-manager\s`, Action: Deny, Tag: "nix", Kind: KindCommand},
			{Match: `^git\b(\s+-C\s+\S+|\s+--?\S+)*\s+push\b`, Action: Prompt, Tag: "deploy", Kind: KindCommand},
			{Match: `^npm publish`, Action: Prompt, Tag: "deploy", Kind: KindCommand},
		},
	}
	tests := []struct {
		name  string
		cmd   string
		want  string
		index int
	}{
		// The two reported false positives.
		{"ssh remote command", "ssh umenoya-server1 'which python3; which nix home-manager'", Allow, 0},
		{"heredoc body", "cat >> NOTES.local.md <<'EOF'\nthen run git push\nEOF", Allow, 0},
		{"message to another agent", `herdr agent prompt sub "please git push it"`, Allow, 0},
		{"commit message", `git commit -m "git push later"`, Allow, 0},
		{"echo", "echo nix build", Allow, 0},
		// Detections that the anchored rules used to miss.
		{"after cd", "cd pkg && npm publish", Prompt, 2},
		{"after assignment", "NPM_TOKEN=x npm publish", Prompt, 1},
		{"inside bash -c", `bash -c "git -C repo push"`, Prompt, 2},
		{"inside substitution", "echo $(nix build .)", Deny, 2},
		// The strictest command decides, not the first one.
		{"allow then deny", "nix develop -c true && nix build", Deny, 2},
		{"prompt then deny", "git push; home-manager switch", Deny, 2},
		{"allow only", "nix develop", Allow, 0},
		// Unresolvable lines fall back to the raw string.
		{"dynamic name, anchored rule on raw line", "nix build; $x", Deny, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := rs.EvaluateCommand(tt.cmd)
			if res.Action != tt.want {
				t.Fatalf("action = %q, want %q (%s)", res.Action, tt.want, res.Reason())
			}
			if tt.want != Allow && res.CommandIndex != tt.index {
				t.Errorf("index = %d, want %d (%s)", res.CommandIndex, tt.index, res.Reason())
			}
		})
	}
}

func TestEvaluateCommandFallback(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{Match: `\bgit\s+push\b`, Action: Prompt, Tag: "deploy", Kind: KindCommand},
		},
	}
	// The command name is an expansion: an unanchored rule still matches.
	res := rs.EvaluateCommand(`$run "git push"`)
	if res.Action != Prompt {
		t.Errorf("got %q, want prompt", res.Action)
	}
	// A syntax error is matched as before, too.
	res = rs.EvaluateCommand("git push '")
	if res.Action != Prompt || res.CommandIndex != 0 {
		t.Errorf("got %q index %d, want prompt on the raw line", res.Action, res.CommandIndex)
	}
	if !strings.Contains(res.Reason(), "whole line") {
		t.Errorf("reason should say the raw line was matched: %q", res.Reason())
	}
}

func TestResultReason(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{{Match: `^git\s+push\b`, Action: Prompt, Tag: "deploy", Kind: KindCommand}},
	}
	got := rs.EvaluateCommand("cd repo && git push origin main").Reason()
	want := `rule "^git\\s+push\\b" [deploy] matched command #2: git push origin main`
	if got != want {
		t.Errorf("reason = %q\nwant     %q", got, want)
	}
	if r := rs.EvaluateCommand("git status").Reason(); r != "" {
		t.Errorf("allowed command should have no reason, got %q", r)
	}
}
