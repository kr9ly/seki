//go:build linux

package netns

import "testing"

func TestResolveClaudeProfileNameEnvOverride(t *testing.T) {
	t.Setenv("SEKI_CLAUDE_PROFILE", "burst")
	t.Setenv("SEKI_CWD", "/home/someone/projects/anything")

	name, err := resolveClaudeProfileName()
	if err != nil {
		t.Fatalf("resolveClaudeProfileName: %v", err)
	}
	if name != "burst" {
		t.Errorf("got %q, want %q (env override must win over cwd resolution)", name, "burst")
	}
}

func TestResolveClaudeProfileNameNoCwdNoOverride(t *testing.T) {
	t.Setenv("SEKI_CLAUDE_PROFILE", "")
	t.Setenv("SEKI_CWD", "")

	name, err := resolveClaudeProfileName()
	if err != nil {
		t.Fatalf("resolveClaudeProfileName: %v", err)
	}
	if name != "" {
		t.Errorf("got %q, want empty when neither override nor cwd is set", name)
	}
}
