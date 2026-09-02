package claudecfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveProfileNameEnvOverride(t *testing.T) {
	t.Setenv("SEKI_CLAUDE_PROFILE", "burst")
	t.Setenv("SEKI_CWD", "/home/someone/projects/anything")

	name, _, err := ResolveProfileName()
	if err != nil {
		t.Fatalf("ResolveProfileName: %v", err)
	}
	if name != "burst" {
		t.Errorf("got %q, want %q (env override must win over cwd resolution)", name, "burst")
	}
}

func TestResolveProfileNameNoCwdNoOverride(t *testing.T) {
	t.Setenv("SEKI_CLAUDE_PROFILE", "")
	t.Setenv("SEKI_CWD", "")

	name, _, err := ResolveProfileName()
	if err != nil {
		t.Fatalf("ResolveProfileName: %v", err)
	}
	if name != "" {
		t.Errorf("got %q, want empty when neither override nor cwd is set", name)
	}
}

func TestSetupFromEnvRespectsExistingConfigDir(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "/somewhere")
	t.Setenv("SEKI_CLAUDE_PROFILE", "burst")
	sess, name, err := SetupFromEnv()
	if err != nil || sess != nil || name != "" {
		t.Fatalf("got (%v, %q, %v), want no session when CLAUDE_CONFIG_DIR is preset", sess, name, err)
	}
}

// Legacy darwin layout: ~/.claude-profiles/<p> itself was CLAUDE_CONFIG_DIR,
// so the profile's identity lives in <p>/.claude.json rather than
// oauthAccount.json. Setup must adopt it into the store.
func TestSetupMigratesLegacyDarwinIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	prof := filepath.Join(home, ".claude-profiles", "work")
	os.MkdirAll(prof, 0700)
	os.WriteFile(filepath.Join(prof, ".claude.json"),
		[]byte(`{"oauthAccount":{"accountUuid":"legacy-acct"},"projects":{}}`), 0600)
	os.WriteFile(filepath.Join(home, ".claude.json"),
		[]byte(`{"oauthAccount":{"accountUuid":"host-acct"}}`), 0600)

	sess, err := Setup("work", false)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sess.Dir)

	stored, err := os.ReadFile(filepath.Join(prof, "oauthAccount.json"))
	if err != nil || string(stored) != `{"accountUuid":"legacy-acct"}` {
		t.Fatalf("oauthAccount.json = %q, %v; want legacy identity adopted", stored, err)
	}
	view, _ := os.ReadFile(filepath.Join(sess.Dir, ".claude.json"))
	if !contains(view, "legacy-acct") || contains(view, "host-acct") {
		t.Errorf("session view must carry the migrated identity, got %s", view)
	}
}

func TestSetupDefaultProfileAdoptsLegacyStoreCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prof := filepath.Join(home, ".claude-profiles", "personal")
	os.MkdirAll(prof, 0700)
	os.MkdirAll(filepath.Join(home, ".claude"), 0700)
	login := `{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":200}}`
	os.WriteFile(filepath.Join(prof, ".credentials.json"), []byte(login), 0600)

	sess, err := Setup("personal", true)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sess.Dir)

	canon, _ := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json"))
	if string(canon) != login {
		t.Errorf("~/.claude/.credentials.json = %q, want legacy store login adopted", canon)
	}
	got, _ := os.ReadFile(filepath.Join(sess.Dir, ".credentials.json"))
	if string(got) != login {
		t.Errorf("session credentials = %q, want seeded from adopted login", got)
	}
}

func contains(b []byte, s string) bool { return strings.Contains(string(b), s) }
