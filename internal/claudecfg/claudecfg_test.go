package claudecfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func parseTop(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, data)
	}
	return m
}

func accountUUID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var a struct {
		AccountUUID string `json:"accountUuid"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("unmarshal oauthAccount: %v\n%s", err, raw)
	}
	return a.AccountUUID
}

func TestSwapOAuthAccountReplaces(t *testing.T) {
	host := []byte(`{"oauthAccount":{"accountUuid":"host"},"numStartups":3}`)
	stored := []byte(`{"accountUuid":"profile"}`)

	out, err := swapOAuthAccount(host, stored)
	if err != nil {
		t.Fatalf("swapOAuthAccount: %v", err)
	}
	m := parseTop(t, out)
	if got := accountUUID(t, m["oauthAccount"]); got != "profile" {
		t.Errorf("oauthAccount = %s, want profile", got)
	}
	if string(m["numStartups"]) != "3" {
		t.Errorf("numStartups = %s, want 3", m["numStartups"])
	}
}

func TestSwapOAuthAccountStripsWhenStoreEmpty(t *testing.T) {
	host := []byte(`{"oauthAccount":{"accountUuid":"host"}}`)
	for _, stored := range [][]byte{nil, {}, []byte("not json")} {
		out, err := swapOAuthAccount(host, stored)
		if err != nil {
			t.Fatalf("swapOAuthAccount: %v", err)
		}
		if _, ok := parseTop(t, out)["oauthAccount"]; ok {
			t.Errorf("stored=%q: oauthAccount not stripped", stored)
		}
	}
}

func TestSwapOAuthAccountEmptyHost(t *testing.T) {
	out, err := swapOAuthAccount(nil, []byte(`{"accountUuid":"p"}`))
	if err != nil {
		t.Fatalf("swapOAuthAccount: %v", err)
	}
	if got := accountUUID(t, parseTop(t, out)["oauthAccount"]); got != "p" {
		t.Errorf("oauthAccount = %s, want p", got)
	}
}

func TestSwapOAuthAccountBadHost(t *testing.T) {
	if _, err := swapOAuthAccount([]byte("not json"), nil); err == nil {
		t.Fatal("expected error for unparseable host JSON")
	}
}

func TestMergeClaudeJSONKeepsHostIdentity(t *testing.T) {
	host := []byte(`{"oauthAccount":{"accountUuid":"host"},"numStartups":3}`)
	session := []byte(`{"oauthAccount":{"accountUuid":"session"},"numStartups":4}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	m := parseTop(t, out)
	if got := accountUUID(t, m["oauthAccount"]); got != "host" {
		t.Errorf("oauthAccount = %s, want host", got)
	}
	if string(m["numStartups"]) != "4" {
		t.Errorf("numStartups = %s, want 4", m["numStartups"])
	}
}

func TestMergeClaudeJSONNoHostIdentity(t *testing.T) {
	host := []byte(`{}`)
	session := []byte(`{"oauthAccount":{"accountUuid":"session"}}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	if _, ok := parseTop(t, out)["oauthAccount"]; ok {
		t.Error("session identity leaked into host file")
	}
}

func TestMergeClaudeJSONProjectsPerKey(t *testing.T) {
	host := []byte(`{"projects":{"/a":{"x":1},"/b":{"x":2}}}`)
	session := []byte(`{"projects":{"/b":{"x":9},"/c":{"x":3}}}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	var m struct {
		Projects map[string]struct {
			X int `json:"x"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key, want := range map[string]int{"/a": 1, "/b": 9, "/c": 3} {
		if got, ok := m.Projects[key]; !ok || got.X != want {
			t.Errorf("projects[%s] = %+v, want x=%d", key, got, want)
		}
	}
}

func TestMergeClaudeJSONCorruptHost(t *testing.T) {
	out, err := mergeClaudeJSON([]byte("garbage"), []byte(`{"numStartups":5}`))
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	if string(parseTop(t, out)["numStartups"]) != "5" {
		t.Error("session fields lost when host is corrupt")
	}
}

// setupHome builds a fake $HOME with a host ~/.claude.json, a ~/.claude dir
// carrying shared assets and host credentials, and a profile store for "work".
func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	writeFile(t, filepath.Join(home, ".claude.json"),
		`{"oauthAccount":{"accountUuid":"host"},"numStartups":3,"projects":{"/a":{"x":1}}}`)

	claudeDir := filepath.Join(home, ".claude")
	writeFile(t, filepath.Join(claudeDir, ".credentials.json"), cred("host-cred", 1000))
	writeFile(t, filepath.Join(claudeDir, "settings.json"), `{"verbose":false}`)
	writeFile(t, filepath.Join(claudeDir, "skills", "foo.md"), "skill")

	workDir := filepath.Join(home, ".claude-profiles", "work")
	writeFile(t, filepath.Join(workDir, ".credentials.json"), cred("work-cred", 1000))
	writeFile(t, filepath.Join(workDir, "oauthAccount.json"), `{"accountUuid":"work"}`)
	return home
}

// cred builds a usable credentials file in Claude Code's on-disk shape.
func cred(token string, expiresAt int64) string {
	return fmt.Sprintf(
		`{"claudeAiOauth":{"accessToken":"at-%s","refreshToken":"rt-%s","expiresAt":%d}}`,
		token, token, expiresAt)
}

// stubCred is what Claude Code leaves behind after a failed refresh logs the
// session out: the shape survives but the tokens are empty.
const stubCred = `{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0}}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestSetupMaterializesSessionDir(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("work", false)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if want := filepath.Join(home, ".claude-profiles", "work", "sessions", strconv.Itoa(os.Getpid())); s.Dir != want {
		t.Errorf("Dir = %s, want %s", s.Dir, want)
	}

	view := parseTop(t, []byte(readFile(t, filepath.Join(s.Dir, ".claude.json"))))
	if got := accountUUID(t, view["oauthAccount"]); got != "work" {
		t.Errorf("view oauthAccount = %s, want work", got)
	}
	if string(view["numStartups"]) != "3" {
		t.Errorf("view numStartups = %s, want 3", view["numStartups"])
	}

	if got := readFile(t, filepath.Join(s.Dir, ".credentials.json")); got != cred("work-cred", 1000) {
		t.Errorf("credentials = %s, want work store copy", got)
	}
	if fi, err := os.Lstat(filepath.Join(s.Dir, ".credentials.json")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Error(".credentials.json must be a private copy, not a symlink")
	}

	link, err := os.Readlink(filepath.Join(s.Dir, "settings.json"))
	if err != nil {
		t.Fatalf("settings.json is not a symlink: %v", err)
	}
	if want := filepath.Join(home, ".claude", "settings.json"); link != want {
		t.Errorf("settings.json -> %s, want %s", link, want)
	}
	if got := readFile(t, filepath.Join(s.Dir, "skills", "foo.md")); got != "skill" {
		t.Errorf("skills not reachable through symlink: %q", got)
	}
}

func TestSetupDefaultProfileUsesHostCredentials(t *testing.T) {
	setupHome(t)

	s, err := Setup("personal", true)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := readFile(t, filepath.Join(s.Dir, ".credentials.json")); got != cred("host-cred", 1000) {
		t.Errorf("credentials = %s, want host copy for default profile", got)
	}
}

func TestSetupFreshProfileStripsIdentity(t *testing.T) {
	setupHome(t)

	s, err := Setup("fresh", false)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	view := parseTop(t, []byte(readFile(t, filepath.Join(s.Dir, ".claude.json"))))
	if _, ok := view["oauthAccount"]; ok {
		t.Error("host identity leaked into a profile with no stored account")
	}
	if got := readFile(t, filepath.Join(s.Dir, ".credentials.json")); got != "{}\n" {
		t.Errorf("credentials = %q, want empty seed", got)
	}
}

func TestSyncBackPersistsIdentityCredentialsAndMerge(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("work", false)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Simulate a session that re-logged-in, bumped a counter, added a
	// project, and refreshed credentials.
	writeFile(t, filepath.Join(s.Dir, ".claude.json"),
		`{"oauthAccount":{"accountUuid":"work2"},"numStartups":4,"projects":{"/b":{"x":2}}}`)
	writeFile(t, filepath.Join(s.Dir, ".credentials.json"), cred("work-cred2", 2000))

	s.SyncBack()

	store := filepath.Join(home, ".claude-profiles", "work")
	if got := accountUUID(t, json.RawMessage(readFile(t, filepath.Join(store, "oauthAccount.json")))); got != "work2" {
		t.Errorf("stored oauthAccount = %s, want work2", got)
	}
	if got := readFile(t, filepath.Join(store, ".credentials.json")); got != cred("work-cred2", 2000) {
		t.Errorf("stored credentials = %s, want refreshed copy", got)
	}

	host := parseTop(t, []byte(readFile(t, filepath.Join(home, ".claude.json"))))
	if got := accountUUID(t, host["oauthAccount"]); got != "host" {
		t.Errorf("host oauthAccount = %s, want host (identity must not leak)", got)
	}
	if string(host["numStartups"]) != "4" {
		t.Errorf("host numStartups = %s, want 4", host["numStartups"])
	}
	var hp struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(home, ".claude.json"))), &hp); err != nil {
		t.Fatal(err)
	}
	if _, ok := hp.Projects["/a"]; !ok {
		t.Error("host project /a wiped by session snapshot")
	}
	if _, ok := hp.Projects["/b"]; !ok {
		t.Error("session project /b not merged into host")
	}

	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) {
		t.Error("session dir not removed")
	}
}

func TestSyncBackDefaultProfileCredentialsToHost(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("personal", true)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	writeFile(t, filepath.Join(s.Dir, ".credentials.json"), cred("host-cred2", 2000))

	s.SyncBack()

	if got := readFile(t, filepath.Join(home, ".claude", ".credentials.json")); got != cred("host-cred2", 2000) {
		t.Errorf("host credentials = %s, want refreshed copy", got)
	}
}

func TestSyncBackRejectsLoggedOutStub(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("personal", true)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// A failed refresh logged this session out; the store still holds a
	// usable login that must survive.
	writeFile(t, filepath.Join(s.Dir, ".credentials.json"), stubCred)

	s.SyncBack()

	if got := readFile(t, filepath.Join(home, ".claude", ".credentials.json")); got != cred("host-cred", 1000) {
		t.Errorf("host credentials = %s, want untouched store copy", got)
	}
}

func TestSyncBackRejectsStalerCredentials(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("work", false)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Another session rotated the token while this one ran.
	store := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	writeFile(t, store, cred("rotated", 5000))
	writeFile(t, filepath.Join(s.Dir, ".credentials.json"), cred("old", 1000))

	s.SyncBack()

	if got := readFile(t, store); got != cred("rotated", 5000) {
		t.Errorf("stored credentials = %s, want the fresher rotation kept", got)
	}
}

func TestSyncCredentialsPushesFresherSession(t *testing.T) {
	home := setupHome(t)
	sess := filepath.Join(home, "sess-creds.json")
	canon := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	writeFile(t, sess, cred("fresh", 9000))

	syncCredentials(home, sess, canon, true)

	if got := readFile(t, canon); got != cred("fresh", 9000) {
		t.Errorf("canonical = %s, want fresher session copy pushed", got)
	}
}

func TestSyncCredentialsPullsFresherCanonical(t *testing.T) {
	home := setupHome(t)
	sess := filepath.Join(home, "sess-creds.json")
	canon := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	writeFile(t, canon, cred("peer-login", 9000))
	// The session got logged out (stub) — the peer's login must flow in.
	writeFile(t, sess, stubCred)

	syncCredentials(home, sess, canon, true)

	if got := readFile(t, sess); got != cred("peer-login", 9000) {
		t.Errorf("session copy = %s, want fresher canonical pulled", got)
	}
}

func TestSyncCredentialsNoPullWithoutPullBack(t *testing.T) {
	home := setupHome(t)
	sess := filepath.Join(home, "sess-creds.json")
	canon := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	writeFile(t, canon, cred("peer-login", 9000))
	writeFile(t, sess, stubCred)

	syncCredentials(home, sess, canon, false)

	if got := readFile(t, sess); got != stubCred {
		t.Errorf("session copy = %s, want untouched without pullBack", got)
	}
}

func TestCredExpiry(t *testing.T) {
	cases := []struct {
		name   string
		data   string
		expiry int64
		ok     bool
	}{
		{"usable", cred("x", 42), 42, true},
		{"logged-out stub", stubCred, 0, false},
		{"missing refresh token", `{"claudeAiOauth":{"accessToken":"at","expiresAt":7}}`, 0, false},
		{"empty seed", "{}\n", 0, false},
		{"corrupt", "not json", 0, false},
	}
	for _, c := range cases {
		expiry, ok := credExpiry([]byte(c.data))
		if expiry != c.expiry || ok != c.ok {
			t.Errorf("%s: credExpiry = (%d, %v), want (%d, %v)", c.name, expiry, ok, c.expiry, c.ok)
		}
	}
}

func TestSyncBackSalvagesNewEntries(t *testing.T) {
	home := setupHome(t)

	s, err := Setup("work", false)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Claude Code created state that had no ~/.claude counterpart to symlink.
	writeFile(t, filepath.Join(s.Dir, "sessions-state", "log.jsonl"), "entry")
	writeFile(t, filepath.Join(s.Dir, "policy-limits.json"), `{}`)
	// A name that exists in ~/.claude already must not be clobbered.
	writeFile(t, filepath.Join(home, ".claude", "existing.json"), "host")
	writeFile(t, filepath.Join(s.Dir, "existing.json"), "session")

	s.SyncBack()

	if got := readFile(t, filepath.Join(home, ".claude", "sessions-state", "log.jsonl")); got != "entry" {
		t.Errorf("salvaged dir content = %q, want entry", got)
	}
	if got := readFile(t, filepath.Join(home, ".claude", "policy-limits.json")); got != `{}` {
		t.Errorf("salvaged file = %q", got)
	}
	if got := readFile(t, filepath.Join(home, ".claude", "existing.json")); got != "host" {
		t.Errorf("existing host file clobbered: %q", got)
	}
}

func TestPruneStaleRemovesDeadSessionDirs(t *testing.T) {
	home := setupHome(t)
	sessions := filepath.Join(home, ".claude-profiles", "work", "sessions")

	// Far beyond kernel.pid_max (2^22) — cannot be a live pid.
	writeFile(t, filepath.Join(sessions, "99999999", "new-state.json"), "orphan")
	writeFile(t, filepath.Join(sessions, "not-a-pid", "keep"), "keep")

	if _, err := Setup("work", false); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if _, err := os.Stat(filepath.Join(sessions, "99999999")); !os.IsNotExist(err) {
		t.Error("stale session dir not pruned")
	}
	if got := readFile(t, filepath.Join(home, ".claude", "new-state.json")); got != "orphan" {
		t.Errorf("stale dir state not salvaged: %q", got)
	}
	if _, err := os.Stat(filepath.Join(sessions, "not-a-pid")); err != nil {
		t.Error("non-pid entry must be left alone")
	}
}

func TestPruneStaleSyncsFresherCredentials(t *testing.T) {
	home := setupHome(t)
	sessions := filepath.Join(home, ".claude-profiles", "work", "sessions")

	// A /login happened in a session that later crashed — fresher than the
	// store, so it must survive the prune.
	writeFile(t, filepath.Join(sessions, "99999999", ".credentials.json"), cred("crashed-login", 9000))

	if _, err := Setup("work", false); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	store := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	if got := readFile(t, store); got != cred("crashed-login", 9000) {
		t.Errorf("stored credentials = %s, want crashed session's fresher login", got)
	}
}

func TestPruneStaleRejectsStalerCredentials(t *testing.T) {
	home := setupHome(t)
	sessions := filepath.Join(home, ".claude-profiles", "work", "sessions")

	writeFile(t, filepath.Join(sessions, "99999999", ".credentials.json"), cred("ancient", 1))

	if _, err := Setup("work", false); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	store := filepath.Join(home, ".claude-profiles", "work", ".credentials.json")
	if got := readFile(t, store); got != cred("work-cred", 1000) {
		t.Errorf("stored credentials = %s, want store kept over staler stale-dir copy", got)
	}
}
