// Package claudecfg materializes a per-session Claude Code config directory
// and points the session at it via CLAUDE_CONFIG_DIR.
//
// ~/.claude.json holds Claude Code's account identity (oauthAccount) mixed
// with state that should stay shared across profiles (mcpServers, per-project
// trust, prompt history). Earlier seki versions bind-mounted per-profile
// copies of ~/.claude.json and ~/.claude/.credentials.json, but Claude Code
// rewrites both via atomic rename, which detaches a file bind mount — after
// that the session wrote the shared host file directly and concurrent
// sessions could observe (and nearly persist) each other's identity.
//
// The session directory sidesteps renames entirely: it is private to one
// session, so every rewrite lands inside it. Layout:
//
//   - .claude.json      — host ~/.claude.json snapshot with oauthAccount
//     swapped for the profile's stored identity (merged view)
//   - .credentials.json — copy of the profile's credentials
//   - everything else   — symlinks to the entries of ~/.claude, so hooks,
//     settings.json, skills, plugins, and transcripts stay shared. Claude
//     Code writes through the symlinks (verified: /config settings writes
//     resolve the link rather than replacing it).
//
// Credentials do not wait for exit: StartCredentialSync reconciles the
// session copy with the canonical store while the session runs (see
// credsync.go), so token rotations propagate between concurrent sessions and
// a logged-out stub never overwrites a usable login.
//
// SyncBack persists identity to the profile store, runs a final guarded
// credentials push, merges non-identity ~/.claude.json changes into the host
// file, moves any files Claude Code created next to the symlinks back into
// ~/.claude, and removes the directory.
package claudecfg

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/kr9ly/seki/internal/profile"
)

// Session is one materialized config directory. Dir is the value to expose
// as CLAUDE_CONFIG_DIR.
type Session struct {
	Dir       string
	profile   string
	isDefault bool
	home      string

	stopSync chan struct{}
	syncDone chan struct{}
}

// Setup builds the per-session config directory for the given profile.
// isDefault marks the config's default profile, whose credentials canonically
// live in ~/.claude/.credentials.json rather than the profile store.
func Setup(profileName string, isDefault bool) (*Session, error) {
	if profileName == "" {
		return nil, fmt.Errorf("empty profile name")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	s := &Session{profile: profileName, isDefault: isDefault, home: home}

	sessions := filepath.Join(home, ".claude-profiles", profileName, "sessions")
	s.pruneStale(sessions)

	s.Dir = filepath.Join(sessions, strconv.Itoa(os.Getpid()))
	// A leftover dir from a recycled pid would leak stale state into this
	// session; start from scratch.
	if err := os.RemoveAll(s.Dir); err != nil {
		return nil, fmt.Errorf("clear session dir: %w", err)
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir session dir: %w", err)
	}

	// Merged view: host snapshot with the profile's stored identity swapped
	// in — or stripped when the profile has none yet, which makes Claude Code
	// re-fetch the account behind the profile's credentials instead of
	// inheriting another profile's identity from the host snapshot.
	hostData, err := os.ReadFile(s.hostClaudeJSONPath())
	if os.IsNotExist(err) {
		hostData = []byte("{}")
	} else if err != nil {
		return nil, err
	}
	s.migrateLegacyIdentity()
	if isDefault {
		// The legacy darwin layout kept even the default profile's login in
		// the profile store; adopt it if it is the fresher usable login.
		if legacy, err := profile.CredentialsPath(profileName); err == nil {
			syncCredentials(home, legacy, s.credentialsPath(), false)
		}
	}
	storedOA, err := os.ReadFile(s.oauthAccountPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	view, err := swapOAuthAccount(hostData, storedOA)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.hostClaudeJSONPath(), err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, ".claude.json"), view, 0600); err != nil {
		return nil, err
	}

	cred, err := os.ReadFile(s.credentialsPath())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		cred = []byte("{}\n")
	}
	if err := os.WriteFile(filepath.Join(s.Dir, ".credentials.json"), cred, 0600); err != nil {
		return nil, err
	}

	// Shared assets: symlink every existing ~/.claude entry. New entries
	// Claude Code creates during the session land in the session dir and are
	// salvaged back by SyncBack.
	entries, err := os.ReadDir(s.claudeDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == ".credentials.json" {
			continue
		}
		if err := os.Symlink(filepath.Join(s.claudeDir(), e.Name()), filepath.Join(s.Dir, e.Name())); err != nil {
			return nil, fmt.Errorf("symlink %s: %w", e.Name(), err)
		}
	}
	return s, nil
}

// SyncBack persists the session's state and removes the session directory.
// Call it after the user command exits. Errors are reported to stderr but
// never abort the remaining steps — each piece of state is worth saving on
// its own.
func (s *Session) SyncBack() {
	s.stopCredentialSync()

	sessionData, err := os.ReadFile(filepath.Join(s.Dir, ".claude.json"))
	if err == nil && len(sessionData) > 4 {
		s.saveIdentity(sessionData)
		s.mergeToHost(sessionData)
	}

	// Final guarded push: only a usable login fresher than the store is
	// persisted — a logged-out stub or a token another session already
	// superseded must not clobber the canonical file.
	syncCredentials(s.home, filepath.Join(s.Dir, ".credentials.json"), s.credentialsPath(), false)

	salvage(s.Dir, s.claudeDir())
	if err := os.RemoveAll(s.Dir); err != nil {
		fmt.Fprintf(os.Stderr, "seki: remove session config dir: %v\n", err)
	}
}

// saveIdentity stores the session's oauthAccount in the profile store. The
// session file is private to this session, so whatever identity it carries
// was obtained with this profile's credentials (or an explicit in-session
// /login) — no cross-profile contamination is possible.
func (s *Session) saveIdentity(sessionData []byte) {
	var session map[string]json.RawMessage
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return
	}
	oa, ok := session["oauthAccount"]
	if !ok {
		return
	}
	oaPath := s.oauthAccountPath()
	if err := os.MkdirAll(filepath.Dir(oaPath), 0755); err != nil {
		return
	}
	if err := os.WriteFile(oaPath, oa, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "seki: save oauthAccount for %s: %v\n", s.profile, err)
	}
}

// mergeToHost overlays the session's non-identity changes onto the host
// ~/.claude.json under a cross-session lock.
func (s *Session) mergeToHost(sessionData []byte) {
	unlock, err := lockClaudeJSONSync(s.home)
	if err == nil {
		defer unlock()
	}

	hostPath := s.hostClaudeJSONPath()
	hostData, err := os.ReadFile(hostPath)
	if err != nil {
		hostData = []byte("{}")
	}
	merged, err := mergeClaudeJSON(hostData, sessionData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: merge claude.json: %v\n", err)
		return
	}
	if err := writeFileAtomic(hostPath, merged, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "seki: replace claude.json: %v\n", err)
	}
}

func (s *Session) hostClaudeJSONPath() string {
	return filepath.Join(s.home, ".claude.json")
}

func (s *Session) claudeDir() string {
	return filepath.Join(s.home, ".claude")
}

func (s *Session) oauthAccountPath() string {
	return filepath.Join(s.home, ".claude-profiles", s.profile, "oauthAccount.json")
}

// credentialsPath returns the canonical credentials location this session
// seeds from and syncs back to: ~/.claude for the default profile (so host
// sessions outside seki stay in sync), the profile store otherwise.
func (s *Session) credentialsPath() string {
	if s.isDefault {
		return filepath.Join(s.claudeDir(), ".credentials.json")
	}
	p, err := profile.CredentialsPath(s.profile)
	if err != nil {
		return filepath.Join(s.home, ".claude-profiles", s.profile, ".credentials.json")
	}
	return p
}

// salvage moves regular (non-symlink) entries Claude Code created in the
// session dir back into ~/.claude, so state like new transcript dirs is not
// lost with the session dir. Entries that already exist in ~/.claude (e.g.
// created by a concurrent session) are left behind and removed with the dir.
func salvage(dir, claudeDir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == ".claude.json" || name == ".credentials.json" {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		dst := filepath.Join(claudeDir, name)
		if _, err := os.Lstat(dst); err == nil || !os.IsNotExist(err) {
			continue
		}
		if err := os.MkdirAll(claudeDir, 0700); err != nil {
			return
		}
		if err := os.Rename(filepath.Join(dir, name), dst); err != nil {
			fmt.Fprintf(os.Stderr, "seki: salvage %s: %v\n", name, err)
		}
	}
}

// pruneStale removes session dirs whose owning process is gone (crash,
// SIGKILL), salvaging their new entries first. Credentials go through the
// guarded sync, so a /login performed in a crashed session survives if it is
// fresher than the store. Identity is not synced — it may be older than the
// store and there is no freshness clock to tell.
func (s *Session) pruneStale(sessions string) {
	entries, err := os.ReadDir(sessions)
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		// Signal 0 probes existence; EPERM still means the pid is alive.
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			continue
		}
		dir := filepath.Join(sessions, e.Name())
		salvage(dir, s.claudeDir())
		syncCredentials(s.home, filepath.Join(dir, ".credentials.json"), s.credentialsPath(), false)
		os.RemoveAll(dir)
	}
}

// lockClaudeJSONSync serializes host ~/.claude.json merges across
// concurrently exiting sessions. It only guards seki against seki — a live
// host Claude Code session can still race the merge, which is the same
// lost-update window concurrent host sessions have natively.
func lockClaudeJSONSync(home string) (func(), error) {
	return flockPath(filepath.Join(home, ".claude-profiles", ".claude.json.seki-lock"))
}

func flockPath(lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// swapOAuthAccount returns hostJSON with the top-level oauthAccount field
// replaced by storedOA, or removed when storedOA is empty or invalid.
func swapOAuthAccount(hostJSON, storedOA []byte) ([]byte, error) {
	m := map[string]json.RawMessage{}
	if len(hostJSON) > 0 {
		if err := json.Unmarshal(hostJSON, &m); err != nil {
			return nil, err
		}
	}
	if len(storedOA) > 0 && json.Valid(storedOA) {
		m["oauthAccount"] = storedOA
	} else {
		delete(m, "oauthAccount")
	}
	return json.MarshalIndent(m, "", "  ")
}

// mergeClaudeJSON overlays the session's top-level fields onto the host's,
// except oauthAccount (the host file keeps its own identity) and projects,
// which is merged per key so a stale session snapshot doesn't wipe entries
// another session added while this one ran.
func mergeClaudeJSON(hostJSON, sessionJSON []byte) ([]byte, error) {
	var session map[string]json.RawMessage
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return nil, err
	}
	merged := map[string]json.RawMessage{}
	if err := json.Unmarshal(hostJSON, &merged); err != nil {
		merged = map[string]json.RawMessage{}
	}
	hostOA, hostHadOA := merged["oauthAccount"]
	hostProjects := merged["projects"]
	for k, v := range session {
		if k == "oauthAccount" {
			continue
		}
		if k == "projects" {
			merged[k] = mergeProjects(hostProjects, v)
			continue
		}
		merged[k] = v
	}
	if hostHadOA {
		merged["oauthAccount"] = hostOA
	} else {
		delete(merged, "oauthAccount")
	}
	return json.MarshalIndent(merged, "", "  ")
}

func mergeProjects(hostRaw, sessionRaw json.RawMessage) json.RawMessage {
	var hostM, sessM map[string]json.RawMessage
	if err := json.Unmarshal(sessionRaw, &sessM); err != nil {
		if len(hostRaw) > 0 {
			return hostRaw
		}
		return sessionRaw
	}
	if err := json.Unmarshal(hostRaw, &hostM); err != nil || hostM == nil {
		hostM = map[string]json.RawMessage{}
	}
	maps.Copy(hostM, sessM)
	out, err := json.Marshal(hostM)
	if err != nil {
		return sessionRaw
	}
	return out
}

// ResolveProfileName returns the Claude profile for this seki session: the
// SEKI_CLAUDE_PROFILE override (`seki exec --claude-profile`) wins over
// cwd-based resolution from config via SEKI_CWD. Empty means no profile
// applies. The returned config is nil when it was not needed.
func ResolveProfileName() (string, *profile.Config, error) {
	if name := os.Getenv("SEKI_CLAUDE_PROFILE"); name != "" {
		return name, nil, nil
	}
	cwd := os.Getenv("SEKI_CWD")
	if cwd == "" {
		return "", nil, nil
	}
	cfg, err := profile.LoadConfig()
	if err != nil {
		return "", nil, fmt.Errorf("load config: %w", err)
	}
	if cfg == nil {
		return "", nil, nil
	}
	return cfg.Resolve(cwd), cfg, nil
}

// SetupFromEnv resolves the profile (ResolveProfileName) and materializes
// its config directory, shared by the linux and darwin backends. An existing
// CLAUDE_CONFIG_DIR means the caller manages Claude Code's config themselves:
// seki neither redirects nor syncs back. Credential sync is started; the
// caller must call SyncBack after the user command exits. A nil session with
// a nil error means no profile applies.
func SetupFromEnv() (*Session, string, error) {
	if os.Getenv("CLAUDE_CONFIG_DIR") != "" {
		return nil, "", nil
	}
	name, cfg, err := ResolveProfileName()
	if err != nil || name == "" {
		return nil, "", err
	}
	if cfg == nil {
		cfg, _ = profile.LoadConfig()
	}
	isDefault := cfg != nil && name == cfg.Default
	sess, err := Setup(name, isDefault)
	if err != nil {
		return nil, "", err
	}
	sess.StartCredentialSync()
	return sess, name, nil
}

// migrateLegacyIdentity seeds the profile store from the layout the darwin
// backend used before per-session dirs: ~/.claude-profiles/<p> itself was
// CLAUDE_CONFIG_DIR, so Claude Code left a .claude.json (carrying the
// profile's oauthAccount) there. Only runs when the store has no identity yet.
func (s *Session) migrateLegacyIdentity() {
	if _, err := os.Stat(s.oauthAccountPath()); err == nil {
		return
	}
	legacy, err := os.ReadFile(filepath.Join(s.home, ".claude-profiles", s.profile, ".claude.json"))
	if err != nil {
		return
	}
	s.saveIdentity(legacy)
}
