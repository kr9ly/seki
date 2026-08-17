//go:build linux

package netns

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ~/.claude.json holds Claude Code's account identity (oauthAccount) mixed
// with state that should stay shared across profiles (mcpServers, per-project
// trust, prompt history). Binding only .credentials.json separates tokens but
// leaves identity shared, so every session displays — and feature-gates on —
// whichever account logged in last on the host.
//
// bindClaudeJSON therefore binds a per-profile copy of ~/.claude.json with
// only the oauthAccount field swapped for the profile's stored identity.
// Everything else is a session-start snapshot of the host file; sync-back
// merges non-identity changes to the host file on exit.
//
// Claude Code rewrites ~/.claude.json via atomic rename, which (as with
// .credentials.json, see SyncBackCredentials) detaches the bind mount and
// replaces the host file directly. After that point the session writes the
// host file live, including its swapped oauthAccount — the host file's
// oauthAccount is therefore scratch, owned by whichever session wrote last,
// same as the host ~/.claude/.credentials.json. Sync-back detects which of
// the two states it is in via os.SameFile.

func hostClaudeJSONPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".claude.json")
}

func profileClaudeJSONPath(profileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude-profiles", profileName, ".claude.json"), nil
}

func oauthAccountPath(profileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude-profiles", profileName, "oauthAccount.json"), nil
}

// bindClaudeJSON bind-mounts a profile-specific copy of ~/.claude.json over
// the host file. The copy is the host file with oauthAccount replaced by the
// profile's stored identity — or removed when the profile has none yet, which
// makes Claude Code re-fetch the account behind the bound credentials instead
// of inheriting another profile's identity from the host snapshot.
func bindClaudeJSON(profileName string) error {
	if profileName == "" {
		return nil
	}
	hostPath := hostClaudeJSONPath()
	if hostPath == "" {
		return nil
	}

	hostData, err := os.ReadFile(hostPath)
	if os.IsNotExist(err) {
		// Mount target must exist. A missing host file also means there is
		// no shared state to snapshot.
		hostData = []byte("{}")
		if werr := os.WriteFile(hostPath, []byte("{}\n"), 0600); werr != nil {
			return fmt.Errorf("create %s: %w", hostPath, werr)
		}
	} else if err != nil {
		return err
	}

	oaPath, err := oauthAccountPath(profileName)
	if err != nil {
		return err
	}
	storedOA, err := os.ReadFile(oaPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	copyData, err := swapOAuthAccount(hostData, storedOA)
	if err != nil {
		return fmt.Errorf("parse %s: %w", hostPath, err)
	}

	copyPath, err := profileClaudeJSONPath(profileName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(copyPath), 0755); err != nil {
		return fmt.Errorf("mkdir profile dir: %w", err)
	}
	if err := os.WriteFile(copyPath, copyData, 0600); err != nil {
		return fmt.Errorf("write profile copy: %w", err)
	}

	if err := syscall.Mount(copyPath, hostPath, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount %s -> %s: %w", copyPath, hostPath, err)
	}
	return nil
}

// SyncBackClaudeJSON persists the session's oauthAccount to the profile store
// and, when the bind mount survived the session (no atomic rename happened),
// merges non-identity changes back into the host ~/.claude.json. Call it
// alongside SyncBackCredentials, after the user command exits but before the
// mount namespace is torn down.
func SyncBackClaudeJSON() {
	profileName, err := resolveClaudeProfileName()
	if err != nil || profileName == "" {
		return
	}
	hostPath := hostClaudeJSONPath()
	if hostPath == "" {
		return
	}

	sessionData, err := os.ReadFile(hostPath)
	if err != nil || len(sessionData) <= 4 {
		return
	}
	var session map[string]json.RawMessage
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return
	}

	// Save the session's identity to the profile store. Guard against saving
	// a different account: once the bind detaches, the host file (and thus a
	// concurrently exiting session's view) can carry another profile's
	// oauthAccount, and persisting it here would cross-contaminate stores.
	// An empty store accepts anything — bootstrap only ever sees an identity
	// fetched with this profile's own token, because bindClaudeJSON strips
	// the inherited one.
	if oa, ok := session["oauthAccount"]; ok {
		if oaPath, err := oauthAccountPath(profileName); err == nil {
			stored, rerr := os.ReadFile(oaPath)
			if rerr != nil || sameAccount(stored, oa) {
				if err := os.MkdirAll(filepath.Dir(oaPath), 0755); err == nil {
					if err := os.WriteFile(oaPath, oa, 0600); err != nil {
						fmt.Fprintf(os.Stderr, "seki: save oauthAccount for %s: %v\n", profileName, err)
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "seki: claude.json: session identity is not profile %s's account — not saved\n", profileName)
			}
		}
	}

	// If the path still resolves to the profile copy, the bind is intact and
	// the host file never saw this session's changes. Unmount to reach the
	// real host file, then merge everything except identity back into it.
	// If the bind detached, Claude Code has been writing the host file
	// directly and there is nothing to merge.
	copyPath, err := profileClaudeJSONPath(profileName)
	if err != nil {
		return
	}
	hostSt, err1 := os.Stat(hostPath)
	copySt, err2 := os.Stat(copyPath)
	if err1 != nil || err2 != nil || !os.SameFile(hostSt, copySt) {
		return
	}
	if err := syscall.Unmount(hostPath, 0); err != nil {
		fmt.Fprintf(os.Stderr, "seki: unmount %s: %v\n", hostPath, err)
		return
	}

	unlock, err := lockClaudeJSONSync()
	if err == nil {
		defer unlock()
	}

	hostData, err := os.ReadFile(hostPath)
	if err != nil {
		hostData = []byte("{}")
	}
	merged, err := mergeClaudeJSON(hostData, sessionData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: merge claude.json: %v\n", err)
		return
	}
	tmp := hostPath + ".seki-tmp"
	if err := os.WriteFile(tmp, merged, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "seki: write merged claude.json: %v\n", err)
		return
	}
	if err := os.Rename(tmp, hostPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "seki: replace claude.json: %v\n", err)
	}
}

// lockClaudeJSONSync serializes concurrent sync-backs from sessions exiting
// at the same time. It only guards seki against seki — a live Claude Code
// session that already detached its bind can still race the merge, which is
// the same lost-update window concurrent host sessions have natively.
func lockClaudeJSONSync() (func(), error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(home, ".claude-profiles", ".claude.json.seki-lock")
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
	for k, v := range sessM {
		hostM[k] = v
	}
	out, err := json.Marshal(hostM)
	if err != nil {
		return sessionRaw
	}
	return out
}

// sameAccount reports whether two oauthAccount blobs refer to the same
// account. Unparseable or uuid-less blobs never match.
func sameAccount(a, b []byte) bool {
	type acct struct {
		AccountUUID string `json:"accountUuid"`
	}
	var x, y acct
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return x.AccountUUID != "" && x.AccountUUID == y.AccountUUID
}
