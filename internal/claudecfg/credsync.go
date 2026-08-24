package claudecfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials are the one piece of session state that cannot wait for exit.
// Claude Code rotates the OAuth refresh token: once one session refreshes,
// every other session's forked copy holds a token the server has invalidated.
// A session whose refresh fails logs itself out and rewrites its copy as a
// stub with empty tokens — and the old exit-time sync-back would persist that
// stub over the store, forcing a fresh /login on every subsequent session.
//
// syncCredentials repairs both directions: rotations and logins are pushed to
// the canonical store as they happen, sessions pull fresher tokens written by
// their peers, and a file that is not a usable login (or is staler than the
// other side) never overwrites anything.

const credSyncInterval = 5 * time.Second

// credExpiry reports whether data is a usable Claude Code login — non-empty
// access and refresh tokens — and its expiresAt, which every login and
// refresh rotation bumps, making it the freshness clock for comparisons.
func credExpiry(data []byte) (int64, bool) {
	var c struct {
		OAuth struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return 0, false
	}
	if c.OAuth.AccessToken == "" || c.OAuth.RefreshToken == "" {
		return 0, false
	}
	return c.OAuth.ExpiresAt, true
}

// syncCredentials copies the fresher usable credentials file over the staler
// one, under the cross-session lock. Push (session → canonical) always
// applies; pull (canonical → session) only when pullBack — a dir about to be
// removed has nothing to gain from a pull. Equal freshness is a no-op, so
// concurrent reconcilers converge instead of ping-ponging.
func syncCredentials(home, sessionPath, canonicalPath string, pullBack bool) {
	unlock, err := lockCredentialsSync(home)
	if err == nil {
		defer unlock()
	}

	sess, _ := os.ReadFile(sessionPath)
	canon, _ := os.ReadFile(canonicalPath)
	sessExp, sessOK := credExpiry(sess)
	canonExp, canonOK := credExpiry(canon)
	switch {
	case sessOK && (!canonOK || sessExp > canonExp):
		if err := writeFileAtomic(canonicalPath, sess, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "seki: sync credentials to %s: %v\n", canonicalPath, err)
		}
	case pullBack && canonOK && (!sessOK || canonExp > sessExp):
		if err := writeFileAtomic(sessionPath, canon, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "seki: pull credentials into session: %v\n", err)
		}
	}
}

// StartCredentialSync launches the background reconciler for the session's
// lifetime. SyncBack stops it and runs a final push.
func (s *Session) StartCredentialSync() {
	if s.stopSync != nil {
		return
	}
	s.stopSync = make(chan struct{})
	s.syncDone = make(chan struct{})
	go func() {
		defer close(s.syncDone)
		ticker := time.NewTicker(credSyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopSync:
				return
			case <-ticker.C:
				syncCredentials(s.home, filepath.Join(s.Dir, ".credentials.json"), s.credentialsPath(), true)
			}
		}
	}()
}

func (s *Session) stopCredentialSync() {
	if s.stopSync == nil {
		return
	}
	close(s.stopSync)
	<-s.syncDone
	s.stopSync = nil
	s.syncDone = nil
}

// lockCredentialsSync serializes credential reconciliation across seki
// sessions. Like lockClaudeJSONSync it only guards seki against seki; Claude
// Code's own atomic renames keep individual files consistent regardless.
func lockCredentialsSync(home string) (func(), error) {
	return flockPath(filepath.Join(home, ".claude-profiles", ".credentials.seki-lock"))
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.seki-tmp%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
