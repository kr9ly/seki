//go:build linux

package netns

import (
	"encoding/json"
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
	host := []byte(`{"oauthAccount":{"accountUuid":"host"},"mcpServers":{"skeleton":{}}}`)
	stored := []byte(`{"accountUuid":"profile"}`)

	out, err := swapOAuthAccount(host, stored)
	if err != nil {
		t.Fatalf("swapOAuthAccount: %v", err)
	}
	m := parseTop(t, out)
	if got := accountUUID(t, m["oauthAccount"]); got != "profile" {
		t.Errorf("oauthAccount uuid = %q, want profile's", got)
	}
	if _, ok := m["mcpServers"]; !ok {
		t.Error("mcpServers dropped — shared state must survive the swap")
	}
}

func TestSwapOAuthAccountStripsWhenStoreEmpty(t *testing.T) {
	host := []byte(`{"oauthAccount":{"accountUuid":"host"},"numStartups":3}`)

	for _, stored := range [][]byte{nil, {}, []byte("not json")} {
		out, err := swapOAuthAccount(host, stored)
		if err != nil {
			t.Fatalf("swapOAuthAccount: %v", err)
		}
		m := parseTop(t, out)
		if _, ok := m["oauthAccount"]; ok {
			t.Errorf("stored=%q: oauthAccount survived, want stripped so Claude Code re-fetches identity", stored)
		}
	}
}

func TestSwapOAuthAccountEmptyHost(t *testing.T) {
	out, err := swapOAuthAccount(nil, []byte(`{"accountUuid":"p"}`))
	if err != nil {
		t.Fatalf("swapOAuthAccount: %v", err)
	}
	m := parseTop(t, out)
	if got := accountUUID(t, m["oauthAccount"]); got != "p" {
		t.Errorf("oauthAccount uuid = %q", got)
	}
}

func TestSwapOAuthAccountBadHost(t *testing.T) {
	if _, err := swapOAuthAccount([]byte("not json"), nil); err == nil {
		t.Error("want error on unparseable host file")
	}
}

func TestMergeClaudeJSONKeepsHostIdentity(t *testing.T) {
	host := []byte(`{"oauthAccount":{"accountUuid":"host"},"numStartups":1}`)
	session := []byte(`{"oauthAccount":{"accountUuid":"profile"},"numStartups":2}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	m := parseTop(t, out)
	if got := accountUUID(t, m["oauthAccount"]); got != "host" {
		t.Errorf("oauthAccount uuid = %q, want host's — session identity must not leak to the host file", got)
	}
	if string(m["numStartups"]) != "2" {
		t.Errorf("numStartups = %s, want session's value 2", m["numStartups"])
	}
}

func TestMergeClaudeJSONNoHostIdentity(t *testing.T) {
	host := []byte(`{}`)
	session := []byte(`{"oauthAccount":{"accountUuid":"profile"}}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	m := parseTop(t, out)
	if _, ok := m["oauthAccount"]; ok {
		t.Error("session oauthAccount copied onto a host file that had none")
	}
}

func TestMergeClaudeJSONProjectsPerKey(t *testing.T) {
	host := []byte(`{"projects":{"/a":{"trust":"old"},"/b":{"trust":"kept"}}}`)
	session := []byte(`{"projects":{"/a":{"trust":"new"}}}`)

	out, err := mergeClaudeJSON(host, session)
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	m := parseTop(t, out)
	var projects map[string]map[string]string
	if err := json.Unmarshal(m["projects"], &projects); err != nil {
		t.Fatalf("projects: %v", err)
	}
	if projects["/a"]["trust"] != "new" {
		t.Errorf("/a trust = %q, want session's update", projects["/a"]["trust"])
	}
	if projects["/b"]["trust"] != "kept" {
		t.Errorf("/b trust = %q, want host entry preserved against stale session snapshot", projects["/b"]["trust"])
	}
}

func TestMergeClaudeJSONCorruptHost(t *testing.T) {
	out, err := mergeClaudeJSON([]byte("garbage"), []byte(`{"numStartups":5}`))
	if err != nil {
		t.Fatalf("mergeClaudeJSON: %v", err)
	}
	m := parseTop(t, out)
	if string(m["numStartups"]) != "5" {
		t.Errorf("numStartups = %s", m["numStartups"])
	}
}

func TestSameAccount(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"match", `{"accountUuid":"x"}`, `{"accountUuid":"x","emailAddress":"e"}`, true},
		{"differ", `{"accountUuid":"x"}`, `{"accountUuid":"y"}`, false},
		{"missing uuid", `{}`, `{}`, false},
		{"unparseable", `nope`, `{"accountUuid":"x"}`, false},
	}
	for _, c := range cases {
		if got := sameAccount([]byte(c.a), []byte(c.b)); got != c.want {
			t.Errorf("%s: sameAccount = %v, want %v", c.name, got, c.want)
		}
	}
}
