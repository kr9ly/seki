package profile

import (
	"encoding/json"
	"testing"
)

func TestResolve(t *testing.T) {
	cfg := &Config{
		Default: "personal",
		Projects: []ProjectMapping{
			{Match: "/home/user/projects/kurashiru-*", Profile: "work"},
			{Match: "/home/user/projects/nell-*", Profile: "work"},
		},
	}

	tests := []struct {
		cwd  string
		want string
	}{
		{"/home/user/projects/kurashiru-android", "work"},
		{"/home/user/projects/nell-api-replace", "work"},
		{"/home/user/projects/seki", "personal"},
		{"/home/user/projects/muchi", "personal"},
	}

	for _, tt := range tests {
		got := cfg.Resolve(tt.cwd)
		if got != tt.want {
			t.Errorf("Resolve(%q) = %q, want %q", tt.cwd, got, tt.want)
		}
	}
}

func TestResolveNoDefault(t *testing.T) {
	cfg := &Config{
		Projects: []ProjectMapping{
			{Match: "/home/user/projects/work-*", Profile: "work"},
		},
	}

	if got := cfg.Resolve("/home/user/projects/personal"); got != "" {
		t.Errorf("Resolve with no default = %q, want empty", got)
	}
	if got := cfg.Resolve("/home/user/projects/work-repo"); got != "work" {
		t.Errorf("Resolve work pattern = %q, want work", got)
	}
}

func TestResolveNilConfig(t *testing.T) {
	var cfg *Config
	if got := cfg.Resolve("/any/path"); got != "" {
		t.Errorf("Resolve on nil config = %q, want empty", got)
	}
}

func TestResolveFirstMatch(t *testing.T) {
	cfg := &Config{
		Projects: []ProjectMapping{
			{Match: "/home/user/projects/app-*", Profile: "team-a"},
			{Match: "/home/user/projects/app-*", Profile: "team-b"},
		},
	}

	if got := cfg.Resolve("/home/user/projects/app-foo"); got != "team-a" {
		t.Errorf("first match = %q, want team-a", got)
	}
}

func TestGlobalConfigServicesparse(t *testing.T) {
	raw := `{
		"sandbox_env": {"FOO": "bar"},
		"services": [
			{
				"name": "test-svc",
				"command": ["sleep", "1000"],
				"ready_socket": "$XDG_RUNTIME_DIR/test.sock",
				"ready_timeout_sec": 30,
				"stop_command": ["echo", "stopping"],
				"env": {"EXTRA": "val"}
			}
		]
	}`
	var gc GlobalConfig
	if err := json.Unmarshal([]byte(raw), &gc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(gc.Services) != 1 {
		t.Fatalf("want 1 service, got %d", len(gc.Services))
	}
	svc := gc.Services[0]
	if svc.Name != "test-svc" {
		t.Errorf("Name = %q, want test-svc", svc.Name)
	}
	if len(svc.Command) != 2 || svc.Command[0] != "sleep" || svc.Command[1] != "1000" {
		t.Errorf("Command = %v, want [sleep 1000]", svc.Command)
	}
	if svc.ReadySocket != "$XDG_RUNTIME_DIR/test.sock" {
		t.Errorf("ReadySocket = %q, want $XDG_RUNTIME_DIR/test.sock", svc.ReadySocket)
	}
	if svc.ReadyTimeoutSec != 30 {
		t.Errorf("ReadyTimeoutSec = %d, want 30", svc.ReadyTimeoutSec)
	}
	if len(svc.StopCommand) != 2 || svc.StopCommand[0] != "echo" {
		t.Errorf("StopCommand = %v, want [echo stopping]", svc.StopCommand)
	}
	if svc.Env["EXTRA"] != "val" {
		t.Errorf("Env[EXTRA] = %q, want val", svc.Env["EXTRA"])
	}
	if gc.SandboxEnv["FOO"] != "bar" {
		t.Errorf("SandboxEnv[FOO] = %q, want bar", gc.SandboxEnv["FOO"])
	}
}

func TestGlobalConfigServicesEmpty(t *testing.T) {
	// services absent → empty slice, no error
	raw := `{"sandbox_env": {"X": "1"}}`
	var gc GlobalConfig
	if err := json.Unmarshal([]byte(raw), &gc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(gc.Services) != 0 {
		t.Errorf("want 0 services, got %d", len(gc.Services))
	}
}

func TestServiceDefaults(t *testing.T) {
	// ready_timeout_sec absent → zero (caller defaults to 15)
	raw := `{"services":[{"name":"s","command":["true"]}]}`
	var gc GlobalConfig
	if err := json.Unmarshal([]byte(raw), &gc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if gc.Services[0].ReadyTimeoutSec != 0 {
		t.Errorf("want 0, got %d", gc.Services[0].ReadyTimeoutSec)
	}
}

// TestMatchServicesNoMatch — match field absent → service applies to all cwds.
func TestMatchServicesNoMatch(t *testing.T) {
	services := []Service{
		{Name: "global-svc", Command: []string{"sleep", "1000"}},
	}
	got := MatchServices("/home/user/projects/any-project", services)
	if len(got) != 1 || got[0].Name != "global-svc" {
		t.Errorf("MatchServices with no match field = %v, want [global-svc]", got)
	}
}

// TestMatchServicesMatchHit — match field set and cwd matches → service included.
func TestMatchServicesMatchHit(t *testing.T) {
	services := []Service{
		{Name: "work-svc", Match: "/home/user/projects/work-*", Command: []string{"sleep", "1000"}},
	}
	got := MatchServices("/home/user/projects/work-repo", services)
	if len(got) != 1 || got[0].Name != "work-svc" {
		t.Errorf("MatchServices hit = %v, want [work-svc]", got)
	}
}

// TestMatchServicesMatchMiss — match field set but cwd does not match → service excluded.
func TestMatchServicesMatchMiss(t *testing.T) {
	services := []Service{
		{Name: "work-svc", Match: "/home/user/projects/work-*", Command: []string{"sleep", "1000"}},
	}
	got := MatchServices("/home/user/projects/personal-project", services)
	if len(got) != 0 {
		t.Errorf("MatchServices miss = %v, want []", got)
	}
}

// TestMatchServicesZeroAfterFilter — all services filtered out → empty slice (supervisor not started).
func TestMatchServicesZeroAfterFilter(t *testing.T) {
	services := []Service{
		{Name: "svc-a", Match: "/home/user/projects/a-*", Command: []string{"sleep", "1"}},
		{Name: "svc-b", Match: "/home/user/projects/b-*", Command: []string{"sleep", "2"}},
	}
	got := MatchServices("/home/user/projects/unrelated", services)
	if len(got) != 0 {
		t.Errorf("MatchServices all-filtered = %v, want []", got)
	}
}

// TestMatchServicesMixed — mix of match and no-match services.
func TestMatchServicesMixed(t *testing.T) {
	services := []Service{
		{Name: "global-svc", Command: []string{"sleep", "1000"}},
		{Name: "work-svc", Match: "/home/user/projects/work-*", Command: []string{"sleep", "1000"}},
		{Name: "other-svc", Match: "/home/user/projects/other-*", Command: []string{"sleep", "1000"}},
	}
	got := MatchServices("/home/user/projects/work-repo", services)
	if len(got) != 2 {
		t.Fatalf("MatchServices mixed = %d services, want 2", len(got))
	}
	if got[0].Name != "global-svc" || got[1].Name != "work-svc" {
		t.Errorf("MatchServices mixed names = [%s, %s], want [global-svc, work-svc]",
			got[0].Name, got[1].Name)
	}
}

// TestMatchServicesMatchParse — match field survives JSON round-trip.
func TestMatchServicesMatchParse(t *testing.T) {
	raw := `{"services":[
		{"name":"scoped","match":"/home/user/projects/myapp-*","command":["sleep","1"]},
		{"name":"global","command":["sleep","2"]}
	]}`
	var gc GlobalConfig
	if err := json.Unmarshal([]byte(raw), &gc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if gc.Services[0].Match != "/home/user/projects/myapp-*" {
		t.Errorf("Match = %q, want /home/user/projects/myapp-*", gc.Services[0].Match)
	}
	if gc.Services[1].Match != "" {
		t.Errorf("Match for global service = %q, want empty", gc.Services[1].Match)
	}

	// Verify filtering via MatchServices
	hit := MatchServices("/home/user/projects/myapp-backend", gc.Services)
	if len(hit) != 2 {
		t.Errorf("hit cwd: want 2 services, got %d", len(hit))
	}
	miss := MatchServices("/home/user/projects/unrelated", gc.Services)
	if len(miss) != 1 || miss[0].Name != "global" {
		t.Errorf("miss cwd: want [global], got %v", miss)
	}
}
