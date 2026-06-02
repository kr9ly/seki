package profile

import "testing"

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
