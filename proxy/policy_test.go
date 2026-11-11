package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadsAPolicy(t *testing.T) {
	path := writePolicy(t, `
[secrets.GITLAB_TOKEN]
hosts  = ["GitLab.com"]
header = "private-token"

[secrets.REGISTRY_PASSWORD]
hosts      = ["registry.example.com"]
basic_auth = { username = "deploy-bot" }

[secrets.MAPS_KEY]
hosts = ["maps.googleapis.com", "gitlab.com"]
query = "key"
`)

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := p.Names(); !slices.Equal(got, []string{"GITLAB_TOKEN", "MAPS_KEY", "REGISTRY_PASSWORD"}) {
		t.Fatalf("names = %v", got)
	}
	if got := p.Hosts(); !slices.Equal(got, []string{"gitlab.com", "maps.googleapis.com", "registry.example.com"}) {
		t.Fatalf("hosts = %v", got)
	}
	if h := p.Secrets["GITLAB_TOKEN"].Header; h != "Private-Token" {
		t.Fatalf("header not canonical: %q", h)
	}
	if u := p.Secrets["REGISTRY_PASSWORD"].BasicAuth.Username; u != "deploy-bot" {
		t.Fatalf("username = %q", u)
	}
	if got := p.RulesFor("gitlab.com"); len(got) != 2 {
		t.Fatalf("rules for gitlab.com = %v", got)
	}
	if got := p.RulesFor("evil.example"); len(got) != 0 {
		t.Fatalf("rules for an unknown host = %v", got)
	}
}

func TestMissingPolicyIsEmpty(t *testing.T) {
	p, err := LoadPolicy(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Secrets) != 0 {
		t.Fatalf("secrets = %v", p.Secrets)
	}
}

func TestRejectsUnsafePolicies(t *testing.T) {
	cases := map[string]string{
		"wildcard host":    `[secrets.A]` + "\n" + `hosts = ["*.github.io"]` + "\n" + `header = "X"`,
		"bare host":        `[secrets.A]` + "\n" + `hosts = ["localhost"]` + "\n" + `header = "X"`,
		"host with port":   `[secrets.A]` + "\n" + `hosts = ["gitlab.com:8443"]` + "\n" + `header = "X"`,
		"host with scheme": `[secrets.A]` + "\n" + `hosts = ["https://gitlab.com"]` + "\n" + `header = "X"`,
		"ip address":       `[secrets.A]` + "\n" + `hosts = ["10.0.0.1"]` + "\n" + `header = "X"`,
		"no hosts":         `[secrets.A]` + "\n" + `header = "X"`,
		"no slot":          `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]`,
		"two slots":        `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "X"` + "\n" + `query = "key"`,
		"framing header":   `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "host"`,
		"odd query name":   `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `query = "a&b"`,
		"reserved name":    `[secrets.PATH]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "X"`,
		"loader variable":  `[secrets.DYLD_INSERT_LIBRARIES]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "X"`,
		"bad name":         `[secrets."A-B"]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "X"`,
		"typo in a key":    `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `hedaer = "X"`,
		"unknown approve":  `[secrets.A]` + "\n" + `hosts = ["gitlab.com"]` + "\n" + `header = "X"` + "\n" + `approve = "sometimes"`,
		"not toml":         `this is not toml`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy(writePolicy(t, body)); err == nil {
				t.Fatal("policy was accepted")
			}
		})
	}
}

func TestErrorsNameTheFile(t *testing.T) {
	path := writePolicy(t, `[secrets.A]`+"\n"+`hosts = ["*.x.com"]`+"\n"+`header = "X"`)

	_, err := LoadPolicy(path)

	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "secrets.A") {
		t.Fatalf("err = %v", err)
	}
}

func TestApproveSetting(t *testing.T) {
	cases := []struct {
		approve, method string
		ask             bool
	}{
		{"", "POST", false},
		{"never", "DELETE", false},
		{"writes", "GET", false},
		{"writes", "HEAD", false},
		{"writes", "POST", true},
		{"writes", "PATCH", true},
		{"writes", "OPTIONS", true},
		{"always", "GET", true},
	}
	for _, c := range cases {
		body := "[secrets.A]\nhosts = [\"gitlab.com\"]\nheader = \"X\"\n"
		if c.approve != "" {
			body += "approve = \"" + c.approve + "\"\n"
		}
		p, err := LoadPolicy(writePolicy(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Secrets["A"].NeedsApproval(c.method); got != c.ask {
			t.Errorf("approve=%q %s: asks = %v", c.approve, c.method, got)
		}
	}
}
