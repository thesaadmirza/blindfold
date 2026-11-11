package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const projectPolicy = "[secrets.PROJECT_KEY]\nhosts = [\"api.example.com\"]\nheader = \"X-Key\"\n"

// setupProject makes a private dir with one project token, writes the
// project's .blindfold.toml, and approves the given content
func setupProject(t *testing.T, current, approved string) (private, project string) {
	t.Helper()
	private, project = t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(private, "trusted"), 0o700)
	os.WriteFile(tokensFile(private), []byte("tok1\t"+project+"\n"), 0o600)
	if current != "" {
		os.WriteFile(filepath.Join(project, ProjectPolicyFile), []byte(current), 0o600)
	}
	if approved != "" {
		os.WriteFile(trustedFile(private, "tok1"), []byte(approved), 0o600)
	}
	return private, project
}

func TestApprovedProjectIsLoaded(t *testing.T) {
	private, project := setupProject(t, projectPolicy, projectPolicy)

	got := loadProjects(private)

	if p := got["tok1"]; p == nil || p.Path != project || p.Policy.Secrets["PROJECT_KEY"] == nil {
		t.Fatalf("projects = %+v", got)
	}
}

func TestProjectsThatAreNotApprovedAreIgnored(t *testing.T) {
	cases := map[string][2]string{
		"never approved":       {projectPolicy, ""},
		"edited since":         {projectPolicy + "\n# one more line\n", projectPolicy},
		"file removed":         {"", projectPolicy},
		"approved but invalid": {"[secrets.X]\nhosts = [\"*.a.com\"]\nheader = \"X\"\n", "[secrets.X]\nhosts = [\"*.a.com\"]\nheader = \"X\"\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			private, _ := setupProject(t, c[0], c[1])

			if got := loadProjects(private); len(got) != 0 {
				t.Fatalf("projects = %+v", got)
			}
		})
	}
}

func TestProjectsStampIsStableAndSeesEdits(t *testing.T) {
	private, project := setupProject(t, projectPolicy, projectPolicy)
	os.WriteFile(tokensFile(private), []byte("tok1\t"+project+"\ntok2\t"+t.TempDir()+"\ntok3\t/x\n"), 0o600)
	first := projectsStamp(private)

	for i := 0; i < 20; i++ {
		if projectsStamp(private) != first {
			t.Fatal("stamp changed with nothing edited")
		}
	}
	os.WriteFile(filepath.Join(project, ProjectPolicyFile), []byte(projectPolicy+"\n"), 0o600)
	if projectsStamp(private) == first {
		t.Fatal("stamp missed an edit to the project policy")
	}
}

func TestProxyTokenComesFromTheProxyPassword(t *testing.T) {
	r, _ := http.NewRequest("CONNECT", "http://x", nil)
	r.SetBasicAuth("blindfold", "tok1")
	r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))

	if got := proxyToken(r); got != "tok1" {
		t.Fatalf("token = %q", got)
	}
	if got := proxyToken(&http.Request{Header: http.Header{}}); got != "" {
		t.Fatalf("token without a header = %q", got)
	}
}
