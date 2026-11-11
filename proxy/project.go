package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ProjectPolicyFile is the policy a project can ship in its root
const ProjectPolicyFile = ".blindfold.toml"

// Project is a project whose .blindfold.toml the user approved
type Project struct {
	Path   string
	Policy *Policy
}

// The private dir holds what the sandbox must neither read nor write:
//
//	tokens.tsv         one "token<TAB>id<TAB>project path" line per project
//	trusted/<id>.toml  the exact copy of a .blindfold.toml the user approved
//
// The token is secret: it's what a request shows to be from that project. The
// id only names files, so listing the folder gives no token away. The guard
// creates both, and the approval dialog writes trusted copies.
func tokensFile(private string) string { return filepath.Join(private, "tokens.tsv") }

func trustedFile(private, id string) string {
	return filepath.Join(private, "trusted", id+".toml")
}

type tokenEntry struct{ id, path string }

// readTokens maps each token to its project's id and path
func readTokens(private string) map[string]tokenEntry {
	tokens := map[string]tokenEntry{}
	f, err := os.Open(tokensFile(private))
	if err != nil {
		return tokens
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 3)
		if len(fields) == 3 && fields[0] != "" && fields[1] != "" && filepath.IsAbs(fields[2]) {
			tokens[fields[0]] = tokenEntry{id: fields[1], path: fields[2]}
		}
	}
	return tokens
}

// loadProjects returns the approved projects by token. A project counts only
// while its .blindfold.toml is byte for byte the copy the user approved, so an
// edit, by anyone, switches it off until it's approved again.
func loadProjects(private string) map[string]*Project {
	projects := map[string]*Project{}
	if private == "" {
		return projects
	}
	for token, e := range readTokens(private) {
		approved, err := os.ReadFile(trustedFile(private, e.id))
		if err != nil {
			continue
		}
		current, err := os.ReadFile(filepath.Join(e.path, ProjectPolicyFile))
		if err != nil || !bytes.Equal(current, approved) {
			continue
		}
		pol, err := ParsePolicy(approved)
		if err != nil {
			log.Printf("%s: %v", filepath.Join(e.path, ProjectPolicyFile), err)
			continue
		}
		projects[token] = &Project{Path: e.path, Policy: pol}
	}
	return projects
}

// projectsStamp changes whenever anything loadProjects reads changes
func projectsStamp(private string) string {
	if private == "" {
		return ""
	}
	var b strings.Builder
	tokens := readTokens(private)
	fmt.Fprint(&b, stamp(tokensFile(private)))
	for _, token := range slices.Sorted(maps.Keys(tokens)) {
		e := tokens[token]
		fmt.Fprint(&b, "|", e.id, stamp(trustedFile(private, e.id)), stamp(filepath.Join(e.path, ProjectPolicyFile)))
	}
	return b.String()
}

// proxyToken is the project token a client sent as its proxy password, from
// a proxy URL like http://blindfold:TOKEN@127.0.0.1:PORT
func proxyToken(r *http.Request) string {
	auth, ok := strings.CutPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
	if !ok {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return ""
	}
	_, token, _ := strings.Cut(string(raw), ":")
	return token
}
