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
//	tokens.tsv            one "token<TAB>project path" line per project
//	trusted/<token>.toml  the exact copy of a .blindfold.toml the user approved
//
// The guard creates tokens and the approval dialog writes trusted copies.
func tokensFile(private string) string { return filepath.Join(private, "tokens.tsv") }

func trustedFile(private, token string) string {
	return filepath.Join(private, "trusted", token+".toml")
}

// readTokens maps each token to its project path
func readTokens(private string) map[string]string {
	tokens := map[string]string{}
	f, err := os.Open(tokensFile(private))
	if err != nil {
		return tokens
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		token, path, ok := strings.Cut(sc.Text(), "\t")
		if ok && token != "" && filepath.IsAbs(path) {
			tokens[token] = path
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
	for token, path := range readTokens(private) {
		approved, err := os.ReadFile(trustedFile(private, token))
		if err != nil {
			continue
		}
		current, err := os.ReadFile(filepath.Join(path, ProjectPolicyFile))
		if err != nil || !bytes.Equal(current, approved) {
			continue
		}
		pol, err := ParsePolicy(approved)
		if err != nil {
			log.Printf("%s: %v", filepath.Join(path, ProjectPolicyFile), err)
			continue
		}
		projects[token] = &Project{Path: path, Policy: pol}
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
		path := filepath.Join(tokens[token], ProjectPolicyFile)
		fmt.Fprint(&b, "|", token, stamp(trustedFile(private, token)), stamp(path))
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
