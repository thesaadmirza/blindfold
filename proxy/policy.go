package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Policy says where each secret may be sent and in which part of the request.
// It holds names and rules, never values.
type Policy struct {
	Secrets map[string]*Rule `toml:"secrets"`
}

// Rule is one [secrets.NAME] table. Exactly one of Header, BasicAuth and
// Query is set: the value only ever goes in that one place.
type Rule struct {
	Hosts     []string   `toml:"hosts"`
	Header    string     `toml:"header"`
	BasicAuth *BasicAuth `toml:"basic_auth"`
	Query     string     `toml:"query"`
}

type BasicAuth struct {
	// Username, when set, must match the one the client sends
	Username string `toml:"username"`
}

var (
	secretName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	queryName  = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)
)

// The guard exports each secret name as an environment variable holding its
// placeholder, so a name that shadows one of these would break the sandbox.
var reservedNames = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "PWD", "OLDPWD", "IFS",
	"ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4", "LANG", "TERM",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
	"GIT_SSL_CAINFO", "PIP_CERT",
}

// Headers that carry framing or routing; putting a secret in them makes no sense
var forbiddenHeaders = []string{
	"Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade",
	"Te", "Trailer", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization",
}

// LoadPolicy reads a policy file. A missing file is an empty policy, so
// lockdown works before anyone writes one.
func LoadPolicy(path string) (*Policy, error) {
	p := &Policy{}
	meta, err := toml.DecodeFile(path, p)
	if errors.Is(err, fs.ErrNotExist) {
		return &Policy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// A typo like "hosst" must not silently drop a rule
	if extra := meta.Undecoded(); len(extra) > 0 {
		return nil, fmt.Errorf("%s: unknown key %q", path, extra[0].String())
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func (p *Policy) validate() error {
	for name, r := range p.Secrets {
		if !secretName.MatchString(name) {
			return fmt.Errorf("secrets.%s: names may only use letters, digits and _", name)
		}
		if slices.Contains(reservedNames, strings.ToUpper(name)) {
			return fmt.Errorf("secrets.%s: that name is reserved for the sandbox's own environment", name)
		}
		if err := r.validate(); err != nil {
			return fmt.Errorf("secrets.%s: %w", name, err)
		}
	}
	return nil
}

func (r *Rule) validate() error {
	if len(r.Hosts) == 0 {
		return errors.New("hosts is empty")
	}
	for i, h := range r.Hosts {
		if err := checkHost(h); err != nil {
			return err
		}
		r.Hosts[i] = strings.ToLower(h)
	}

	slots := 0
	if r.Header != "" {
		slots++
		r.Header = http.CanonicalHeaderKey(r.Header)
		if slices.Contains(forbiddenHeaders, r.Header) {
			return fmt.Errorf("header %q can't carry a secret", r.Header)
		}
	}
	if r.BasicAuth != nil {
		slots++
	}
	if r.Query != "" {
		slots++
		if !queryName.MatchString(r.Query) {
			return fmt.Errorf("query %q is not a plain parameter name", r.Query)
		}
	}
	if slots != 1 {
		return errors.New("set exactly one of header, basic_auth and query")
	}
	return nil
}

// checkHost accepts exact DNS names only. No wildcards, since *.github.io
// would hand the secret to anyone who can make a subdomain, and no IPs or
// ports, which the local CA can't constrain by name.
func checkHost(h string) error {
	if strings.Contains(h, "*") {
		return fmt.Errorf("host %q: wildcards are not allowed", h)
	}
	if net.ParseIP(h) != nil {
		return fmt.Errorf("host %q: use a domain name, not an IP address", h)
	}
	labels := strings.Split(strings.ToLower(h), ".")
	if len(labels) < 2 {
		return fmt.Errorf("host %q: use a full domain name", h)
	}
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return fmt.Errorf("host %q is not a plain domain name", h)
		}
	}
	return nil
}

// Names returns the secret names in a stable order
func (p *Policy) Names() []string { return slices.Sorted(maps.Keys(p.Secrets)) }

// Hosts returns every host any rule names, sorted and without repeats
func (p *Policy) Hosts() []string {
	var hosts []string
	for _, r := range p.Secrets {
		hosts = append(hosts, r.Hosts...)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// RulesFor returns the secrets that may be sent to host
func (p *Policy) RulesFor(host string) map[string]*Rule {
	out := map[string]*Rule{}
	for name, r := range p.Secrets {
		if slices.Contains(r.Hosts, host) {
			out[name] = r
		}
	}
	return out
}

func placeholder(name string) string { return "{{" + name + "}}" }
