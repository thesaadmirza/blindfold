package main

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// AuditEntry is one line of the audit log: a secret used, or a use refused.
// Paths are kept, since they're what an investigation needs; query strings
// are not, since they can carry data.
type AuditEntry struct {
	Time     string `json:"ts"`
	Decision string `json:"decision"`
	Secret   string `json:"secret,omitempty"`
	Project  string `json:"project,omitempty"`
	Method   string `json:"method,omitempty"`
	Host     string `json:"host"`
	Path     string `json:"path,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Decisions in the audit log
const (
	auditFilled      = "filled"           // the value went into the request
	auditEchoed      = "echoed"           // the response held the value; it was scrubbed
	auditWrongHost   = "refused-host"     // request for another host inside a tunnel
	auditWrongUser   = "refused-username" // basic auth with a username the policy doesn't allow
	auditMissing     = "refused-missing"  // no stored value to fill in
	auditEncoding    = "refused-encoding" // a response Blindfold couldn't check
	auditOutsideSlot = "outside-slot"     // placeholder sent somewhere other than its slot
	auditPlainHTTP   = "plain-http"       // placeholder sent over plain HTTP, never filled
)

func (p *Proxy) auditLog(e AuditEntry) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	p.audit(e)
}

// placeholdersIn returns which of names have a placeholder in the request's
// headers or URL. The body isn't read.
func placeholdersIn(r *http.Request, names []string) []string {
	var found []string
	for _, name := range names {
		ph := placeholder(name)
		if strings.Contains(r.URL.RawQuery, ph) || strings.Contains(r.URL.Path, ph) || headerContains(r.Header, ph) {
			found = append(found, name)
		}
	}
	slices.Sort(found)
	return found
}

func headerContains(h http.Header, s string) bool {
	for _, vals := range h {
		for _, v := range vals {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}
