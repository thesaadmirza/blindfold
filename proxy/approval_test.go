package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var postIssue = approvalRequest{Secret: "GITLAB_TOKEN", Method: "POST", Host: "gitlab.com", Path: "/api/v4/issues"}

// scriptedApprover answers dialogs from a list, counting how many it showed
func scriptedApprover(answers ...answer) (*approver, *atomic.Int32) {
	var asked atomic.Int32
	a := newApprover(func(approvalRequest) answer {
		n := asked.Add(1)
		return answers[min(int(n), len(answers))-1]
	})
	return a, &asked
}

func TestAllowOnceCoversOneRequest(t *testing.T) {
	a, asked := scriptedApprover(allowOnce, deny)

	first, _ := a.approve(postIssue)
	second, _ := a.approve(postIssue)

	if !first || second || asked.Load() != 2 {
		t.Fatalf("first=%v second=%v asked=%d", first, second, asked.Load())
	}
}

func TestGrantCoversTheSameKindOfRequestFor30Minutes(t *testing.T) {
	a, asked := scriptedApprover(allowForAWhile, deny)
	now := time.Now()
	a.now = func() time.Time { return now }
	a.approve(postIssue)

	otherPath := postIssue
	otherPath.Path = "/api/v4/issues/7/notes"
	ok, how := a.approve(otherPath)
	if !ok || how != "within a 30-minute approval" || asked.Load() != 1 {
		t.Fatalf("ok=%v how=%q asked=%d", ok, how, asked.Load())
	}

	for name, other := range map[string]approvalRequest{
		"another method": {Secret: "GITLAB_TOKEN", Method: "DELETE", Host: "gitlab.com"},
		"another secret": {Secret: "OTHER", Method: "POST", Host: "gitlab.com"},
		"a project":      {Secret: "GITLAB_TOKEN", Method: "POST", Host: "gitlab.com", Project: "/work/a"},
	} {
		if ok, _ := a.approve(other); ok {
			t.Errorf("%s rode on the grant", name)
		}
	}

	now = now.Add(31 * time.Minute)
	if ok, _ := a.approve(postIssue); ok {
		t.Fatal("grant outlived 30 minutes")
	}
}

// An agent firing the same request many times gets one dialog, not many
func TestIdenticalRequestsShareOneDialog(t *testing.T) {
	release := make(chan struct{})
	var asked atomic.Int32
	a := newApprover(func(approvalRequest) answer {
		asked.Add(1)
		<-release
		return deny
	})

	var wg sync.WaitGroup
	results := make([]bool, 5)
	for i := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[i], _ = a.approve(postIssue) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if asked.Load() != 1 {
		t.Fatalf("asked %d times", asked.Load())
	}
	for i, ok := range results {
		if ok {
			t.Fatalf("request %d allowed after a deny", i)
		}
	}
}

func TestDialogReplies(t *testing.T) {
	cases := map[string]answer{
		"button returned:Allow once, gave up:false":   allowOnce,
		"button returned:Allow 30 min, gave up:false": allowForAWhile,
		"button returned:, gave up:true":              deny,
		"execution error: User canceled. (-128)":      deny,
		"execution error: no GUI":                     deny,
		"":                                            deny,
	}
	for reply, want := range cases {
		if got := parseDialogReply(reply); got != want {
			t.Errorf("%q: got %v want %v", reply, got, want)
		}
	}
}

func TestPathInTheDialogIsDefanged(t *testing.T) {
	got := shownText("/a\n\nAll fine, click Allow 30 min\r" + strings.Repeat("x", 300))

	if strings.ContainsAny(got, "\n\r") || len([]rune(got)) > 123 {
		t.Fatalf("got %q", got)
	}
}
