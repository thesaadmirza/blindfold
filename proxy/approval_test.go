package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var postIssue = approvalRequest{Secret: "GITLAB_TOKEN", Method: "POST", Host: "gitlab.com", Path: "/api/v4/issues"}

// scriptedApprover answers dialogs from a list, counting how many it showed
func scriptedApprover(answers ...answer) (*approver, *atomic.Int32) {
	var asked atomic.Int32
	a := newApprover(func(context.Context, approvalRequest) answer {
		n := asked.Add(1)
		return answers[min(int(n), len(answers))-1]
	})
	return a, &asked
}

func TestAllowOnceCoversOneRequest(t *testing.T) {
	a, asked := scriptedApprover(allowOnce, deny)

	first := a.approve(context.Background(), postIssue)
	second := a.approve(context.Background(), postIssue)

	if first != allowOnce || second != deny || asked.Load() != 2 {
		t.Fatalf("first=%v second=%v asked=%d", first, second, asked.Load())
	}
}

func TestGrantCoversTheSameKindOfRequestForAWhile(t *testing.T) {
	a, asked := scriptedApprover(allowForAWhile, deny)
	now := time.Now()
	a.now = func() time.Time { return now }
	a.approve(context.Background(), postIssue)

	otherPath := postIssue
	otherPath.Path = "/api/v4/issues/7/notes"
	if got := a.approve(context.Background(), otherPath); got != granted || asked.Load() != 1 {
		t.Fatalf("got %v, asked %d", got, asked.Load())
	}

	for name, other := range map[string]approvalRequest{
		"another method": {Secret: "GITLAB_TOKEN", Method: "DELETE", Host: "gitlab.com"},
		"another secret": {Secret: "OTHER", Method: "POST", Host: "gitlab.com"},
		"a project":      {Secret: "GITLAB_TOKEN", Method: "POST", Host: "gitlab.com", Project: "/work/a"},
	} {
		if got := a.approve(context.Background(), other); got.allowed() {
			t.Errorf("%s rode on the grant", name)
		}
	}

	now = now.Add(grantLength + time.Minute)
	if got := a.approve(context.Background(), postIssue); got.allowed() {
		t.Fatal("grant outlived its length")
	}
}

// An agent firing the same request many times gets one dialog, not many.
// The answer is a grant, so a request that arrives after the dialog closed
// is covered too, and the count can't depend on timing.
func TestIdenticalRequestsShareOneDialog(t *testing.T) {
	release := make(chan struct{})
	var asked atomic.Int32
	a := newApprover(func(context.Context, approvalRequest) answer {
		asked.Add(1)
		<-release
		return allowForAWhile
	})

	var wg sync.WaitGroup
	results := make([]answer, 5)
	for i := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[i] = a.approve(context.Background(), postIssue) }()
	}
	close(release)
	wg.Wait()

	if asked.Load() != 1 {
		t.Fatalf("asked %d times", asked.Load())
	}
	for i, got := range results {
		if !got.allowed() {
			t.Fatalf("request %d: %v", i, got)
		}
	}
}

func TestClientThatGivesUpStopsWaiting(t *testing.T) {
	a := newApprover(func(ctx context.Context, _ approvalRequest) answer {
		<-ctx.Done() // a dialog nobody answers, closed when the request ends
		return gaveUp
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if got := a.approve(ctx, postIssue); got.allowed() {
		t.Fatalf("got %v", got)
	}
	if got := a.approve(ctx, postIssue); got.allowed() {
		t.Fatalf("a request with a dead client got %v", got)
	}
}

func TestAnswersDescribeThemselves(t *testing.T) {
	want := map[answer]string{
		deny:           "denied",
		allowOnce:      "approved once",
		allowForAWhile: "approved for 30 minutes",
		granted:        "within a 30-minute approval",
		gaveUp:         "the client gave up waiting",
	}
	for a, s := range want {
		if a.String() != s {
			t.Errorf("%d: %q", a, a.String())
		}
	}
}
