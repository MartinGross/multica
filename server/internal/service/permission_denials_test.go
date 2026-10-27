package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestPermissionDenialsNotice(t *testing.T) {
	got := PermissionDenialsNotice([]PermissionDenial{
		{Tool: "Bash", Input: "rm -rf ../remote.git .", ReasonType: "safetyCheck", Reason: "Dangerous rm operation"},
		{Tool: "Bash", Input: "echo `whoami`", ReasonType: "classifier"},
		{Tool: "auto review", ReasonType: "high", Reason: "uploads credentials"},
	})
	want := "Blocked by the agent's permission check and not executed:\n" +
		"\n- Bash: `rm -rf ../remote.git .` (safetyCheck: Dangerous rm operation)" +
		"\n- Bash: `echo 'whoami'` (classifier)" +
		"\n- auto review (high: uploads credentials)" +
		"\n\nTo allow an action, run it yourself or add an allow rule for it and trigger the agent again."
	if got != want {
		t.Fatalf("notice mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestPermissionDenialsNoticeCapsList(t *testing.T) {
	denials := make([]PermissionDenial, MaxPermissionDenialsPerComment+3)
	for i := range denials {
		denials[i] = PermissionDenial{Tool: "Bash", Input: fmt.Sprintf("cmd-%d", i)}
	}
	got := PermissionDenialsNotice(denials)
	if strings.Contains(got, fmt.Sprintf("cmd-%d", MaxPermissionDenialsPerComment)) {
		t.Fatalf("notice lists more than %d denials:\n%s", MaxPermissionDenialsPerComment, got)
	}
	if !strings.Contains(got, "…and 3 more") {
		t.Fatalf("notice does not count the hidden denials:\n%s", got)
	}
}

func TestNotePermissionDenialsSkipsTasksWithoutIssue(t *testing.T) {
	// Queries is nil: reaching the database here would panic.
	s := &TaskService{}
	s.NotePermissionDenials(context.Background(), db.AgentTaskQueue{}, []PermissionDenial{{Tool: "Bash", Input: "git push --force"}})
}
