package handler

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
)

func TestReportTaskPermissionDenialsPostsSystemComment(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()

	agentID := createHandlerTestAgent(t, "PermissionDenials", []byte("[]"))
	issueID := dbfx.Issue(t, "permission denials issue")
	taskID := dbfx.Task(t, agentID, testutil.Cols{
		"runtime_id": handlerTestRuntimeID(t),
		"issue_id":   issueID,
		"status":     "running",
	})

	req := newOwnerDaemonRequest("POST", "/api/daemon/tasks/"+taskID+"/permission-denials", map[string]any{
		"denials": []map[string]any{{
			"tool":        "Bash",
			"input":       "rm -rf ../remote.git .\x00",
			"reason_type": "safetyCheck",
			"reason":      "Dangerous rm operation",
		}},
	})
	testutil.Call(t, testHandler.ReportTaskPermissionDenials, withURLParam(req, "taskId", taskID)).Want(http.StatusOK)

	var commentType, authorType, authorID, sourceTaskID, content string
	if err := testPool.QueryRow(ctx, `
		SELECT type, author_type, author_id::text, COALESCE(source_task_id::text, ''), content
		FROM comment WHERE issue_id = $1
	`, issueID).Scan(&commentType, &authorType, &authorID, &sourceTaskID, &content); err != nil {
		t.Fatalf("load comment: %v", err)
	}
	// A system author keeps HasAgentCommentedSince false, so the agent's own
	// reply still gets its fallback comment when the run completes.
	if commentType != "system" || authorType != "system" || sourceTaskID != taskID {
		t.Fatalf("comment = type %q, author %s/%s, source task %q; want system comment from task %s",
			commentType, authorType, authorID, sourceTaskID, taskID)
	}
	if !strings.Contains(content, "Bash: `rm -rf ../remote.git .`") || !strings.Contains(content, "safetyCheck: Dangerous rm operation") {
		t.Fatalf("comment content missing the denial:\n%s", content)
	}
	if strings.ContainsRune(content, 0) {
		t.Fatalf("comment content kept a NUL byte: %q", content)
	}
}
