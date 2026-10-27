package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/dbid"
	"github.com/multica-ai/multica/server/pkg/protocol"
	"github.com/multica-ai/multica/server/pkg/redact"
)

// MaxPermissionDenialsPerComment caps how many refused tool calls one comment
// lists; the rest are counted, not shown.
const MaxPermissionDenialsPerComment = 10

// PermissionDenial is one tool call the agent's provider refused to run.
type PermissionDenial struct {
	Tool       string
	Input      string
	ReasonType string
	Reason     string
}

// NotePermissionDenials posts the tool calls a run was refused as a system
// comment on the task's issue, so a person can decide whether to allow them.
// Chat and other issue-less tasks have nowhere to post and are skipped.
//
// The daemon reports denials before /complete, so the comment is authored by
// "system", not the agent: HasAgentCommentedSince counts every agent-authored
// comment, and an agent-authored notice would suppress the fallback comment
// that carries the agent's actual reply.
func (s *TaskService) NotePermissionDenials(ctx context.Context, task db.AgentTaskQueue, denials []PermissionDenial) {
	if !task.IssueID.Valid || len(denials) == 0 {
		return
	}
	issue, err := s.Queries.GetIssue(ctx, task.IssueID)
	if err != nil {
		slog.Warn("permission denials: load issue failed",
			"error", err, "task_id", util.UUIDToString(task.ID))
		return
	}
	content := truncateFallbackCommentBody(redact.Text(PermissionDenialsNotice(denials)), maxSynthesizedFallbackCommentRunes)
	// author_type='system', author_id=zero UUID, as in noteRuntimeUnusable.
	created, err := s.Queries.CreateComment(ctx, db.CreateCommentParams{
		ID:           dbid.NewV7(),
		IssueID:      issue.ID,
		WorkspaceID:  issue.WorkspaceID,
		AuthorType:   "system",
		AuthorID:     pgtype.UUID{Valid: true},
		Content:      content,
		Type:         "system",
		ParentID:     task.TriggerCommentID,
		SourceTaskID: task.ID,
	})
	if err != nil {
		slog.Warn("permission denials: create system comment failed",
			"error", err, "task_id", util.UUIDToString(task.ID))
		return
	}
	if s.Bus == nil {
		return
	}
	comment := created.Comment()
	commentFields := commentEventFields(comment)
	commentFields["revision"] = comment.Revision
	s.Bus.Publish(events.Event{
		Type:        protocol.EventCommentCreated,
		WorkspaceID: util.UUIDToString(issue.WorkspaceID),
		ActorType:   "system",
		Payload: map[string]any{
			"comment":        commentFields,
			"issue_title":    issue.Title,
			"issue_status":   issue.Status,
			"issue_revision": created.IssueRevision,
		},
	})
}

// PermissionDenialsNotice renders the comment body for refused tool calls.
func PermissionDenialsNotice(denials []PermissionDenial) string {
	var b strings.Builder
	b.WriteString("Blocked by the agent's permission check and not executed:\n")
	shown := denials
	if len(shown) > MaxPermissionDenialsPerComment {
		shown = shown[:MaxPermissionDenialsPerComment]
	}
	for _, d := range shown {
		b.WriteString("\n- ")
		label := d.Tool
		if label == "" {
			label = "tool call"
		}
		if d.Input != "" {
			fmt.Fprintf(&b, "%s: `%s`", label, strings.ReplaceAll(d.Input, "`", "'"))
		} else {
			b.WriteString(label)
		}
		switch {
		case d.ReasonType != "" && d.Reason != "":
			fmt.Fprintf(&b, " (%s: %s)", d.ReasonType, d.Reason)
		case d.ReasonType != "":
			fmt.Fprintf(&b, " (%s)", d.ReasonType)
		case d.Reason != "":
			fmt.Fprintf(&b, " (%s)", d.Reason)
		}
	}
	if rest := len(denials) - len(shown); rest > 0 {
		fmt.Fprintf(&b, "\n- …and %d more", rest)
	}
	b.WriteString("\n\nTo allow an action, run it yourself or add an allow rule for it and trigger the agent again.")
	return b.String()
}
