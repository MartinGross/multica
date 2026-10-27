package agent

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

// maxPermissionDenialInputRunes bounds the input summary so one huge command
// or patch cannot dominate the issue comment built from it.
const maxPermissionDenialInputRunes = 300

// summarizePermissionDenialInput reduces a tool input to one readable line:
// the shell command when there is one, else the file path, else compact JSON.
func summarizePermissionDenialInput(input json.RawMessage) string {
	if len(input) == 0 {
		return ""
	}
	var fields map[string]any
	if err := json.Unmarshal(input, &fields); err == nil {
		for _, key := range []string{"command", "file_path", "path", "url"} {
			if v, ok := fields[key].(string); ok && strings.TrimSpace(v) != "" {
				return clipPermissionDenialInput(v)
			}
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, input); err != nil {
		return clipPermissionDenialInput(string(input))
	}
	return clipPermissionDenialInput(compact.String())
}

func clipPermissionDenialInput(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) <= maxPermissionDenialInputRunes {
		return s
	}
	return string(runes[:maxPermissionDenialInputRunes]) + "…"
}

// claudePermissionDenials merges Claude Code's two denial signals. The
// mid-stream system/permission_denied event carries the reason but not the
// input; the result event's permission_denials list carries the input but not
// the reason. A run killed before its result event still reports the events.
type claudePermissionDenials struct {
	order []string
	byID  map[string]*PermissionDenial
}

func newClaudePermissionDenials() *claudePermissionDenials {
	return &claudePermissionDenials{byID: make(map[string]*PermissionDenial)}
}

func (c *claudePermissionDenials) entry(toolUseID, toolName string) *PermissionDenial {
	key := toolUseID
	if key == "" {
		key = "#" + strconv.Itoa(len(c.order))
	}
	d, ok := c.byID[key]
	if !ok {
		d = &PermissionDenial{}
		c.byID[key] = d
		c.order = append(c.order, key)
	}
	if d.Tool == "" {
		d.Tool = toolName
	}
	return d
}

func (c *claudePermissionDenials) observeEvent(msg claudeSDKMessage) {
	d := c.entry(msg.ToolUseID, msg.ToolName)
	d.ReasonType = msg.DecisionReasonType
	d.Reason = clipPermissionDenialInput(msg.DecisionReason)
}

func (c *claudePermissionDenials) observeResult(list []claudePermissionDenial) {
	for _, item := range list {
		d := c.entry(item.ToolUseID, item.ToolName)
		if summary := summarizePermissionDenialInput(item.ToolInput); summary != "" {
			d.Input = summary
		}
	}
}

func (c *claudePermissionDenials) list() []PermissionDenial {
	if len(c.order) == 0 {
		return nil
	}
	out := make([]PermissionDenial, 0, len(c.order))
	for _, key := range c.order {
		out = append(out, *c.byID[key])
	}
	return out
}

// codexPermissionDenials records Codex auto-review policy denials. Review
// notifications arrive on the app-server reader goroutine while the result is
// assembled on another, hence the lock. Each reviewId is recorded once.
type codexPermissionDenials struct {
	mu   sync.Mutex
	seen map[string]struct{}
	list []PermissionDenial
}

// observe records a finished review whose status is "denied" and that carries
// a risk level. A denial without a risk level is a reviewer failure (for
// example a 429), not a policy decision; codexGuardianRateLimitCircuit
// handles those.
func (c *codexPermissionDenials) observe(params map[string]any) {
	reviewID, _ := params["reviewId"].(string)
	review, _ := params["review"].(map[string]any)
	if reviewID == "" || review == nil {
		return
	}
	if status, _ := review["status"].(string); status != "denied" {
		return
	}
	risk, ok := review["riskLevel"].(string)
	if !ok || risk == "" {
		return
	}
	rationale, _ := review["rationale"].(string)
	// Codex 0.164.0 reports the reviewed call as
	// "action": {"type":"command","command":"…","cwd":"…"}.
	var input string
	if action, ok := params["action"]; ok && action != nil {
		if raw, err := json.Marshal(action); err == nil {
			input = summarizePermissionDenialInput(raw)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.seen[reviewID]; dup {
		return
	}
	if c.seen == nil {
		c.seen = make(map[string]struct{})
	}
	c.seen[reviewID] = struct{}{}
	c.list = append(c.list, PermissionDenial{
		Tool:       "auto review",
		Input:      input,
		ReasonType: risk,
		Reason:     clipPermissionDenialInput(rationale),
	})
}

func (c *codexPermissionDenials) snapshot() []PermissionDenial {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.list) == 0 {
		return nil
	}
	return append([]PermissionDenial(nil), c.list...)
}
