package agent

import (
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"
)

func TestCodexAutoReviewDeclinesApprovalRequests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method string
		params string
		want   map[string]any
	}{
		{"item/commandExecution/requestApproval", `{"command":"git push --force"}`, map[string]any{"decision": "decline"}},
		{"item/fileChange/requestApproval", `{"reason":"write outside workspace"}`, map[string]any{"decision": "decline"}},
		{"execCommandApproval", `{"command":["rm","-rf","/"]}`, map[string]any{"decision": map[string]any{"denied": map[string]any{"rejection": codexAutoReviewRejection}}}},
		{"item/permissions/requestApproval", `{"permissions":{"network":{"enabled":true}}}`, map[string]any{"permissions": map[string]any{}, "scope": "turn"}},
		{"mcpServer/elicitation/request", `{}`, map[string]any{"action": "decline", "content": nil, "_meta": nil}},
	}
	for i, tc := range cases {
		c, fs, _ := newTestCodexClient(t)
		c.autoReview = true
		line, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": tc.method, "params": json.RawMessage(tc.params)})
		c.handleLine(string(line))

		lines := fs.Lines()
		if len(lines) != 1 {
			t.Fatalf("%s: expected 1 response, got %d", tc.method, len(lines))
		}
		var resp struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.method, err)
		}
		if !reflect.DeepEqual(resp.Result, tc.want) {
			t.Fatalf("%s: result = %v, want %v", tc.method, resp.Result, tc.want)
		}
		denials := c.permissionDenials.snapshot()
		if len(denials) != 1 || denials[0].Tool != tc.method || denials[0].ReasonType != "declined" {
			t.Fatalf("%s: denials = %+v, want one declined entry", tc.method, denials)
		}
	}
}

func TestCodexAutoReviewRecordsDeclinedCommand(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestCodexClient(t)
	c.autoReview = true
	c.handleLine(`{"jsonrpc":"2.0","id":7,"method":"item/commandExecution/requestApproval","params":{"itemId":"i","threadId":"t","turnId":"u","startedAtMs":1,"command":"git push --force origin main"}}`)

	if got := c.permissionDenials.snapshot(); len(got) != 1 || got[0].Input != "git push --force origin main" {
		t.Fatalf("denials = %+v, want the declined command as input", got)
	}
}

func TestFilterCodexApprovalConfigOverrides(t *testing.T) {
	t.Parallel()

	args := []string{
		"-c", "approval_policy=never",
		"-c", "model=gpt-5.6-sol",
		"--config=sandbox_mode=danger-full-access",
		"-c", "sandbox_workspace_write.network_access=false",
		"-c", "profiles.fast.approvals_reviewer=user",
		"-c", "approval_policy_note=keep", // different key, same prefix
	}
	got := filterCodexApprovalConfigOverrides(args, slog.Default())
	want := []string{"-c", "model=gpt-5.6-sol", "-c", "approval_policy_note=keep"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered = %q, want %q", got, want)
	}
}
