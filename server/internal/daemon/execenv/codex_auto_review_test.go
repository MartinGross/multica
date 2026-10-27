package execenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexAutoReviewPolicy(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		policy, err := codexAutoReviewPolicy(goos, windowsSandboxAbsent)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", goos, err)
		}
		if policy.Mode != "workspace-write" || !policy.NetworkAccess || !policy.AutoReview {
			t.Fatalf("%s: policy = %+v, want workspace-write with network and auto review", goos, policy)
		}
	}

	if _, err := codexAutoReviewPolicy("windows", windowsSandboxAbsent); err == nil {
		t.Fatal("windows without a native sandbox must refuse auto review instead of running unsandboxed")
	}
	if policy, err := codexAutoReviewPolicy("windows", windowsSandboxNative); err != nil || policy.Mode != "workspace-write" || !policy.AutoReview {
		t.Fatalf("windows with native sandbox: policy = %+v, err = %v", policy, err)
	}
}

func TestEnsureCodexSandboxConfigAutoReviewOwnsApprovalKeys(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	user := strings.Join([]string{
		`model = "gpt-5.6-sol"`,
		`approval_policy = "never"`,
		`approvals_reviewer = "user"`,
		``,
		`[profiles.fast]`,
		`model = "gpt-5.6-mini"`,
		`approval_policy = "never"`,
		``,
	}, "\n")
	if err := os.WriteFile(configPath, []byte(user), 0o644); err != nil {
		t.Fatal(err)
	}
	policy, err := codexAutoReviewPolicy("linux", windowsSandboxAbsent)
	if err != nil {
		t.Fatal(err)
	}

	for run := 0; run < 2; run++ { // idempotent across reuse
		if err := ensureCodexSandboxConfig(configPath, policy, "0.164.0", nil); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	root := got
	if idx := strings.Index(got, "[profiles.fast]"); idx >= 0 {
		root = got[:idx]
	}
	for _, line := range []string{
		`sandbox_mode = "workspace-write"`,
		`sandbox_workspace_write.network_access = true`,
		`approval_policy = "on-request"`,
		`approvals_reviewer = "auto_review"`,
	} {
		if strings.Count(root, line) != 1 {
			t.Fatalf("root table should assign %q exactly once:\n%s", line, got)
		}
	}
	if strings.Contains(root, `approval_policy = "never"`) || strings.Contains(root, `approvals_reviewer = "user"`) {
		t.Fatalf("user's root approval keys must be stripped (duplicate keys make Codex reject the file):\n%s", got)
	}
	if strings.Contains(got, `approval_policy = "never"`) {
		t.Fatalf("profile-scoped approval keys must be stripped, a selected profile would override the block:\n%s", got)
	}
	if !strings.Contains(got, "[profiles.fast]\nmodel = \"gpt-5.6-mini\"") {
		t.Fatalf("other profile keys must be preserved:\n%s", got)
	}
	if !strings.Contains(got, `model = "gpt-5.6-sol"`) {
		t.Fatalf("unrelated user keys must be preserved:\n%s", got)
	}
}

func TestEnsureCodexSandboxConfigWithoutAutoReviewWritesNoApprovalKeys(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := ensureCodexSandboxConfig(configPath, codexSandboxPolicyFor("linux", "0.164.0"), "0.164.0", nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "approval") {
		t.Fatalf("default policy must not touch approval keys:\n%s", data)
	}
}
