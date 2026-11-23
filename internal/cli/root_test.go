package cli

import (
	"bytes"
	"errors"
	"github.com/caseypc/wasp/internal/network"
	"strings"
	"testing"
)

func runCLI(args ...string) (string, string, error) {
	root := NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}
func TestRootHelpAndCommandDiscovery(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}} {
		stdout, _, err := runCLI(args...)
		if err != nil {
			t.Fatalf("runCLI(%v): %v", args, err)
		}
		if !bytes.Contains([]byte(stdout), []byte("scan")) || !bytes.Contains([]byte(stdout), []byte("modules")) {
			t.Fatalf("help missing commands: %s", stdout)
		}
	}
}
func TestInvalidCommandAndPrivateTargetHaveDistinctExitCodes(t *testing.T) {
	_, _, err := runCLI("not-a-command")
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command error = %v", err)
	}
	_, _, err = runCLI("scan", "https://127.0.0.1", "--format", "json")
	var denied exitError
	if !errors.As(err, &denied) || denied.code != 4 || !errors.Is(err, network.ErrScopeDenied) {
		t.Fatalf("private target error = %v, want scope exit 4", err)
	}
}
func TestPlannedModulesAreNotAdvertisedAsImplemented(t *testing.T) {
	stdout, _, err := runCLI("modules", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "email") || !strings.Contains(stdout, "planned") || !strings.Contains(stdout, "SPF") {
		t.Fatalf("expected email to be labeled planned: %s", stdout)
	}
}
func TestVersionBanners(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct{ style, want string }{
		{"normal", "▐▙█▟▌▐▌ ▐▌▗▄▄▞▘▐▌ v."},
		{"short", "┗┻┛╹ ╹┗━┛╹ v."},
		{"text", "WASP (Website Audit & Security Profiler) v"},
	} {
		stdout, stderr, err := runCLI("version", "--banner", tc.style)
		if err != nil || stderr != "" || !strings.Contains(stdout, tc.want) || !strings.Contains(stdout, "Report schema: 1.0.0") || strings.Contains(stdout, "\x1b") {
			t.Fatalf("version %s: stdout=%q stderr=%q error=%v", tc.style, stdout, stderr, err)
		}
	}
	_, _, err := runCLI("version", "--banner", "invalid")
	var usage exitError
	if !errors.As(err, &usage) || usage.code != 2 {
		t.Fatalf("invalid style error: %v", err)
	}
}
