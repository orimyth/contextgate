package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunWrap registers an MCP server wrapped with contextgate into Claude Code.
//
// Usage: contextgate wrap <name> [--scope user|project] -- <command> [args...]
func RunWrap(args []string) error {
	if len(args) == 0 {
		return printWrapUsage()
	}

	name := args[0]
	rest := args[1:]

	// Parse optional --scope
	scope := "user"
	var cmdArgs []string
	foundSep := false
	for i, a := range rest {
		if a == "--" {
			cmdArgs = rest[i+1:]
			foundSep = true
			break
		}
		if a == "--scope" && i+1 < len(rest) {
			scope = rest[i+1]
		}
	}

	if !foundSep || len(cmdArgs) == 0 {
		return printWrapUsage()
	}

	// Check claude CLI is available
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("'claude' CLI not found in PATH. Install Claude Code first: https://docs.anthropic.com/en/docs/claude-code")
	}

	gateBinary := SelfPath()

	// Build: claude mcp add --transport stdio --scope <scope> <name> -- contextgate --dashboard :9000 -- <command> <args...>
	claudeArgs := []string{
		"mcp", "add",
		"--transport", "stdio",
		"--scope", scope,
		name,
		"--",
		gateBinary,
		"--dashboard", ":9000",
		"--",
	}
	claudeArgs = append(claudeArgs, cmdArgs...)

	fmt.Printf("Registering '%s' with Claude Code...\n\n", name)
	fmt.Printf("  claude %s\n\n", strings.Join(claudeArgs, " "))

	cmd := exec.Command("claude", claudeArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude mcp add failed: %w", err)
	}

	fmt.Printf("Done! '%s' is now registered in Claude Code (%s scope).\n\n", name, scope)
	fmt.Println("The dashboard will be available at http://localhost:9000")
	fmt.Printf("when Claude Code uses the '%s' server.\n", name)
	return nil
}

func printWrapUsage() error {
	fmt.Fprintln(os.Stderr, "Usage: contextgate wrap <name> [--scope user|project] -- <command> [args...]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Registers an MCP server in Claude Code, wrapped with ContextGate.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  contextgate wrap my-fs -- npx -y @modelcontextprotocol/server-filesystem /tmp")
	fmt.Fprintln(os.Stderr, "  contextgate wrap github --scope project -- npx -y @modelcontextprotocol/server-github")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  --scope user     Available in all projects (default)")
	fmt.Fprintln(os.Stderr, "  --scope project  Only for this project")
	return fmt.Errorf("missing arguments")
}
