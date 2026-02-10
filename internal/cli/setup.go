package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// RunSetup runs the interactive setup wizard.
func RunSetup() error {
	fmt.Println("ContextGate Setup")
	fmt.Println("=================")
	fmt.Println()

	gateBinary := SelfPath()
	fmt.Printf("Binary: %s\n\n", gateBinary)

	// Detect clients
	clients := DetectClients()
	fmt.Println("Detected MCP clients:")
	fmt.Println()

	hasAny := false
	for _, c := range clients {
		status := "not found"
		if c.Available {
			status = "found"
			hasAny = true
		}
		fmt.Printf("  %-16s %s\n", c.Name+":", status)
	}
	fmt.Println()

	if !hasAny {
		fmt.Println("No MCP clients detected. Install Claude Desktop, Claude Code, or Cursor first.")
		return nil
	}

	reader := bufio.NewReader(os.Stdin)

	// Process each available client
	for _, c := range clients {
		if !c.Available {
			continue
		}

		switch c.Kind {
		case "claude-code":
			if err := setupClaudeCode(reader, gateBinary); err != nil {
				fmt.Printf("  Error: %v\n\n", err)
			}
		case "claude-desktop":
			if err := setupConfigFile(reader, c, gateBinary); err != nil {
				fmt.Printf("  Error: %v\n\n", err)
			}
		case "cursor":
			if err := setupConfigFile(reader, c, gateBinary); err != nil {
				fmt.Printf("  Error: %v\n\n", err)
			}
		}
	}

	fmt.Println("Setup complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Restart your MCP client (Claude Desktop / Cursor / Claude Code)")
	fmt.Println("  2. Open http://localhost:9000 to view the dashboard")
	fmt.Println("  3. Start using your AI agent — all traffic will appear in real time")
	fmt.Println()

	return nil
}

func setupClaudeCode(reader *bufio.Reader, gateBinary string) error {
	fmt.Println("--- Claude Code ---")
	fmt.Println()

	// List existing servers
	out, err := exec.Command("claude", "mcp", "list").CombinedOutput()
	if err != nil {
		fmt.Println("  Could not list existing MCP servers.")
		fmt.Println("  You can manually add a server with:")
		fmt.Println()
		printClaudeCodeExample(gateBinary)
		return nil
	}

	existing := strings.TrimSpace(string(out))
	if existing == "" || existing == "No MCP servers configured" {
		fmt.Println("  No existing MCP servers configured in Claude Code.")
		fmt.Println()
		fmt.Print("  Would you like to add a filesystem server wrapped with ContextGate? [Y/n] ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			return addDemoServer(gateBinary)
		}
		fmt.Println()
		fmt.Println("  You can add any server later with:")
		printClaudeCodeExample(gateBinary)
		return nil
	}

	fmt.Println("  Existing MCP servers:")
	fmt.Println()
	for _, line := range strings.Split(existing, "\n") {
		fmt.Printf("    %s\n", line)
	}
	fmt.Println()
	fmt.Print("  Would you like to add a ContextGate-wrapped demo server? [Y/n] ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer == "" || answer == "y" || answer == "yes" {
		return addDemoServer(gateBinary)
	}

	fmt.Println()
	fmt.Println("  To wrap any existing server, use:")
	printClaudeCodeExample(gateBinary)
	return nil
}

func addDemoServer(gateBinary string) error {
	home, _ := os.UserHomeDir()
	fmt.Println()
	fmt.Println("  Adding filesystem server wrapped with ContextGate...")

	cmd := exec.Command("claude", "mcp", "add",
		"--transport", "stdio",
		"--scope", "user",
		"contextgate-fs",
		"--",
		gateBinary,
		"--dashboard", ":9000",
		"--", "npx", "-y", "@modelcontextprotocol/server-filesystem", home,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude mcp add failed: %w", err)
	}
	fmt.Println("  Added 'contextgate-fs' to Claude Code (user scope)")
	fmt.Println()
	return nil
}

func setupConfigFile(reader *bufio.Reader, client MCPClient, gateBinary string) error {
	fmt.Printf("--- %s ---\n", client.Name)
	fmt.Println()

	if client.ConfigPath == "" {
		fmt.Printf("  Config path unknown for %s\n\n", client.Name)
		return nil
	}

	// Read existing servers
	servers, err := ReadServersFromConfig(client.ConfigPath)
	if err != nil {
		fmt.Printf("  Could not read config at %s\n", client.ConfigPath)
		fmt.Printf("  Error: %v\n\n", err)
		return nil
	}

	if len(servers) == 0 {
		fmt.Println("  No stdio MCP servers found in config.")
		fmt.Println()
		return nil
	}

	// Show servers
	fmt.Printf("  Found %d MCP server(s):\n\n", len(servers))
	unwrapped := 0
	for i, s := range servers {
		wrapped := ""
		if isContextGateWrapped(s.Command, s.Args) {
			wrapped = " (already wrapped)"
		} else {
			unwrapped++
		}
		fmt.Printf("    %d. %s → %s %s%s\n", i+1, s.Name, s.Command, strings.Join(s.Args, " "), wrapped)
	}
	fmt.Println()

	if unwrapped == 0 {
		fmt.Println("  All servers are already wrapped with ContextGate.")
		fmt.Println()
		return nil
	}

	fmt.Printf("  Wrap %d unwrapped server(s) with ContextGate? [Y/n] ", unwrapped)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Println("  Skipped.")
		fmt.Println()
		return nil
	}

	// Ask for dashboard port
	port := ":9000"
	fmt.Printf("  Dashboard port [%s]: ", port)
	portAnswer, _ := reader.ReadString('\n')
	portAnswer = strings.TrimSpace(portAnswer)
	if portAnswer != "" {
		if _, err := strconv.Atoi(strings.TrimPrefix(portAnswer, ":")); err == nil {
			if !strings.HasPrefix(portAnswer, ":") {
				portAnswer = ":" + portAnswer
			}
			port = portAnswer
		}
	}

	count, err := WrapConfigFile(client.ConfigPath, gateBinary, port)
	if err != nil {
		return fmt.Errorf("failed to wrap config: %w", err)
	}

	fmt.Printf("  Wrapped %d server(s) in %s\n", count, client.ConfigPath)
	fmt.Println()
	return nil
}

func printClaudeCodeExample(gateBinary string) {
	fmt.Println()
	fmt.Printf("    claude mcp add --transport stdio --scope user my-server \\\n")
	fmt.Printf("      -- %s --dashboard :9000 \\\n", gateBinary)
	fmt.Printf("      -- npx -y @modelcontextprotocol/server-filesystem /tmp\n")
	fmt.Println()
}
