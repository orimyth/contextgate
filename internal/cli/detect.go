package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// MCPClient represents a detected MCP client installation.
type MCPClient struct {
	Name       string // "Claude Desktop", "Claude Code", "Cursor"
	Kind       string // "claude-desktop", "claude-code", "cursor"
	ConfigPath string // path to the config file
	Available  bool
}

// MCPServerEntry represents a server entry in a config file.
type MCPServerEntry struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
}

// MCPConfig is the shared format for claude_desktop_config.json and .cursor/mcp.json.
type MCPConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

// serverJSON is the parsed form of a single server entry.
type serverJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
}

// DetectClients finds installed MCP clients on this system.
func DetectClients() []MCPClient {
	var clients []MCPClient

	// Claude Desktop
	desktopPath := claudeDesktopConfigPath()
	clients = append(clients, MCPClient{
		Name:       "Claude Desktop",
		Kind:       "claude-desktop",
		ConfigPath: desktopPath,
		Available:  fileExists(desktopPath),
	})

	// Claude Code
	claudeCodeAvailable := commandExists("claude")
	clients = append(clients, MCPClient{
		Name:      "Claude Code",
		Kind:      "claude-code",
		Available: claudeCodeAvailable,
	})

	// Cursor — check global config
	cursorPath := cursorGlobalConfigPath()
	clients = append(clients, MCPClient{
		Name:       "Cursor",
		Kind:       "cursor",
		ConfigPath: cursorPath,
		Available:  fileExists(cursorPath) || commandExists("cursor"),
	})

	return clients
}

// ReadServersFromConfig reads MCP server entries from a JSON config file
// (claude_desktop_config.json or .cursor/mcp.json format).
func ReadServersFromConfig(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg MCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var servers []MCPServerEntry
	for name, raw := range cfg.MCPServers {
		var s serverJSON
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		// Skip remote/http/sse servers — we can only wrap stdio
		if s.Type == "http" || s.Type == "sse" || s.URL != "" {
			continue
		}
		servers = append(servers, MCPServerEntry{
			Name:    name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
		})
	}
	return servers, nil
}

// WrapConfigFile reads a config file, wraps each server with contextgate, and writes it back.
func WrapConfigFile(path string, gateBinary string, dashPort string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	var cfg MCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0, err
	}

	wrapped := 0
	for name, raw := range cfg.MCPServers {
		var s serverJSON
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}

		// Skip remote servers
		if s.Type == "http" || s.Type == "sse" || s.URL != "" {
			continue
		}

		// Skip if already wrapped with contextgate
		if isContextGateWrapped(s.Command, s.Args) {
			continue
		}

		// Build new args: --dashboard :PORT -- original_command original_args...
		newArgs := []string{"--dashboard", dashPort, "--", s.Command}
		newArgs = append(newArgs, s.Args...)

		s.Command = gateBinary
		s.Args = newArgs

		newRaw, err := json.Marshal(s)
		if err != nil {
			continue
		}
		cfg.MCPServers[name] = newRaw
		wrapped++
	}

	if wrapped == 0 {
		return 0, nil
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return 0, err
	}

	if err := os.WriteFile(path, out, 0644); err != nil {
		return 0, err
	}

	return wrapped, nil
}

// isContextGateWrapped checks if a server entry is already wrapped with contextgate.
func isContextGateWrapped(command string, args []string) bool {
	base := filepath.Base(command)
	if base == "contextgate" || base == "contextgate.exe" {
		return true
	}
	for _, a := range args {
		if filepath.Base(a) == "contextgate" {
			return true
		}
	}
	return false
}

// SelfPath returns the absolute path to the currently running contextgate binary.
func SelfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "contextgate"
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	return resolved
}

func claudeDesktopConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		appdata := os.Getenv("APPDATA")
		return filepath.Join(appdata, "Claude", "claude_desktop_config.json")
	default: // linux
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "claude", "claude_desktop_config.json")
	}
}

func cursorGlobalConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "mcp.json")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// IsAlreadyWrapped checks if a command string contains "contextgate".
func IsAlreadyWrapped(cmd string) bool {
	return strings.Contains(filepath.Base(cmd), "contextgate")
}
