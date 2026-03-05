package scaffold

const tmplMainGo = `package main

import (
	"fmt"
	"os"
	"strings"

	hooks "github.com/checkmarx/agenthooks"
)

// =============================================================================
// agenthooks — Unified Security Hooks for AI Coding Agents
//
// Write your security logic ONCE, works across ALL five agents:
//   Claude Code   Cursor   Windsurf Cascade   Factory Droid   Gemini CLI
//
// Build:   go build -o my-hooks .
// Install: agenthooks install ./my-hooks
// =============================================================================

func main() {
	// Register handlers (all optional — only register what you need).
	hooks.WhenAgentIdle(handleIdle)
	hooks.BeforeToolCall(handleTool)
	hooks.AfterFileWrite(handleFileWrite)
	hooks.BeforePrompt(handlePrompt)

	// Dispatch MUST be the last call in main.
	hooks.Dispatch()
}

// =============================================================================
// 1. WhenAgentIdle — Control when the agent is allowed to stop
// =============================================================================
// Fires on: Claude Stop, Cursor stop, Windsurf post-cascade-response,
//           Factory Droid Stop, Gemini after-agent
//
// ev fields:
//   ev.Agent          hooks.AgentID   // AgentClaude | AgentCursor | AgentWindsurf | AgentDroid | AgentGemini
//   ev.SessionID      string          // Unique session identifier
//   ev.IsRepeat       bool            // Claude/Droid: true when already in a continuation loop
//   ev.AutoRetryCount int             // Cursor: number of automatic follow-up turns so far
//   ev.IsLooping()    bool            // Helper: returns true when a continuation loop is detected
//
// Return options:
//   hooks.Resume()            — let the agent finish normally
//   hooks.Interrupt("msg")    — inject a follow-up task (Claude/Cursor/Droid only)
// =============================================================================

func handleIdle(ev hooks.AgentIdleEvent) hooks.IdleVerdict {
	// IMPORTANT: always guard against infinite loops first.
	if ev.IsLooping() {
		return hooks.Resume()
	}

	// Example: require tests to pass before Claude finishes.
	// if ev.Agent == hooks.AgentClaude {
	//     return hooks.Interrupt("Please run 'go test ./...' and fix any failures before stopping.")
	// }

	// Example: log idle events for audit.
	// fmt.Fprintf(os.Stderr, "[idle] agent=%s session=%s\n", ev.Agent, ev.SessionID)

	return hooks.Resume()
}

// =============================================================================
// 2. BeforeToolCall — Gate shell commands and MCP tool invocations
// =============================================================================
// Fires on: Claude PreToolUse, Cursor beforeShellExecution / beforeMCPExecution,
//           Windsurf pre_run_command / pre_mcp_tool_use,
//           Factory Droid PreToolUse, Gemini BeforeTool
//
// ev fields:
//   ev.Agent      hooks.AgentID     // which agent is calling
//   ev.Kind       hooks.ToolKind    // ToolKindShell | ToolKindMCP | ToolKindBuiltin
//   ev.ToolName   string            // name of the tool or MCP method
//   ev.Input      string            // raw command string (shell) or JSON input (MCP/builtin)
//   ev.ServerURL  string            // MCP server URL (Cursor / Windsurf)
//   ev.WorkDir    string            // working directory at time of call
//   ev.IsMCP()    bool              // shorthand: ev.Kind == ToolKindMCP
//
// Return options:
//   hooks.Allow()                   — permit the tool call
//   hooks.AllowWithNote("msg")      — permit and inject a note into the agent context
//   hooks.Deny("reason")            — block the tool call
//   hooks.AskUser("question")       — pause and ask the human (Cursor / Windsurf)
// =============================================================================

func handleTool(ev hooks.ToolCallEvent) hooks.ToolVerdict {
	// -------------------------------------------------------------------------
	// Shell command security
	// -------------------------------------------------------------------------
	if ev.Kind == hooks.ToolKindShell {
		cmd := strings.ToLower(ev.Input)

		// Block destructive commands.
		if strings.Contains(cmd, "rm -rf /") || strings.Contains(cmd, "rm -rf ~") {
			return hooks.Deny("Blocked: destructive rm command")
		}

		// Block pipe-to-shell patterns.
		if strings.Contains(cmd, "curl | bash") || strings.Contains(cmd, "wget -o- | sh") {
			return hooks.Deny("Blocked: pipe-to-shell execution is not allowed")
		}

		// Ask user before publishing or force-pushing.
		if strings.Contains(cmd, "npm publish") || strings.Contains(cmd, "git push --force") {
			return hooks.AskUser("This will publish/force-push. Please confirm.")
		}

		// TODO: add your own shell command rules here.
	}

	// -------------------------------------------------------------------------
	// MCP tool security
	// -------------------------------------------------------------------------
	if ev.IsMCP() {
		// Allowlist trusted MCP servers.
		trusted := []string{
			"https://mcp.example.com",
			"http://localhost:3000",
		}
		ok := ev.ServerURL == ""
		for _, t := range trusted {
			if strings.HasPrefix(ev.ServerURL, t) {
				ok = true
				break
			}
		}
		if !ok {
			return hooks.Deny("Blocked: MCP server not in allowlist: " + ev.ServerURL)
		}

		// Block dangerous MCP tools by name.
		if ev.ToolName == "execute_code" || ev.ToolName == "eval" {
			return hooks.Deny("Blocked: code-execution MCP tools are not allowed")
		}

		// TODO: add your own MCP tool rules here.
	}

	// -------------------------------------------------------------------------
	// Generic tool logging
	// -------------------------------------------------------------------------
	fmt.Fprintf(os.Stderr, "[tool] agent=%s kind=%s tool=%s cwd=%s\n",
		ev.Agent, ev.Kind, ev.ToolName, ev.WorkDir)

	return hooks.Allow()
}

// =============================================================================
// 3. AfterFileWrite — Scan files after the agent writes them
// =============================================================================
// Fires on: Claude PostToolUse (Write/Edit), Cursor afterFileEdit,
//           Windsurf post_write_code,
//           Factory Droid PostToolUse (Write/Edit), Gemini AfterTool (file tools)
//
// ev fields:
//   ev.Agent      hooks.AgentID   // which agent wrote the file
//   ev.FilePath   string          // absolute path of the file that was written
//   ev.Before     string          // file content before the edit (empty for new files)
//   ev.After      string          // file content after the edit
//   ev.WorkDir    string          // working directory
//
// Return options:
//   hooks.AcceptWrite()             — accept the edit
//   hooks.RejectWrite("reason")     — reject and revert the edit (Claude only)
//   hooks.AnnotateWrite("note")     — accept and inject a note into the agent context
// =============================================================================

func handleFileWrite(ev hooks.FileWriteEvent) hooks.FileWriteVerdict {
	lower := strings.ToLower(ev.After)

	// Block secrets from being written to disk.
	secretPatterns := []string{
		"api_key=", "apikey=",
		"password=", "passwd=",
		"aws_access_key_id", "aws_secret_access_key",
		"bearer ", "token=",
		"-----begin rsa", "-----begin openssh", "private_key",
	}
	for _, pat := range secretPatterns {
		if strings.Contains(lower, pat) {
			return hooks.RejectWrite("Secret detected in " + ev.FilePath + ": use environment variables instead")
		}
	}

	// Warn about TODO markers left behind.
	if strings.Contains(ev.After, "TODO") {
		return hooks.AnnotateWrite("File contains TODO markers — remember to resolve them.")
	}

	// Log all writes for audit trail.
	fmt.Fprintf(os.Stderr, "[file-write] agent=%s path=%s\n", ev.Agent, ev.FilePath)

	return hooks.AcceptWrite()
}

// =============================================================================
// 4. BeforePrompt — Inspect user prompts before they reach the agent
// =============================================================================
// Fires on: Claude UserPromptSubmit, Cursor beforeSubmitPrompt,
//           Windsurf pre_user_prompt,
//           Factory Droid UserPromptSubmit, Gemini BeforeAgent
//
// ev fields:
//   ev.Agent      hooks.AgentID   // which agent is receiving the prompt
//   ev.SessionID  string          // session identifier
//   ev.Prompt     string          // full text the user typed
//
// Return options:
//   hooks.AcceptPrompt()            — pass the prompt through unchanged
//   hooks.RejectPrompt("reason")    — block prompt submission with a message to the user
//   hooks.EnrichPrompt("extra")     — append extra context before forwarding
// =============================================================================

func handlePrompt(ev hooks.PromptEvent) hooks.PromptVerdict {
	lower := strings.ToLower(ev.Prompt)

	// Detect common secret patterns.
	secretTriggers := []struct {
		pattern string
		message string
	}{
		{"api_key=", "API key detected — use environment variables instead of hardcoding secrets."},
		{"password=", "Password detected — never include passwords in prompts."},
		{"aws_access_key_id", "AWS credentials detected — use IAM roles or environment variables."},
		{"bearer ", "Auth token detected — remove secrets from your prompt."},
		{"token=", "Token detected — remove secrets from your prompt."},
		{"-----begin rsa", "Private key detected — never share private keys in prompts."},
		{"-----begin openssh", "SSH private key detected — never share private keys in prompts."},
	}
	for _, t := range secretTriggers {
		if strings.Contains(lower, t.pattern) {
			return hooks.RejectPrompt(t.message)
		}
	}

	// Detect well-known token prefixes (case-sensitive).
	if strings.Contains(ev.Prompt, "ghp_") || strings.Contains(ev.Prompt, "gho_") {
		return hooks.RejectPrompt("GitHub token detected — these should never appear in prompts.")
	}
	if strings.Contains(ev.Prompt, "sk-") {
		return hooks.RejectPrompt("OpenAI API key detected — use environment variables.")
	}

	// Optionally inject standing instructions.
	// return hooks.EnrichPrompt("Always follow our security coding standards.")

	return hooks.AcceptPrompt()
}
`

const tmplReadme = `# My agenthooks Project

One hooks binary for Claude Code, Cursor, Windsurf Cascade, Factory Droid, and Gemini CLI.

## Quick Start

` + "```" + `bash
# 1. Initialize your Go module
go mod init github.com/your-org/your-hooks

# 2. Add the dependency
go get github.com/checkmarx/agenthooks@latest
go mod tidy

# 3. Build your binary
go build -o my-hooks .

# 4. Install hooks into all five agent configs
agenthooks install ./my-hooks
` + "```" + `

## Unified Handlers

| Handler | Purpose | Can Block? |
|---|---|---|
| ` + "`WhenAgentIdle`" + ` | Control when the agent is allowed to finish | Claude / Cursor / Droid |
| ` + "`BeforeToolCall`" + ` | Gate shell commands and MCP tool invocations | All five agents |
| ` + "`AfterFileWrite`" + ` | Scan file content after writes | Claude (full); others observe |
| ` + "`BeforePrompt`" + ` | Inspect user prompts for secrets / policy | All five agents |

## Testing Locally

` + "```" + `bash
# Build
go build -o my-hooks .

# Simulate a Claude stop event
echo '{"session_id":"s1","hook_event_name":"Stop","stop_hook_active":false}' \
  | ./my-hooks claude-stop

# Simulate a dangerous shell command (Cursor)
echo '{"command":"rm -rf /","cwd":"/tmp"}' \
  | ./my-hooks cursor-before-shell

# Simulate a prompt with a secret (Claude)
echo '{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"use api_key=abc123"}' \
  | ./my-hooks claude-user-prompt-submit
` + "```" + `
`

const tmplGitignore = `my-hooks
my-hooks.exe
dist/
.env
`

const tmplPolicyJSON = `{
  "blocked_shell_patterns": [
    "rm -rf /",
    "curl | bash",
    "wget -O- | sh"
  ],
  "allowed_mcp_servers": [],
  "secret_patterns": [
    "api_key=",
    "password=",
    "aws_access_key_id"
  ]
}
`
