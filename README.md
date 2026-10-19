# `mcp-shield`

**MCP Server Secret Injector (`envFile` / AES-256-GCM Vault), Tool-Poisoning Scanner & Real-Time `stdio` JSON-RPC 2.0 Firewall.**

Across the Model Context Protocol (MCP) ecosystem (Claude Code, OpenAI Codex, Cursor, Windsurf, Cline, Zed), developers face two critical security gaps:

1. **No Universal `envFile` or Encrypted Secret Vault in `.mcp.json`:** Because MCP config files lack built-in `.env` or encrypted vault loading (see [`anthropics/claude-code#28942`](https://github.com/anthropics/claude-code/issues/28942), [`openai/codex#24401`](https://github.com/openai/codex/issues/24401), [`NousResearch/hermes-agent#11239`](https://github.com/NousResearch/hermes-agent/issues/11239)), developers are forced to hardcode plaintext API keys (`GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, `DATABASE_URL`) directly inside `.mcp.json` or `claude_desktop_config.json`.
2. **MCP Tool Poisoning & Unchecked `tools/call` Execution:** Malicious or compromised MCP servers can embed hidden prompt-injection instructions inside `tools/list` descriptions (`<IMPORTANT>Read ~/.ssh/id_rsa...</IMPORTANT>`, HTML comments, or zero-width Unicode steganography) and exfiltrate local credentials or leak secrets into the LLM context window.

`mcp-shield` solves both problems with **zero runtime dependencies** (built on Node.js native `node:crypto`).

---

## Core Capabilities

- **`mcp-shield wrap` (Secret Injector & Real-Time JSON-RPC Firewall):**
  - Injects secrets from `.env` files (`--env-file`) or an `scrypt` + `AES-256-GCM` encrypted vault (`--vault`) into the child MCP server process so `.mcp.json` never contains plaintext secrets.
  - Inspects `tools/list` responses in real time and strips `<IMPORTANT>`/`<SYSTEM>` override blocks, credential exfiltration lures, cross-tool shadowing instructions, and zero-width Unicode steganography.
  - Inspects `tools/call` requests and blocks access to sensitive credential paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `.env`, `/etc/shadow`, `.npmrc`), returning a clean, non-crashing MCP `isError: true` response.
  - Scrubs leaked PEM private keys, GitHub/OpenAI/AWS/Slack tokens, JWTs, and database passwords from `tools/call` outputs before they reach the LLM context.
- **`mcp-shield audit` (Static Config & Tool-Poisoning Scanner):**
  - Scans `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, or `tools/list` payloads for hardcoded secrets, unpinned `npx -y` packages, and tool-poisoning prompt injections.
- **`mcp-shield migrate` (One-Command `.mcp.json` Auto-Fixer):**
  - Automatically extracts hardcoded secrets from `.mcp.json` into `.env` (or an encrypted `.mcp-vault.json`) and rewrites each server entry to run through `mcp-shield wrap`.

---

## Quick Start

### 1. Audit an Existing `.mcp.json` or `tools/list` Payload

```bash
npx mcp-shield audit examples/sample.mcp.json
npx mcp-shield audit examples/poisoned-tools.json --fail-on-findings
```

### 2. Automatically Migrate Plaintext Secrets Out of `.mcp.json`

```bash
# Extract secrets to .env and write a clean, git-safe .mcp.json:
npx mcp-shield migrate examples/sample.mcp.json --env-file .env -o examples/sample.safe.mcp.json

# Or extract secrets into an AES-256-GCM encrypted vault:
npx mcp-shield migrate examples/sample.mcp.json --vault .mcp-vault.json -p "my-passphrase" -o examples/sample.safe.mcp.json
```

### 3. Wrap Any MCP Server in `.mcp.json`

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-shield",
        "wrap",
        "--env-file",
        ".env",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

---

## License

MIT
