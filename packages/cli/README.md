# Metis Reverse CLI (`metis-reverse-cli`)

> One-click multi-agent setup, doctor & uninstaller for **Metis Reverse** MCP.

## Quick Start

```bash
# Interactive setup (auto-detects Cursor, Claude, Antigravity, etc.)
npx metis-reverse-cli setup

# Check installed health & detection
npx metis-reverse-cli doctor

# Dry-run preview without touching disk
npx metis-reverse-cli preview

# Clean uninstall from agents
npx metis-reverse-cli uninstall
```

## Features

- **20+ Supported AI Agents**: Seamlessly configures Cursor, Claude Code, Claude Desktop, Antigravity, VS Code, Trae, Codex, Gemini CLI, Windsurf, OpenCode, and more.
- **Evidence-Grounded Reverse Engineering**: Deploys the full Metis Reverse skill manifest and reference doctrine.
- **Safe & Non-Destructive**: Automatic `.bak` backups before modifying configurations, dry-run previews, and clean uninstallation.
- **Zero Heavy Dependencies**: Pure Node.js CLI powered by `@clack/prompts`.
