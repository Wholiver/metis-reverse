# Metis Reverse install guide (beginner)

**English** · [简体中文](INSTALL.zh-CN.md)

Written for the current **1.0.1** CLI. Flow: install Node + uv → run one `setup` → pick agents → see the completion line → **restart** those apps.

> **Install the right package.** The published CLI is [`metis-reverse-cli`](https://www.npmjs.com/package/metis-reverse-cli). The older npm name `metis-reverse` is still stuck at **0.0.1** and is **not** this release. Prefer:
>
> ```bash
> npx metis-reverse-cli@latest setup
> ```
>
> (or pin `@1.0.1`). The engine is **not** on npm or PyPI. Setup writes an MCP entry that uses `uvx` from the GitHub **`latest`** tag.

## Prerequisites

| Tool | Why | Version |
| --- | --- | --- |
| [Node.js](https://nodejs.org/) | Runs `npx` / the CLI | **18+** (LTS recommended) |
| [uv](https://docs.astral.sh/uv/) | Provides `uvx` for the MCP engine | Any build where `uv --version` works |

After installing either tool, **close and reopen the terminal**, or you may still get `command not found`.

## Step 0: Open a terminal

- **Windows**: Windows key → `PowerShell` → open Windows PowerShell
- **macOS**: `Command + Space` → `Terminal` → Enter
- **Linux**: usually `Ctrl + Alt + T`

## Step 1: Install Node.js

1. Download the **LTS** installer from https://nodejs.org/en/download (follow the page on Linux)
2. Reopen the terminal and run:

```bash
node -v
```

Anything like `v18` / `v20` / `v22` is fine.

## Step 2: Install uv

uv pulls the analysis engine and brings its own Python — you do not install Python separately.

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Reopen the terminal, then:

```bash
uv --version
```

Alternatives: `brew install uv` (macOS) or `winget install --id=astral-sh.uv -e` (Windows).

## Step 3: Run setup

If you use **Claude Desktop**, **fully quit** it first (not just close the window).

```bash
npx metis-reverse-cli@latest setup
```

The first `npx` run may ask to download/execute the package — accept that. Then you get the Metis Reverse installer UI (banner like `METIS REVERSE  Agent Installer & MCP Manager  v1.0.1`).

### What you will see

1. **Detecting installed AI agents…**  
   Scans the ~20+ supported coding agents on this machine.

2. **Which agents should Metis Reverse be installed into?**  
   Multi-select. Detected / already configured agents sort first, with hints like `detected` / `MCP active`.  
   - Arrow keys to move  
   - **Space** to toggle  
   - Some terminals: `a` to toggle all  
   - **Enter** to confirm  
   At least one selection is required.

3. **Install complete Agent Skill package (SKILL.md + reverse references + rules)?**  
   Default Yes. Installs the skill pack where supported (Cursor also gets rules). Press Enter for the default.

4. **Installation Plan**  
   Shows MCP config paths per agent and whether Skill distribution is enabled. Existing config files are backed up as **`.bak`** before write.

5. **Apply these configurations to selected agents?**  
   Default Yes. Confirm to write.

### Success looks like

```text
Setup complete! Please restart your selected agents to activate Metis Reverse.
```

Per-agent `MCP` / `Skill` lines show what was written (or why a step failed).

### Skip the menus

```bash
npx metis-reverse-cli@latest setup --client cursor --client claude_code --yes
```

MCP only (no Skill):

```bash
npx metis-reverse-cli@latest setup --client cursor --yes --no-skill
```

Or install the CLI globally first:

```bash
npm install -g metis-reverse-cli@latest
metis setup
```

(`metis` and `metis-reverse` are the same binary.)

## Step 4: Restart your apps

**Fully quit and reopen** every app you selected. Without a restart they will not load the new MCP config.

## Step 5: Check with doctor

```bash
npx metis-reverse-cli@latest doctor
```

Lists each supported agent: detected or not, MCP Ready / None, Skill Ready / None / N/A.  
When configured you should see something like:

```text
Metis Reverse is active on N agent(s).
All systems operational.
```

If nothing is configured yet, it tells you to run `setup`.

Machine-readable output (includes config paths):

```bash
npx metis-reverse-cli@latest doctor --json
```

In Cursor you can also open **Settings → MCP** and confirm `metis-reverse` with about **29** task-level tools.

## Useful commands

| Command | What it does |
| --- | --- |
| `npx metis-reverse-cli@latest setup` | Interactive install (default command) |
| `npx metis-reverse-cli@latest preview` | Dry-run: same UI/detection, **no disk writes** |
| `npx metis-reverse-cli@latest doctor` | Health check |
| `npx metis-reverse-cli@latest uninstall` | Remove only Metis Reverse (leave other MCP servers) |

Aliases: `setup` → `init` / `install`; `doctor` → `check` / `status`; `uninstall` → `remove`.

## Troubleshooting

**`node` / `npx` not found**  
Node missing, or terminal not restarted after install. Reopen; otherwise reinstall LTS.

**`uv` / `uvx` not found**  
Back to Step 2; reopen the terminal. The MCP engine needs `uvx`.

**`npx` is slow or hangs**  
Try a registry mirror, for example:

```bash
npx --registry=https://registry.npmmirror.com metis-reverse-cli@latest setup
```

**Windows: script execution disabled**

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Type `Y` when asked, then reopen the terminal.

**No agents selected**  
Use Space in the list, or:

```bash
npx metis-reverse-cli@latest setup --client cursor --yes
```

**Where were configs written?**  
Check the Installation Plan in setup, or:

```bash
npx metis-reverse-cli@latest doctor --json
```

There is **no** `clients` subcommand in 1.0.x.

**Wrong package name**  
Use `metis-reverse-cli@latest` (or `@1.0.1`). Old `metis-reverse` is still 0.0.1.

**Still stuck**  
Paste the full `npx metis-reverse-cli@latest doctor` output into a [GitHub Issue](https://github.com/Wholiver/metis-reverse/issues), or ask in the Metis QQ group: **801193315**.
