# Metis Reverse install guide (for beginners)

**English** · [简体中文](INSTALL.zh-CN.md)

The whole thing is five steps: **open a terminal → paste one command → press Enter → see `Done.` → restart your app**.

First you need two small tools, Node.js and uv. Each step below says exactly what to do.

> **Install the right package.** The published CLI is [`metis-reverse-cli`](https://www.npmjs.com/package/metis-reverse-cli). The older npm name `metis-reverse` is still stuck at **0.0.1** and is **not** this release. Prefer `npx metis-reverse-cli@latest setup` (or pin `@1.0.1`). The engine is pulled from the GitHub **`latest`** tag.

## Step 0: Open a terminal

A terminal is a window where you type commands.

- **Windows**: press the Windows key, type `PowerShell`, and open "Windows PowerShell".
- **macOS**: press `Command + Space`, type `Terminal`, press Enter.
- **Linux**: usually `Ctrl + Alt + T`.

![Open a terminal](images/readme/tutorial/open-terminal.png)

"Paste a command" below means: copy it into this window and press Enter.

## Step 1: Install Node.js

1. Go to https://nodejs.org/en/download and download the **LTS** installer.
2. Run it and click Next until it finishes. On Linux, follow the instructions on that page.
3. **Close the terminal and open it again**, then paste:

```bash
node -v
```

A version like `v20.19.2` (anything **18 or newer**) means it worked.

## Step 2: Install uv

uv downloads and runs the Metis Reverse engine (`uvx` from GitHub; there is **no** PyPI package yet). It also installs the Python it needs, so you don't install Python yourself.

**Windows** (in PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux**:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Close the terminal and open it again**, then check:

```bash
uv --version
```

Output like `uv 0.x.x` means it worked. You can also use `brew install uv` (macOS) or `winget install --id=astral-sh.uv -e` (Windows).

## Step 3: Run the install command

> If you use Claude Desktop, **fully quit** it first (not just close the window).

Paste this and press Enter:

```bash
npx metis-reverse-cli@latest setup
```

The first run can take a few minutes while it downloads engine dependencies. If it looks stuck, leave the window open.

You will see a few prompts:

- **Whether to install `metis-reverse-cli`**: type `y` and Enter.
- **A list of apps**: coding agents found on your machine (Cursor, Claude Code, VS Code, …). Use the arrow keys, Space to select, Enter to confirm.
- **`Install Agent Skill where supported?`**: default is Yes — press Enter.
- **Setup plan**: lists files it will change. Existing MCP configs are backed up as `.bak` first.
- **`Proceed with installation?`**: default is Yes — press Enter.

![setup app picker](images/readme/tutorial/setup-pick.png)

Success looks like:

```
Done. Restart the configured agents to load Metis Reverse.
```

![Install finished](images/readme/tutorial/setup-done.png)

Skip the picker by naming clients directly, for example:

```bash
npx metis-reverse-cli@latest setup --client cursor --client claude_code --yes
```

Or install the CLI globally first, then run the same wizard:

```bash
npm install -g metis-reverse-cli@latest
metis setup
```

## Step 4: Restart your apps

**Fully quit and reopen** every app you selected. Without a restart they will not load the new config.

## Step 5: Check (optional)

```bash
npx metis-reverse-cli@latest doctor
```

The last line should be `Healthy: yes`. Configured clients show `registered`. For machine-readable output use `doctor --json`.

WARN lines are usually fine for first use. Optional backends (for example Ghidra via `GHIDRA_INSTALL_DIR`) show up in doctor when present.

![doctor check](images/readme/tutorial/doctor.png)

You can also confirm in the app: open its MCP settings (Cursor: **Settings → MCP**). You should see `metis-reverse` with about **29** task-level tools.

Remove only Metis Reverse (leave other MCP servers alone):

```bash
npx metis-reverse-cli@latest uninstall
```

Dry-run / preview without writing files:

```bash
npx metis-reverse-cli@latest preview
```

## Troubleshooting

**`node` or `npx` is not recognized / command not found**  
Node.js is missing, or the terminal was not restarted after install. Close and reopen the terminal; if that fails, reinstall the Node.js LTS build.

**`uv` / `uvx` not found**  
uv is missing, or the terminal was not restarted. Go back to Step 2.

**`npx` is very slow or hangs**  
Often a network issue. Try a mirror, for example:

```bash
npx --registry=https://registry.npmmirror.com metis-reverse-cli@latest setup
```

**Windows: script execution is disabled**  
In PowerShell, run this, type `Y` when asked, then reopen the terminal:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**`No clients selected`**  
Nothing was checked in the list. Run setup again and press Space to select, or pass clients explicitly:

```bash
npx metis-reverse-cli@latest setup --client cursor --yes
```

**Where did it write the config?**  
Run `npx metis-reverse-cli@latest doctor` (or `doctor --json`). The `clients` subcommand was removed in 1.0.x.

**Wrong package name**  
Use `metis-reverse-cli@latest` (or pin `@1.0.1`). The old name `metis-reverse` is still 0.0.1 and is not this release.

**Still stuck**  
Paste the full output of `npx metis-reverse-cli@latest doctor` into a [GitHub Issue](https://github.com/Wholiver/metis-reverse/issues), or ask in the Metis QQ group: **801193315**.
