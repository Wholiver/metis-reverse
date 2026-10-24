"use strict";

const path = require("node:path");
const fs = require("node:fs");

function resolveHome(env = process.env, platform = process.platform) {
  if (platform === "win32") {
    return env.USERPROFILE || env.HOME || path.join(env.HOMEDRIVE || "C:", env.HOMEPATH || "\\");
  }
  return env.HOME || "/";
}

function resolveXdgConfig(home, env = process.env) {
  return env.XDG_CONFIG_HOME || path.join(home, ".config");
}

function resolveAppData(home, env = process.env) {
  return env.APPDATA || path.join(home, "AppData", "Roaming");
}

/**
 * Returns complete definition catalog for supported AI coding agents.
 * Paths are resolved dynamically based on platform and environment.
 */
function getAgentDefinitions(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const home = options.home || resolveHome(env, platform);
  const xdgConfig = resolveXdgConfig(home, env);
  const appData = resolveAppData(home, env);

  const claudeDesktopDir =
    platform === "win32"
      ? path.join(appData, "Claude")
      : platform === "darwin"
      ? path.join(home, "Library", "Application Support", "Claude")
      : path.join(xdgConfig, "Claude");

  const vscodeUserDir =
    platform === "win32"
      ? path.join(appData, "Code", "User")
      : platform === "darwin"
      ? path.join(home, "Library", "Application Support", "Code", "User")
      : path.join(xdgConfig, "Code", "User");

  const traeUserDir =
    platform === "win32"
      ? path.join(appData, "Trae", "User")
      : platform === "darwin"
      ? path.join(home, "Library", "Application Support", "Trae", "User")
      : path.join(xdgConfig, "Trae", "User");

  const devinDir = platform === "win32" ? path.join(appData, "devin") : path.join(xdgConfig, "devin");

  return [
    {
      id: "cursor",
      displayName: "Cursor",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".cursor", "mcp.json"),
      markerPaths: [path.join(home, ".cursor"), path.join(home, ".cursor", "mcp.json")],
      skillPath: path.join(home, ".cursor", "skills", "metis-reverse"),
      rulesPath: path.join(home, ".cursor", "rules", "metis-reverse.mdc"),
    },
    {
      id: "claude_code",
      displayName: "Claude Code",
      format: "json",
      serverProperty: "mcpServers",
      configPath: env.CLAUDE_CONFIG_DIR
        ? path.join(env.CLAUDE_CONFIG_DIR, ".claude.json")
        : path.join(home, ".claude.json"),
      markerPaths: [
        env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"),
        path.join(home, ".claude.json"),
      ],
      skillPath: path.join(env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"), "skills", "metis-reverse"),
    },
    {
      id: "claude_desktop",
      displayName: "Claude Desktop",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(claudeDesktopDir, "claude_desktop_config.json"),
      markerPaths: [claudeDesktopDir],
      skillPath: null,
    },
    {
      id: "antigravity",
      displayName: "Antigravity",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".gemini", "config", "mcp_config.json"),
      markerPaths: [path.join(home, ".gemini", "config"), path.join(home, ".gemini", "antigravity")],
      skillPath: path.join(home, ".gemini", "config", "skills", "metis-reverse"),
    },
    {
      id: "codex",
      displayName: "Codex",
      format: "toml",
      serverProperty: "mcp_servers",
      configPath: env.CODEX_HOME
        ? path.join(env.CODEX_HOME, "config.toml")
        : path.join(home, ".codex", "config.toml"),
      markerPaths: [env.CODEX_HOME || path.join(home, ".codex")],
      skillPath: path.join(home, ".agents", "skills", "metis-reverse"),
    },
    {
      id: "gemini_cli",
      displayName: "Gemini CLI",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(env.GEMINI_CLI_HOME || home, ".gemini", "settings.json"),
      markerPaths: [path.join(env.GEMINI_CLI_HOME || home, ".gemini")],
      skillPath: path.join(env.GEMINI_CLI_HOME || home, ".agents", "skills", "metis-reverse"),
    },
    {
      id: "vscode",
      displayName: "VS Code",
      format: "jsonc",
      serverProperty: "mcpServers",
      configPath: path.join(vscodeUserDir, "mcp.json"),
      markerPaths: [vscodeUserDir],
      skillPath: null,
    },
    {
      id: "trae",
      displayName: "Trae",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(traeUserDir, "mcp.json"),
      markerPaths: [traeUserDir, path.join(home, ".trae")],
      skillPath: path.join(home, ".trae", "skills", "metis-reverse"),
    },
    {
      id: "windsurf",
      displayName: "Windsurf",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".codeium", "windsurf", "mcp_config.json"),
      markerPaths: [path.join(home, ".codeium", "windsurf")],
      skillPath: null,
    },
    {
      id: "opencode",
      displayName: "OpenCode",
      format: "jsonc",
      serverProperty: "mcpServers",
      configPath: env.OPENCODE_CONFIG || path.join(xdgConfig, "opencode", "opencode.json"),
      markerPaths: [
        env.OPENCODE_CONFIG_DIR || path.join(xdgConfig, "opencode"),
        path.join(home, ".opencode"),
      ],
      skillPath: path.join(home, ".agents", "skills", "metis-reverse"),
    },
    {
      id: "workbuddy",
      displayName: "WorkBuddy",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".workbuddy", "mcp.json"),
      markerPaths: [path.join(home, ".workbuddy")],
      skillPath: path.join(home, ".workbuddy", "skills", "metis-reverse"),
    },
    {
      id: "copilot_cli",
      displayName: "GitHub Copilot CLI",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(env.COPILOT_HOME || path.join(home, ".copilot"), "mcp-config.json"),
      markerPaths: [env.COPILOT_HOME || path.join(home, ".copilot")],
      skillPath: path.join(env.COPILOT_HOME || path.join(home, ".copilot"), "skills", "metis-reverse"),
    },
    {
      id: "devin",
      displayName: "Devin",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(devinDir, "mcp_config.json"),
      markerPaths: [devinDir],
      skillPath: null,
    },
    {
      id: "kimi",
      displayName: "Kimi Code",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(env.KIMI_CODE_HOME || path.join(home, ".kimi-code"), "mcp.json"),
      markerPaths: [env.KIMI_CODE_HOME || path.join(home, ".kimi-code")],
      skillPath: path.join(env.KIMI_CODE_HOME || path.join(home, ".kimi-code"), "skills", "metis-reverse"),
    },
    {
      id: "qwen_code",
      displayName: "Qwen Code",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(env.QWEN_HOME || path.join(home, ".qwen"), "settings.json"),
      markerPaths: [env.QWEN_HOME || path.join(home, ".qwen")],
      skillPath: path.join(env.QWEN_HOME || path.join(home, ".qwen"), "skills", "metis-reverse"),
    },
    {
      id: "grok_build",
      displayName: "Grok Build",
      format: "toml",
      serverProperty: "mcp_servers",
      configPath: path.join(env.GROK_HOME || path.join(home, ".grok"), "config.toml"),
      markerPaths: [env.GROK_HOME || path.join(home, ".grok")],
      skillPath: null,
    },
    {
      id: "hermes",
      displayName: "Hermes",
      format: "yaml",
      serverProperty: "mcp_servers",
      configPath: path.join(home, ".hermes", "config.yaml"),
      markerPaths: [path.join(home, ".hermes")],
      skillPath: path.join(home, ".hermes", "skills", "metis-reverse"),
    },
    {
      id: "qoder",
      displayName: "Qoder",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(env.QODER_CONFIG_DIR || path.join(home, ".qoder"), "settings.json"),
      markerPaths: [env.QODER_CONFIG_DIR || path.join(home, ".qoder")],
      skillPath: path.join(env.QODER_CONFIG_DIR || path.join(home, ".qoder"), "skills", "metis-reverse"),
    },
    {
      id: "droid",
      displayName: "Factory Droid",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".factory", "mcp.json"),
      markerPaths: [path.join(home, ".factory")],
      skillPath: path.join(home, ".factory", "skills", "metis-reverse"),
    },
    {
      id: "omp",
      displayName: "OMP",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".omp", "agent", "mcp.json"),
      markerPaths: [path.join(home, ".omp")],
      skillPath: path.join(home, ".omp", "skills", "metis-reverse"),
    },
    {
      id: "pi",
      displayName: "Pi",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".pi", "agent", "mcp.json"),
      markerPaths: [path.join(home, ".pi")],
      skillPath: path.join(home, ".pi", "skills", "metis-reverse"),
    },
    {
      id: "zcode",
      displayName: "ZCode",
      format: "json",
      serverProperty: "mcpServers",
      configPath: path.join(home, ".zcode", "cli", "config.json"),
      markerPaths: [path.join(home, ".zcode")],
      skillPath: path.join(home, ".zcode", "skills", "metis-reverse"),
    },
    {
      id: "dsh",
      displayName: "DeepSeek Harness",
      format: "yaml",
      serverProperty: "mcp_servers",
      configPath: path.join(home, ".dsh", "cordis.patch.yml"),
      markerPaths: [path.join(home, ".dsh")],
      skillPath: path.join(home, ".agents", "skills", "metis-reverse"),
    },
  ];
}

/**
 * Checks whether an agent is detected on the local system.
 */
function isAgentDetected(agent) {
  for (const marker of agent.markerPaths) {
    try {
      if (fs.existsSync(marker)) {
        return true;
      }
    } catch {
      // Ignored
    }
  }
  return false;
}

module.exports = {
  getAgentDefinitions,
  isAgentDetected,
  resolveHome,
};
