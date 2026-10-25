"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_MCP_KEY = "metis-reverse";
const DEFAULT_COMMAND = "uvx";
const DEFAULT_ARGS = [
  "--from",
  "git+https://github.com/Wholiver/metis-reverse.git@latest",
  "metis-reverse",
];

function getDefaultMcpSpec(options = {}) {
  return {
    command: options.command || DEFAULT_COMMAND,
    args: options.args || DEFAULT_ARGS,
  };
}

/**
 * Strip comments and trailing commas from JSON/JSONC string.
 */
function stripJsonComments(jsonString) {
  let insideString = false;
  let stringChar = "";
  let isEscaped = false;
  let result = "";

  for (let i = 0; i < jsonString.length; i++) {
    const ch = jsonString[i];
    const next = jsonString[i + 1];

    if (insideString) {
      result += ch;
      if (isEscaped) {
        isEscaped = false;
      } else if (ch === "\\") {
        isEscaped = true;
      } else if (ch === stringChar) {
        insideString = false;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      insideString = true;
      stringChar = ch;
      result += ch;
      continue;
    }

    // Line comment
    if (ch === "/" && next === "/") {
      while (i < jsonString.length && jsonString[i] !== "\n") {
        i++;
      }
      if (i < jsonString.length) {
        result += jsonString[i];
      }
      continue;
    }

    // Block comment
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < jsonString.length && !(jsonString[i] === "*" && jsonString[i + 1] === "/")) {
        i++;
      }
      i++; // skip /
      continue;
    }

    result += ch;
  }

  // Remove trailing commas before } or ]
  return result.replace(/,\s*([\]}])/g, "$1");
}

function parseJsonSafe(content) {
  try {
    return JSON.parse(content);
  } catch {
    return JSON.parse(stripJsonComments(content));
  }
}

/**
 * Checks whether metis-reverse MCP is configured for the given agent.
 */
function checkMcpConfigured(agent) {
  const configPath = agent.configPath;
  if (!configPath || !fs.existsSync(configPath)) {
    return { configured: false, detail: "Configuration file does not exist" };
  }

  try {
    const raw = fs.readFileSync(configPath, "utf8");
    if (agent.format === "toml") {
      const hasSection =
        raw.includes(`[${agent.serverProperty}.${DEFAULT_MCP_KEY}]`) ||
        raw.includes(`[mcpServers.${DEFAULT_MCP_KEY}]`) ||
        raw.includes(`[mcp_servers.${DEFAULT_MCP_KEY}]`);
      return { configured: hasSection, detail: hasSection ? "Found TOML section" : "Not configured" };
    }

    if (agent.format === "yaml") {
      const hasYamlKey = raw.includes(`${DEFAULT_MCP_KEY}:`);
      return { configured: hasYamlKey, detail: hasYamlKey ? "Found YAML key" : "Not configured" };
    }

    // JSON / JSONC
    const parsed = parseJsonSafe(raw);
    const key = agent.serverProperty || "mcpServers";
    const servers = parsed[key] || parsed.mcpServers || parsed.mcp_servers || {};
    const configured = Boolean(servers[DEFAULT_MCP_KEY]);
    return { configured, detail: configured ? "Configured in JSON" : "Not configured", spec: servers[DEFAULT_MCP_KEY] };
  } catch (err) {
    return { configured: false, detail: `Error reading config: ${err.message}` };
  }
}

/**
 * Writes or updates metis-reverse MCP configuration for the given agent.
 */
function writeMcpConfig(agent, options = {}) {
  const dryRun = Boolean(options.dryRun);
  const spec = getDefaultMcpSpec(options);
  const configPath = agent.configPath;

  if (!configPath) {
    return { status: "failed", detail: "No configuration path for agent" };
  }

  if (dryRun) {
    return { status: "planned", detail: `Would write to ${configPath}` };
  }

  // Ensure parent directory exists
  const parentDir = path.dirname(configPath);
  fs.mkdirSync(parentDir, { recursive: true });

  const exists = fs.existsSync(configPath);
  let raw = exists ? fs.readFileSync(configPath, "utf8") : "";

  // Make a backup if file exists and no backup exists
  if (exists) {
    const backupPath = `${configPath}.bak`;
    if (!fs.existsSync(backupPath)) {
      try {
        fs.writeFileSync(backupPath, raw, "utf8");
      } catch {
        // Backup failure is non-fatal
      }
    }
  }

  if (agent.format === "toml") {
    return writeTomlMcp(configPath, raw, agent.serverProperty || "mcp_servers", spec);
  }

  if (agent.format === "yaml") {
    return writeYamlMcp(configPath, raw, agent.serverProperty || "mcp_servers", spec);
  }

  // Default JSON / JSONC
  return writeJsonMcp(configPath, raw, agent.serverProperty || "mcpServers", spec);
}

function writeJsonMcp(configPath, raw, serverProperty, spec) {
  let doc = {};
  if (raw.trim()) {
    try {
      doc = parseJsonSafe(raw);
    } catch (err) {
      return { status: "failed", detail: `Cannot parse existing JSON in ${configPath}: ${err.message}` };
    }
  }

  if (!doc[serverProperty] || typeof doc[serverProperty] !== "object") {
    doc[serverProperty] = {};
  }

  doc[serverProperty][DEFAULT_MCP_KEY] = spec;
  fs.writeFileSync(configPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
  return { status: "configured", detail: `Configured ${configPath}` };
}

function writeTomlMcp(configPath, raw, serverProperty, spec) {
  const sectionHeader = `[${serverProperty}.${DEFAULT_MCP_KEY}]`;
  const argsFormatted = JSON.stringify(spec.args);
  const newSection = `\n${sectionHeader}\ncommand = "${spec.command}"\nargs = ${argsFormatted}\n`;

  let updated = raw;
  const regex = new RegExp(`\\[${serverProperty}\\.${DEFAULT_MCP_KEY}\\][\\s\\S]*?(?=(\\n\\[|$))`);
  if (regex.test(raw)) {
    updated = raw.replace(regex, `${sectionHeader}\ncommand = "${spec.command}"\nargs = ${argsFormatted}\n`);
  } else {
    updated = raw.trimEnd() + (raw.trim() ? "\n\n" : "") + newSection.trim() + "\n";
  }

  fs.writeFileSync(configPath, updated, "utf8");
  return { status: "configured", detail: `Configured TOML in ${configPath}` };
}

function writeYamlMcp(configPath, raw, serverProperty, spec) {
  const argsLines = spec.args.map((a) => `      - ${JSON.stringify(a)}`).join("\n");
  const block = `  ${DEFAULT_MCP_KEY}:\n    command: ${JSON.stringify(spec.command)}\n    args:\n${argsLines}\n`;

  let updated = raw;
  if (!raw.includes(`${serverProperty}:`)) {
    updated = raw.trimEnd() + (raw.trim() ? "\n\n" : "") + `${serverProperty}:\n` + block;
  } else {
    const mcpBlockRegex = new RegExp(`(\\s*${DEFAULT_MCP_KEY}:[\\s\\S]*?)(?=(\\n\\s{2}[a-zA-Z0-9_-]+:|\\n\\S|$))`);
    if (mcpBlockRegex.test(raw)) {
      updated = raw.replace(mcpBlockRegex, `\n${block.trimEnd()}`);
    } else {
      updated = raw.replace(new RegExp(`(${serverProperty}:[\\r\\n]*)`), `$1${block}`);
    }
  }

  fs.writeFileSync(configPath, updated, "utf8");
  return { status: "configured", detail: `Configured YAML in ${configPath}` };
}

/**
 * Removes metis-reverse MCP configuration for the given agent.
 */
function removeMcpConfig(agent, options = {}) {
  const dryRun = Boolean(options.dryRun);
  const configPath = agent.configPath;

  if (!configPath || !fs.existsSync(configPath)) {
    return { status: "skipped", detail: "Configuration file does not exist" };
  }

  if (dryRun) {
    return { status: "planned", detail: `Would remove from ${configPath}` };
  }

  const raw = fs.readFileSync(configPath, "utf8");

  if (agent.format === "toml") {
    const serverProperty = agent.serverProperty || "mcp_servers";
    const sectionHeader = `[${serverProperty}.${DEFAULT_MCP_KEY}]`;
    if (!raw.includes(sectionHeader)) {
      return { status: "skipped", detail: "Not present in TOML" };
    }
    const regex = new RegExp(`\\[${serverProperty}\\.${DEFAULT_MCP_KEY}\\][\\s\\S]*?(?=(\\n\\[|$))`);
    const updated = raw.replace(regex, "").trim() + "\n";
    fs.writeFileSync(configPath, updated, "utf8");
    return { status: "removed", detail: `Removed from ${configPath}` };
  }

  if (agent.format === "yaml") {
    if (!raw.includes(`${DEFAULT_MCP_KEY}:`)) {
      return { status: "skipped", detail: "Not present in YAML" };
    }
    const mcpBlockRegex = new RegExp(`\\n?\\s*${DEFAULT_MCP_KEY}:[\\s\\S]*?(?=(\\n\\s{2}[a-zA-Z0-9_-]+:|\\n\\S|$))`);
    const updated = raw.replace(mcpBlockRegex, "").trim() + "\n";
    fs.writeFileSync(configPath, updated, "utf8");
    return { status: "removed", detail: `Removed from ${configPath}` };
  }

  // JSON
  try {
    const doc = parseJsonSafe(raw);
    const key = agent.serverProperty || "mcpServers";
    let found = false;

    if (doc[key] && doc[key][DEFAULT_MCP_KEY]) {
      delete doc[key][DEFAULT_MCP_KEY];
      found = true;
    }
    if (doc.mcpServers && doc.mcpServers[DEFAULT_MCP_KEY]) {
      delete doc.mcpServers[DEFAULT_MCP_KEY];
      found = true;
    }

    if (!found) {
      return { status: "skipped", detail: "Not present in JSON" };
    }

    fs.writeFileSync(configPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
    return { status: "removed", detail: `Removed from ${configPath}` };
  } catch (err) {
    return { status: "failed", detail: `Cannot parse JSON during removal: ${err.message}` };
  }
}

module.exports = {
  DEFAULT_MCP_KEY,
  DEFAULT_COMMAND,
  DEFAULT_ARGS,
  getDefaultMcpSpec,
  checkMcpConfigured,
  writeMcpConfig,
  removeMcpConfig,
  stripJsonComments,
  parseJsonSafe,
};
