"use strict";

const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const {
  writeMcpConfig,
  removeMcpConfig,
  checkMcpConfigured,
  stripJsonComments,
  DEFAULT_MCP_KEY,
} = require("../src/config-engine");

describe("Config Engine Tests", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "metis-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  test("stripJsonComments handles single-line and multi-line comments", () => {
    const raw = `{\n  // single line comment\n  "key": "value" /* block comment */,\n}`;
    const clean = stripJsonComments(raw);
    const parsed = JSON.parse(clean);
    assert.strictEqual(parsed.key, "value");
  });

  test("writes and removes JSON MCP configuration safely with backup", () => {
    const cfgPath = path.join(tempDir, "cursor-mcp.json");
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({ mcpServers: { otherServer: { command: "node" } } }, null, 2),
      "utf8"
    );

    const agent = {
      id: "cursor",
      format: "json",
      serverProperty: "mcpServers",
      configPath: cfgPath,
    };

    // Before write
    const initialCheck = checkMcpConfigured(agent);
    assert.strictEqual(initialCheck.configured, false);

    // Write
    const writeRes = writeMcpConfig(agent);
    assert.strictEqual(writeRes.status, "configured");
    assert.strictEqual(fs.existsSync(`${cfgPath}.bak`), true);

    const afterWrite = checkMcpConfigured(agent);
    assert.strictEqual(afterWrite.configured, true);
    assert.strictEqual(afterWrite.spec.command, "uvx");

    // Preserve existing server
    const parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    assert.ok(parsed.mcpServers.otherServer);
    assert.ok(parsed.mcpServers[DEFAULT_MCP_KEY]);

    // Remove
    const removeRes = removeMcpConfig(agent);
    assert.strictEqual(removeRes.status, "removed");

    const afterRemove = checkMcpConfigured(agent);
    assert.strictEqual(afterRemove.configured, false);
    const finalParsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    assert.ok(finalParsed.mcpServers.otherServer);
    assert.strictEqual(finalParsed.mcpServers[DEFAULT_MCP_KEY], undefined);
  });

  test("writes and removes TOML configuration", () => {
    const cfgPath = path.join(tempDir, "codex.toml");
    fs.writeFileSync(cfgPath, `[general]\nmodel = "gpt-4"\n`, "utf8");

    const agent = {
      id: "codex",
      format: "toml",
      serverProperty: "mcp_servers",
      configPath: cfgPath,
    };

    const writeRes = writeMcpConfig(agent);
    assert.strictEqual(writeRes.status, "configured");

    const check = checkMcpConfigured(agent);
    assert.strictEqual(check.configured, true);

    const content = fs.readFileSync(cfgPath, "utf8");
    assert.match(content, /\[mcp_servers\.metis-reverse\]/);
    assert.match(content, /command = "uvx"/);

    const removeRes = removeMcpConfig(agent);
    assert.strictEqual(removeRes.status, "removed");
    const checkAfter = checkMcpConfigured(agent);
    assert.strictEqual(checkAfter.configured, false);
  });

  test("writes and removes YAML configuration", () => {
    const cfgPath = path.join(tempDir, "hermes.yaml");
    fs.writeFileSync(cfgPath, `version: 1\n`, "utf8");

    const agent = {
      id: "hermes",
      format: "yaml",
      serverProperty: "mcp_servers",
      configPath: cfgPath,
    };

    const writeRes = writeMcpConfig(agent);
    assert.strictEqual(writeRes.status, "configured");

    const check = checkMcpConfigured(agent);
    assert.strictEqual(check.configured, true);

    const removeRes = removeMcpConfig(agent);
    assert.strictEqual(removeRes.status, "removed");
  });
});
