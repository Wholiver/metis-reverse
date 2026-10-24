"use strict";

const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const { runSetup } = require("../src/commands/setup");
const { runDoctor } = require("../src/commands/doctor");
const { runUninstall } = require("../src/commands/uninstall");
const { checkMcpConfigured } = require("../src/config-engine");
const { checkSkillInstalled } = require("../src/skill-distributor");
const { getAgentDefinitions } = require("../src/agents-spec");

describe("Full Lifecycle Integration Tests", () => {
  let mockHome;

  beforeEach(() => {
    mockHome = fs.mkdtempSync(path.join(os.tmpdir(), "metis-home-"));
    // Create markers for cursor and antigravity
    fs.mkdirSync(path.join(mockHome, ".cursor"), { recursive: true });
    fs.mkdirSync(path.join(mockHome, ".gemini", "config"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(mockHome, { recursive: true, force: true });
  });

  test("runs setup -> doctor -> uninstall lifecycle end-to-end", async () => {
    const opts = {
      home: mockHome,
      client: ["cursor", "antigravity"],
      yes: true,
      dryRun: false,
    };

    // 1. Setup
    const setupCode = await runSetup(opts);
    assert.strictEqual(setupCode, 0);

    const agents = getAgentDefinitions(opts);
    const cursor = agents.find((a) => a.id === "cursor");
    const antigravity = agents.find((a) => a.id === "antigravity");

    // Check Cursor MCP & Skill & Rule
    const cursorMcp = checkMcpConfigured(cursor);
    assert.strictEqual(cursorMcp.configured, true);
    assert.strictEqual(cursorMcp.spec.command, "uvx");

    const cursorSkill = checkSkillInstalled(cursor);
    assert.strictEqual(cursorSkill.installed, true);
    assert.strictEqual(fs.existsSync(cursor.rulesPath), true);

    // Check Antigravity MCP & Skill
    const antiMcp = checkMcpConfigured(antigravity);
    assert.strictEqual(antiMcp.configured, true);
    const antiSkill = checkSkillInstalled(antigravity);
    assert.strictEqual(antiSkill.installed, true);

    // 2. Doctor
    const doctorCode = await runDoctor({ ...opts, json: true });
    assert.strictEqual(doctorCode, 0);

    // 3. Uninstall
    const uninstallCode = await runUninstall(opts);
    assert.strictEqual(uninstallCode, 0);

    // Verify uninstalled
    const cursorMcpAfter = checkMcpConfigured(cursor);
    assert.strictEqual(cursorMcpAfter.configured, false);
    const cursorSkillAfter = checkSkillInstalled(cursor);
    assert.strictEqual(cursorSkillAfter.installed, false);
    assert.strictEqual(fs.existsSync(cursor.rulesPath), false);

    const antiMcpAfter = checkMcpConfigured(antigravity);
    assert.strictEqual(antiMcpAfter.configured, false);
  });
});
