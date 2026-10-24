"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const { getAgentDefinitions, isAgentDetected } = require("../src/agents-spec");

describe("Agents Spec Tests", () => {
  test("defines all 23 supported agents with required fields", () => {
    const agents = getAgentDefinitions();
    assert.ok(agents.length >= 20, "Should support at least 20 agents");

    const ids = new Set(agents.map((a) => a.id));
    const expected = [
      "cursor",
      "claude_code",
      "claude_desktop",
      "antigravity",
      "codex",
      "gemini_cli",
      "vscode",
      "trae",
      "windsurf",
      "opencode",
      "workbuddy",
      "copilot_cli",
      "devin",
      "kimi",
      "qwen_code",
      "grok_build",
      "hermes",
      "qoder",
      "droid",
      "omp",
      "pi",
      "zcode",
      "dsh",
    ];

    for (const exp of expected) {
      assert.ok(ids.has(exp), `Expected agent ${exp} to be present in definitions`);
    }

    for (const a of agents) {
      assert.ok(a.id, "Agent must have an id");
      assert.ok(a.displayName, "Agent must have a displayName");
      assert.ok(a.format, "Agent must specify config format");
      assert.ok(a.configPath, "Agent must specify configPath");
      assert.ok(Array.isArray(a.markerPaths), "Agent must specify markerPaths array");
    }
  });

  test("isAgentDetected correctly identifies presence based on markerPaths", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "marker-test-"));
    try {
      const mockMarker = path.join(tempDir, ".mock-agent");
      const agent = {
        id: "mock",
        markerPaths: [mockMarker],
      };

      assert.strictEqual(isAgentDetected(agent), false);
      fs.mkdirSync(mockMarker);
      assert.strictEqual(isAgentDetected(agent), true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
