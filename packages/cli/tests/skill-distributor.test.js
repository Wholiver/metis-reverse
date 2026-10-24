"use strict";

const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const {
  installSkill,
  uninstallSkill,
  checkSkillInstalled,
} = require("../src/skill-distributor");

describe("Skill Distributor Tests", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "metis-skill-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  test("installs full skill bundle including references and cursor rule, and uninstalls cleanly", () => {
    const targetSkillDir = path.join(tempDir, "cursor", "skills", "metis-reverse");
    const targetRulesPath = path.join(tempDir, "cursor", "rules", "metis-reverse.mdc");

    const agent = {
      id: "cursor",
      displayName: "Cursor",
      skillPath: targetSkillDir,
      rulesPath: targetRulesPath,
    };

    // Initial check
    const initialCheck = checkSkillInstalled(agent);
    assert.strictEqual(initialCheck.installed, false);

    // Install
    const installRes = installSkill(agent);
    assert.strictEqual(installRes.status, "installed");

    // Verify files
    assert.strictEqual(fs.existsSync(path.join(targetSkillDir, "SKILL.md")), true);
    assert.strictEqual(
      fs.existsSync(path.join(targetSkillDir, "references", "tools-catalog-and-schemas.md")),
      true
    );
    assert.strictEqual(
      fs.existsSync(path.join(targetSkillDir, "references", "polyglot-and-degradation-guide.md")),
      true
    );
    assert.strictEqual(
      fs.existsSync(path.join(targetSkillDir, "references", "escape-hatch-probe-recipes.md")),
      true
    );
    assert.strictEqual(fs.existsSync(targetRulesPath), true);

    const checkAfter = checkSkillInstalled(agent);
    assert.strictEqual(checkAfter.installed, true);
    assert.strictEqual(checkAfter.hasReferences, true);

    // Uninstall
    const uninstallRes = uninstallSkill(agent);
    assert.strictEqual(uninstallRes.status, "removed");
    assert.strictEqual(fs.existsSync(targetSkillDir), false);
    assert.strictEqual(fs.existsSync(targetRulesPath), false);

    const checkFinal = checkSkillInstalled(agent);
    assert.strictEqual(checkFinal.installed, false);
  });
});
