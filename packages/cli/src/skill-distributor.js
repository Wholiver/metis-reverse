"use strict";

const fs = require("node:fs");
const path = require("node:path");

/**
 * Resolves source directory containing the Skill assets.
 */
function resolveSkillSourceDir() {
  const localAssets = path.resolve(__dirname, "..", "assets", "skills");
  if (fs.existsSync(path.join(localAssets, "SKILL.md"))) {
    return localAssets;
  }

  // Fallbacks in repo
  const repoSkillMcp = path.resolve(__dirname, "..", "..", "..", "skills", "metis-reverse-mcp");
  if (fs.existsSync(path.join(repoSkillMcp, "SKILL.md"))) {
    return repoSkillMcp;
  }

  const repoSkill = path.resolve(__dirname, "..", "..", "..", "skills", "metis-reverse");
  if (fs.existsSync(path.join(repoSkill, "SKILL.md"))) {
    return repoSkill;
  }

  return null;
}

/**
 * Resolves Cursor MDC rule source file.
 */
function resolveCursorMdcSource() {
  const localMdc = path.resolve(__dirname, "..", "assets", "cursor-rules", "metis-reverse.mdc");
  if (fs.existsSync(localMdc)) {
    return localMdc;
  }

  const repoMdc = path.resolve(__dirname, "..", "..", "..", ".cursor", "rules", "metis-reverse.mdc");
  if (fs.existsSync(repoMdc)) {
    return repoMdc;
  }

  return null;
}

/**
 * Checks whether skill is installed for the given agent.
 */
function checkSkillInstalled(agent) {
  if (!agent.skillPath) {
    return { supported: false, installed: false, detail: "Agent does not support external skills" };
  }

  const manifest = path.join(agent.skillPath, "SKILL.md");
  const installed = fs.existsSync(manifest);
  const referencesDir = path.join(agent.skillPath, "references");
  const hasReferences = fs.existsSync(referencesDir);

  return {
    supported: true,
    installed,
    path: agent.skillPath,
    hasReferences,
    detail: installed ? (hasReferences ? "Complete skill package installed" : "SKILL.md installed") : "Not installed",
  };
}

/**
 * Recursively copies a directory.
 */
function copyDirSync(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirSync(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Installs skill assets (and Cursor MDC rules if applicable) for an agent.
 */
function installSkill(agent, options = {}) {
  const dryRun = Boolean(options.dryRun);
  if (!agent.skillPath) {
    return { status: "skipped", detail: "Agent does not support skills" };
  }

  const sourceDir = resolveSkillSourceDir();
  if (!sourceDir) {
    return { status: "failed", detail: "Skill assets source directory not found" };
  }

  if (dryRun) {
    return { status: "planned", detail: `Would install skill into ${agent.skillPath}` };
  }

  try {
    fs.mkdirSync(agent.skillPath, { recursive: true });
    copyDirSync(sourceDir, agent.skillPath);

    // If agent specifies a custom rulesPath (e.g. Cursor rules)
    if (agent.rulesPath) {
      const mdcSource = resolveCursorMdcSource();
      if (mdcSource) {
        fs.mkdirSync(path.dirname(agent.rulesPath), { recursive: true });
        fs.copyFileSync(mdcSource, agent.rulesPath);
      }
    }

    return { status: "installed", detail: `Installed skill at ${agent.skillPath}` };
  } catch (err) {
    return { status: "failed", detail: `Failed to install skill: ${err.message}` };
  }
}

/**
 * Uninstalls skill assets for an agent.
 */
function uninstallSkill(agent, options = {}) {
  const dryRun = Boolean(options.dryRun);
  const hasSkill = agent.skillPath && fs.existsSync(agent.skillPath);
  const hasRules = agent.rulesPath && fs.existsSync(agent.rulesPath);

  if (!hasSkill && !hasRules) {
    return { status: "skipped", detail: "No skill or rules installed" };
  }

  if (dryRun) {
    const targets = [hasSkill ? agent.skillPath : null, hasRules ? agent.rulesPath : null].filter(Boolean);
    return { status: "planned", detail: `Would delete ${targets.join(", ")}` };
  }

  try {
    if (hasSkill) {
      fs.rmSync(agent.skillPath, { recursive: true, force: true });
    }
    if (hasRules) {
      fs.rmSync(agent.rulesPath, { force: true });
    }
    return { status: "removed", detail: `Removed skill from ${agent.skillPath || agent.rulesPath}` };
  } catch (err) {
    return { status: "failed", detail: `Failed to remove skill: ${err.message}` };
  }
}

module.exports = {
  resolveSkillSourceDir,
  resolveCursorMdcSource,
  checkSkillInstalled,
  installSkill,
  uninstallSkill,
};
