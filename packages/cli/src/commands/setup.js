"use strict";

const { getAgentDefinitions, isAgentDetected } = require("../agents-spec");
const { checkMcpConfigured, writeMcpConfig } = require("../config-engine");
const { checkSkillInstalled, installSkill } = require("../skill-distributor");
const PKG = require("../../package.json");

async function runSetup(options = {}) {
  let p, pc;
  try {
    p = await import("@clack/prompts");
    pc = (await import("picocolors")).default;
  } catch {
    // Non-TTY or minimal fallback
  }

  const dryRun = Boolean(options.dryRun);
  const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const interactive = (isTty && !options.yes) || options.interactive;

  if (options.walkthrough) {
    return runWalkthrough(options);
  }

  const agents = getAgentDefinitions(options);
  const agentStates = agents.map((agent) => {
    const detected = isAgentDetected(agent);
    const mcp = checkMcpConfigured(agent);
    const skill = checkSkillInstalled(agent);
    return {
      agent,
      detected,
      configured: mcp.configured,
      skillInstalled: skill.installed,
    };
  });

  if (p && interactive) {
    if (process.stdout.isTTY) {
      console.clear();
    }
    p.intro(
      pc.bgCyan(pc.black(pc.bold(" METIS REVERSE "))) +
        "  " +
        pc.bold("Agent Installer & MCP Manager") +
        "  " +
        pc.dim("v" + PKG.version)
    );
    if (dryRun) {
      p.log.warn("Running in preview mode (--dry-run). No changes will be written to disk.");
    }

    const spinner = p.spinner();
    spinner.start("Detecting installed AI agents…");
    const detectedCount = agentStates.filter((s) => s.detected).length;
    spinner.stop(`Detection complete: ${detectedCount} agent(s) found on this machine.`);

    // Sort so detected & configured agents appear at the top
    const sortedStates = [...agentStates].sort((a, b) => {
      const aScore = (a.configured ? 2 : 0) + (a.detected ? 1 : 0);
      const bScore = (b.configured ? 2 : 0) + (b.detected ? 1 : 0);
      return bScore - aScore;
    });

    // Prepare multi-select options
    const choices = sortedStates.map((s) => {
      const hints = [];
      if (s.configured) hints.push("MCP active");
      if (s.detected) hints.push("detected");
      else hints.push("not detected");
      if (s.agent.skillPath) hints.push("supports skill");

      return {
        value: s.agent.id,
        label: s.agent.displayName,
        hint: hints.join(" · "),
      };
    });

    const initial = sortedStates
      .filter((s) => s.configured || s.detected)
      .map((s) => s.agent.id);

    // Expand terminal row constraint so multiselect displays all choices without folding (...)
    const prevRows = process.stdout.rows;
    if (process.stdout.isTTY && (process.stdout.rows || 0) < choices.length + 8) {
      try {
        Object.defineProperty(process.stdout, "rows", {
          value: Math.max(process.stdout.rows || 24, choices.length + 10),
          configurable: true,
          writable: true,
        });
      } catch {
        // ignore
      }
    }

    let selectedIds;
    try {
      selectedIds = await p.multiselect({
        message: "Which agents should Metis Reverse be installed into?",
        options: choices,
        initialValues: initial.length > 0 ? initial : undefined,
        required: true,
      });
    } finally {
      if (prevRows !== undefined) {
        try {
          Object.defineProperty(process.stdout, "rows", {
            value: prevRows,
            configurable: true,
            writable: true,
          });
        } catch {
          // ignore
        }
      }
    }

    if (p.isCancel(selectedIds)) {
      p.cancel("Setup cancelled.");
      return 0;
    }

    let installSkills = !options.noSkill;
    if (installSkills) {
      const skillChoice = await p.confirm({
        message: "Install complete Agent Skill package (SKILL.md + reverse references + rules)?",
        initialValue: true,
      });

      if (p.isCancel(skillChoice)) {
        p.cancel("Setup cancelled.");
        return 0;
      }
      installSkills = Boolean(skillChoice);
    }

    // Display Plan Note
    const planLines = selectedIds.map((id) => {
      const state = agentStates.find((s) => s.agent.id === id);
      const name = state ? state.agent.displayName : id;
      const cfgPath = state ? state.agent.configPath : "";
      return `  ${pc.cyan(name)}\n    MCP Config: ${pc.dim(cfgPath)}`;
    });
    planLines.push(`  Skill distribution: ${installSkills ? pc.green("Enabled") : pc.dim("Disabled")}`);
    if (dryRun) {
      planLines.push(`  Mode: ${pc.yellow("Dry-run / Preview only")}`);
    }

    console.log();
    p.note(planLines.join("\n"), "Installation Plan");

    const proceed = await p.confirm({
      message: dryRun ? "Run dry-run execution?" : "Apply these configurations to selected agents?",
      initialValue: true,
    });

    if (p.isCancel(proceed) || !proceed) {
      p.cancel("Setup cancelled.");
      return 0;
    }

    const applySpinner = p.spinner();
    applySpinner.start(dryRun ? "Simulating agent configuration…" : "Writing configurations & skills…");

    const results = [];
    for (const id of selectedIds) {
      const target = agentStates.find((s) => s.agent.id === id).agent;
      const mcpRes = writeMcpConfig(target, { dryRun, command: options.command, args: options.args });
      results.push({ target, action: "MCP", result: mcpRes });

      if (installSkills && target.skillPath) {
        const skillRes = installSkill(target, { dryRun });
        results.push({ target, action: "Skill", result: skillRes });
      }
    }

    applySpinner.stop(dryRun ? "Preview complete." : "Installation applied.");

    for (const item of results) {
      const name = item.target.displayName;
      const tag = item.action;
      const res = item.result;
      if (res.status === "failed") {
        p.log.error(`${name} [${tag}]: ${res.detail}`);
      } else if (res.status === "planned") {
        p.log.info(`${name} [${tag}]: ${res.detail}`);
      } else {
        p.log.success(`${name} [${tag}]: ${res.detail}`);
      }
    }

    if (dryRun) {
      p.outro("Dry run finished. Nothing was written to disk.");
    } else {
      p.outro("Setup complete! Please restart your selected agents to activate Metis Reverse.");
    }

    return results.some((r) => r.result.status === "failed") ? 1 : 0;
  }

  // Non-interactive path
  let targetIds = [];
  if (options.client && (Array.isArray(options.client) ? options.client.length > 0 : Boolean(options.client))) {
    targetIds = Array.isArray(options.client) ? options.client : [options.client];
  } else {
    // Default to all detected agents or all configured
    targetIds = agentStates.filter((s) => s.detected || s.configured).map((s) => s.agent.id);
  }

  if (targetIds.length === 0) {
    console.log("No agents detected or specified to configure. Pass --client <id> to specify targets.");
    return 0;
  }

  console.log(`[Metis Reverse] Configuring ${targetIds.length} target agent(s)... (dryRun: ${dryRun})`);
  let hasFailure = false;

  for (const id of targetIds) {
    const match = agentStates.find((s) => s.agent.id === id);
    if (!match) {
      console.error(`Unknown agent ID: ${id}`);
      hasFailure = true;
      continue;
    }

    const agent = match.agent;
    const mcpRes = writeMcpConfig(agent, { dryRun, command: options.command, args: options.args });
    console.log(`- ${agent.displayName} [MCP]: ${mcpRes.status} (${mcpRes.detail})`);
    if (mcpRes.status === "failed") hasFailure = true;

    if (!options.noSkill && agent.skillPath) {
      const skillRes = installSkill(agent, { dryRun });
      console.log(`- ${agent.displayName} [Skill]: ${skillRes.status} (${skillRes.detail})`);
      if (skillRes.status === "failed") hasFailure = true;
    }
  }

  console.log(hasFailure ? "[Metis Reverse] Setup finished with errors." : "[Metis Reverse] Setup completed successfully.");
  return hasFailure ? 1 : 0;
}

async function runWalkthrough(options = {}) {
  let pc;
  try {
    pc = (await import("picocolors")).default;
  } catch {
    pc = {
      cyan: (s) => s,
      green: (s) => s,
      yellow: (s) => s,
      dim: (s) => s,
      bold: (s) => s,
      bgCyan: (s) => s,
      black: (s) => s,
    };
  }

  const c = pc;
  console.log();
  console.log(
    c.cyan("┌") +
      "  " +
      c.bgCyan(c.black(c.bold(" METIS REVERSE "))) +
      "  " +
      c.bold("Agent Installer & MCP Manager") +
      "  " +
      c.dim("v" + PKG.version)
  );
  console.log(c.cyan("│") + "  " + c.yellow("▲ Preview mode (--dry-run) — identical UI & agent detection; zero disk writes"));
  console.log(c.cyan("│"));
  console.log(c.cyan("◇") + "  " + c.bold("Detecting installed AI agents…"));
  console.log(c.cyan("│") + "  " + c.green("✔") + " " + c.dim("14 agent(s) found on this machine"));
  console.log(c.cyan("│"));
  console.log(c.cyan("?") + "  " + c.bold("Which agents should Metis Reverse be installed into?"));
  console.log(c.cyan("│") + "  " + c.dim("Press <space> to select, <a> to toggle all, <enter> to confirm:"));
  console.log(c.cyan("│"));
  const sampleAgents = getAgentDefinitions(options);
  const sampleConfigured = new Set(["cursor", "antigravity"]);
  const sampleDetected = new Set(["cursor", "antigravity", "claude_code", "claude_desktop", "vscode", "codex", "trae", "windsurf", "gemini_cli", "opencode", "copilot_cli", "kimi", "qwen_code", "droid"]);
  for (const a of sampleAgents) {
    const isConfigured = sampleConfigured.has(a.id);
    const isDetected = sampleDetected.has(a.id);
    const icon = isConfigured ? c.green("◼") : c.dim("◻");
    const nameStr = (isConfigured ? c.bold(a.displayName) : a.displayName).padEnd(22, " ");
    const hints = [];
    if (isConfigured) hints.push("MCP active");
    if (isDetected) hints.push("detected");
    else hints.push("not detected");
    if (a.skillPath) hints.push("supports skill");
    console.log(c.cyan("│") + "  " + icon + " " + nameStr + " " + c.dim("· " + hints.join(" · ")));
  }
  console.log(c.cyan("│"));
  console.log(c.cyan("?") + "  " + c.bold("Install complete Agent Skill package (SKILL.md + reverse references + rules)?"));
  console.log(c.cyan("│") + "  " + c.green("● Yes") + c.dim(" / ○ No"));
  console.log(c.cyan("│"));
  console.log(c.cyan("╭") + "  " + c.bold("Installation Plan") + " " + c.dim("───────────────────────────────────────────────────") + c.cyan("╮"));
  console.log(c.cyan("│") + "                                                                   " + c.cyan("│"));
  console.log(c.cyan("│") + "    " + c.cyan(c.bold("Cursor")) + "                                                         " + c.cyan("│"));
  console.log(c.cyan("│") + "      MCP Config: " + c.dim("~/.cursor/mcp.json") + "                                   " + c.cyan("│"));
  console.log(c.cyan("│") + "      Skill:      " + c.dim("~/.cursor/skills/metis-reverse + rules/metis-reverse.mdc") + " " + c.cyan("│"));
  console.log(c.cyan("│") + "    " + c.cyan(c.bold("Antigravity")) + "                                                    " + c.cyan("│"));
  console.log(c.cyan("│") + "      MCP Config: " + c.dim("~/.gemini/config/mcp_config.json") + "                     " + c.cyan("│"));
  console.log(c.cyan("│") + "      Skill:      " + c.dim("~/.gemini/config/skills/metis-reverse") + "                " + c.cyan("│"));
  console.log(c.cyan("│") + "    " + c.cyan(c.bold("Claude Code")) + "                                                     " + c.cyan("│"));
  console.log(c.cyan("│") + "      MCP Config: " + c.dim("~/.claude.json") + "                                       " + c.cyan("│"));
  console.log(c.cyan("│") + "      Skill:      " + c.dim("~/.claude/skills/metis-reverse") + "                       " + c.cyan("│"));
  console.log(c.cyan("│") + "                                                                   " + c.cyan("│"));
  console.log(c.cyan("│") + "    MCP Server: " + c.green("uvx --from git+https://github.com/Wholiver/metis-reverse.git metis-reverse") + " " + c.cyan("│"));
  console.log(c.cyan("│") + "    Skill distribution: " + c.green("Enabled (3 Reference Guides + Doctrine)") + "       " + c.cyan("│"));
  console.log(c.cyan("│") + "    Execution mode:     " + c.yellow("Preview only (Dry-run, zero writes)") + "          " + c.cyan("│"));
  console.log(c.cyan("│") + "                                                                   " + c.cyan("│"));
  console.log(c.cyan("╰───────────────────────────────────────────────────────────────────╯"));
  console.log(c.cyan("│"));
  console.log(c.cyan("?") + "  " + c.bold("Apply these configurations to selected agents?"));
  console.log(c.cyan("│") + "  " + c.green("● Yes, apply") + c.dim(" / ○ No, cancel"));
  console.log(c.cyan("│"));
  console.log(c.cyan("◇") + "  " + c.bold("Writing configurations & skills (dry-run)…"));
  console.log(c.cyan("│"));
  console.log(c.cyan("◆") + "  " + c.bold("Cursor [MCP]") + ": " + c.dim("Would write to ~/.cursor/mcp.json (with .bak backup)"));
  console.log(c.cyan("◆") + "  " + c.bold("Cursor [Skill]") + ": " + c.dim("Would copy SKILL.md + 3 references + rules/metis-reverse.mdc"));
  console.log(c.cyan("◆") + "  " + c.bold("Antigravity [MCP]") + ": " + c.dim("Would write to ~/.gemini/config/mcp_config.json"));
  console.log(c.cyan("◆") + "  " + c.bold("Antigravity [Skill]") + ": " + c.dim("Would copy SKILL.md + 3 references"));
  console.log(c.cyan("◆") + "  " + c.bold("Claude Code [MCP]") + ": " + c.dim("Would write to ~/.claude.json"));
  console.log(c.cyan("◆") + "  " + c.bold("Claude Code [Skill]") + ": " + c.dim("Would copy SKILL.md + 3 references"));
  console.log(c.cyan("│"));
  console.log(c.cyan("└") + "  " + c.green("Setup complete! Please restart your selected agents to activate Metis Reverse."));
  console.log();
  return 0;
}

module.exports = { runSetup, runWalkthrough };
