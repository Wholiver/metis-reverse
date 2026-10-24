"use strict";

const { getAgentDefinitions } = require("../agents-spec");
const { checkMcpConfigured, removeMcpConfig } = require("../config-engine");
const { checkSkillInstalled, uninstallSkill } = require("../skill-distributor");

async function runUninstall(options = {}) {
  let p, pc;
  try {
    p = await import("@clack/prompts");
    pc = (await import("picocolors")).default;
  } catch {
    // Non-TTY fallback
  }

  const dryRun = Boolean(options.dryRun);
  const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const interactive = isTty && !options.yes;

  const agents = getAgentDefinitions(options);
  const installedAgents = [];

  for (const agent of agents) {
    const mcp = checkMcpConfigured(agent);
    const skill = checkSkillInstalled(agent);
    if (mcp.configured || skill.installed) {
      installedAgents.push({
        agent,
        mcpConfigured: mcp.configured,
        skillInstalled: skill.installed,
      });
    }
  }

  if (p && interactive) {
    p.intro("Metis Reverse — Uninstall");
    if (dryRun) {
      p.log.warn("Running in preview mode (--dry-run). No changes will be written to disk.");
    }

    if (installedAgents.length === 0) {
      p.log.info("Metis Reverse is not currently configured in any supported agent.");
      p.outro("Nothing to uninstall.");
      return 0;
    }

    const choices = installedAgents.map((item) => {
      const parts = [];
      if (item.mcpConfigured) parts.push("MCP server");
      if (item.skillInstalled) parts.push("Skill package");
      return {
        value: item.agent.id,
        label: item.agent.displayName,
        hint: parts.join(" + "),
      };
    });

    const selectedIds = await p.multiselect({
      message: "Which agents would you like to remove Metis Reverse from?",
      options: choices,
      initialValues: choices.map((c) => c.value),
      required: true,
    });

    if (p.isCancel(selectedIds)) {
      p.cancel("Uninstall cancelled.");
      return 0;
    }

    const confirm = await p.confirm({
      message: `Are you sure you want to remove Metis Reverse from ${selectedIds.length} agent(s)?`,
      initialValue: true,
    });

    if (p.isCancel(confirm) || !confirm) {
      p.cancel("Uninstall cancelled.");
      return 0;
    }

    const spinner = p.spinner();
    spinner.start("Removing Metis Reverse configurations and skills…");

    const results = [];
    for (const id of selectedIds) {
      const target = installedAgents.find((i) => i.agent.id === id).agent;
      const mcpRes = removeMcpConfig(target, { dryRun });
      const skillRes = uninstallSkill(target, { dryRun });
      results.push({ target, mcpRes, skillRes });
    }

    spinner.stop(dryRun ? "Preview complete." : "Removal complete.");

    for (const res of results) {
      const name = res.target.displayName;
      if (res.mcpRes.status === "removed") {
        p.log.success(`${name}: MCP server removed`);
      }
      if (res.skillRes.status === "removed") {
        p.log.success(`${name}: Skill package deleted`);
      }
    }

    p.outro(dryRun ? "Preview finished. Nothing was removed." : "Metis Reverse has been cleanly uninstalled from selected agents.");
    return 0;
  }

  // Non-interactive path
  let targetIds = [];
  if (options.client && (Array.isArray(options.client) ? options.client.length > 0 : Boolean(options.client))) {
    targetIds = Array.isArray(options.client) ? options.client : [options.client];
  } else {
    targetIds = installedAgents.map((i) => i.agent.id);
  }

  if (targetIds.length === 0) {
    console.log("No installed agents to uninstall.");
    return 0;
  }

  console.log(`[Metis Reverse] Uninstalling from ${targetIds.length} agent(s)... (dryRun: ${dryRun})`);
  for (const id of targetIds) {
    const match = agents.find((a) => a.id === id);
    if (!match) continue;

    const mcpRes = removeMcpConfig(match, { dryRun });
    const skillRes = uninstallSkill(match, { dryRun });
    console.log(`- ${match.displayName}: MCP [${mcpRes.status}], Skill [${skillRes.status}]`);
  }

  console.log("[Metis Reverse] Uninstall completed.");
  return 0;
}

module.exports = { runUninstall };
