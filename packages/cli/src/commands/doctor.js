"use strict";

const { getAgentDefinitions, isAgentDetected } = require("../agents-spec");
const { checkMcpConfigured } = require("../config-engine");
const { checkSkillInstalled } = require("../skill-distributor");

async function runDoctor(options = {}) {
  let p, pc;
  try {
    p = await import("@clack/prompts");
    pc = (await import("picocolors")).default;
  } catch {
    // Fallback if imported in test environment
  }

  const agents = getAgentDefinitions(options);
  const rows = [];

  for (const agent of agents) {
    const detected = isAgentDetected(agent);
    const mcp = checkMcpConfigured(agent);
    const skill = checkSkillInstalled(agent);

    rows.push({
      agent,
      detected,
      mcpConfigured: mcp.configured,
      skillInstalled: skill.installed,
      skillSupported: skill.supported,
    });
  }

  if (options.json) {
    const output = rows.map((r) => ({
      id: r.agent.id,
      name: r.agent.displayName,
      detected: r.detected,
      mcp_configured: r.mcpConfigured,
      skill_installed: r.skillInstalled,
      config_path: r.agent.configPath,
      skill_path: r.agent.skillPath,
    }));
    console.log(JSON.stringify(output, null, 2));
    return 0;
  }

  if (p) {
    p.intro("Metis Reverse — Agent Health Doctor");
  } else {
    console.log("=== Metis Reverse — Agent Health Doctor ===");
  }

  const detectedRows = rows.filter((r) => r.detected);
  const configuredRows = rows.filter((r) => r.mcpConfigured || r.skillInstalled);

  console.log(`\nDetected Agents (${detectedRows.length}/${rows.length}):`);
  for (const r of rows) {
    const detectSymbol = r.detected ? (pc ? pc.green("✓ Detected") : "[Detected]") : (pc ? pc.dim("✗ Not found") : "[Not found]");
    const mcpSymbol = r.mcpConfigured ? (pc ? pc.green("MCP: Ready") : "MCP: Ready") : (pc ? pc.dim("MCP: None") : "MCP: None");
    const skillSymbol = !r.skillSupported
      ? (pc ? pc.dim("Skill: N/A") : "Skill: N/A")
      : r.skillInstalled
      ? (pc ? pc.green("Skill: Ready") : "Skill: Ready")
      : (pc ? pc.dim("Skill: None") : "Skill: None");

    const label = (r.agent.displayName + ":").padEnd(24, " ");
    console.log(`  ${label} ${detectSymbol.padEnd(20, " ")} | ${mcpSymbol.padEnd(16, " ")} | ${skillSymbol}`);
  }

  console.log();
  if (p) {
    if (configuredRows.length === 0) {
      p.log.warn("Metis Reverse is not configured on any detected agents yet.");
      p.outro("Run `npx metis-reverse-cli setup` to install.");
    } else {
      p.log.success(`Metis Reverse is active on ${configuredRows.length} agent(s).`);
      p.outro("All systems operational.");
    }
  }

  return 0;
}

module.exports = { runDoctor };
