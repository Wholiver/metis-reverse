#!/usr/bin/env node
"use strict";

const { runSetup } = require("../src/commands/setup");
const { runDoctor } = require("../src/commands/doctor");
const { runUninstall } = require("../src/commands/uninstall");
const PKG = require("../package.json");

function printHelp() {
  console.log(`
Metis Reverse CLI — v${PKG.version}
Evidence-grounded Agentic Reverse Engineering Installer & Manager

Usage:
  npx metis-reverse-cli [command] [options]
  metis [command] [options]

Commands:
  setup            Interactively configure Metis Reverse MCP & Skills for your agents (default)
  doctor           Inspect health & detection status of all supported agents
  uninstall        Cleanly remove Metis Reverse MCP and Skills from agents
  preview          Dry-run simulation of the setup process

Options:
  -y, --yes        Non-interactive mode (automatically configure detected agents)
  --dry-run        Simulate operations without writing changes to disk
  --no-skill       Skip installing Agent Skill packages (configure MCP only)
  --client <id>    Specify target agent ID (e.g. cursor, claude_code, antigravity)
  --json           Output machine-readable JSON (supported by doctor)
  -v, --version    Show version number
  -h, --help       Show this help message

Examples:
  npx metis-reverse-cli setup
  npx metis-reverse-cli preview
  npx metis-reverse-cli doctor
  npx metis-reverse-cli setup --client cursor --yes
  npx metis-reverse-cli uninstall
`);
}

async function main(argv) {
  const args = argv.slice();
  const options = {
    client: [],
    dryRun: false,
    yes: false,
    noSkill: false,
    json: false,
    walkthrough: false,
  };

  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      printHelp();
      return 0;
    }
    if (arg === "-v" || arg === "--version") {
      console.log(PKG.version);
      return 0;
    }
    if (arg === "--dry-run") {
      options.dryRun = true;
      continue;
    }
    if (arg === "--walkthrough" || arg === "--demo") {
      options.walkthrough = true;
      continue;
    }
    if (arg === "-y" || arg === "--yes") {
      options.yes = true;
      continue;
    }
    if (arg === "--no-skill") {
      options.noSkill = true;
      continue;
    }
    if (arg === "--json") {
      options.json = true;
      continue;
    }
    if (arg === "--client" && i + 1 < args.length) {
      options.client.push(args[++i]);
      continue;
    }
    if (arg.startsWith("-")) {
      console.error(`Unknown option: ${arg}`);
      printHelp();
      return 1;
    }
    positional.push(arg);
  }

  const command = positional[0] || "setup";

  if (command === "setup" || command === "init" || command === "install") {
    return runSetup(options);
  }

  if (command === "preview") {
    options.dryRun = true;
    return runSetup(options);
  }

  if (command === "doctor" || command === "check" || command === "status") {
    return runDoctor(options);
  }

  if (command === "uninstall" || command === "remove") {
    return runUninstall(options);
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  return 1;
}

main(process.argv.slice(2))
  .then((code) => process.exit(typeof code === "number" ? code : 0))
  .catch((err) => {
    console.error(err && err.message ? err.message : err);
    process.exit(1);
  });
