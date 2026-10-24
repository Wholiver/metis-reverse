"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const CLI_BIN = path.resolve(__dirname, "..", "bin", "metis.js");

describe("CLI End-to-End Tests", () => {
  test("shows version on --version", () => {
    const res = spawnSync(process.execPath, [CLI_BIN, "--version"], { encoding: "utf8" });
    assert.strictEqual(res.status, 0);
    assert.match(res.stdout, /\d+\.\d+\.\d+/);
  });

  test("shows help on --help", () => {
    const res = spawnSync(process.execPath, [CLI_BIN, "--help"], { encoding: "utf8" });
    assert.strictEqual(res.status, 0);
    assert.match(res.stdout, /Metis Reverse CLI/);
    assert.match(res.stdout, /setup/);
    assert.match(res.stdout, /doctor/);
    assert.match(res.stdout, /uninstall/);
  });

  test("doctor returns valid JSON array with --json", () => {
    const res = spawnSync(process.execPath, [CLI_BIN, "doctor", "--json"], { encoding: "utf8" });
    assert.strictEqual(res.status, 0);
    const data = JSON.parse(res.stdout);
    assert.ok(Array.isArray(data));
    assert.ok(data.length >= 20);
    const cursor = data.find((d) => d.id === "cursor");
    assert.ok(cursor);
    assert.strictEqual(cursor.name, "Cursor");
  });

  test("preview / dry-run runs without error", () => {
    const res = spawnSync(
      process.execPath,
      [CLI_BIN, "preview", "--yes", "--client", "cursor"],
      { encoding: "utf8" }
    );
    assert.strictEqual(res.status, 0);
    assert.match(res.stdout, /Configuring/);
  });
});
