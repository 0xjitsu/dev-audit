#!/usr/bin/env node
const { execFileSync } = require("child_process");
const { join } = require("path");

if (process.platform !== "darwin") {
  console.error("Error: dev-audit only supports macOS.");
  process.exit(1);
}

const script = join(__dirname, "dev-audit.sh");
const args = process.argv.slice(2);

try {
  execFileSync("/bin/bash", [script, ...args], {
    stdio: "inherit",
    env: { ...process.env, PATH: `/opt/homebrew/bin:/opt/homebrew/sbin:${process.env.PATH}` },
  });
} catch (err) {
  process.exit(err.status || 1);
}
