#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = dirname(__dirname);

const args = process.argv.slice(2);
const command = args[0] || "help";

function printBanner() {
  console.log("\x1b[36m%s\x1b[0m", "============================================================");
  console.log("\x1b[1m\x1b[34m%s\x1b[0m", "   AS Inspect — Understand applications with evidence.");
  console.log("\x1b[32m%s\x1b[0m", "   Developed by Abu Safyan");
  console.log("\x1b[36m%s\x1b[0m", "============================================================");
  console.log();
}

function ensurePython() {
  const check = spawnSync("python", ["--version"], { encoding: "utf8" });
  if (check.status === 0) return "python";
  const checkPy = spawnSync("py", ["--version"], { encoding: "utf8" });
  if (checkPy.status === 0) return "py";
  
  const common = [
    "C:\\Program Files\\Python314\\python.exe",
    "C:\\Program Files\\Python313\\python.exe",
    "C:\\Program Files\\Python312\\python.exe",
    "C:\\Program Files\\Python311\\python.exe"
  ];
  for (const p of common) {
    if (existsSync(p)) return p;
  }
  return null;
}

if (command === "setup") {
  printBanner();
  console.log("[*] Running universal AI agent setup (matching REA setup protocol)...");
  
  const home = homedir();
  const appData = process.env.APPDATA || join(home, "AppData", "Roaming");
  
  const targets = [
    {
      name: "Claude Desktop",
      path: join(appData, "Claude", "claude_desktop_config.json")
    },
    {
      name: "Cursor Editor",
      path: join(home, ".cursor", "mcp.json")
    },
    {
      name: "Antigravity / Gemini CLI",
      path: join(home, ".gemini", "antigravity", "mcp_servers.json")
    }
  ];

  const mcpServerScript = join(projectRoot, "apps", "as_inspect_mcp.py");
  let pyExec = ensurePython() || "python";

  let configured = 0;
  for (const target of targets) {
    try {
      const dir = dirname(target.path);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

      let data = {};
      if (existsSync(target.path)) {
        try {
          copyFileSync(target.path, target.path + ".backup.json");
          data = JSON.parse(readFileSync(target.path, "utf8"));
        } catch (e) {
          data = {};
        }
      }

      if (!data.mcpServers) data.mcpServers = {};
      data.mcpServers["as-inspect"] = {
        command: pyExec,
        args: [mcpServerScript]
      };

      writeFileSync(target.path, JSON.stringify(data, null, 2), "utf8");
      console.log(`\x1b[32m[+] [SUCCESS]\x1b[0m ${target.name} configured!`);
      console.log(`    Config: ${target.path}`);
      configured++;
    } catch (err) {
      console.log(`\x1b[33m[-] [SKIPPED]\x1b[0m ${target.name} (${err.message})`);
    }
  }

  // Install Agent Skill
  const srcSkill = join(projectRoot, "skills", "as-inspect", "SKILL.md");
  const destSkillDir = join(home, ".gemini", "antigravity", "skills", "as-inspect");
  if (existsSync(srcSkill)) {
    try {
      if (!existsSync(destSkillDir)) mkdirSync(destSkillDir, { recursive: true });
      copyFileSync(srcSkill, join(destSkillDir, "SKILL.md"));
      console.log(`\x1b[32m[+] [SKILL REGISTERED]\x1b[0m Workflow instructions installed at:`);
      console.log(`    ${destSkillDir}`);
    } catch (e) {}
  }

  console.log(`\n\x1b[32m[+] Setup complete! Registered in ${configured} AI coding agent(s).\x1b[0m`);
  console.log("[*] Restart Claude Desktop / Cursor to activate AS Inspect MCP.\n");

} else if (command === "mcp") {
  const pyExec = ensurePython() || "python";
  const mcpScript = join(projectRoot, "apps", "as_inspect_mcp.py");
  const child = spawn(pyExec, [mcpScript], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code || 0));

} else if (command === "analyze" || command === "hash" || command === "detect" || command === "report") {
  const pyExec = ensurePython() || "python";
  const cliScript = join(projectRoot, "apps", "cli", "as_inspect_cli.py");
  const child = spawn(pyExec, [cliScript, ...args], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code || 0));

} else {
  printBanner();
  console.log("Commands (REA-compatible):");
  console.log("  node scripts/as-inspect.mjs setup             Register AS Inspect in all AI agents");
  console.log("  node scripts/as-inspect.mjs analyze <target>  Run full binary/package analysis");
  console.log("  node scripts/as-inspect.mjs hash <target>     Compute cryptographic hashes");
  console.log("  node scripts/as-inspect.mjs detect <target>   Detect application frameworks");
  console.log("  node scripts/as-inspect.mjs mcp               Start MCP server directly");
  console.log();
}
