# AS Inspect

<p align="center">
  <strong>Understand applications with evidence.</strong>
</p>

<p align="center">
  <a href="https://github.com/abusafyan-official/AS-Inspect/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
  <a href="https://github.com/abusafyan-official/AS-Inspect/releases"><img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/platform-Windows%20x64-informational.svg" alt="Platform"></a>
  <a href="#"><img src="https://img.shields.io/badge/MCP-Ready-purple.svg" alt="MCP"></a>
</p>

<p align="center">
  <em>Evidence-based Windows application & binary reverse engineering toolkit for AI coding agents and security researchers.</em><br>
  <strong>Developed by Abu Safyan</strong>
</p>

---

## Quick Start

On Windows, static PE analysis, ASAR extraction, framework detection, and security capability mapping require no external debuggers or disassemblers. Built-in parsers read binaries safely without execution.

### Set up your agent

To install and register AS Inspect into all your AI coding agents automatically:

```powershell
git clone https://github.com/abusafyan-official/AS-Inspect.git
cd AS-Inspect
python setup.py
```

Setup automatically detects, configures, and registers AS Inspect's MCP server into:
- **Claude Desktop** (`claude_desktop_config.json`)
- **Cursor Editor** (`.cursor/mcp.json`)
- **Antigravity / Gemini CLI** (`mcp_servers.json`)

Restart your AI agent afterward to immediately start inspecting applications with evidence!

Choose your agents, review the proposed changes, and approve them. Setup adds AS Inspect's MCP server and matching workflow instructions, with backups of existing configuration. Restart your agent afterward.

Setup supports Claude Code, Cursor, Gemini CLI, Grok Build, and Antigravity. See [installation and setup](https://github.com/abusafyan-official/AS-Inspect/blob/main/README.md#what-you-can-analyze) for provider configuration and manual MCP registration.

MCP uses compact input schemas by default to reduce context overhead. Set `AS_INSPECT_MCP_PROFILE=full` in your MCP registration when you need the complete advertised field guidance and nested validation details. Both profiles keep the full tool set and canonical server validation.

### Ask your agent

> *"Understand how file operations and network requests work in the target app, show me the evidence, and explain the security capabilities."*

Replace target app with your binary (e.g. `notepad.exe` or `app.asar`) and the feature you want to understand.

### Use the terminal

Inspect an extracted JavaScript/Electron app directory or ASAR:

```powershell
python apps/cli/as_inspect_cli.py analyze "C:/Program Files/App/resources/app.asar" --markdown
```

The result includes modules, imports, Electron boundaries, and their evidence. Replace the path with your target, such as `"C:/Windows/System32/notepad.exe"`.

To use the `as-inspect` command for regular use:

```powershell
python apps/cli/as_inspect_cli.py analyze target.exe --markdown report.md
```

For native analysis, configure an AI provider first if using optional LLM explanation layers. See the CLI commands below for native inspection, hashes, and reports:

```powershell
# Calculate cryptographic hashes
python apps/cli/as_inspect_cli.py hash target.exe

# Detect frameworks (.NET, Electron, Python, Qt)
python apps/cli/as_inspect_cli.py detect target.exe

# Generate interactive dark-mode HTML report
python apps/cli/as_inspect_cli.py report target.exe --format html > report.html
```

### Update AS Inspect

AS Inspect changes quickly, and new releases include frequent capability updates. Keep your installation up to date:

```powershell
git pull origin main
```

To refresh your agent registrations and analyzers, run the setup command printed by the update.

---

## How AS Inspect works

Your agent calls AS Inspect through MCP to inspect the target and trace relevant code. AS Inspect returns findings with their evidence. The agent uses them to ask follow-up questions, explain the behavior, or write and test an implementation. CLI commands use the same workflows.

<p align="center">
  <img src="assets/figures/as-inspect-investigation-flow.svg" alt="AS Inspect investigation flow" width="100%">
</p>

$$\text{Observed Fact} \neq \text{Inference} \neq \text{AI Explanation}$$

---

## What you can analyze

AS Inspect requires Windows x64 and Python 3.8+. Built-in tools and target coverage include:

Target | What AS Inspect returns | Requirements and guide
---|---|---
**Native Binaries (`.exe`, `.dll`, `.sys`)** | Architecture (x86/x64/ARM), entry point, image base, Shannon section entropy, imports, exports | Built-in native parser; no debugger or runtime required
**PE Authenticode Certificates** | WIN_CERTIFICATE table presence, certificate directory size, signed vs. unsigned status | Built-in static PE inspection
**Packer & Obfuscator Signatures** | Detection of UPX (`.upx0`), Aspack, MPRESS, Themida/WinLicense, and VMProtect markers | Built-in signature matching & high-entropy alerts
**Security Capabilities** | Categorized Win32 behavior mapping: Network/Sockets, Memory Injection, Registry Persistence, Anti-Debug | Built-in API semantic dictionary
**Electron / ASAR Archives** | File tree inventory, file sizes, extension distributions, header directory facts | Built-in zero-dependency ASAR reader
**JavaScript / TypeScript Bundles** | Module dependencies, `require`/`import` calls, functions, embedded URLs | Static AST regex engine; non-executing
**Windows Installers (`.msi`)** | OLE Compound Document Binary validation and stream structure verification | Built-in header validator
**Application Folders & Bundles** | Full directory trees, key application manifests (`package.json`, `.config`), and binary assets | Built-in recursive filesystem scanner
**Discovered URLs & Endpoints** | Static URLs, domains, and paths discovered in binary and script sections | Built-in scanner; never performs active outbound network calls

Static JavaScript, PE, and ASAR inspection read the supplied files without running the application. AS Inspect guarantees non-execution safety.

---

## 🧪 Verified Test Suite

```powershell
python -m pytest tests/
```

```text
tests/test_analyzers.py ....                                             [ 57%]
tests/test_pe_and_edgecases.py ...                                       [100%]

============================== 7 passed in 0.56s ==============================
```

---

## 🛡️ Security & Responsible Inspection

- **Non-Execution Guarantee:** AS Inspect is a static analysis engine. It never executes `.exe`, `.dll`, `.bat`, or `.js` payloads.
- **Network Safety:** Discovered URLs and domains are strictly cataloged; AS Inspect does not perform outbound HTTP network requests against discovered endpoints.
- **Privacy First:** Credentials, tokens, and sensitive strings are masked on extraction.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  <strong>AS Inspect</strong> — Understand applications with evidence.<br>
  Built with ❤️ by <strong>Abu Safyan</strong>
</p>
