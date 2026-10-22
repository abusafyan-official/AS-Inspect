---
name: as-inspect
description: Evidence-based Windows application inspection toolkit with native PE, ASAR, framework detection, and security capabilities mapping.
---

# AS Inspect Agent Skill

Use AS Inspect to safely reverse engineer and inspect Windows executables, libraries, Electron packages, and application bundles without running untrusted code.

## Guiding Principles

1. **Evidence-First:** Differentiate strictly between:
   - `OBSERVED`: Direct binary artifacts (entry points, section entropy, hashes, imports)
   - `INFERRED`: Confident deductions (framework identification, packer signatures)
   - `AI_EXPLANATION`: Synthesized insights citing specific Evidence IDs (`EV-000123`).

2. **Non-Execution Safety:** Never execute or launch untrusted binaries, scripts, or installers during inspection.

## Available Tools

- `inspect_file(path)`: Performs comprehensive static analysis of `.exe`, `.dll`, `.msi`, `.asar`, `.js`, or folders.
- `get_hashes(path)`: Calculates MD5, SHA-1, and SHA-256 digests.
- `detect_framework(path)`: Identifies Electron, .NET Framework / Core, Python (PyInstaller), Qt, and Java.
