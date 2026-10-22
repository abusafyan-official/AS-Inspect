import json
import os
import shutil
import sys

def get_claude_desktop_config_path():
    appdata = os.environ.get("APPDATA", "")
    if sys.platform == "win32":
        return os.path.join(appdata, "Claude", "claude_desktop_config.json")
    elif sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")
    else:
        return os.path.expanduser("~/.config/Claude/claude_desktop_config.json")

def get_cursor_mcp_config_path():
    home = os.path.expanduser("~")
    return os.path.join(home, ".cursor", "mcp.json")

def get_antigravity_mcp_path():
    home = os.path.expanduser("~")
    return os.path.join(home, ".gemini", "antigravity", "mcp_servers.json")

def install_mcp_with_backup(config_path, server_command, server_args):
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        data = {}

        # 1. Automatic Backup of existing config
        if os.path.exists(config_path):
            backup_path = config_path + ".backup.json"
            try:
                shutil.copy2(config_path, backup_path)
            except Exception:
                pass
            with open(config_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = {}

        if "mcpServers" not in data:
            data["mcpServers"] = {}

        data["mcpServers"]["as-inspect"] = {
            "command": server_command,
            "args": server_args
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return True, "Configured successfully (backup created)"
    except Exception as e:
        return False, str(e)

def setup_all_ai_agents():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mcp_script = os.path.join(project_root, "apps", "as_inspect_mcp.py")
    py_exec = sys.executable

    targets = [
        ("Claude Desktop", get_claude_desktop_config_path()),
        ("Cursor Editor", get_cursor_mcp_config_path()),
        ("Antigravity / Gemini CLI", get_antigravity_mcp_path())
    ]

    print("\n" + "=" * 60)
    print("   AS Inspect — Universal AI Agent MCP & Skills Setup")
    print("   Developed by Abu Safyan")
    print("=" * 60 + "\n")
    print("[*] Detecting installed AI Coding Agents and creating backups...")

    configured_count = 0
    for agent_name, config_path in targets:
        success, msg = install_mcp_with_backup(config_path, py_exec, [mcp_script])
        if success:
            print(f" [+] [SUCCESS] {agent_name}")
            print(f"     Path: {config_path}")
            configured_count += 1
        else:
            print(f" [-] [SKIPPED] {agent_name} ({msg})")

    # Install Agent Skill to Antigravity / Gemini directory if present
    gemini_skills_dir = os.path.join(os.path.expanduser("~"), ".gemini", "antigravity", "skills", "as-inspect")
    src_skill = os.path.join(project_root, "skills", "as-inspect", "SKILL.md")
    if os.path.exists(src_skill):
        try:
            os.makedirs(gemini_skills_dir, exist_ok=True)
            shutil.copy2(src_skill, os.path.join(gemini_skills_dir, "SKILL.md"))
            print(f" [+] [SKILL INSTALLED] Workflow instructions registered at:\n     {gemini_skills_dir}")
        except Exception:
            pass

    print(f"\n[+] Completed: {configured_count} AI agent(s) configured with AS Inspect MCP server & workflow skills.")
    print("[*] Please restart Claude Desktop or Cursor to activate the new tools.\n")

if __name__ == "__main__":
    setup_all_ai_agents()
