import json
import os
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

def install_mcp_to_file(config_path, server_command, server_args):
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        data = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        
        if "mcpServers" not in data:
            data["mcpServers"] = {}

        data["mcpServers"]["as-inspect"] = {
            "command": server_command,
            "args": server_args
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return True, "Configured successfully"
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
    print("   AS Inspect — Universal AI Agent MCP Auto-Configurator")
    print("   Developed by Abu Safyan")
    print("=" * 60 + "\n")

    for agent_name, config_path in targets:
        print(f"[*] Detecting {agent_name} configuration...")
        success, msg = install_mcp_to_file(config_path, py_exec, [mcp_script])
        if success:
            print(f" [+] [SUCCESS] {agent_name} configured at:\n     {config_path}")
        else:
            print(f" [-] [SKIPPED] {agent_name} ({msg})")

    print("\n[+] All detected AI agents are now connected to AS Inspect MCP!")
    print("[*] Please restart Claude Desktop / Cursor to activate the new tools.\n")

if __name__ == "__main__":
    setup_all_ai_agents()
