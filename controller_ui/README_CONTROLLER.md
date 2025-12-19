# Windows MCP Controller UI

A lightweight Tkinter desktop controller for managing the `windows-mcp` server and running Codex tasks non-interactively.

## Prerequisites
- Windows with Python 3.11+ installed and added to PATH
- [uv](https://github.com/astral-sh/uv) providing the `uvx` shim
- `codex` CLI available on PATH (for `codex exec` / `codex e`)

## Setup (PowerShell)
```powershell
# From the repository root
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r controller_ui\requirements.txt

# First run (will prompt to set a password)
python controller_ui\app.py
```

## Running
```powershell
.\.venv\Scripts\Activate.ps1
python controller_ui\app.py
```

- Use the **Settings** tab to configure Codex command, model, timeouts, retries, delays, dry-run, confirmation prompts, and MCP auto-start/auto-restart.
- Use the **Tasks** tab to manage task definitions and run them individually or in sequence.
- The **Scheduler** tab provides a simple daily scheduler for task runs.
- Logs stream to the **Logs** tab and are also written to `controller_ui\data\app.log`.

## Notes
- If `uvx` or `codex` are missing, the UI will display a clear message in the Logs tab.
- A global STOP hotkey defaults to `Ctrl+Alt+S` when the optional `keyboard` package is available; otherwise, use the STOP button.
- A basic command blocklist is enabled by default to avoid dangerous commands.
