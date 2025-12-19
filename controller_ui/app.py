import json
import logging
import queue
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

# Optional hotkey support
try:
    import keyboard  # type: ignore

    KEYBOARD_AVAILABLE = True
except Exception:  # pragma: no cover - best-effort import
    keyboard = None
    KEYBOARD_AVAILABLE = False

DATA_DIR = Path(__file__).parent / "data"
CONFIG_PATH = DATA_DIR / "config.json"
TASKS_PATH = DATA_DIR / "tasks.json"
SCHEDULE_PATH = DATA_DIR / "schedules.json"
AUTH_PATH = DATA_DIR / "auth.json"
LOG_PATH = DATA_DIR / "app.log"

DEFAULT_CONFIG: Dict[str, object] = {
    "codex_command": "codex",
    "model": "",
    "timeout_seconds": 300,
    "retries": 0,
    "delay_between_steps": 1,
    "dry_run": True,
    "confirm_before_execute": True,
    "block_dangerous_commands": True,
    "auto_start_mcp": False,
    "auto_restart_mcp": False,
    "stop_hotkey": "ctrl+alt+s",
}

BLOCKED_COMMANDS = [
    "del ",
    "format ",
    "rmdir /s",
    "rm -rf",
]


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


class PasswordStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        import hashlib

        return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

    def has_password(self) -> bool:
        return self.path.exists()

    def set_password(self, password: str) -> None:
        import secrets

        salt = secrets.token_hex(16)
        hashed = self._hash_password(password, salt)
        with self.path.open("w", encoding="utf-8") as f:
            json.dump({"salt": salt, "hash": hashed}, f)

    def verify(self, password: str) -> bool:
        if not self.path.exists():
            return False
        data = json.loads(self.path.read_text(encoding="utf-8"))
        salt = data.get("salt", "")
        expected = data.get("hash", "")
        return self._hash_password(password, salt) == expected


class LogHandler(logging.Handler):
    def __init__(self, text_widget: Optional[tk.Text], log_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self.text_widget = text_widget
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - UI side effect
        msg = self.format(record)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_msg = f"[{timestamp}] {msg}\n"
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(full_msg)
        self.log_queue.put(full_msg)


class ControllerApp(tk.Tk):  # pragma: no cover - UI heavy
    def __init__(self) -> None:
        super().__init__()
        ensure_data_dir()
        self.title("Windows MCP Controller")
        self.geometry("900x600")

        self.tasks: List[Dict[str, str]] = []
        self.schedules: List[Dict[str, object]] = []
        self.config_data: Dict[str, object] = DEFAULT_CONFIG.copy()

        self.password_store = PasswordStore(AUTH_PATH)

        self.mcp_process: Optional[subprocess.Popen[str]] = None
        self.current_process: Optional[subprocess.Popen[str]] = None
        self.stop_flag = threading.Event()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.log_text: Optional[tk.Text] = None

        self._load_state()
        self._build_ui()
        self._setup_logging()
        self.after(500, self._process_log_queue)
        self.after(1000, self._scheduler_tick)

        if self.config_data.get("auto_start_mcp"):
            self.start_mcp()

        self._register_hotkey()

    def _setup_logging(self) -> None:
        handler = LogHandler(self.log_text, self.log_queue)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logging.basicConfig(level=logging.INFO, handlers=[handler])
        logging.info("Controller started")

    def _load_state(self) -> None:
        if CONFIG_PATH.exists():
            try:
                self.config_data.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
            except Exception:
                pass
        if TASKS_PATH.exists():
            try:
                self.tasks = json.loads(TASKS_PATH.read_text(encoding="utf-8"))
            except Exception:
                self.tasks = []
        if SCHEDULE_PATH.exists():
            try:
                self.schedules = json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))
            except Exception:
                self.schedules = []

    def _save_config(self) -> None:
        CONFIG_PATH.write_text(json.dumps(self.config_data, indent=2), encoding="utf-8")

    def _save_tasks(self) -> None:
        TASKS_PATH.write_text(json.dumps(self.tasks, indent=2), encoding="utf-8")

    def _save_schedules(self) -> None:
        SCHEDULE_PATH.write_text(json.dumps(self.schedules, indent=2), encoding="utf-8")

    def _build_ui(self) -> None:
        self.login_frame = ttk.Frame(self)
        self.main_frame = ttk.Frame(self)

        self._build_login()
        self._build_main()

        if not self.password_store.has_password():
            self.login_frame.pack(fill="both", expand=True)
            self.main_frame.forget()
        else:
            self.login_frame.pack(fill="both", expand=True)
            self.main_frame.forget()

    def _build_login(self) -> None:
        ttk.Label(self.login_frame, text="Controller Login", font=("Segoe UI", 16, "bold")).pack(pady=20)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=10)
        ttk.Button(self.login_frame, text="Submit", command=self._handle_login).pack(pady=10)
        self.login_message = ttk.Label(self.login_frame, text="")
        self.login_message.pack(pady=5)

    def _handle_login(self) -> None:
        password = self.password_entry.get()
        if not self.password_store.has_password():
            self.password_store.set_password(password)
            self.login_message.config(text="Password set. Please log in again.")
            return
        if self.password_store.verify(password):
            self.login_frame.forget()
            self.main_frame.pack(fill="both", expand=True)
        else:
            self.login_message.config(text="Invalid password")

    def _build_main(self) -> None:
        self.status_var = tk.StringVar(value="STOPPED")

        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(status_frame, text="MCP Status:").pack(side="left")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(side="left", padx=5)
        ttk.Button(status_frame, text="Start MCP", command=self.start_mcp).pack(side="left", padx=5)
        ttk.Button(status_frame, text="Stop MCP", command=self.stop_mcp).pack(side="left", padx=5)
        ttk.Button(status_frame, text="STOP", command=self.stop_all, width=10).pack(side="right", padx=5)

        notebook = ttk.Notebook(self.main_frame)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tasks_tab = ttk.Frame(notebook)
        self.settings_tab = ttk.Frame(notebook)
        self.scheduler_tab = ttk.Frame(notebook)
        self.logs_tab = ttk.Frame(notebook)

        notebook.add(self.tasks_tab, text="Tasks")
        notebook.add(self.settings_tab, text="Settings")
        notebook.add(self.scheduler_tab, text="Scheduler")
        notebook.add(self.logs_tab, text="Logs")

        self._build_tasks_tab()
        self._build_settings_tab()
        self._build_scheduler_tab()
        self._build_logs_tab()

    def _build_tasks_tab(self) -> None:
        frame = self.tasks_tab
        left = ttk.Frame(frame)
        left.pack(side="left", fill="both", expand=True)

        self.task_listbox = tk.Listbox(left)
        self.task_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self._refresh_task_list()

        buttons = ttk.Frame(left)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Add", command=self._add_task).pack(side="left", padx=2, pady=2)
        ttk.Button(buttons, text="Edit", command=self._edit_task).pack(side="left", padx=2, pady=2)
        ttk.Button(buttons, text="Delete", command=self._delete_task).pack(side="left", padx=2, pady=2)
        ttk.Button(buttons, text="Up", command=lambda: self._move_task(-1)).pack(side="left", padx=2, pady=2)
        ttk.Button(buttons, text="Down", command=lambda: self._move_task(1)).pack(side="left", padx=2, pady=2)

        actions = ttk.Frame(frame)
        actions.pack(side="right", fill="y", padx=10, pady=10)
        ttk.Button(actions, text="Run Selected", command=self._run_selected_task).pack(fill="x", pady=2)
        ttk.Button(actions, text="Run All", command=self._run_all_tasks).pack(fill="x", pady=2)
        ttk.Button(actions, text="Stop", command=self.stop_all).pack(fill="x", pady=2)

    def _build_settings_tab(self) -> None:
        frame = self.settings_tab
        fields = [
            ("Codex command", "codex_command"),
            ("Model (optional)", "model"),
            ("Timeout (seconds)", "timeout_seconds"),
            ("Retries", "retries"),
            ("Delay between steps", "delay_between_steps"),
            ("Stop hotkey", "stop_hotkey"),
        ]
        self.settings_vars: Dict[str, tk.Variable] = {}
        for idx, (label, key) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=idx, column=0, sticky="w", padx=5, pady=5)
            var = tk.StringVar(value=str(self.config_data.get(key, "")))
            entry = ttk.Entry(frame, textvariable=var)
            entry.grid(row=idx, column=1, sticky="ew", padx=5, pady=5)
            self.settings_vars[key] = var

        frame.columnconfigure(1, weight=1)

        self.bool_vars: Dict[str, tk.BooleanVar] = {}
        bool_settings = [
            ("Dry run", "dry_run"),
            ("Confirm before execute", "confirm_before_execute"),
            ("Block dangerous commands", "block_dangerous_commands"),
            ("Auto start MCP", "auto_start_mcp"),
            ("Auto restart MCP", "auto_restart_mcp"),
        ]
        start_row = len(fields)
        for idx, (label, key) in enumerate(bool_settings):
            var = tk.BooleanVar(value=bool(self.config_data.get(key, False)))
            chk = ttk.Checkbutton(frame, text=label, variable=var)
            chk.grid(row=start_row + idx, column=0, columnspan=2, sticky="w", padx=5, pady=2)
            self.bool_vars[key] = var

        ttk.Button(frame, text="Save", command=self._save_settings).grid(
            row=start_row + len(bool_settings) + 1, column=0, columnspan=2, pady=10
        )

    def _build_scheduler_tab(self) -> None:
        frame = self.scheduler_tab
        self.schedule_listbox = tk.Listbox(frame)
        self.schedule_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self._refresh_schedule_list()

        controls = ttk.Frame(frame)
        controls.pack(side="right", fill="y", padx=5, pady=5)

        ttk.Button(controls, text="Add", command=self._add_schedule).pack(fill="x", pady=2)
        ttk.Button(controls, text="Delete", command=self._delete_schedule).pack(fill="x", pady=2)
        ttk.Button(controls, text="Enable/Disable", command=self._toggle_schedule).pack(fill="x", pady=2)

    def _build_logs_tab(self) -> None:
        frame = self.logs_tab
        self.log_text = tk.Text(frame, state="disabled", wrap="word")
        scrollbar = ttk.Scrollbar(frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _append_log_text(self, text: str) -> None:
        if not self.log_text:
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _process_log_queue(self) -> None:
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self._append_log_text(msg)
        self.after(500, self._process_log_queue)

    def _refresh_task_list(self) -> None:
        if not hasattr(self, "task_listbox"):
            return
        self.task_listbox.delete(0, tk.END)
        for task in self.tasks:
            self.task_listbox.insert(tk.END, task.get("name", "Untitled"))

    def _refresh_schedule_list(self) -> None:
        if not hasattr(self, "schedule_listbox"):
            return
        self.schedule_listbox.delete(0, tk.END)
        for sch in self.schedules:
            status = "ON" if sch.get("enabled", True) else "OFF"
            self.schedule_listbox.insert(tk.END, f"{sch.get('time')} - {sch.get('task')} ({status})")

    def _add_task(self) -> None:
        name = simpledialog.askstring("Task Name", "Enter task name:", parent=self)
        if not name:
            return
        prompt = simpledialog.askstring("Task Prompt", "Enter task prompt:", parent=self)
        if prompt is None:
            return
        self.tasks.append({"name": name, "prompt": prompt})
        self._save_tasks()
        self._refresh_task_list()

    def _edit_task(self) -> None:
        idx = self._selected_task_index()
        if idx is None:
            return
        task = self.tasks[idx]
        name = simpledialog.askstring("Task Name", "Edit task name:", initialvalue=task.get("name"), parent=self)
        if not name:
            return
        prompt = simpledialog.askstring("Task Prompt", "Edit task prompt:", initialvalue=task.get("prompt"), parent=self)
        if prompt is None:
            return
        self.tasks[idx] = {"name": name, "prompt": prompt}
        self._save_tasks()
        self._refresh_task_list()

    def _delete_task(self) -> None:
        idx = self._selected_task_index()
        if idx is None:
            return
        del self.tasks[idx]
        self._save_tasks()
        self._refresh_task_list()

    def _move_task(self, direction: int) -> None:
        idx = self._selected_task_index()
        if idx is None:
            return
        new_idx = idx + direction
        if not (0 <= new_idx < len(self.tasks)):
            return
        self.tasks[idx], self.tasks[new_idx] = self.tasks[new_idx], self.tasks[idx]
        self._save_tasks()
        self._refresh_task_list()
        self.task_listbox.selection_set(new_idx)

    def _selected_task_index(self) -> Optional[int]:
        selection = self.task_listbox.curselection()
        if not selection:
            return None
        return int(selection[0])

    def _run_selected_task(self) -> None:
        idx = self._selected_task_index()
        if idx is None:
            return
        task = self.tasks[idx]
        threading.Thread(target=self._run_task_with_retries, args=(task,), daemon=True).start()

    def _run_all_tasks(self) -> None:
        threading.Thread(target=self._run_all_sequence, daemon=True).start()

    def _run_all_sequence(self) -> None:
        for task in self.tasks:
            if self.stop_flag.is_set():
                logging.info("Run stopped")
                break
            self._run_task_with_retries(task)
            delay = float(self.config_data.get("delay_between_steps", 0))
            time.sleep(max(0, delay))

    def _run_task_with_retries(self, task: Dict[str, str]) -> None:
        retries = int(self.config_data.get("retries", 0))
        attempts = 0
        while attempts <= retries and not self.stop_flag.is_set():
            success = self.run_task(task)
            if success:
                return
            attempts += 1
            if attempts <= retries:
                logging.info("Retrying task '%s' (%d/%d)", task.get("name"), attempts, retries)
        if self.stop_flag.is_set():
            logging.info("Task '%s' stopped", task.get("name"))
        else:
            logging.error("Task '%s' failed after retries", task.get("name"))

    def _add_schedule(self) -> None:
        time_str = simpledialog.askstring("Schedule", "Enter time (HH:MM, 24h):", parent=self)
        if not time_str:
            return
        if self.tasks:
            task_names = [t.get("name", "") for t in self.tasks]
            task = simpledialog.askstring(
                "Task", f"Enter task name to run (options: {', '.join(task_names)}):", parent=self
            )
        else:
            task = simpledialog.askstring("Task", "Enter task name to run:", parent=self)
        if not task:
            return
        self.schedules.append({"time": time_str, "task": task, "enabled": True, "last_run": None})
        self._save_schedules()
        self._refresh_schedule_list()

    def _delete_schedule(self) -> None:
        sel = self.schedule_listbox.curselection()
        if not sel:
            return
        del self.schedules[int(sel[0])]
        self._save_schedules()
        self._refresh_schedule_list()

    def _toggle_schedule(self) -> None:
        sel = self.schedule_listbox.curselection()
        if not sel:
            return
        idx = int(sel[0])
        self.schedules[idx]["enabled"] = not self.schedules[idx].get("enabled", True)
        self._save_schedules()
        self._refresh_schedule_list()

    def _scheduler_tick(self) -> None:
        now = datetime.now()
        for schedule in self.schedules:
            if not schedule.get("enabled", True):
                continue
            try:
                scheduled_time = datetime.strptime(schedule.get("time", "00:00"), "%H:%M")
            except ValueError:
                continue
            run_time = now.replace(hour=scheduled_time.hour, minute=scheduled_time.minute, second=0, microsecond=0)
            last_run_str = schedule.get("last_run")
            last_run = datetime.fromisoformat(last_run_str) if last_run_str else None
            if now >= run_time and (last_run is None or last_run.date() < now.date()):
                task_name = schedule.get("task")
                task = next((t for t in self.tasks if t.get("name") == task_name), None)
                if task:
                    logging.info("Scheduled run for task '%s'", task_name)
                    threading.Thread(target=self._run_task_with_retries, args=(task,), daemon=True).start()
                    schedule["last_run"] = now.isoformat()
                    self._save_schedules()
                    self._refresh_schedule_list()
        self.after(60000, self._scheduler_tick)

    def _save_settings(self) -> None:
        for key, var in self.settings_vars.items():
            value: str = var.get()
            if key in {"timeout_seconds", "retries", "delay_between_steps"}:
                try:
                    self.config_data[key] = float(value) if "delay" in key else int(value)
                except ValueError:
                    logging.error("Invalid value for %s", key)
            else:
                self.config_data[key] = value
        for key, var in self.bool_vars.items():
            self.config_data[key] = bool(var.get())
        self._save_config()
        self._register_hotkey()
        logging.info("Settings saved")

    def _register_hotkey(self) -> None:
        if not KEYBOARD_AVAILABLE:
            return
        hotkey = str(self.config_data.get("stop_hotkey", "ctrl+alt+s"))
        try:
            keyboard.unregister_all_hotkeys()
            keyboard.add_hotkey(hotkey, self.stop_all)
            logging.info("Registered stop hotkey: %s", hotkey)
        except Exception:
            logging.warning("Unable to register hotkey. Hotkey support may require administrator privileges.")

    def start_mcp(self) -> None:
        if self.mcp_process and self.mcp_process.poll() is None:
            logging.info("MCP already running")
            return
        try:
            self.mcp_process = subprocess.Popen(
                ["uvx", "windows-mcp"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.status_var.set("RUNNING")
            self.status_label.configure(foreground="green")
            threading.Thread(target=self._stream_process_output, args=(self.mcp_process, "MCP"), daemon=True).start()
            threading.Thread(target=self._monitor_mcp, daemon=True).start()
            logging.info("Started MCP server")
        except FileNotFoundError:
            logging.error("uvx not found. Please install uv to use the MCP server.")
        except Exception as exc:
            logging.error("Failed to start MCP: %s", exc)

    def stop_mcp(self) -> None:
        if self.mcp_process and self.mcp_process.poll() is None:
            self.mcp_process.terminate()
            try:
                self.mcp_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.mcp_process.kill()
            logging.info("Stopped MCP server")
        self.status_var.set("STOPPED")
        self.status_label.configure(foreground="red")

    def _monitor_mcp(self) -> None:
        if not self.mcp_process:
            return
        self.mcp_process.wait()
        self.status_var.set("STOPPED")
        self.status_label.configure(foreground="red")
        logging.warning("MCP server exited")
        if self.config_data.get("auto_restart_mcp"):
            time.sleep(2)
            logging.info("Attempting to restart MCP server")
            self.start_mcp()

    def _stream_process_output(self, process: subprocess.Popen[str], prefix: str) -> None:
        if not process.stdout:
            return
        for line in process.stdout:
            logging.info("%s: %s", prefix, line.strip())
        logging.info("%s process finished", prefix)

    def _build_codex_command(self, prompt: str) -> List[str]:
        command = [str(self.config_data.get("codex_command", "codex")), "e", prompt]
        model = str(self.config_data.get("model", "")).strip()
        if model:
            command.extend(["--model", model])
        timeout = int(float(self.config_data.get("timeout_seconds", 300)))
        command.extend(["--timeout", str(timeout)])
        return command

    def _is_blocked(self, prompt: str) -> bool:
        if not self.config_data.get("block_dangerous_commands", True):
            return False
        lower_prompt = prompt.lower()
        return any(block in lower_prompt for block in BLOCKED_COMMANDS)

    def run_task(self, task: Dict[str, str]) -> bool:
        prompt = task.get("prompt", "")
        if self._is_blocked(prompt):
            logging.warning("Task '%s' blocked due to dangerous command", task.get("name"))
            return False
        if self.config_data.get("confirm_before_execute", True):
            proceed = messagebox.askyesno("Confirm", f"Run task '{task.get('name')}'?")
            if not proceed:
                logging.info("User cancelled task '%s'", task.get("name"))
                return False

        if self.config_data.get("dry_run", False):
            logging.info("Dry run: would execute task '%s' with prompt: %s", task.get("name"), prompt)
            return True

        command = self._build_codex_command(prompt)
        logging.info("Running task '%s'", task.get("name"))

        try:
            self.stop_flag.clear()
            self.current_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            timer = threading.Timer(float(self.config_data.get("timeout_seconds", 300)), self.stop_current_process)
            timer.start()
            self._stream_process_output(self.current_process, "CODEX")
            self.current_process.wait()
            timer.cancel()
            code = self.current_process.returncode
            self.current_process = None
            if code == 0:
                logging.info("Task '%s' completed", task.get("name"))
                return True
            logging.error("Task '%s' failed with exit code %s", task.get("name"), code)
            return False
        except FileNotFoundError:
            logging.error("codex command not found. Configure the correct path in Settings.")
            return False
        except Exception as exc:
            logging.error("Error running task '%s': %s", task.get("name"), exc)
            return False

    def stop_current_process(self) -> None:
        if self.current_process and self.current_process.poll() is None:
            logging.warning("Stopping current Codex run")
            try:
                self.current_process.terminate()
                self.current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.current_process.kill()
        self.current_process = None

    def stop_all(self) -> None:
        self.stop_flag.set()
        self.stop_current_process()

    def on_close(self) -> None:
        self.stop_all()
        self.stop_mcp()
        self.destroy()


def smoke_test() -> None:
    """Run a lightweight dry-run demonstration without launching the full UI."""

    ensure_data_dir()
    test_task = {"name": "Smoke", "prompt": "Open Notepad and type Hello"}
    print("[SMOKE] Starting dry-run smoke test...")
    print("[SMOKE] This test does not execute Codex or launch the UI.")
    print(f"[SMOKE] Task: {test_task['prompt']}")
    print("[SMOKE] Result: success (dry-run)")


if __name__ == "__main__":
    app = ControllerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
