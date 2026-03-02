"""
Automaite Desktop Agent — entry point.

Connects to the cloud relay at term.automaite.ca rather than running an
embedded relay.  On first run it performs a device-code flow so the user
can approve the device from a browser, then saves the returned agent_token
for all subsequent runs.
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
import webbrowser

import requests

import auto_detect
import config_store
from tray import TrayApp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("automaite.main")

STARTUP_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_REG_NAME = "AutomaiteAgent"


# ---------------------------------------------------------------------------
# GUI helpers (works even with console=False)
# ---------------------------------------------------------------------------

def _show_error(title: str, message: str) -> None:
    """Show a GUI error dialog (safe when console=False)."""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showerror(title, message, parent=root)
    root.destroy()


def _show_info(title: str, message: str) -> None:
    """Show a GUI info dialog (safe when console=False)."""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showinfo(title, message, parent=root)
    root.destroy()


def _show_agent_setup(agents: list[dict]) -> list[str]:
    """Show agent config dialog. Returns list of custom agent paths to save.

    If agents are auto-detected, shows them and offers to add more.
    If none found, prompts user to provide a path.
    """
    from tkinter import filedialog

    installed = [a for a in agents if a["installed"]]
    custom_paths: list[str] = []

    # Load any previously saved custom agents
    cfg = config_store.load()
    existing_custom = cfg.get("custom_agents", [])

    # If we have auto-detected agents, skip
    if installed:
        return [p for p in existing_custom if p]

    # If custom agents are already configured, skip
    if existing_custom:
        return [p for p in existing_custom if p]

    # No agents found and no custom config — show setup dialog
    result = {"paths": list(existing_custom)}

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    dlg = tk.Toplevel(root)
    dlg.title("Automaite — Configure Agent")
    dlg.resizable(False, False)
    dlg.attributes("-topmost", True)

    w, h = 440, 320
    sw = dlg.winfo_screenwidth()
    sh = dlg.winfo_screenheight()
    dlg.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    dlg.configure(bg="#18181b")

    frame = tk.Frame(dlg, bg="#18181b", padx=24, pady=20)
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame, text="No AI agents detected automatically",
        font=("Segoe UI", 11), fg="#a1a1aa", bg="#18181b",
    ).pack(pady=(0, 8))

    tk.Label(
        frame,
        text="Automaite needs to know how to launch your agent.\n"
             "Browse to the executable, or type the command you use.",
        font=("Segoe UI", 9), fg="#71717a", bg="#18181b",
        justify="center",
    ).pack(pady=(0, 12))

    tk.Label(
        frame, text="Agent command or path:",
        font=("Segoe UI", 9), fg="#71717a", bg="#18181b",
        anchor="w",
    ).pack(fill="x")

    entry_frame = tk.Frame(frame, bg="#18181b")
    entry_frame.pack(fill="x", pady=(2, 8))

    path_var = tk.StringVar(value=existing_custom[0] if existing_custom else "")
    path_entry = tk.Entry(
        entry_frame, textvariable=path_var,
        font=("Consolas", 10), fg="#a1a1aa", bg="#27272a",
        relief="flat", insertbackground="#a1a1aa",
    )
    path_entry.pack(side="left", fill="x", expand=True, ipady=4)

    def _browse():
        fp = filedialog.askopenfilename(
            title="Select your agent CLI",
            filetypes=[("Executables", "*.exe *.cmd *.bat *.ps1"), ("All files", "*.*")],
            parent=dlg,
        )
        if fp:
            path_var.set(fp)

    tk.Button(
        entry_frame, text="Browse...",
        font=("Segoe UI", 9), fg="white", bg="#3f3f46",
        activebackground="#52525b", activeforeground="white",
        relief="flat", cursor="hand2", padx=8,
        command=_browse,
    ).pack(side="left", padx=(6, 0))

    tk.Label(
        frame,
        text="Examples:  claude  |  C:\\path\\to\\claude.exe  |  gemini",
        font=("Segoe UI", 8), fg="#525252", bg="#18181b",
    ).pack(pady=(0, 16))

    def _save_and_close():
        val = path_var.get().strip()
        if val:
            result["paths"] = [val]
        dlg.destroy()
        root.destroy()

    tk.Button(
        frame, text="Save",
        font=("Segoe UI", 11, "bold"), fg="white", bg="#7c3aed",
        activebackground="#6d28d9", activeforeground="white",
        relief="flat", cursor="hand2", padx=20, pady=8,
        command=_save_and_close,
    ).pack(pady=(0, 6))

    tk.Label(
        frame,
        text="You can change this later from the tray icon menu.",
        font=("Segoe UI", 8), fg="#525252", bg="#18181b",
    ).pack()

    dlg.protocol("WM_DELETE_WINDOW", _save_and_close)
    root.mainloop()

    return result["paths"]


# ---------------------------------------------------------------------------
# Windows auto-start
# ---------------------------------------------------------------------------

def _get_exe_path() -> str:
    """Get path to the running executable (works for PyInstaller and dev)."""
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(sys.argv[0])


def _enable_autostart() -> None:
    """Add Automaite to Windows startup via registry."""
    try:
        import winreg
        exe_path = _get_exe_path()
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, STARTUP_REG_KEY,
            0, winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, STARTUP_REG_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
        logger.info("Auto-start enabled: %s", exe_path)
    except Exception:
        logger.warning("Failed to set auto-start registry key", exc_info=True)


def _is_autostart_enabled() -> bool:
    """Check if Automaite is already in Windows startup."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, STARTUP_REG_KEY,
            0, winreg.KEY_READ,
        )
        try:
            winreg.QueryValueEx(key, STARTUP_REG_NAME)
            return True
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Device-code setup flow
# ---------------------------------------------------------------------------

def setup_device_code(relay_url: str) -> tuple[str, str]:
    """Run the device-code OAuth-style flow.  Returns (agent_token, email)."""

    # Step 1: request a device + user code from the relay
    try:
        resp = requests.post(f"{relay_url}/api/agent/device-code", timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        _show_error(
            "Connection Failed",
            f"Could not reach the Automaite relay.\n\n"
            f"URL: {relay_url}\n"
            f"Error: {exc}\n\n"
            f"Check your internet connection and try again.",
        )
        raise

    data = resp.json()
    device_code = data["device_code"]
    user_code = data["user_code"]
    expires_in = data["expires_in"]

    connect_url = f"{relay_url}/connect?code={user_code}"
    logger.info("Device code flow started: user_code=%s", user_code)

    # Show pairing dialog AND poll in the background simultaneously.
    # The dialog stays open until approval is detected or the user closes it.
    approval_result: dict = {}

    def _poll_in_background(root_ref):
        """Poll relay for approval; close dialog automatically when approved."""
        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(3)
            try:
                r = requests.post(
                    f"{relay_url}/api/agent/poll",
                    json={"device_code": device_code},
                    timeout=10,
                )
                logger.info("Poll response: %d", r.status_code)
            except requests.RequestException as exc:
                logger.warning("Poll network error: %s", exc)
                continue

            if r.status_code == 404:
                break  # expired
            if r.status_code >= 400:
                continue

            result = r.json()
            if result["status"] == "approved":
                approval_result["token"] = result["agent_token"]
                approval_result["email"] = result.get("email", "")
                logger.info("Approval detected via poll!")
                # Close the dialog from the main thread
                try:
                    root_ref.after(0, root_ref.destroy)
                except Exception:
                    pass
                return

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    dlg = tk.Toplevel(root)
    dlg.title("Automaite — Pair Your Desktop")
    dlg.resizable(False, False)
    dlg.attributes("-topmost", True)

    w, h = 380, 340
    sw = dlg.winfo_screenwidth()
    sh = dlg.winfo_screenheight()
    dlg.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    dlg.configure(bg="#18181b")

    frame = tk.Frame(dlg, bg="#18181b", padx=24, pady=20)
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame, text="Link this computer to your account",
        font=("Segoe UI", 11), fg="#a1a1aa", bg="#18181b",
    ).pack(pady=(0, 12))

    tk.Label(
        frame, text="Your pairing code:",
        font=("Segoe UI", 9), fg="#71717a", bg="#18181b",
    ).pack()

    tk.Label(
        frame, text=user_code,
        font=("Consolas", 28, "bold"), fg="#a78bfa", bg="#18181b",
    ).pack(pady=(4, 12))

    tk.Label(
        frame,
        text="Sign in at term.automaite.ca with the Google\n"
             "account you want to use, then approve.",
        font=("Segoe UI", 9), fg="#71717a", bg="#18181b",
        justify="center",
    ).pack(pady=(0, 12))

    def _open_browser():
        webbrowser.open(connect_url)

    btn = tk.Button(
        frame, text="Open Browser to Approve",
        font=("Segoe UI", 11, "bold"), fg="white", bg="#7c3aed",
        activebackground="#6d28d9", activeforeground="white",
        relief="flat", cursor="hand2", padx=16, pady=8,
        command=_open_browser,
    )
    btn.pack(pady=(0, 6))

    tk.Label(
        frame, text="or copy this URL into any browser:",
        font=("Segoe UI", 8), fg="#525252", bg="#18181b",
    ).pack(pady=(0, 2))

    url_entry = tk.Entry(
        frame, font=("Consolas", 8), fg="#a1a1aa", bg="#27272a",
        relief="flat", readonlybackground="#27272a", justify="center",
    )
    url_entry.insert(0, connect_url)
    url_entry.configure(state="readonly")
    url_entry.pack(fill="x", pady=(0, 6))
    url_entry.bind("<Button-1>", lambda e: (url_entry.configure(state="normal"),
                                            url_entry.select_range(0, "end"),
                                            url_entry.configure(state="readonly")))

    dlg.protocol("WM_DELETE_WINDOW", lambda: root.destroy())

    # Start polling in background thread
    poll_thread = threading.Thread(
        target=_poll_in_background, args=(root,), daemon=True,
    )
    poll_thread.start()

    root.mainloop()

    # Dialog closed — either approval was detected or user closed manually
    if approval_result.get("token"):
        return approval_result["token"], approval_result.get("email", "")

    # Dialog was closed manually — keep polling synchronously
    logger.info("Dialog closed, continuing to poll...")
    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(3)
        try:
            resp = requests.post(
                f"{relay_url}/api/agent/poll",
                json={"device_code": device_code},
                timeout=10,
            )
            logger.info("Poll response: %d", resp.status_code)
        except requests.RequestException:
            continue

        if resp.status_code == 404:
            _show_error(
                "Code Expired",
                "The pairing code expired before it was approved.\n\n"
                "Restart Automaite to try again.",
            )
            raise RuntimeError("Device code expired")
        if resp.status_code >= 400:
            continue

        result = resp.json()
        if result["status"] == "approved":
            return result["agent_token"], result.get("email", "")

    _show_error(
        "Pairing Timed Out",
        "No approval was received within 5 minutes.\n\n"
        "Make sure you're signed in at term.automaite.ca,\n"
        "then restart Automaite to try again.",
    )
    raise RuntimeError("Device code expired — no approval received")


# ---------------------------------------------------------------------------
# Agent startup
# ---------------------------------------------------------------------------

def start_agent(relay_url: str, agent_token: str, custom_agents: list[str] | None = None) -> None:
    """Launch the agent WebSocket loop in a daemon background thread."""
    from agent.agent import run_agent, DEFAULT_ALLOWED_COMMANDS

    ws_url = relay_url.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/ws/agent"

    # Merge custom agent paths into the allowlist
    allowed = set(DEFAULT_ALLOWED_COMMANDS)
    for path in (custom_agents or []):
        # Add the full path and the base name (sans extension)
        allowed.add(path)
        base = os.path.basename(path).lower()
        for ext in (".cmd", ".bat", ".exe", ".ps1"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        allowed.add(base)

    def _run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            run_agent(
                relay_url=ws_url,
                agent_key=agent_token,
                session_idle_timeout=7200,
                allowed_commands=allowed,
            )
        )

    thread = threading.Thread(target=_run, daemon=True, name="agent")
    thread.start()
    logger.info("Agent thread started (ws_url=%s)", ws_url)


# ---------------------------------------------------------------------------
# Quit handler
# ---------------------------------------------------------------------------

def on_quit() -> None:
    logger.info("Quit requested — shutting down.")
    raise SystemExit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = config_store.load()
    relay_url = cfg.get("relay_url", "https://term.automaite.ca")

    # First-time setup: obtain an agent token via device-code flow
    if not cfg.get("agent_token"):
        try:
            token, email = setup_device_code(relay_url)
        except Exception as exc:
            logger.error("Device-code setup failed: %s", exc)
            raise SystemExit(1)

        cfg["agent_token"] = token
        config_store.save(cfg)

        # Enable auto-start on first successful pairing
        if not _is_autostart_enabled():
            _enable_autostart()

        account_line = f"Linked to: {email}\n\n" if email else ""
        _show_info(
            "Connected",
            f"{account_line}"
            f"Your desktop agent is now linked to your account.\n\n"
            f"Automaite will start automatically when you log in.\n"
            f"Look for the purple 'A' icon in your system tray.\n\n"
            f"To switch accounts, right-click the tray icon\n"
            f"and choose 'Disconnect / Re-pair'.",
        )

    agent_token = cfg["agent_token"]

    # Detect installed CLI agents; prompt for custom path if none found
    agents = auto_detect.detect_agents()
    summary = auto_detect.get_summary()
    logger.info("Agent detection: %s", summary)

    custom_agents = _show_agent_setup(agents)
    if custom_agents:
        cfg["custom_agents"] = custom_agents
        config_store.save(cfg)
        logger.info("Custom agents saved: %s", custom_agents)

    # Ensure auto-start is set (covers upgrades)
    if not _is_autostart_enabled():
        _enable_autostart()

    # Start the WebSocket agent in the background
    start_agent(relay_url, agent_token, custom_agents=cfg.get("custom_agents", []))

    # Start the system tray app (blocks until quit)
    tray = TrayApp(
        relay_url=relay_url,
        on_quit=on_quit,
        agent_connected_fn=lambda: True,  # TODO: wire up real connection state
    )

    signal.signal(signal.SIGINT, lambda *_: on_quit())
    tray.run()


if __name__ == "__main__":
    main()
