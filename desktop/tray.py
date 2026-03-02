"""
System tray app for Automaite Desktop Agent (cloud relay mode).
"""

import os
import sys
import threading
import webbrowser
import tkinter as tk
from tkinter import messagebox

import pystray
from PIL import Image, ImageDraw

import auto_detect
import config_store


def _create_icon_image(size: int = 64) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 4
    draw.ellipse(
        [margin, margin, size - margin, size - margin],
        fill=(124, 58, 237, 255),
        outline=(30, 30, 48, 255),
        width=2,
    )
    try:
        from PIL import ImageFont
        font = ImageFont.truetype("arial", size // 3)
    except Exception:
        from PIL import ImageFont
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "A", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(
        ((size - tw) / 2 - bbox[0], (size - th) / 2 - bbox[1]),
        "A", fill="white", font=font,
    )
    return img


class TrayApp:
    def __init__(self, relay_url: str, on_quit: callable, agent_connected_fn: callable):
        self.relay_url = relay_url
        self.on_quit = on_quit
        self.agent_connected_fn = agent_connected_fn

        icon_image = _create_icon_image(64)

        # Build detected agents submenu
        agents = auto_detect.detect_agents()
        cfg = config_store.load()
        custom = cfg.get("custom_agents", [])

        agent_items = []
        for a in agents:
            if a["installed"]:
                label = f"{a['display_name']} ({a['version']})"
            else:
                label = f"{a['display_name']} — not installed"
            agent_items.append(pystray.MenuItem(label, None, enabled=False))
        for path in custom:
            agent_items.append(pystray.MenuItem(f"Custom: {path}", None, enabled=False))

        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", self._open_dashboard),
            pystray.MenuItem("Detected Agents", pystray.Menu(*agent_items)),
            pystray.MenuItem("Configure Agents...", self._configure_agents),
            pystray.MenuItem("Status", self._show_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Disconnect / Re-pair", self._disconnect),
            pystray.MenuItem("Start with Windows", self._toggle_autostart,
                             checked=lambda _: self._is_autostart()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )
        self._icon = pystray.Icon(
            name="AutomaiteAgent",
            icon=icon_image,
            title="Automaite Agent — Connected",
            menu=menu,
        )

    def _open_dashboard(self, icon, item):
        webbrowser.open(self.relay_url)

    def _show_status(self, icon, item):
        threading.Thread(target=self._show_status_popup, daemon=True).start()

    def _show_status_popup(self):
        connected = self.agent_connected_fn()

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        popup = tk.Toplevel(root)
        popup.title("Agent Status")
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        w, h = 280, 120
        sw = popup.winfo_screenwidth()
        sh = popup.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        popup.geometry(f"{w}x{h}+{x}+{y}")

        if connected:
            symbol = "\u2713"
            color = "#16a34a"
            message = "Agent connected"
        else:
            symbol = "\u2717"
            color = "#dc2626"
            message = "Agent disconnected"

        frame = tk.Frame(popup, padx=20, pady=20)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text=f"{symbol}  {message}",
            font=("Segoe UI", 13),
            fg=color,
        ).pack(pady=(0, 14))

        tk.Button(
            frame,
            text="OK",
            width=8,
            command=lambda: (popup.destroy(), root.destroy()),
        ).pack()

        popup.protocol("WM_DELETE_WINDOW", lambda: (popup.destroy(), root.destroy()))
        root.mainloop()

    def _configure_agents(self, icon, item):
        threading.Thread(target=self._do_configure_agents, daemon=True).start()

    def _do_configure_agents(self):
        from tkinter import filedialog

        cfg = config_store.load()
        existing = cfg.get("custom_agents", [])

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        dlg = tk.Toplevel(root)
        dlg.title("Configure Agent")
        dlg.resizable(False, False)
        dlg.attributes("-topmost", True)

        w, h = 420, 200
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        dlg.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        frame = tk.Frame(dlg, padx=20, pady=16)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame, text="Agent command or path:",
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        entry_frame = tk.Frame(frame)
        entry_frame.pack(fill="x", pady=(4, 8))

        path_var = tk.StringVar(value=existing[0] if existing else "")
        path_entry = tk.Entry(entry_frame, textvariable=path_var, font=("Consolas", 10))
        path_entry.pack(side="left", fill="x", expand=True, ipady=3)

        def _browse():
            fp = filedialog.askopenfilename(
                title="Select your agent CLI",
                filetypes=[("Executables", "*.exe *.cmd *.bat *.ps1"), ("All files", "*.*")],
                parent=dlg,
            )
            if fp:
                path_var.set(fp)

        tk.Button(entry_frame, text="Browse...", command=_browse).pack(side="left", padx=(6, 0))

        tk.Label(
            frame, text="Examples:  claude  |  C:\\path\\to\\claude.exe  |  gemini",
            font=("Segoe UI", 8), fg="#666",
        ).pack(anchor="w", pady=(0, 12))

        def _save():
            val = path_var.get().strip()
            cfg2 = config_store.load()
            cfg2["custom_agents"] = [val] if val else []
            config_store.save(cfg2)
            messagebox.showinfo(
                "Saved",
                "Agent path saved. Restart Automaite for\n"
                "the change to take effect.",
                parent=dlg,
            )
            dlg.destroy()
            root.destroy()

        btn_frame = tk.Frame(frame)
        btn_frame.pack()
        tk.Button(btn_frame, text="Save", width=10, command=_save).pack(side="left", padx=4)
        tk.Button(
            btn_frame, text="Cancel", width=10,
            command=lambda: (dlg.destroy(), root.destroy()),
        ).pack(side="left", padx=4)

        dlg.protocol("WM_DELETE_WINDOW", lambda: (dlg.destroy(), root.destroy()))
        root.mainloop()

    def _disconnect(self, icon, item):
        threading.Thread(target=self._do_disconnect, daemon=True).start()

    def _do_disconnect(self):
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        confirm = messagebox.askyesno(
            "Disconnect",
            "This will unlink your desktop from your account.\n\n"
            "Automaite will restart and ask you to pair again.\n\n"
            "Continue?",
            parent=root,
        )
        root.destroy()
        if not confirm:
            return

        # Clear the saved token
        cfg = config_store.load()
        cfg["agent_token"] = ""
        config_store.save(cfg)

        # Restart the exe to trigger re-pairing
        exe = sys.executable if getattr(sys, "frozen", False) else sys.argv[0]
        os.startfile(exe)
        self._icon.stop()
        self.on_quit()

    def _is_autostart(self) -> bool:
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_READ,
            )
            try:
                winreg.QueryValueEx(key, "AutomaiteAgent")
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)
        except Exception:
            return False

    def _toggle_autostart(self, icon, item):
        try:
            import winreg
            reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            if self._is_autostart():
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, reg_key,
                    0, winreg.KEY_SET_VALUE,
                )
                winreg.DeleteValue(key, "AutomaiteAgent")
                winreg.CloseKey(key)
            else:
                exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, reg_key,
                    0, winreg.KEY_SET_VALUE,
                )
                winreg.SetValueEx(key, "AutomaiteAgent", 0, winreg.REG_SZ, f'"{exe}"')
                winreg.CloseKey(key)
        except Exception:
            pass

    def _quit(self, icon, item):
        self._icon.stop()
        self.on_quit()

    def run(self):
        """Block and run the tray icon (required for Windows)."""
        self._icon.run()
