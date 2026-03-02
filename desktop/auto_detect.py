"""Detect installed CLI agents (claude, gemini, codex)."""

import os
import shutil
import subprocess
import logging

# Hide console windows when running --version checks on Windows
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

logger = logging.getLogger("automaite.detect")

AGENTS = {
    "claude": {
        "binary": "claudereal",
        "display_name": "Claude Code",
        "install_url": "https://docs.anthropic.com/en/docs/claude-code/overview",
    },
    "gemini": {
        "binary": "geminireal",
        "display_name": "Gemini CLI",
        "install_url": "https://github.com/google-gemini/gemini-cli",
    },
    "codex": {
        "binary": "codexreal",
        "display_name": "Codex CLI",
        "install_url": "https://github.com/openai/codex",
    },
}


def detect_agents() -> list[dict]:
    """Detect which CLI agents are installed and their versions."""
    results = []
    for name, info in AGENTS.items():
        binary = shutil.which(info["binary"])
        version = None
        if binary:
            try:
                result = subprocess.run(
                    [binary, "--version"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=_CREATE_NO_WINDOW,
                )
                version = result.stdout.strip() or result.stderr.strip()
                version = version.split("\n")[0][:100]
            except (subprocess.TimeoutExpired, OSError):
                version = "unknown"

        results.append({
            "name": name,
            "display_name": info["display_name"],
            "installed": binary is not None,
            "version": version,
            "path": binary,
            "install_url": info["install_url"],
        })

    return results


def get_summary() -> str:
    """Return a human-readable summary of detected agents."""
    agents = detect_agents()
    installed = [a for a in agents if a["installed"]]
    if not installed:
        return "No agents detected"
    names = [f"{a['display_name']} ({a['version']})" for a in installed]
    return "Detected: " + ", ".join(names)
