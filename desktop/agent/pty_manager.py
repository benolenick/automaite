import os
import time
import threading
import logging
import asyncio
from typing import Callable
from winpty import PtyProcess

# Env vars that Claude Code sets to detect nesting — strip them so spawned
# agents don't think they're running inside another agent.
_STRIP_ENV = {
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE",
    "CLAUDE_CODE_ENTRY_POINT",
    "CLAUDE_CODE_PACKAGE_DIR",
    "CLAUDE_CODE_SESSION",
    "CLAUDE_SKIP_PERMISSIONS",
    "PARENT_CLAUDE_SESSION",
    "CLAUDE_CHAT_ID",
}

logger = logging.getLogger("agent.pty")


class PtySession:
    def __init__(
        self,
        session_id: str,
        command: str,
        cols: int,
        rows: int,
        on_output: Callable[[str, bytes], None],
        on_exit: Callable[[str], None],
        loop: asyncio.AbstractEventLoop,
    ):
        self.session_id = session_id
        self.command = command
        self.cols = cols
        self.rows = rows
        self.on_output = on_output
        self.on_exit = on_exit
        self.loop = loop
        self.process: PtyProcess | None = None
        self._reader_thread: threading.Thread | None = None
        self._alive = False
        self.last_activity = time.time()

    def spawn(self, extra_env: dict[str, str] | None = None):
        logger.info("Spawning PTY for %s: %s", self.session_id, self.command)
        clean_env = {k: v for k, v in os.environ.items() if k not in _STRIP_ENV}
        # Inject API keys and other env vars from the relay
        if extra_env:
            clean_env.update(extra_env)
        # Ensure node and npm global bin are on PATH for gemini/codex CLIs
        _extra_paths = [
            os.path.expandvars(r"%PROGRAMFILES%\nodejs"),
            os.path.expandvars(r"%APPDATA%\npm"),
        ]
        current_path = clean_env.get("PATH", clean_env.get("Path", ""))
        for p in _extra_paths:
            if p and p not in current_path:
                current_path = p + os.pathsep + current_path
        clean_env["PATH"] = current_path
        self.process = PtyProcess.spawn(
            self.command,
            dimensions=(self.rows, self.cols),
            env=clean_env,
        )
        self._alive = True
        self.last_activity = time.time()
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name=f"pty-{self.session_id[:8]}"
        )
        self._reader_thread.start()

    def _read_loop(self):
        try:
            while self._alive and self.process and self.process.isalive():
                try:
                    data = self.process.read(4096)
                    if data:
                        self.last_activity = time.time()
                        if isinstance(data, str):
                            raw = data.encode("utf-8", errors="replace")
                        else:
                            raw = data
                        self.loop.call_soon_threadsafe(
                            self.on_output, self.session_id, raw
                        )
                except EOFError:
                    break
                except UnicodeDecodeError as e:
                    logger.debug("PTY encoding error for %s: %s", self.session_id, e)
                    continue
                except Exception:
                    if self._alive:
                        logger.exception("PTY read error for %s", self.session_id)
                    break
        finally:
            self._alive = False
            self.loop.call_soon_threadsafe(self.on_exit, self.session_id)

    def write(self, data: str):
        if self.process and self._alive:
            try:
                self.last_activity = time.time()
                logger.debug("Writing to PTY %s: %r", self.session_id[:8], data[:50])
                self.process.write(data)
            except Exception:
                logger.exception("PTY write error for %s", self.session_id)
        else:
            logger.warning("Write to dead/missing PTY %s (alive=%s, proc=%s)",
                          self.session_id[:8], self._alive, self.process is not None)

    def resize(self, cols: int, rows: int):
        self.cols = cols
        self.rows = rows
        if self.process and self._alive:
            try:
                self.process.setwinsize(rows, cols)
            except Exception:
                logger.debug("PTY resize failed for %s", self.session_id)

    def kill(self):
        self._alive = False
        if self.process:
            try:
                if self.process.isalive():
                    self.process.terminate()
            except Exception:
                logger.debug("PTY kill failed for %s", self.session_id)


class PtyManager:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.sessions: dict[str, PtySession] = {}
        self._output_queue: asyncio.Queue = asyncio.Queue()

    @property
    def output_queue(self) -> asyncio.Queue:
        return self._output_queue

    def _on_output(self, session_id: str, data: bytes):
        self._output_queue.put_nowait((session_id, data))

    def _on_exit(self, session_id: str):
        self._output_queue.put_nowait((session_id, None))

    def spawn(self, session_id: str, command: str, cols: int, rows: int, extra_env: dict[str, str] | None = None):
        if session_id in self.sessions:
            logger.warning("Session %s already exists", session_id)
            return
        session = PtySession(
            session_id=session_id,
            command=command,
            cols=cols,
            rows=rows,
            on_output=self._on_output,
            on_exit=self._on_exit,
            loop=self.loop,
        )
        self.sessions[session_id] = session
        session.spawn(extra_env=extra_env)

    def write(self, session_id: str, data: str):
        session = self.sessions.get(session_id)
        if session:
            session.write(data)

    def resize(self, session_id: str, cols: int, rows: int):
        session = self.sessions.get(session_id)
        if session:
            session.resize(cols, rows)

    def kill(self, session_id: str):
        session = self.sessions.pop(session_id, None)
        if session:
            session.kill()

    def kill_all(self):
        for sid in list(self.sessions.keys()):
            self.kill(sid)
