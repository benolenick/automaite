"""Linux PTY session manager using pty.fork()."""

import asyncio
import fcntl
import logging
import os
import pty
import signal
import struct
import termios
import time
from dataclasses import dataclass, field

logger = logging.getLogger("agent.pty")


@dataclass
class PtySession:
    sid: str
    pid: int
    fd: int
    last_activity: float = field(default_factory=time.time)


class PtyManager:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.sessions: dict[str, PtySession] = {}
        self.output_queue: asyncio.Queue = asyncio.Queue()
        self.loop = loop

    def spawn(self, sid: str, command: str, cols: int, rows: int, extra_env: dict | None = None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        env.setdefault("TERM", "xterm-256color")
        env.setdefault("HOME", os.path.expanduser("~"))
        env.setdefault("LANG", "en_US.UTF-8")

        pid, fd = pty.fork()
        if pid == 0:
            # Child process
            try:
                os.execvpe("/bin/bash", ["/bin/bash", "-c", command], env)
            except Exception:
                os._exit(1)

        # Parent process: set window size and non-blocking
        self._set_winsize(fd, cols, rows)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        session = PtySession(sid=sid, pid=pid, fd=fd)
        self.sessions[sid] = session
        self.loop.add_reader(fd, self._on_output, sid, fd)
        logger.info("Spawned PTY for session %s (pid %d, cmd=%r)", sid[:8], pid, command)

    def _set_winsize(self, fd: int, cols: int, rows: int):
        size = struct.pack("HHHH", rows, cols, 0, 0)
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
        except Exception:
            pass

    def _on_output(self, sid: str, fd: int):
        try:
            data = os.read(fd, 4096)
            if data:
                session = self.sessions.get(sid)
                if session:
                    session.last_activity = time.time()
                self.loop.call_soon_threadsafe(
                    self.output_queue.put_nowait, (sid, data)
                )
            else:
                self._session_done(sid, fd)
        except OSError:
            self._session_done(sid, fd)

    def _session_done(self, sid: str, fd: int):
        try:
            self.loop.remove_reader(fd)
        except Exception:
            pass
        try:
            os.close(fd)
        except Exception:
            pass
        session = self.sessions.pop(sid, None)
        if session:
            try:
                os.waitpid(session.pid, os.WNOHANG)
            except Exception:
                pass
        self.loop.call_soon_threadsafe(
            self.output_queue.put_nowait, (sid, None)
        )
        logger.info("PTY session %s ended", sid[:8])

    def write(self, sid: str, data: str):
        session = self.sessions.get(sid)
        if session:
            session.last_activity = time.time()
            try:
                os.write(session.fd, data.encode("utf-8", errors="replace"))
            except OSError:
                logger.warning("Write failed for session %s", sid[:8])

    def resize(self, sid: str, cols: int, rows: int):
        session = self.sessions.get(sid)
        if session:
            self._set_winsize(session.fd, cols, rows)
            try:
                os.kill(session.pid, signal.SIGWINCH)
            except Exception:
                pass

    def kill(self, sid: str):
        session = self.sessions.pop(sid, None)
        if session:
            try:
                self.loop.remove_reader(session.fd)
            except Exception:
                pass
            try:
                os.kill(session.pid, signal.SIGTERM)
            except Exception:
                pass
            try:
                os.close(session.fd)
            except Exception:
                pass
            try:
                os.waitpid(session.pid, os.WNOHANG)
            except Exception:
                pass

    def kill_all(self):
        for sid in list(self.sessions.keys()):
            self.kill(sid)
