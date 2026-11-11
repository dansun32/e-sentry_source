"""Run a command in a pseudo-terminal and render its output with pyte (test-only dependency)."""
import fcntl, os, pty, select, struct, sys, termios, time
import pyte


class PtyScreen:
    def __init__(self, argv, cols=160, rows=45, env=None):
        self.cols, self.rows = cols, rows
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        pid, fd = pty.fork()
        if pid == 0:
            e = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8", LC_ALL="C.UTF-8", **(env or {}))
            os.execvpe(argv[0], argv, e)
        self.pid, self.fd = pid, fd
        self.resize(cols, rows)
        self.exit = None

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.screen.resize(rows, cols)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        try:
            os.kill(self.pid, 28)  # SIGWINCH
        except OSError:
            pass

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                self.stream.feed(data)

    def send(self, keys, wait=0.6):
        os.write(self.fd, keys if isinstance(keys, bytes) else keys.encode())
        self.pump(wait)

    def text(self):
        return "\n".join(self.screen.display)

    def close(self, timeout=3):
        end = time.time() + timeout
        while time.time() < end:
            p, st = os.waitpid(self.pid, os.WNOHANG)
            if p:
                self.exit = st
                return st
            self.pump(0.1)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        return None
