"""Bounded subprocess pipe reads that also work with Windows anonymous pipes."""
import os
import queue
import threading


class PipeReader:
    def __init__(self, pipe):
        self.pipe = pipe
        self.chunks = queue.Queue(maxsize=16)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._read, name="git-stderr-reader", daemon=True)
        self.thread.start()

    def _put(self, item):
        while not self.stopped.is_set():
            try:
                self.chunks.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def _read(self):
        try:
            while not self.stopped.is_set():
                chunk = os.read(self.pipe.fileno(), 4096)
                if not chunk:
                    break
                self._put(chunk)
        except OSError as exc:
            self._put(exc)
        finally:
            self.pipe.close()
            self._put(None)

    def read(self, timeout=0.1):
        """Return a chunk/EOF, or an empty chunk while waiting for output."""
        try:
            item = self.chunks.get(timeout=timeout)
        except queue.Empty:
            return b""
        if isinstance(item, OSError):
            raise item
        return item

    def close(self):
        # The caller terminates/reaps the child before closing the reader.
        self.stopped.set()
        self.thread.join(timeout=2)
