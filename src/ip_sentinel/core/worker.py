"""Background worker infrastructure utilizing PySide6 QRunnable and QThreadPool.

Ensures UI thread responsiveness by running network lookups, DNS resolution,
and report rendering off the main GUI event thread.
"""

import inspect
import logging
import sys
import traceback
from typing import Any, Callable, Tuple

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

logger = logging.getLogger("ip_sentinel.worker")


class WorkerSignals(QObject):
    """Signals emitted by background Worker instances to main Qt thread."""

    started = Signal()
    progress = Signal(int, str)  # (percentage_0_100, status_message)
    result = Signal(object)      # Return value from task function
    error = Signal(tuple)       # (exception_type, exception_value, traceback_text)
    finished = Signal()


class Worker(QRunnable):
    """Generic QRunnable worker for executing callables asynchronously in QThreadPool."""

    def __init__(self, fn: Callable, *args: Any, **kwargs: Any):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        
        # Inject progress callback parameter into kwargs ONLY if expected by target fn
        try:
            sig = inspect.signature(self.fn)
            has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            if ("progress_callback" in sig.parameters or has_var_kw) and "progress_callback" not in self.kwargs:
                self.kwargs["progress_callback"] = self._emit_progress
        except (ValueError, TypeError):
            pass

    def _emit_progress(self, percent: int, message: str) -> None:
        """Helper callback passed to worker target functions."""
        self.signals.progress.emit(percent, message)

    def run(self) -> None:
        """Execute task inside QThreadPool worker thread."""
        logger.debug(f"Starting background worker execution for {self.fn.__name__}")
        self.signals.started.emit()

        try:
            res = self.fn(*self.args, **self.kwargs)
            self.signals.result.emit(res)
        except Exception as err:
            logger.error(f"Worker task {self.fn.__name__} raised exception: {err}")
            tb_text = traceback.format_exc()
            exctype, val, _ = sys.exc_info()
            self.signals.error.emit((exctype or Exception, val or err, tb_text))
        finally:
            self.signals.finished.emit()
            logger.debug(f"Finished background worker execution for {self.fn.__name__}")


class TaskPool:
    """Helper manager around PySide6 global QThreadPool."""

    @staticmethod
    def execute(fn: Callable, *args: Any, **kwargs: Any) -> WorkerSignals:
        """Submit a callable task to global QThreadPool and return its signals hub."""
        worker = Worker(fn, *args, **kwargs)
        QThreadPool.globalInstance().start(worker)
        return worker.signals
