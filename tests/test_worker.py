"""Unit tests for background Worker and QThreadPool task execution."""

import time
from PySide6.QtCore import QCoreApplication
from ip_sentinel.core.worker import TaskPool, Worker


def sample_task(x: int, y: int, progress_callback=None):
    time.sleep(0.02)
    if progress_callback:
        progress_callback(50, "Halfway done")
    time.sleep(0.05)
    return x + y


def test_worker_execution(qapp):
    results = []
    errors = []
    progresses = []

    signals = TaskPool.execute(sample_task, 10, 20)
    signals.result.connect(lambda res: results.append(res))
    signals.error.connect(lambda err: errors.append(err))
    signals.progress.connect(lambda pct, msg: progresses.append((pct, msg)))

    # Process Qt events until worker completes
    start = time.time()
    while not results and not errors and (time.time() - start < 3.0):
        QCoreApplication.processEvents()
        time.sleep(0.01)

    # Process remaining queued events
    for _ in range(10):
        QCoreApplication.processEvents()
        time.sleep(0.01)

    assert len(results) == 1
    assert results[0] == 30
    assert len(errors) == 0
    assert len(progresses) >= 1


def test_worker_start_method(qapp):
    results = []
    worker = Worker(sample_task, 5, 15)
    worker.signals.result.connect(lambda res: results.append(res))
    worker.start()

    start = time.time()
    while not results and (time.time() - start < 3.0):
        QCoreApplication.processEvents()

    assert len(results) == 1
    assert results[0] == 20
