import threading
import asyncio
import time

_shutdown_event = threading.Event()
_active_threads = set()
_active_tasks = set()
_lock = threading.Lock()
_condition = threading.Condition(_lock)

def request_shutdown():
    _shutdown_event.set()

def clear_shutdown():
    with _condition:
        if _active_threads or _active_tasks:
            raise RuntimeError(f"仍有 {len(_active_threads)} 线程/{len(_active_tasks)} 协程未退出")
    _shutdown_event.clear()

def is_shutdown_requested() -> bool:
    return _shutdown_event.is_set()

def wait_for_shutdown(timeout: float = None) -> bool:
    return _shutdown_event.wait(timeout)

def register_thread(thread: threading.Thread):
    with _condition:
        _active_threads.add(thread)
        _condition.notify_all()

def unregister_thread(thread: threading.Thread):
    with _condition:
        _active_threads.discard(thread)
        _condition.notify_all()

def register_task(task: asyncio.Task):
    def on_done(t):
        with _condition:
            _active_tasks.discard(t)
            _condition.notify_all()
    task.add_done_callback(on_done)
    with _condition:
        _active_tasks.add(task)
        _condition.notify_all()

def wait_all(timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    with _condition:
        while _active_threads or _active_tasks:
            remaining = deadline - time.time()
            if remaining <= 0:
                return False
            _condition.wait(timeout=remaining)
    return True