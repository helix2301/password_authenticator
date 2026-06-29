import gc
import sys
import ctypes
import platform


def clear_clipboard_securely(window, passes=3):
    """
    Clear the Tk clipboard several times.

    Note:
    Tkinter cannot guarantee that another application has not already read
    the clipboard, but this reduces lingering clipboard exposure.
    """
    try:
        for _ in range(passes):
            window.clipboard_clear()
            window.clipboard_append("")
            window.update()
        window.clipboard_clear()
        window.update()
    except Exception:
        pass


def cancel_timer(window, timer_id):
    if timer_id is None:
        return

    try:
        window.after_cancel(timer_id)
    except Exception:
        pass


def wipe_decrypted_cache(cache):
    """
    Best-effort removal of decrypted values from Python memory.

    Python strings are immutable, so true zeroization is not guaranteed.
    This clears references and lets garbage collection reclaim memory.
    """
    try:
        if isinstance(cache, dict):
            for key in list(cache.keys()):
                cache[key] = None
            cache.clear()
    except Exception:
        pass


def force_garbage_collection():
    try:
        gc.collect()
    except Exception:
        pass


def disable_core_dumps_best_effort():
    """
    Best-effort core dump disabling.

    Works on many Unix/macOS systems. Windows generally does not use this
    same mechanism. Failure is ignored because support varies by platform.
    """
    if platform.system() not in ("Darwin", "Linux"):
        return

    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def best_effort_lock_memory():
    """
    Best-effort attempt to reduce paging of process memory.

    This may fail without elevated permissions and is intentionally optional.
    It is not a substitute for OS-level secure memory APIs.
    """
    system = platform.system()

    try:
        if system == "Linux":
            libc = ctypes.CDLL("libc.so.6")
            libc.mlockall(1 | 2)  # MCL_CURRENT | MCL_FUTURE
        elif system == "Darwin":
            libc = ctypes.CDLL("libc.dylib")
            libc.mlockall(1 | 2)
    except Exception:
        pass


def harden_process_best_effort():
    disable_core_dumps_best_effort()
    best_effort_lock_memory()


def secure_window_shutdown(window, timers=None, decrypted_cache=None):
    """
    Central secure shutdown routine:
    - cancels timers
    - clears clipboard immediately
    - clears decrypted cache
    - forces garbage collection
    - destroys the Tk window
    """
    timers = timers or []

    for timer_id in timers:
        cancel_timer(window, timer_id)

    clear_clipboard_securely(window)
    wipe_decrypted_cache(decrypted_cache)
    force_garbage_collection()

    try:
        window.destroy()
    except Exception:
        pass
