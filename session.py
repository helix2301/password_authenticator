import os
import time
import secrets
import hashlib
import gc
from dataclasses import dataclass, field


@dataclass
class SecureSession:
    """
    Best-effort secure session object.

    Python cannot guarantee KeePassXC-level memory protection because Python
    strings/bytes are immutable and garbage-collected. This class reduces
    exposure by:
    - keeping session IDs separate from database data
    - tracking activity
    - keeping the DEK in a mutable bytearray
    - overwriting the mutable DEK on lock/logout
    """
    dek_bytes: bytes
    session_id: str = field(default_factory=lambda: secrets.token_hex(32))
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    is_active: bool = True

    def __post_init__(self):
        self._dek = bytearray(self.dek_bytes)
        self.dek_bytes = b""

    def touch(self):
        self.last_activity = time.time()

    def get_dek(self):
        if not self.is_active:
            raise RuntimeError("Session is locked.")
        return bytes(self._dek)

    def fingerprint(self):
        return hashlib.sha256(bytes(self._dek) + self.session_id.encode()).hexdigest()

    def wipe(self):
        try:
            for i in range(len(self._dek)):
                self._dek[i] = 0
            self._dek.clear()
        except Exception:
            pass

        self.is_active = False
        self.session_id = ""
        gc.collect()
