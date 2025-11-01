import time
import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple


@dataclass
class Challenge:
    challenge: str
    difficulty: int
    expires_at: float


class PyCap:
    """Minimal Python-only proof-of-work challenge provider.

    - issue() returns a short-lived challenge and difficulty
    - verify(nonce) recomputes sha256(f"{challenge}:{nonce}") and checks
      leading hex zeros against difficulty and expiration window
    """

    def __init__(self, difficulty: int = 4, ttl_seconds: int = 180):
        self._difficulty = int(difficulty)
        self._ttl = int(ttl_seconds)

    def issue(self) -> Challenge:
        return Challenge(
            challenge=secrets.token_hex(16),
            difficulty=self._difficulty,
            expires_at=time.time() + self._ttl,
        )

    @staticmethod
    def _hash(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def verify(self, ch: Challenge, nonce: str) -> Tuple[bool, str]:
        if time.time() > ch.expires_at:
            return False, "Challenge expired"
        digest = self._hash(f"{ch.challenge}:{nonce}")
        if not digest.startswith("0" * ch.difficulty):
            return False, "Insufficient PoW difficulty"
        return True, "ok"


