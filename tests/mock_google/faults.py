"""Injected failures.

    mock_google.faults.fail("/revoke", 500)                    # next revoke fails
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=1) # one 401, then OK
    mock_google.faults.fail("/token", 503, times=None)         # always

``path`` is a prefix of the request path; ``method`` optionally narrows it.
A matching request is still recorded in the request log, with the injected
status. OAuth paths get the flat OAuth error body, everything else a
``google.rpc.Status`` one.

The service account ``keys.SA_TOKEN_500`` also gets a 500 on its first token
exchange, without any setup.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class _Rule:
    path: str
    status: int
    remaining: int | None  # None = forever
    method: str | None


class Faults:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules: list[_Rule] = []
        self._token_500_seen: set[str] = set()

    def fail(
        self,
        path: str,
        status: int,
        *,
        times: int | None = 1,
        method: str | None = None,
    ) -> None:
        """Answer the next ``times`` matching requests (``None`` = all) with ``status``."""
        with self._lock:
            self._rules.append(
                _Rule(path, status, times, method.upper() if method else None)
            )

    def clear(self) -> None:
        with self._lock:
            self._rules.clear()

    def take(self, method: str, path: str) -> int | None:
        """The injected status for this request, consuming one use; else None."""
        with self._lock:
            for rule in self._rules:
                if not path.startswith(rule.path):
                    continue
                if rule.method is not None and rule.method != method:
                    continue
                if rule.remaining is not None:
                    rule.remaining -= 1
                    if rule.remaining == 0:
                        self._rules.remove(rule)
                return rule.status
        return None

    def token_500_once(self, client_email: str, magic_email: str) -> bool:
        """True the first time ``magic_email`` asks for a token."""
        if client_email != magic_email:
            return False
        with self._lock:
            if client_email in self._token_500_seen:
                return False
            self._token_500_seen.add(client_email)
            return True
