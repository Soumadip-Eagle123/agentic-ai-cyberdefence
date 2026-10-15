"""Key material for Layer 6.

Two independent keys, never the same value:

* the **chain key** authenticates the audit chain (HMAC), and
* the **pseudonym key** derives operational pseudonyms.

Reusing one key for both is poor hygiene: anyone who needs to verify the chain
would also be able to reverse every pseudonym by brute-forcing the small
identifier space. ``KeyRing`` keeps them separate and refuses to let them match.

Resolution order for each key: explicit argument, environment variable, key file
named by ``ACCDS_KEY_FILE``, then a clearly-labelled development default.
Production use must not reach the default; ``KeyRing.require_managed()`` enforces that.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

ENV_CHAIN_KEY = "ACCDS_CHAIN_KEY"
ENV_PSEUDONYM_KEY = "ACCDS_PSEUDONYM_KEY"
ENV_KEY_FILE = "ACCDS_KEY_FILE"

#: Development-only. Never use these where real telemetry is involved.
DEV_CHAIN_KEY = b"accds-layer6-DEV-chain-key-do-not-ship"
DEV_PSEUDONYM_KEY = b"accds-layer6-DEV-pseudonym-key-do-not-ship"


class InsecureKeyError(RuntimeError):
    """Raised when managed keys are required but development defaults are in use."""


def _from_file(name: str) -> Optional[bytes]:
    path = os.environ.get(ENV_KEY_FILE)
    if not path:
        return None
    source = Path(path).expanduser()
    if not source.is_file():
        return None
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    value = data.get(name)
    return str(value).encode("utf-8") if value else None


def _resolve(explicit: Optional[bytes], env_name: str, file_name: str, default: bytes) -> bytes:
    if explicit:
        return explicit
    from_env = os.environ.get(env_name)
    if from_env:
        return from_env.encode("utf-8")
    from_file = _from_file(file_name)
    if from_file:
        return from_file
    return default


@dataclass(frozen=True)
class KeyRing:
    chain_key: bytes
    pseudonym_key: bytes

    def __post_init__(self) -> None:
        if not self.chain_key or not self.pseudonym_key:
            raise ValueError("both chain_key and pseudonym_key must be non-empty")
        if self.chain_key == self.pseudonym_key:
            raise ValueError(
                "chain_key and pseudonym_key must differ: a verifier of the chain "
                "must not thereby be able to reverse pseudonyms"
            )

    @classmethod
    def resolve(
        cls,
        chain_key: Optional[bytes] = None,
        pseudonym_key: Optional[bytes] = None,
    ) -> "KeyRing":
        return cls(
            chain_key=_resolve(chain_key, ENV_CHAIN_KEY, "chain_key", DEV_CHAIN_KEY),
            pseudonym_key=_resolve(pseudonym_key, ENV_PSEUDONYM_KEY, "pseudonym_key", DEV_PSEUDONYM_KEY),
        )

    @classmethod
    def generate(cls) -> "KeyRing":
        return cls(chain_key=secrets.token_bytes(32), pseudonym_key=secrets.token_bytes(32))

    # -- provenance -------------------------------------------------------
    @property
    def uses_dev_chain_key(self) -> bool:
        return self.chain_key == DEV_CHAIN_KEY

    @property
    def uses_dev_pseudonym_key(self) -> bool:
        return self.pseudonym_key == DEV_PSEUDONYM_KEY

    @property
    def is_development(self) -> bool:
        return self.uses_dev_chain_key or self.uses_dev_pseudonym_key

    def require_managed(self) -> None:
        """Fail closed when a deployment still relies on the built-in defaults."""
        if self.is_development:
            raise InsecureKeyError(
                "Layer 6 is using development key material. Set "
                f"{ENV_CHAIN_KEY} and {ENV_PSEUDONYM_KEY} (or {ENV_KEY_FILE}) before "
                "processing anything other than synthetic data."
            )

    def fingerprint(self, which: str = "pseudonym") -> str:
        """A publishable identifier for the key in use, so exports record which key made them.

        This is a salted digest of the key, not the key: it lets a reader tell two
        exports apart without learning the secret.
        """
        key = self.pseudonym_key if which == "pseudonym" else self.chain_key
        return hashlib.sha256(b"accds-key-fingerprint|" + key).hexdigest()[:16]

    def provenance(self) -> Dict[str, object]:
        return {
            "chain_key_fingerprint": self.fingerprint("chain"),
            "pseudonym_key_fingerprint": self.fingerprint("pseudonym"),
            "development_keys_in_use": self.is_development,
        }
