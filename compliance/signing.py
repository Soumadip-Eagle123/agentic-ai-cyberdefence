"""Checkpoint signing for the audit chain.

The HMAC chain already binds every record to its predecessor, so one signature
over the chain head certifies everything beneath it. Layer 6 therefore signs
*checkpoints* (per case, and per evidence-package export) rather than every
record: non-repudiation at roughly one signature per incident.

Two signers ship:

* ``HmacSigner`` - stdlib only, the default. Proves *someone with the key* wrote
  the chain. Symmetric, so it gives integrity but not non-repudiation.
* ``MLDSASigner`` - FIPS 204 (ML-DSA), via ``cryptography`` when installed.
  Asymmetric and post-quantum, so a third party holding only the public key can
  verify, and the signature stays unforgeable across the multi-decade retention
  window that clinical records carry.

ML-DSA is optional on purpose: Layer 6 must keep running with no third-party
dependency, so the import is attempted lazily and failure is reported rather than raised.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Optional

MLDSA_PARAMETER_SETS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DEFAULT_MLDSA_SET = "ML-DSA-65"


def mldsa_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    except Exception:
        return False
    return True


class Signer:
    """Interface for anything that can certify a chain checkpoint."""

    algorithm = "none"
    asymmetric = False

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, signature: bytes, message: bytes) -> bool:
        raise NotImplementedError

    def public_key_hex(self) -> Optional[str]:
        return None


class HmacSigner(Signer):
    """Default signer. Integrity only; anyone who can verify can also forge."""

    algorithm = "HMAC-SHA256"
    asymmetric = False

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("HmacSigner requires a key")
        self._key = key

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._key, message, sha256).digest()

    def verify(self, signature: bytes, message: bytes) -> bool:
        return hmac.compare_digest(signature, self.sign(message))


class MLDSASigner(Signer):
    """FIPS 204 ML-DSA. Asymmetric, post-quantum, third-party verifiable."""

    asymmetric = True

    def __init__(self, parameter_set: str = DEFAULT_MLDSA_SET, private_key: Any = None) -> None:
        if parameter_set not in MLDSA_PARAMETER_SETS:
            raise ValueError(f"parameter_set must be one of {MLDSA_PARAMETER_SETS}")
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
        except Exception as error:  # pragma: no cover - depends on the environment
            raise RuntimeError(
                "ML-DSA signing needs the 'cryptography' package (>=46) built against "
                "OpenSSL 3.5+. Install it, or use HmacSigner."
            ) from error

        self.algorithm = parameter_set
        generators = {
            "ML-DSA-44": mldsa.MLDSA44PrivateKey,
            "ML-DSA-65": mldsa.MLDSA65PrivateKey,
            "ML-DSA-87": mldsa.MLDSA87PrivateKey,
        }
        self._private_key = private_key or generators[parameter_set].generate()
        self._public_key = self._private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
        except Exception:
            return False
        return True

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw.hex()

    def private_key_pem(self) -> bytes:
        """For persisting a signing key. Protect this like any private key."""
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


@dataclass(frozen=True)
class Checkpoint:
    """A signed commitment to the chain state at a moment in time."""

    case_id: Optional[str]
    sequence_count: int
    head_hash: str
    algorithm: str
    signature_hex: str
    public_key_hex: Optional[str]
    signed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "sequence_count": self.sequence_count,
            "head_hash": self.head_hash,
            "algorithm": self.algorithm,
            "signature": self.signature_hex,
            "public_key": self.public_key_hex,
            "signed_at": self.signed_at,
            "third_party_verifiable": self.public_key_hex is not None,
        }


def checkpoint_message(head_hash: str, sequence_count: int, case_id: Optional[str]) -> bytes:
    """Domain-separated, canonical bytes so a signature cannot be replayed elsewhere."""
    return json.dumps(
        {
            "domain": "accds-layer6-checkpoint-v1",
            "head_hash": head_hash,
            "sequence_count": sequence_count,
            "case_id": case_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_checkpoint(
    signer: Signer,
    head_hash: str,
    sequence_count: int,
    case_id: Optional[str] = None,
) -> Checkpoint:
    message = checkpoint_message(head_hash, sequence_count, case_id)
    return Checkpoint(
        case_id=case_id,
        sequence_count=sequence_count,
        head_hash=head_hash,
        algorithm=signer.algorithm,
        signature_hex=signer.sign(message).hex(),
        public_key_hex=signer.public_key_hex(),
        signed_at=datetime.now(timezone.utc).isoformat(),
    )


def verify_checkpoint(checkpoint: Dict[str, Any], signer: Optional[Signer] = None) -> Dict[str, Any]:
    """Verify a checkpoint.

    An ML-DSA checkpoint verifies from its own embedded public key, with no
    signer and no shared secret - which is the entire point of using it.
    An HMAC checkpoint needs the original signer.
    """
    message = checkpoint_message(
        checkpoint["head_hash"], checkpoint["sequence_count"], checkpoint.get("case_id")
    )
    algorithm = checkpoint.get("algorithm", "")
    signature = bytes.fromhex(checkpoint["signature"])

    if algorithm in MLDSA_PARAMETER_SETS:
        public_hex = checkpoint.get("public_key")
        if not public_hex:
            return {"ok": False, "status": "rejected",
                    "reason": "ML-DSA checkpoint carries no public key"}
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
        except Exception:
            return {"ok": None, "status": "unverifiable",
                    "reason": "'cryptography' is not installed; cannot verify ML-DSA"}
        loaders = {
            "ML-DSA-44": mldsa.MLDSA44PublicKey,
            "ML-DSA-65": mldsa.MLDSA65PublicKey,
            "ML-DSA-87": mldsa.MLDSA87PublicKey,
        }
        try:
            loaders[algorithm].from_public_bytes(bytes.fromhex(public_hex)).verify(signature, message)
        except Exception as error:
            return {"ok": False, "status": "rejected", "algorithm": algorithm,
                    "reason": f"signature rejected: {type(error).__name__}"}
        return {"ok": True, "status": "valid", "algorithm": algorithm,
                "reason": "signature valid", "third_party_verifiable": True}

    if signer is None:
        # Symmetric: absence of the key means we cannot judge it either way.
        # That is not evidence of forgery, so it must not fail the package.
        return {
            "ok": None,
            "status": "unverifiable",
            "algorithm": algorithm,
            "reason": f"{algorithm} is symmetric; the original signer is needed to verify it",
            "third_party_verifiable": False,
        }
    ok = signer.verify(signature, message)
    return {
        "ok": ok,
        "status": "valid" if ok else "rejected",
        "algorithm": algorithm,
        "reason": "signature valid" if ok else "signature rejected",
        "third_party_verifiable": False,
    }


def build_signer(kind: str = "hmac", key: Optional[bytes] = None,
                 parameter_set: str = DEFAULT_MLDSA_SET) -> Signer:
    if kind == "hmac":
        return HmacSigner(key or b"accds-layer6-checkpoint")
    if kind in ("mldsa", "ml-dsa", "fips204"):
        return MLDSASigner(parameter_set)
    raise ValueError(f"unknown signer '{kind}'. Use 'hmac' or 'mldsa'.")
