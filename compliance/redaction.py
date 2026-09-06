"""Privacy controls applied before telemetry reaches an operational view.

Two ideas carry the whole module:

1. Pseudonyms are *deterministic* (keyed HMAC), so an analyst can still correlate
   ``asset~9f2c`` across a thousand records without ever learning it was the ICU
   controller. Correlation survives; identity does not.
2. Structured redaction is not enough. Layer 3 writes sentences like
   "...in zone 'Intensive Care Unit' for asset DEV-ICU-MONITOR-01", so every
   surviving string is also scrubbed against the literals seen so far.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_PSEUDONYM_KEY = b"accds-layer6-demo-key-rotate-me"

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")


class FieldAction(str, Enum):
    KEEP = "keep"
    PSEUDONYMIZE = "pseudonymize"
    MASK = "mask"
    DROP = "drop"
    GENERALIZE = "generalize"


@dataclass(frozen=True)
class FieldRule:
    action: FieldAction
    domain: str = "value"
    note: str = ""


def _p(domain: str, note: str = "") -> FieldRule:
    return FieldRule(FieldAction.PSEUDONYMIZE, domain, note)


def _looks_numeric(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


#: Field-level policy keyed by leaf field name, applied at any depth.
#: Anything not listed is kept, which is why the free-text scrubber matters.
DEFAULT_POLICY: Dict[str, FieldRule] = {
    # Identity of machines and people
    "asset_id": _p("asset"),
    "target_asset": _p("asset"),
    "affected_assets": _p("asset"),
    "subject": _p("subject"),
    "src": _p("network"),
    "dst": _p("network"),
    "allowed_peers": _p("network"),
    "peer_address": _p("network"),
    "ip": _p("network"),
    "ip_address": _p("network"),
    "hostname": _p("network"),
    "mac": _p("network"),
    "reviewer": _p("person", "reviewer identity is pseudonymous in operational views"),
    "user": _p("person"),
    "username": _p("person"),
    "operator": _p("person"),
    "analyst": _p("person"),
    # Record identity kept linkable but not guessable
    "event_id": _p("event"),
    "related_events": _p("event"),
    # Direct patient identifiers never reach an operational view
    "patient_id": FieldRule(FieldAction.DROP, note="direct patient identifier"),
    "patient_name": FieldRule(FieldAction.DROP, note="direct patient identifier"),
    "mrn": FieldRule(FieldAction.DROP, note="medical record number"),
    "nhs_number": FieldRule(FieldAction.DROP, note="direct patient identifier"),
    "dob": FieldRule(FieldAction.DROP, note="direct patient identifier"),
    "date_of_birth": FieldRule(FieldAction.DROP, note="direct patient identifier"),
    "payload_body": FieldRule(FieldAction.DROP, note="may contain clinical content"),
    "hl7_message": FieldRule(FieldAction.DROP, note="may contain clinical content"),
    # Forensic-only pointers: the audit_id remains the operational trace handle
    "raw_reference": FieldRule(FieldAction.DROP, note="forensic pointer; trace via audit_id"),
    # Exploitable build detail is coarsened rather than removed
    "software_version": FieldRule(FieldAction.GENERALIZE, note="major version only"),
    # Explicitly retained: these are what make the operational view useful
    "clinical_tier": FieldRule(FieldAction.KEEP),
    "zone": FieldRule(FieldAction.KEEP),
    "owner_zone": FieldRule(FieldAction.KEEP),
    "asset_type": FieldRule(FieldAction.KEEP),
    "anomaly_score": FieldRule(FieldAction.KEEP),
    "risk_score": FieldRule(FieldAction.KEEP),
    "confidence": FieldRule(FieldAction.KEEP),
}


class Pseudonymizer:
    """Keyed, deterministic, non-reversible token generator."""

    def __init__(self, key: bytes = DEFAULT_PSEUDONYM_KEY) -> None:
        if not key:
            raise ValueError("pseudonymization key must not be empty")
        self._key = key

    def token(self, domain: str, value: Any) -> str:
        digest = hmac.new(self._key, f"{domain}:{value}".encode("utf-8"), sha256).hexdigest()
        return f"{domain}~{digest[:12]}"


@dataclass
class RedactionStats:
    kept: int = 0
    pseudonymized: int = 0
    masked: int = 0
    dropped: int = 0
    generalized: int = 0
    text_substitutions: int = 0
    records: int = 0

    @property
    def sensitive_instances(self) -> int:
        return self.pseudonymized + self.masked + self.dropped + self.generalized + self.text_substitutions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "records_redacted": self.records,
            "fields_kept": self.kept,
            "fields_pseudonymized": self.pseudonymized,
            "fields_masked": self.masked,
            "fields_dropped": self.dropped,
            "fields_generalized": self.generalized,
            "free_text_substitutions": self.text_substitutions,
            "sensitive_instances_handled": self.sensitive_instances,
        }


class RedactionEngine:
    """Turns a forensic record into a minimised operational record.

    The engine accumulates a literal -> token map across every record it sees, so
    a value pseudonymized in one record is also scrubbed out of free text in a
    later one.
    """

    def __init__(
        self,
        policy: Optional[Dict[str, FieldRule]] = None,
        key: bytes = DEFAULT_PSEUDONYM_KEY,
    ) -> None:
        self.policy = dict(policy or DEFAULT_POLICY)
        self.pseudonymizer = Pseudonymizer(key)
        self.stats = RedactionStats()
        self._literals: Dict[str, str] = {}

    # -- literal registry -------------------------------------------------
    def register_literal(self, raw: Any, token: str) -> None:
        text = str(raw)
        if len(text) < 3:  # avoid scrubbing trivially short strings out of prose
            return
        if _looks_numeric(text):  # scores and counts are not identifiers
            return
        self._literals[text] = token

    def learn(self, values: Iterable[Any], domain: str = "asset") -> None:
        """Pre-seed the scrubber with known identifiers (e.g. the asset inventory)."""
        for value in values:
            if value:
                self.register_literal(value, self.pseudonymizer.token(domain, value))

    @property
    def known_literals(self) -> Dict[str, str]:
        return dict(self._literals)

    # -- redaction --------------------------------------------------------
    def redact_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Apply field policy, then scrub every surviving string."""
        structured = self._walk(record)
        scrubbed = self._scrub_container(structured)
        self.stats.records += 1
        return scrubbed

    def redact_many(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.redact_record(record) for record in records]

    def _walk(self, node: Any, field_name: str = "") -> Any:
        if isinstance(node, dict):
            result: Dict[str, Any] = {}
            for key, value in node.items():
                rule = self.policy.get(key)
                if rule and rule.action is FieldAction.DROP:
                    self.stats.dropped += 1
                    result[key] = f"[redacted: {rule.note or 'sensitive'}]"
                    continue
                result[key] = self._walk(value, key)
            return result
        if isinstance(node, list):
            return [self._walk(item, field_name) for item in node]
        return self._apply_leaf(field_name, node)

    def _apply_leaf(self, field_name: str, value: Any) -> Any:
        rule = self.policy.get(field_name)
        if rule is None or rule.action is FieldAction.KEEP:
            if rule is not None:
                self.stats.kept += 1
            return value
        if value is None or value == "":
            return value
        if isinstance(value, (bool, int, float)):
            # Identifiers are strings. A numeric leaf under an identifier-shaped
            # field name is a score or a count (Layer 2 emits evidence.components.*),
            # so leave it alone rather than turning a metric into a fake pseudonym.
            self.stats.kept += 1
            return value
        if rule.action is FieldAction.PSEUDONYMIZE:
            token = self.pseudonymizer.token(rule.domain, value)
            self.register_literal(value, token)
            self.stats.pseudonymized += 1
            return token
        if rule.action is FieldAction.MASK:
            self.stats.masked += 1
            return "*" * min(8, len(str(value)))
        if rule.action is FieldAction.GENERALIZE:
            self.stats.generalized += 1
            return self._generalize(value)
        return value

    @staticmethod
    def _generalize(value: Any) -> Any:
        text = str(value)
        if "." in text:
            return text.split(".", 1)[0] + ".x"
        return text

    # -- free-text scrubbing ---------------------------------------------
    def _scrub_container(self, node: Any) -> Any:
        if isinstance(node, dict):
            return {key: self._scrub_container(value) for key, value in node.items()}
        if isinstance(node, list):
            return [self._scrub_container(item) for item in node]
        if isinstance(node, str):
            return self.scrub_text(node)
        return node

    def scrub_text(self, text: str) -> str:
        """Replace known identifiers and identifier-shaped patterns inside prose."""
        result = text
        # Longest first so 'icu-monitor-gw' wins over a shorter overlapping literal.
        for literal in sorted(self._literals, key=len, reverse=True):
            if literal in result and literal != self._literals[literal]:
                result = result.replace(literal, self._literals[literal])
                self.stats.text_substitutions += 1
        for pattern, domain in ((IPV4_PATTERN, "network"), (EMAIL_PATTERN, "person"), (MAC_PATTERN, "network")):
            def _replace(match: "re.Match[str]") -> str:
                self.stats.text_substitutions += 1
                return self.pseudonymizer.token(domain, match.group(0))

            result = pattern.sub(_replace, result)
        return result

    # -- verification ------------------------------------------------------
    def scan_for_leaks(self, rendered: str, extra_terms: Iterable[str] = ()) -> List[str]:
        """Return every raw identifier that still appears in a rendered view."""
        terms = set(self._literals) | {str(term) for term in extra_terms if term}
        return sorted(term for term in terms if term and term in rendered)
