"""ACCDS Layer 6 - Compliance & Privacy.

The secure diary and reporter. Receives records from every other layer, keeps a
tamper-evident chain of custody, applies privacy controls before anything reaches
an operational view, reconstructs incident timelines, and produces evidence
packages and standardized reports.

Safety boundary: this package is record-keeping only. It issues no containment,
enforcement or approval commands, and it performs no network I/O.
"""

from . import emitter  # noqa: F401  (module-level audit sink)
from .access import AccessController, AccessDenied, AccessResult
from .audit_store import ChainedRecord, TamperEvidentAuditStore, compute_hash
from .contracts import (
    AUDIT_CONTRACT_VERSION,
    AccessRole,
    AuditEvent,
    ChainVerification,
    IncidentTimeline,
    Outcome,
    RecordClass,
    TimelineEntry,
    ViewKind,
    new_audit_event,
)
from .datasources import DataSourceNotFound, find_data_dir, findings_file, scenario_file
from .evidence import export_evidence_package, verify_evidence_package
from .keys import InsecureKeyError, KeyRing
from .metrics import audit_completeness, layer6_metrics, leak_scan
from .pipeline import Layer6Result, run_pipeline
from .redaction import FieldAction, FieldRule, Pseudonymizer, RedactionEngine
from .reporting import IncidentReport, build_report, get_adapter, render_markdown
from .retention import RetentionManager, RetentionPolicy
from .signing import (
    Checkpoint,
    HmacSigner,
    MLDSASigner,
    build_signer,
    mldsa_available,
    sign_checkpoint,
    verify_checkpoint,
)
from .timeline import build_timeline, collect_case_records

__all__ = [
    "emitter",
    "Checkpoint",
    "DataSourceNotFound",
    "HmacSigner",
    "InsecureKeyError",
    "KeyRing",
    "MLDSASigner",
    "RetentionManager",
    "RetentionPolicy",
    "build_signer",
    "find_data_dir",
    "findings_file",
    "mldsa_available",
    "scenario_file",
    "sign_checkpoint",
    "verify_checkpoint",
    "AUDIT_CONTRACT_VERSION",
    "AccessController",
    "AccessDenied",
    "AccessResult",
    "AccessRole",
    "AuditEvent",
    "ChainVerification",
    "ChainedRecord",
    "FieldAction",
    "FieldRule",
    "IncidentReport",
    "IncidentTimeline",
    "Layer6Result",
    "Outcome",
    "Pseudonymizer",
    "RecordClass",
    "RedactionEngine",
    "TamperEvidentAuditStore",
    "TimelineEntry",
    "ViewKind",
    "audit_completeness",
    "build_report",
    "build_timeline",
    "collect_case_records",
    "compute_hash",
    "export_evidence_package",
    "get_adapter",
    "layer6_metrics",
    "leak_scan",
    "new_audit_event",
    "render_markdown",
    "run_pipeline",
    "verify_evidence_package",
]
