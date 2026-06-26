"""Compatibility wrapper for shared node-level GT helpers."""

from range.node_gt import (
    GT_SOURCE,
    GT_VERSION,
    SIGNATURE_VERSION,
    TRACE_MODE,
    build_attack_gt_signature,
    collect_signature_window_gt_from_sql,
    load_signature_sets,
    normalize_signature_text,
    write_attack_gt_signature,
)

__all__ = [
    "GT_SOURCE",
    "GT_VERSION",
    "SIGNATURE_VERSION",
    "TRACE_MODE",
    "build_attack_gt_signature",
    "collect_signature_window_gt_from_sql",
    "load_signature_sets",
    "normalize_signature_text",
    "write_attack_gt_signature",
]
