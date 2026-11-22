# -*- coding: utf-8 -*-
"""Deterministic patch validation helpers, shared by the playground and the CI gate.

Two guards beyond the re-scan:
- resource preservation is computed from the python-hcl2 parse tree, so a
  resource that is commented out in the patch no longer counts as preserved;
- patches that introduce scanner suppression comments (Checkov/Trivy) are
  rejected before the re-scan, so a fix cannot "clear" a check by muting it.
"""
import re

SUPPRESSION = re.compile(r"checkov:skip|trivy:ignore", re.I)


def has_suppression(patch):
    """True when the patch text contains a scanner suppression comment."""
    return bool(SUPPRESSION.search(patch or ""))


def resource_addresses(code):
    """(type, name) pairs of every resource block, read from the hcl2 parse tree.

    Commented-out declarations never appear in the parse tree, so they are
    neither required nor credited. Falls back to an empty set when the text
    does not parse (the caller's parse check reports that separately).
    """
    try:
        import hcl2
        doc = hcl2.loads(code or "")
    except Exception:
        return set()
    out = set()
    resources = doc.get("resource") if isinstance(doc, dict) else None
    if resources is None and isinstance(doc, list):
        for d in doc:
            if isinstance(d, dict) and "resource" in d:
                resources = d["resource"]
                break
    for blk in resources or []:
        if isinstance(blk, dict):
            for rtype, bodies in blk.items():
                if isinstance(bodies, dict):
                    for rname in bodies:
                        out.add((rtype, rname))
                elif isinstance(bodies, list):
                    for body in bodies:
                        if isinstance(body, dict):
                            for rname in body:
                                out.add((rtype, rname))
    return out


def resources_preserved(original_code, patch_code):
    """Every resource declared in the original must survive in the patch."""
    return resource_addresses(original_code).issubset(resource_addresses(patch_code))
