# -*- coding: utf-8 -*-
"""Checkov SAST wrapper used as the deterministic analysis stage."""
import json
import os
import re
import tempfile
from concurrent.futures import ProcessPoolExecutor

_SEV_MAP = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "LOW"}


def _scan_one(args):
    fid, code = args
    import warnings

    warnings.filterwarnings("ignore")
    os.environ["CHECKOV_SKIP_UPDATE"] = "true"
    from checkov.runner_filter import RunnerFilter
    from checkov.terraform.runner import Runner

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "main.tf")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)
        try:
            report = Runner().run(
                root_folder=td,
                runner_filter=RunnerFilter(framework=["terraform"]),
            )
        except Exception as e:  # noqa: BLE001
            return fid, {"error": str(e)[:200], "findings": []}
    findings = {}
    for c in report.failed_checks:
        fl = getattr(c, "file_line", None)
        findings[c.check_id] = {
            "check_id": c.check_id,
            "title": (getattr(c, "check_name", "") or "").strip(),
            "resource": getattr(c, "resource", None),
            "severity": _SEV_MAP.get(str(getattr(c, "severity", "") or "").upper(), "MEDIUM"),
            "guideline": getattr(c, "guideline", None),
            "file_line": json.dumps(fl) if fl else None,
        }
    # severity from checkov is often None for terraform; dataset severity is richer,
    # caller may enrich from KB cards.
    out = {"error": None, "findings": findings, "passed": len(report.passed_checks),
           "parse_error": bool(getattr(report, "parsing_errors", []))}
    return fid, out


def scan_batch(files, workers=6):
    """files: dict fid -> code. Returns dict fid -> scan result."""
    results = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for fid, out in ex.map(_scan_one, list(files.items())):
            results[fid] = out
    return results


_HCL_RES = re.compile(r'(resource|data|module|variable|provider)\s+"([a-z0-9_\-]+)"\s+"([^"]+)"', re.I)
_HCL_ATTR = re.compile(r'^\s{2,8}([a-zA-Z_][a-zA-Z0-9_]*)\s*=', re.M)

_ATTR_VOCAB = {
    "versioning", "logging", "acl", "encryption", "encrypt", "kms_master_key_id",
    "sse_algorithm", "public_access_block", "block_public_acls", "ignore_public_acls",
    "block_public_policy", "restrict_public_buckets", "ingress", "egress", "cidr_blocks",
    "from_port", "to_port", "protocol", "ssl", "ssl_enforce", "tls", "min_tls_version",
    "publicly_accessible", "public_network_access", "backup_retention_period", "retention_period",
    "multi_az", "deletion_protection", "audit_logging", "log_analytics", "monitoring",
    "enable_dns_support", "traffic_logging", "flow_log", "access_logging", "bucket_policy",
    "iam", "policy", "assume_role_policy", "admin", "privileged", "root", "password_policy",
    "hardened", "private_cluster", "authorized_networks", "rotate", "rotation", "mfa",
    "delete", "readonly", "readonly_root", "actions", "resources", "effect", "principal",
    "allow", "deny", "trail", "logging_bucket", "log_bucket", "metadata_service",
    "http_tokens", "imds", "server_side_encryption", "customer_master_key", "transparent_data_encryption",
}


def summarize_code(code):
    """Lightweight structural summary of a Terraform file used as the RAG query."""
    blocks = _HCL_RES.findall(code or "")
    resources = sorted({b[1] for b in blocks if b[0] in ("resource", "data")})
    providers = sorted({b[1].split("_")[0] for b in blocks if b[0] in ("resource", "data") and "_" in b[1]})
    attrs = [a.lower() for a in _HCL_ATTR.findall(code or "")]
    security_attrs = sorted({a for a in attrs if a in _ATTR_VOCAB})
    return {
        "n_blocks": len(blocks),
        "resources": resources[:20],
        "providers": providers[:5],
        "security_attributes": security_attrs[:15],
        "all_attrs": sorted(set(attrs))[:30],
    }
