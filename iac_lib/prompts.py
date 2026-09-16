# -*- coding: utf-8 -*-
"""Prompt builders for the four experimental conditions."""

SYSTEM = (
    "You are a senior cloud security engineer specialised in HashiCorp Terraform and "
    "Infrastructure-as-Code (IaC) security. You audit Terraform files for security "
    "misconfigurations and produce hardened, minimally-invasive fixes."
)

SCHEMA = """Respond with a single JSON object, no markdown fences, matching exactly:
{
  "findings": [
    {
      "check_id": "the Checkov-style check identifier if you know it, else \"UNKNOWN\"",
      "title": "short name of the misconfiguration",
      "resource": "terraform resource address, e.g. aws_s3_bucket.my_bucket",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "explanation": "1-2 sentences: why this is a risk in THIS file"
    }
  ],
  "patched_code": "the complete fixed Terraform file",
  "fix_summary": "1-3 sentences describing what you changed"
}"""

RULES = """Rules:
- Audit ONLY the file given below.
- Report real, code-grounded security misconfigurations (encryption, public exposure, IAM wildcards, logging, backups/versioning, secrets, network exposure, etc.). Do not invent resources that are not in the file.
- If the file has no security misconfiguration, return an empty "findings" list and set "patched_code" to the file unchanged.
- "patched_code" must be the FULL fixed file: apply the minimal change that remediates each reported finding, keep every existing resource, variable, provider and output declaration, and keep Terraform syntax strictly valid.
- Never add placeholder credentials or dummy secrets."""

COND_NOTES = {
    "baseline": "",
    "sast": "",
    "rag": "",
    "hybrid": "",
}


def _fmt_cards(cards):
    lines = ["[Retrieved security knowledge base entries]"]
    for c in cards:
        lines.append(
            f"- {c['check_id']} | severity: {c['severity']} | category: {c['category']}\n"
            f"  title: {c['title']}\n"
            f"  guidance: {c.get('description') or c['title']}"
            + (f" | remediation: {c['remediation_hint']}" if c.get("remediation_hint") else "")
        )
    return "\n".join(lines)


def _fmt_sast(findings):
    lines = ["[Static analysis (Checkov 3.3.17) candidate findings on this file]"]
    for c in findings:
        lines.append(
            f"- {c['check_id']} | {c.get('severity','')} | resource: {c.get('resource')}\n"
            f"  title: {c.get('title')}"
        )
    return "\n".join(lines)


def build_prompt(condition, code, sast_findings=None, cards=None):
    """condition in {baseline, sast, rag, hybrid}."""
    parts = [RULES, SCHEMA]
    if condition in ("sast", "hybrid") and sast_findings:
        parts.append(_fmt_sast(sast_findings))
        parts.append(
            "Treat the static-analysis candidates above as an initial triage list: "
            "for each candidate decide whether it is a true issue for THIS file (report it) "
            "or a false positive for this code (do not report it). You may additionally "
            "report genuine misconfigurations the scanner did not flag."
        )
    if condition in ("rag", "hybrid") and cards:
        parts.append(_fmt_cards(cards))
        parts.append(
            "Use the retrieved knowledge base entries as the applicable security policy "
            "reference: report a finding only for rules that actually apply to the code, "
            "and follow their remediation guidance in your patch."
        )
    parts.append("[Terraform file to audit]\n```hcl\n" + code + "\n```")
    return "\n\n".join(parts)
