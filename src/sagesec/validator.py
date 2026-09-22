"""Check LLM output against the facts the pipeline actually retrieved.

The LLM is only ever given CVEs that the matcher found in the vulnerability
database. So any CVE ID that appears in its answer but was NOT in that input
set is, by definition, fabricated. We can detect that mechanically -- no human
grader needed -- and log the rate across every explanation generated.

This is the project's first measurable hallucination metric.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# CVE IDs are CVE-YYYY-NNNN with 4 or more digits in the sequence number.
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> set[str]:
    return {m.upper() for m in CVE_PATTERN.findall(text)}


@dataclass
class ValidationReport:
    mentioned: set[str] = field(default_factory=set)
    grounded: set[str] = field(default_factory=set)
    fabricated: set[str] = field(default_factory=set)

    @property
    def passed(self) -> bool:
        return not self.fabricated


def validate_cve_mentions(llm_output: str, retrieved_cve_ids: set[str]) -> ValidationReport:
    """Compare CVE IDs in the LLM's answer with the ones we gave it.

    If this fails, the explanation should be rejected or regenerated,
    never shown to the user as-is.
    """
    allowed = {c.upper() for c in retrieved_cve_ids}
    mentioned = extract_cve_ids(llm_output)
    return ValidationReport(
        mentioned=mentioned,
        grounded=mentioned & allowed,
        fabricated=mentioned - allowed,
    )
