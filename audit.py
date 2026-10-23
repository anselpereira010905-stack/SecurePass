"""
audit.py

Offline bulk password audit: score many passwords at once and find the
problems that matter across a *set* of credentials -- reuse and
near-duplicates ("Summer2023!" / "Summer2024!").

PRIVACY: the report never retains plaintext. Each item keeps only a
masked preview (first/last character) and a line number. Input lives in
memory for the duration of the call and is never written anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from password_checker import analyze_password

MAX_AUDIT_LINES = 5000


@dataclass
class AuditItem:
    line: int
    masked: str
    score: int
    level: str
    entropy_bits: float
    issues: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    items: list[AuditItem] = field(default_factory=list)
    total: int = 0
    weak_count: int = 0
    reused_count: int = 0
    similar_count: int = 0
    average_score: float = 0.0
    grade: str = "—"

    def to_csv_rows(self) -> list[list[str]]:
        rows = [["line", "masked", "score", "level", "entropy_bits", "issues"]]
        for it in self.items:
            rows.append([str(it.line), it.masked, str(it.score), it.level,
                         str(it.entropy_bits), "; ".join(it.issues)])
        return rows


def mask(password: str) -> str:
    if len(password) <= 2:
        return "•" * len(password)
    return f"{password[0]}{'•' * min(len(password) - 2, 12)}{password[-1]}"


def _similarity_key(password: str) -> str:
    """Letters only, lowercased: 'Summer2023!' and 'summer2024' collide."""
    return re.sub(r"[^a-z]", "", password.lower())


def grade_for(avg: float, weak_ratio: float, reuse_ratio: float) -> str:
    adjusted = avg - weak_ratio * 30 - reuse_ratio * 30
    if adjusted >= 80:
        return "A"
    if adjusted >= 65:
        return "B"
    if adjusted >= 50:
        return "C"
    if adjusted >= 35:
        return "D"
    return "F"


def audit_passwords(passwords: Iterable[str]) -> AuditReport:
    cleaned = [p for p in (line.rstrip("\r\n") for line in passwords) if p.strip()]
    cleaned = cleaned[:MAX_AUDIT_LINES]
    report = AuditReport(total=len(cleaned))
    if not cleaned:
        return report

    exact: dict[str, list[int]] = {}
    similar: dict[str, set[str]] = {}
    for i, pw in enumerate(cleaned):
        exact.setdefault(pw, []).append(i)
        key = _similarity_key(pw)
        if len(key) >= 4:
            similar.setdefault(key, set()).add(pw)

    total_score = 0
    for i, pw in enumerate(cleaned):
        analysis = analyze_password(pw)
        issues = list(analysis.warnings)
        if len(exact[pw]) > 1:
            issues.insert(0, f"Reused {len(exact[pw])}x in this list")
            report.reused_count += 1
        elif len(similar.get(_similarity_key(pw), ())) > 1:
            issues.insert(0, "Near-duplicate of another password")
            report.similar_count += 1
        if analysis.score <= 40:
            report.weak_count += 1
        total_score += analysis.score
        report.items.append(AuditItem(
            line=i + 1, masked=mask(pw), score=analysis.score, level=analysis.level,
            entropy_bits=analysis.entropy_bits, issues=issues,
        ))

    report.average_score = round(total_score / len(cleaned), 1)
    report.grade = grade_for(
        report.average_score,
        report.weak_count / report.total,
        (report.reused_count + report.similar_count) / report.total,
    )
    return report
