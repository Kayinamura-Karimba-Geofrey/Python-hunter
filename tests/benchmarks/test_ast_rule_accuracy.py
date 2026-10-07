"""Precision/recall benchmark for the AST security rules.

Each file in tests/fixtures/benchmarks/ast_rules declares its ground truth on the first
line: `# expect: PYH-AST-004` (one or more comma-separated rule IDs) or `# expect: none`.
The whole corpus is scanned once, and every reported finding is classified as a true
positive, false positive, or false negative against those labels.

To track a new false positive or missed detection, add a labelled file to the corpus. If
a rule regresses below the thresholds, the test prints the per-rule table.
"""

import os
from collections import defaultdict
from pathlib import Path

import pytest

from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase

CORPUS = Path(__file__).resolve().parent.parent / "fixtures" / "benchmarks" / "ast_rules"
MIN_PRECISION = 1.0
MIN_RECALL = 1.0


def _expected_labels() -> dict[str, set[str]]:
    labels: dict[str, set[str]] = {}
    for path in sorted(CORPUS.rglob("*.py")):
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        assert first_line.startswith("# expect:"), f"{path} is missing its '# expect:' label"
        value = first_line.split(":", 1)[1].strip()
        labels[path.name] = set() if value == "none" else {v.strip() for v in value.split(",")}
    return labels


@pytest.fixture(scope="module")
def results() -> dict[str, dict[str, int]]:
    expected = _expected_labels()
    findings, _summary, _rule_results = AnalyzeSecurityUseCase().execute(str(CORPUS))

    reported: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.rule_id.startswith("PYH-AST-"):
            reported[os.path.basename(f.file_path)].add(f.rule_id)

    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for filename, want in expected.items():
        got = reported.get(filename, set())
        for rule in got & want:
            stats[rule]["tp"] += 1
        for rule in got - want:
            stats[rule]["fp"] += 1
        for rule in want - got:
            stats[rule]["fn"] += 1
    return dict(stats)


def _table(stats: dict[str, dict[str, int]]) -> str:
    lines = [f"{'rule':<14}{'tp':>4}{'fp':>4}{'fn':>4}{'precision':>11}{'recall':>8}"]
    for rule in sorted(stats):
        s = stats[rule]
        precision = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 1.0
        recall = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 1.0
        lines.append(f"{rule:<14}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}{precision:>11.2f}{recall:>8.2f}")
    return "\n".join(lines)


def test_corpus_covers_every_ast_rule(results: dict[str, dict[str, int]]) -> None:
    labelled = set().union(*_expected_labels().values())
    assert {f"PYH-AST-{n:03d}" for n in range(1, 11)} <= labelled


def test_ast_rule_precision(results: dict[str, dict[str, int]]) -> None:
    tp = sum(s["tp"] for s in results.values())
    fp = sum(s["fp"] for s in results.values())
    precision = tp / (tp + fp) if tp + fp else 1.0
    assert precision >= MIN_PRECISION, "\n" + _table(results)


def test_ast_rule_recall(results: dict[str, dict[str, int]]) -> None:
    tp = sum(s["tp"] for s in results.values())
    fn = sum(s["fn"] for s in results.values())
    recall = tp / (tp + fn) if tp + fn else 1.0
    assert recall >= MIN_RECALL, "\n" + _table(results)
