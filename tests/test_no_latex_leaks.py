"""Regression check: no LaTeX commands leaked into Python docstrings.

Twice during the round-15 / round-17 review cycles, a reviewer flagged
LaTeX commands that had been written into Python docstrings: a stray
``\\\\`` escape in ch02 (``e.g.\\\\ a Forbidden response``) and a
``\\\\cite{aws-backoff}`` pair in ch03. Both rendered literally when
the docstring was reproduced into the chapter listing PDF.

This test guards the pattern. It scans every Python file under
``book-2/code/`` for LaTeX commands that should never appear in
companion-code source: commands belong in the ``.tex`` chapter files,
not in the Python that the listings reproduce.

When the test fails:
- Replace ``\\\\cite{key}`` with a plain-English citation
  (``(see Brooker, AWS Architecture Blog)``).
- Replace ``\\\\textbf{x}`` with surrounding context that makes the
  emphasis unnecessary, or use ALL CAPS / Python conventions.
- Replace ``\\\\ref{anchor}`` with a section name and let the chapter
  prose handle the cross-reference.
- Replace ``e.g.\\\\ `` with plain ``e.g. `` (no escape).

The ``.tex`` mirror of the same listing can carry the real LaTeX
commands; the source docstring should not.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CODE_ROOT = Path(__file__).resolve().parent.parent


# Patterns we never want to see in a .py source file. Each entry maps a
# human-readable name to the regex; if the regex matches anywhere in any
# .py file under CODE_ROOT, the test fails and prints the offending lines.
FORBIDDEN_PATTERNS: dict[str, str] = {
    "LaTeX_cite":         r"\\cite\{",
    "LaTeX_textbf":       r"\\textbf\{",
    "LaTeX_textit":       r"\\textit\{",
    "LaTeX_emph":         r"\\emph\{",
    "LaTeX_ref":          r"\\ref\{",
    "LaTeX_label":        r"\\label\{",
    "LaTeX_autoref":      r"\\autoref\{",
    "LaTeX_section":      r"\\section\{",
    "LaTeX_subsection":   r"\\subsection\{",
    "LaTeX_paragraph":    r"\\paragraph\{",
    "LaTeX_chapter":      r"\\chapter\{",
    "LaTeX_texttt":       r"\\texttt\{",
    "LaTeX_textsc":       r"\\textsc\{",
    "LaTeX_begin_env":    r"\\begin\{",
    "LaTeX_end_env":      r"\\end\{",
    "LaTeX_emdash_cmd":   r"\\textemdash\b",
    "LaTeX_endash_cmd":   r"\\textendash\b",
    "LaTeX_ellipsis_cmd": r"\\textellipsis\b",
    "tilde_cite":         r"~\\cite",
    "eg_double_bs":       r"e\.g\.\\\\ ",
    "ie_double_bs":       r"i\.e\.\\\\ ",
}


def _iter_python_files() -> list[Path]:
    """Yield every .py file under CODE_ROOT, excluding caches and this test."""
    self_name = Path(__file__).name
    files: list[Path] = []
    for py_file in CODE_ROOT.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        if py_file.name == self_name:
            # The test file itself contains the patterns as regexes; skip it.
            continue
        files.append(py_file)
    return sorted(files)


def test_no_latex_commands_in_python_sources() -> None:
    """No companion-code .py file should contain LaTeX commands.

    Any leak between rendered listing and source docstring will surface
    in the chapter PDF as literal command text (the round-15 \\\\ escape
    and round-17 \\\\cite leaks were both caught this way).
    """
    files = _iter_python_files()
    assert files, f"expected to find Python files under {CODE_ROOT}"

    compiled = {name: re.compile(pat) for name, pat in FORBIDDEN_PATTERNS.items()}
    failures: list[str] = []

    for py_file in files:
        try:
            text = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            failures.append(f"{py_file}: could not read ({exc!r})")
            continue
        for name, regex in compiled.items():
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    short = py_file.relative_to(CODE_ROOT)
                    failures.append(
                        f"{short}:{lineno} [{name}]  {line.strip()[:120]}"
                    )

    if failures:
        formatted = "\n  ".join(failures[:50])
        more = f"\n  ... and {len(failures) - 50} more" if len(failures) > 50 else ""
        pytest.fail(
            "LaTeX commands found in Python source files.\n"
            "These leak into chapter listings when the listing reproduces the\n"
            "docstring. Replace with plain-English text. Offending lines:\n  "
            + formatted
            + more
        )


def test_forbidden_pattern_inventory_is_well_formed() -> None:
    """Sanity check: every pattern compiles and is documented."""
    for name, pattern in FORBIDDEN_PATTERNS.items():
        assert name.replace("_", "").replace("-", "").isalnum(), (
            f"pattern name must be alphanumeric: {name!r}"
        )
        try:
            re.compile(pattern)
        except re.error as exc:
            pytest.fail(f"pattern {name!r} is not a valid regex: {exc!r}")
