"""The real CRI Profile v2.2 Impact Tiering Questionnaire.

Verified against the actual questionnaire: this is a cascading off-ramp
decision tree, not a scored rubric. Nine questions run in a fixed order
across Tier 1 (1.1, 1.2), Tier 2 (2.1, 2.2.A, 2.2.B, 2.3), and Tier 3 (3.1,
3.2.A, 3.2.B) — the first "Yes" (any checkbox checked, for the
multi-checkbox questions) immediately assigns that tier. Falling through
every question with "No" lands at Tier 4, which has no questions of its
own. Every answer is kept (with its justification) for the audit trail,
regardless of whether it was the one that triggered the tier.
"""

from __future__ import annotations

from dataclasses import dataclass

QUESTION_IDS = ("1.1", "1.2", "2.1", "2.2.A", "2.2.B", "2.3", "3.1", "3.2.A", "3.2.B")

# question_id -> tier assigned if the answer is Yes
_TIER_IF_YES: dict[str, int] = {
    "1.1": 1,
    "1.2": 1,
    "2.1": 2,
    "2.2.A": 2,
    "2.2.B": 2,
    "2.3": 2,
    "3.1": 3,
    "3.2.A": 3,
    "3.2.B": 3,
}


class TieringError(Exception):
    pass


@dataclass(frozen=True)
class QuestionAnswer:
    question_id: str
    answer: bool  # True = "Yes" / at least one checkbox checked
    justification: str = ""


@dataclass(frozen=True)
class TieringResult:
    tier: int
    triggering_question_id: str | None  # None means fell through to Tier 4
    answers: tuple[QuestionAnswer, ...]


def compute_tier(answers: list[QuestionAnswer]) -> TieringResult:
    unknown = [a.question_id for a in answers if a.question_id not in _TIER_IF_YES]
    if unknown:
        raise TieringError(f"unknown question id(s): {unknown!r}; expected one of {QUESTION_IDS!r}")

    by_id = {a.question_id: a for a in answers}
    for question_id in QUESTION_IDS:
        answer = by_id.get(question_id)
        if answer is not None and answer.answer:
            return TieringResult(
                tier=_TIER_IF_YES[question_id],
                triggering_question_id=question_id,
                answers=tuple(answers),
            )

    return TieringResult(tier=4, triggering_question_id=None, answers=tuple(answers))
