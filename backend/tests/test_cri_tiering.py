import pytest

from app.services.cri.tiering import QuestionAnswer, TieringError, compute_tier

ALL_NO = [QuestionAnswer(qid, False, "not applicable") for qid in
          ("1.1", "1.2", "2.1", "2.2.A", "2.2.B", "2.3", "3.1", "3.2.A", "3.2.B")]


def _with_yes(question_id: str) -> list[QuestionAnswer]:
    answers = []
    for a in ALL_NO:
        if a.question_id == question_id:
            answers.append(QuestionAnswer(question_id, True, "G-SIB designation"))
        else:
            answers.append(a)
    return answers


@pytest.mark.parametrize(
    "question_id,expected_tier",
    [
        ("1.1", 1),
        ("1.2", 1),
        ("2.1", 2),
        ("2.2.A", 2),
        ("2.2.B", 2),
        ("2.3", 2),
        ("3.1", 3),
        ("3.2.A", 3),
        ("3.2.B", 3),
    ],
)
def test_yes_on_each_question_triggers_expected_tier(question_id, expected_tier):
    result = compute_tier(_with_yes(question_id))
    assert result.tier == expected_tier
    assert result.triggering_question_id == question_id


def test_all_no_falls_through_to_tier_4():
    result = compute_tier(ALL_NO)
    assert result.tier == 4
    assert result.triggering_question_id is None


def test_no_answers_at_all_falls_through_to_tier_4():
    result = compute_tier([])
    assert result.tier == 4
    assert result.triggering_question_id is None


def test_first_matching_question_in_order_wins_even_if_later_also_yes():
    # 1.1 and 3.1 both Yes: the cascade must stop at 1.1 (Tier 1), never
    # reach 3.1, mirroring the real off-ramp semantics.
    answers = _with_yes("1.1")
    answers = [
        QuestionAnswer("3.1", True, "also true") if a.question_id == "3.1" else a
        for a in answers
    ]
    result = compute_tier(answers)
    assert result.tier == 1
    assert result.triggering_question_id == "1.1"


def test_all_answers_preserved_for_audit_trail_regardless_of_trigger():
    answers = _with_yes("2.1")
    result = compute_tier(answers)
    assert len(result.answers) == 9
    assert all(a.justification for a in result.answers)


def test_unknown_question_id_rejected():
    with pytest.raises(TieringError, match="unknown question id"):
        compute_tier([QuestionAnswer("9.9", True, "bogus")])
