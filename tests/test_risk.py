import pytest

from core.risk import raw_score, risk_score


def old_score(counts):
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    return min(100, sum(weights[s] * c for s, c in counts.items()))


@pytest.mark.parametrize("counts", [
    {},
    {"info": 40},
    {"low": 3},
    {"medium": 4},
    {"high": 2, "medium": 3, "low": 5},
    {"critical": 5},                      # exactly 50
    {"critical": 3, "high": 2, "low": 6},
])
def test_scores_up_to_50_are_unchanged(counts):
    assert risk_score(counts) == old_score(counts)
    assert raw_score(counts) <= 50


def test_ci_threshold_of_40_still_trips_at_the_same_point():
    # vulnforge.py exits 1 when the worst score is 40 or more.
    assert risk_score({"high": 5, "low": 4}) == 39
    assert risk_score({"high": 5, "low": 5}) == 40


def test_old_cap_no_longer_hides_the_difference_between_bad_and_much_worse():
    assert old_score({"high": 15}) == old_score({"high": 200}) == 100
    scores = [risk_score({"high": n}) for n in (15, 30, 60, 120)]
    assert scores == sorted(scores) and len(set(scores)) == 4
    assert scores[0] < 100


def test_score_is_monotonic_and_capped_at_100():
    previous = -1
    for n in range(0, 400):
        s = risk_score({"critical": n})
        assert previous <= s <= 100
        previous = s
    assert risk_score({"critical": 10_000}) == 100


def test_unknown_severity_counts_as_zero_instead_of_crashing():
    # The old weights[s] lookup raised KeyError for a label it did not know.
    assert risk_score({"high": 1, "unknown": 9}) == 7
    assert risk_score({"HIGH": 1}) == 7
