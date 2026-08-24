"""The incident range itself. Spec section 9.

These test the *exam*, not the agent. A range that quietly loses a class, or whose classes all
turn out to be the same shape underneath, would let the system pass while testing nothing --
which section 10.1 names as the largest single risk in the project.
"""
from __future__ import annotations

import yaml

import config as cfg
from eval.suite import all_incidents, load_split

REQUIRED_CLASSES = set("ABCDEFGHIJKL")


def _truths():
    out = {}
    for name in all_incidents():
        p = cfg.INCIDENTS_DIR / name / "truth.yaml"
        out[name] = yaml.safe_load(p.read_text(encoding="utf-8"))
    return out


def test_every_class_in_the_catalogue_is_represented():
    """Spec 9 defines twelve classes. A missing class is a blind spot, not a gap in coverage."""
    covered = {str(t.get("class", "?")) for t in _truths().values()}
    missing = REQUIRED_CLASSES - covered
    assert not missing, "classes with no incident: {}".format(sorted(missing))


def test_every_incident_declares_what_it_must_not_stop_at():
    """Depth compliance is the gate that matters most, and it needs something to check."""
    for name, t in _truths().items():
        if t.get("expect_no_fault"):
            continue
        assert t.get("must_not_stop_at"), "{} declares no forbidden terminals".format(name)


def test_every_incident_has_a_cause_or_declares_it_has_none():
    for name, t in _truths().items():
        has_causes = bool(t.get("causes"))
        expects_none = bool(t.get("expect_no_fault"))
        assert has_causes or expects_none, \
            "{} names no cause and does not declare itself a null incident".format(name)


def test_non_repository_causes_declare_their_source():
    """A cause with no repo needs a source, or the grader cannot tell a flag flip from a
    package upgrade -- both would match on an empty repo alone."""
    for name, t in _truths().items():
        for c in t.get("causes") or []:
            if not c.get("repo"):
                assert c.get("source"), \
                    "{}: non-repository cause with no source: {}".format(name, c)


def test_the_range_is_not_all_one_shape():
    """Twelve incidents that are all a config rename would pass the range while testing one
    thing. Causes must span multiple change sources and multiple repositories."""
    sources, repos = set(), set()
    for t in _truths().values():
        for c in t.get("causes") or []:
            sources.add(c.get("source") or "git")
            if c.get("repo"):
                repos.add(c["repo"])
    assert len(sources) >= 4, "causes come from only {}".format(sources)
    assert len(repos) >= 3, "causes touch only {}".format(repos)


def test_the_holdout_split_is_about_thirty_percent():
    """Spec 10.1: thirty percent held out."""
    split = load_split()
    n_hold, n_dev = len(split["holdout"]), len(split["development"])
    frac = n_hold / (n_hold + n_dev)
    assert 0.2 <= frac <= 0.4, "holdout is {:.0%} of the range".format(frac)


def test_the_holdout_split_covers_every_incident_exactly_once():
    split = load_split()
    listed = split["holdout"] + split["development"]
    assert len(listed) == len(set(listed)), "an incident appears in both sets"
    assert set(listed) == set(all_incidents()), \
        "split and incident directory disagree: {}".format(
            set(listed) ^ set(all_incidents()))


def test_the_holdout_file_states_that_it_is_not_yet_a_real_control():
    """The split is bookkeeping until someone who has not read agent/ authors an incident.

    This test exists so that the caveat cannot be quietly deleted while the numbers stay.
    """
    text = (cfg.ROOT / "eval" / "holdout.yaml").read_text(encoding="utf-8").lower()
    assert "authored and debugged" in text
    assert "bookkeeping rather than a control" in text
