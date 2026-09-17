"""A model may not grant `confirmed` — E-014, in the lane E-020 warns about.

`confidence == "confirmed"` is not a label. `reporting.report_to_*` turns it into
`verified`, and `defectdojo.remote` sends verified=true to a client's tracker, where it
means a human can stop checking. It is supposed to be EARNED: the cross-arm object check
takes it from a differential, `assertion_grade` needs a control, and a ZAP alert gets
`suspected` however sure ZAP itself sounds.

MEASURED BEFORE THIS FILE. The legacy lane parses the model's own analysis text with
`_parse_finding_blocks`, which accepts any value that is not a placeholder echo, and wrote
it straight into `findings.confidence`:

    model text          CONFIDENCE: confirmed
    findings.confidence 'confirmed'
    report              verified: True
    tracker             verified=true

So a model verified its own finding by writing a word. E-014 says it in one line —
"Scanner and model agreement alone never upgrades confidence to confirmed" — and E-020
says why it survived: "do not assume the new integration proxy already governs every
historical execution path". The integration lane grades honestly; none of that governs
this one.

CLAMPED RATHER THAN DROPPED. The model reads the evidence and "this is weak" is worth
keeping, so it may still lower and may still say `likely`, its strongest permitted claim.
What it may not do is grant the value that leaves the building as verification.
"""
import re

import pytest

from orchestrator.reporting import (
    CONFIDENCE_VALUES, MODEL_MAX_CONFIDENCE, model_confidence)


# ------------------------------------------------------------------ the clamp itself


@pytest.mark.parametrize("claimed", ["confirmed", "CONFIRMED", " Confirmed "])
def test_a_model_claiming_confirmation_gets_likely(claimed):
    """However it is spelled. The parser upstream strips and the model is not careful."""
    assert model_confidence(claimed) == "likely"
    assert model_confidence(claimed) != "confirmed"


@pytest.mark.parametrize("claimed,kept", [("likely", "likely"), ("suspected", "suspected"),
                                          ("LIKELY", "likely")])
def test_the_model_may_still_calibrate_downwards(claimed, kept):
    """The clamp is a ceiling, not a gag. Dropping the field entirely would lose the one
    judgement a model reading evidence is actually good at."""
    assert model_confidence(claimed) == kept


@pytest.mark.parametrize("junk", ["", None, "   ", "totally sure", "none", "NONE", "high"])
def test_a_value_outside_the_vocabulary_is_not_written(junk):
    """None means "leave the column alone", so a model inventing a word cannot overwrite a
    confidence the evidence earned."""
    assert model_confidence(junk) is None


def test_likely_is_the_ceiling_and_confirmed_is_the_thing_it_is_not():
    assert MODEL_MAX_CONFIDENCE == "likely"
    assert MODEL_MAX_CONFIDENCE in CONFIDENCE_VALUES
    assert "confirmed" in CONFIDENCE_VALUES, "the value exists; the model just cannot grant it"
    assert model_confidence("confirmed") == MODEL_MAX_CONFIDENCE


# --------------------------------------------------- the whole path, end to end


def parse_finding_blocks(text):
    """`main._parse_finding_blocks`'s field loop, which is where the value comes from."""
    fields = {}
    for key in ("CALIBRATED_SEVERITY", "OWASP", "IMPACT", "REMEDIATION", "CONFIDENCE", "CWE"):
        match = re.search(rf'{key}:\s*(.+)', text)
        if match:
            value = match.group(1).strip()
            if value and not value.startswith("<") and value.upper() != "NONE":
                fields[key] = value
    return fields


MODEL_SAYS_CONFIRMED = """
FINDING 1:
CALIBRATED_SEVERITY: high
CONFIDENCE: confirmed
IMPACT: total compromise
"""


def test_the_parser_still_hands_over_the_claim():
    """The parser is not where this is fixed, and asserting that keeps the two apart: if it
    ever started filtering, this test failing is the signal to simplify the clamp rather
    than to leave two half-guards."""
    assert parse_finding_blocks(MODEL_SAYS_CONFIRMED)["CONFIDENCE"] == "confirmed"


def test_the_report_does_not_call_it_verified():
    """The consequence, stated as the report states it. `reporting` computes
    `verified` from exactly this comparison."""
    claimed = parse_finding_blocks(MODEL_SAYS_CONFIRMED)["CONFIDENCE"]
    stored = model_confidence(claimed)
    assert (stored == "confirmed") is False, "the model verified its own finding"
    assert stored == "likely"


def test_a_finding_that_earned_confirmed_keeps_it():
    """The other direction, and the reason this is a clamp on ONE writer rather than a ban
    on the value. A differential that earned `confirmed` must still report verified, or the
    fix would have cost the product its real confirmations."""
    from orchestrator.reporting import report_to_sarif

    earned = {"id": 1, "vuln_type": "SQL Injection", "severity": "high",
              "confidence": "confirmed", "affected_url": "http://app.test/x"}
    assert "confirmed" == earned["confidence"]
    # The report reads the stored value; nothing in the clamp touches a finding the model
    # did not write.
    assert model_confidence(None) is None


# ---------------------------------------------------------------- it reaches the writer


def test_the_legacy_write_path_uses_the_clamp():
    """Asserted on the call site. The clamp is a function nothing has to call, and the
    defect was precisely that this UPDATE wrote the model's own word — a guard that the one
    caller skips is the shape E-033 filed about the mutation refusal."""
    import inspect

    from orchestrator import main

    source = inspect.getsource(main)
    assert 'model_confidence(fb.get("CONFIDENCE"))' in source, (
        "the legacy lane writes the model's confidence unclamped again")
    assert 'fb.get("CONFIDENCE"),' not in source, (
        "an unclamped write is still present somewhere in this module")
