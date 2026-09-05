"""Applications with PLANTED flaws, and controls that have the same shape and
none of the flaw.

Every case defect found on 2026-09-05 -- ATHN-01 flagging correct http->https
redirects as HIGH, BUSL-04 reporting a race test that fired zero requests,
CONF-07 probing HSTS on a different port than it scanned, SESS-02 unable to
reach a verdict without a model, three steps that had never executed -- came
from running the real cases against targets like these. None came from reading
the YAML.

The harness lived in a scratchpad and died with the container, so the same
defects could come back unnoticed. It is committed now and runs in CI.

TWO RULES, and the second is what makes this worth having:

  1. A target PLANTS a flaw in the plainest form an application exhibits it.
     If a case finds nothing here, the case has a gap -- not the target.

  2. Every target has a CONTROL with the same routes and the flaw fixed. A
     case that fires on both is worse than one that fires on neither: it
     teaches an operator to ignore it. Half the defects found were of exactly
     that shape.

Loopback only, ephemeral ports, no external network, no container.
"""
