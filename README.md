# algovoi-ube

An independent, Apache-2.0 conformance harness for [NTI-1](https://github.com/abisheakp197/nti-spec),
the Neutral Trust Infrastructure standard, plus a working coverage map showing
how much of NTI-1 the [AlgoVoi Keystone](https://docs.algovoi.co.uk/keystone)
answers and what is genuinely left over.

Apache-2.0 for a reason. NTI-1's own reference implementation,
`ube-foundation`, is published under PolyForm Shield, which is source available
but not an open licence. This harness therefore talks to a target over HTTP or
imports it when present, and never vendors its code. You can check a
proprietary implementation against an open test suite, which is the point of a
standard.

## What it does

Four things, all of them checkable:

1. **Recomputes an audit chain.** NTI-1 Pillar 4 requires a SHA-256 chained
   trail where tampering with any past event breaks verification. This
   recomputes every hash and every parent link from the raw event data.
2. **Runs the five testable requirements**, T-1.1 through T-5.1, each quoting
   the clause it comes from. A failure points at the document, not an opinion.
3. **Implements the fail-closed rule** from section 6.1, including the
   `incomplete_check` receipt with its three legal reasons, and the LGD state
   machine with only legal transitions allowed.
4. **States the Keystone coverage honestly**, pillar by pillar, rather than
   claiming the whole standard.

## Install and run

```bash
pip install -e ".[test]"
algovoi-ube selftest      # prove the harness itself is correct
algovoi-ube keystone      # what Keystone covers, and what it does not
algovoi-ube verify chain.json
algovoi-ube target https://host   # probe a live implementation's /decide
```

Or without installing:

```bash
python conformance/run.py --self-test
```

No runtime dependencies. The harness is stdlib only, so it runs anywhere Python
3.10 or newer does.

## The one finding worth knowing first

Both audit schemes are real and both recompute. The difference is what they
prove.

The NTI-1 conformance example chains
`sha256(":".join([event_id, agent_id, request_hash, decision, reason, timestamp, parent_hash]))`.
Every stored hash recomputes exactly under that formula, and the published
example is included in `vectors/` so this is demonstrated rather than asserted.

One weakness in the published example: event 1's `request_hash` is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, which is
the SHA-256 of the empty string. No action was ever hashed, so the record does
not say what was evaluated. The harness hashes the canonical form of the actual
request instead, and there is a test for that difference.

## Keystone coverage against NTI-1

Three of seven requirements are fully answered, two partly, two not at all.
This is measured by running `algovoi-ube keystone`, not estimated.

| NTI-1 | Requirement | Keystone | Coverage |
| 3.1 | Principal-bound identity | `passport_ref` | full |
| 3.2 | Policy evaluation, capability caveats | `mandate_ref`, `policy_bound_ref` | full |
| 3.3 | BFT consensus for high-value actions | none | none |
| 3.4 | Tamper-evident audit trail | `decision_ref`, `execution_ref` | full |
| 3.5 | Persistence and export | chain plus `trust_query_ref` | partial |
| 6.1 | Fail-closed on unreachable registry | none | partial |
| 7 | ASL sandbox over AF_UNIX | none | none |

The honest summary: Keystone is a stronger *evidence* chain than NTI-1 asks for,
because each reference hashes the one before it and the decision is a
load-bearing field of the execution, so an execution cannot be claimed by a
different decision. It is weaker at the one thing NTI-1 makes a MUST for
high-value actions, which is multi-agent consensus. Those are different
problems and neither chain is a superset of the other.

## The question the thread left open

Alan Karp asked when a delegation's status should be judged: at grant time, at
invocation, or at completion. `boundary.py` does not pretend to settle it. It
makes the choice explicit, records it on every receipt, and shows what each
choice costs.

- `INVOCATION` keeps atomic execution and does not interrupt, leaving a window
  open until the action finishes.
- `EFFECT` rechecks at the point of irreversible effect and halts mid execution.
  Tighter, but it can abandon an action half done.
- `COMPLETION` judges at the end. The widest window, and the least protection.

A mid-execution halt is only expressible under `EFFECT`. That is the whole
trade, and a standard that does not name its boundary cannot be compared
against another implementation of itself.

## Licence

Apache-2.0. The NTI-1 specification text is CC BY 4.0 and is not reproduced
here; only small quoted fragments for clause references.
