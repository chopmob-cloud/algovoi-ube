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

Seven things, all of them checkable:

1. **Recomputes an audit chain.** NTI-1 Pillar 4 requires a SHA-256 chained
   trail where tampering with any past event breaks verification. This
   recomputes every hash and every parent link from the raw event data.
2. **Runs the testable requirements**, T-1.1 through T-5.1 plus the resume,
   VOC, signature and registry checks added here, each quoting the clause it
   comes from. A failure points at the document, not an opinion.
3. **Implements the fail-closed rule** from section 6.1, including the
   `incomplete_check` receipt with its three legal reasons, and the LGD state
   machine with only legal transitions allowed.
4. **Signs with the mandated scheme.** CRYSTALS-Dilithium5 as ML-DSA-87, in a
   separate Rust process, so the key never enters the process that assembles the
   receipt.
5. **Implements the revocation registry** as a Merkle accumulator whose root
   changes on revocation, so a token proved against an old root is refused at the
   boundary.
6. **Implements Voluntary Oblivious Compliance**: STRICT fails closed, VOC pauses
   and requires a signed exemption, and the grader acts only under a mandate
   issued by someone else.
7. **States the Keystone coverage honestly**, pillar by pillar, rather than
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

No Python runtime dependencies. The harness is stdlib only, so it runs anywhere
Python 3.10 or newer does.

The signature scheme is the exception, and it is deliberately not a Python
package. NTI-1 mandates CRYSTALS-Dilithium5, and the AIW paper requires the key to
live outside the agent's context, so `rust/nti-signer` is a separate binary that
holds the key and signs over a pipe:

```bash
./scripts/build_signer.sh          # builds rust/nti-signer
export NTI_SIGNER_BIN=...          # or let find_core locate it
```

The build needs Rust 1.85 or newer, because the ML-DSA crate pulls dependencies
that use the 2024 edition. `build_signer.sh` checks the version first and tells you
so rather than letting the failure surface from inside a dependency, and it gives
the container command for an older toolchain.

When that binary is absent every signing path raises. There is no fallback to a
weaker signer, because a silent downgrade of the signature is a silent downgrade
of the whole claim.

## The evidence

**Every claim in this repository is generated, not written.** `evidence/EVIDENCE.md`
is produced by `python evidence/collect.py`, and each finding records the SHA-256
of the exact input it was computed from, so a claim is tied to a snapshot rather
than to a moment. `evidence/evidence.json` holds the same findings in machine
readable form. Re-run the collector and either the same verdicts come out or the
claim was wrong.

Eighteen findings, all currently confirmed:

| ID | Finding | Verdict |
| F1 | The published NTI-1 conformance chain recomputes exactly under its documented formula | confirmed |
| F2 | Neither published `request_hash` is the hash of an action, so the record does not say what was evaluated | confirmed |
| F3 | Editing any single field of a past event breaks chain verification | confirmed |
| F4 | `ube-foundation` is PolyForm Shield, so it cannot be vendored into an Apache-2.0 harness | confirmed |
| F5 | Keystone fully answers 3 of 7 NTI-1 requirements, partly 2, not at all 2 | confirmed |
| F6 | An `incomplete_check` cannot be built with an unclassified reason | confirmed |
| F7 | The `REVERIFY` to `RESUMED` edge is declared and withdrawable without a terminal state | confirmed |
| F8 | A valid signature alone does not reach RESUMED; a complete basis is required, on the lifecycle path too | confirmed |
| F9 | An exemption covers a policy violation and cannot cover a revocation or an unknown | confirmed |
| F10 | The wire value does not depend on the receipt being present | confirmed |
| F11 | STRICT denies a violation and VOC pauses, and a revocation halts under both | confirmed |
| F12 | A receipt exempting a revocation cannot be expressed in the schema, the constructor or the grader | confirmed |
| F13 | A receipt edited after signing does not resume the action | confirmed |
| F14 | The canonicaliser matches RFC 8785 on numbers, UTF-16 key order and non-ASCII | confirmed |
| F15 | Signatures use ML-DSA-87 in an isolated process, and the key never crosses the boundary | confirmed |
| F16 | A proof built against a superseded registry root is refused, while the historical root still verifies | confirmed |
| F17 | The declared boundary lets the atomic call finish and refuses the next one, as NTI requires | confirmed |
| F18 | A grader cannot issue its own mandate, signs nothing without one, and its bounds are enforced at signing | confirmed |

The collector refutes its own claims when they do not hold. F2 was originally
written one way, the collector refuted it, and the claim was tightened to what
the data actually shows. That is the point of generating evidence rather than
asserting it.

## What this repository does not claim

It does not say NTI-1 is unsound. F1 shows their hashes are correct and their
chain is sound, and F3 shows the tamper detection works. The list above is not a
verdict on the design; it is the set of gaps that stop an implementer from
checking their work against it, which is a different and more useful criticism.
F5 is the honest measure of what Keystone can and cannot fulfil, including the one
MUST it does not answer.

## What NTI needs to resolve

This harness found gaps in the standard's own material that stop an implementer
from checking their work against it. They are listed here rather than left in the
evidence table, because a finding buried in a table does not reach the people who
can act on it.

Their transition contract already tracks seven open items, OPEN-1 to OPEN-7, which
is to their credit and makes the useful distinction possible: four of the gaps
below are not on that list at all. Those are the ones worth raising, recorded here
as discrete issues so each can be tracked and closed rather than read past.

**NTI-ISSUE-1 — the published `request_hash` is not the hash of an action.** F2, and
not on their open list. In the published conformance chain, event 1's `request_hash`
is exactly the SHA-256 of the empty string, and event 2's is a rearrangement of those
same bytes. The chain verifies, and it does not say what was evaluated; an audit
record that verifies while recording nothing is worse than no record.
*To address:* regenerate the example so each `request_hash` is the hash of the actual
request payload, before the example is copied into implementations.

**NTI-ISSUE-2 — no canonicalisation scheme is named.** Not on their open list, and
absent from both NTI-1 and the contract. A signature needs deterministic bytes, and
nothing says how a receipt is serialised, so two compliant implementations produce
different bytes for the same receipt and neither verifies the other's.
*To address:* name a canonicalisation scheme normatively; RFC 8785 is recommended as
the only such scheme with published test vectors, implemented and tested here in
`canonical.py` (F14). A one-line normative fix with a large interoperability effect.

**NTI-ISSUE-3 — no signature, receipt or negative vectors are published.** Not on
their open list. The `conformance` directory holds an audit log, a README and a
validator. There is no ML-DSA test vector, no example receipt and no negative vector,
so an implementer cannot check their signer or their receipt against anything, and
every suite ends up testing its author's reading of the standard rather than the
standard.
*To address:* publish a known-answer ML-DSA-87 signature vector, at least one valid
example receipt with its canonical bytes and signature, and negative vectors that MUST
be rejected — a tampered receipt, a wrong canonicalisation and an expired capability.

**NTI-ISSUE-4 — the automated grader has no authority model.** Not on their open list.
Issue 21 asks for a grader holding authority to accept risk, and does not say who
issues that authority, for which policies, up to what value, until when, or how it is
withdrawn. Left undefined, every implementation invents its own and no two are
comparable.
*To address:* specify a bounded, signed, revocable mandate — issuer (which MUST differ
from the grader), policy scope, principal scope, value ceiling, expiry, exemption
count, and a revocation check at signing time. `mandate.py` closes the gap here (F18)
as a proposal, not as a reading of the text.

**Section 6 has no tests.** The five testable requirements are T-1.1 to T-5.1, and
they cover identity, governance, consensus, audit and persistence. The entire halt
and revocation machine, including the fail-closed rule in 6.1, sits in section 6 and
appears in none of them, so an implementation can pass every published test while its
resume path does nothing. Their OPEN-1 records that section 1.1 is untestable for a
related reason, so the shape of the problem is already known; the five published
tests are where it bites.

**`resume_basis` is proposed, not agreed.** Their own v0.1.4 marks the field and its
two exemption boundaries as proposed, with no fingerprint. The boundaries are the load
bearing part: an exemption must not cover `authority_revoked`, because revocation is
the issuing authority's decision, and must not cover `authority_not_determined`,
because a signature cannot convert "we do not know" into "we know". Until it is
settled, an accepted risk and a restored condition produce identical records.

**The reference implementation cannot be checked by an open suite.** F4. `ube-foundation`
is PolyForm Shield, source available but not open, so an Apache-2.0 harness cannot
vendor or link it. Their LGD-MedAI demo is Apache-2.0 and runnable in one command,
which is genuinely useful, but it demonstrates the state machine rather than the
sidecar boundary, so there is still no runnable NTI target to probe. Either relicense
the reference or publish a runnable sidecar, otherwise the standard's own example sits
outside the reach of its own test suite.

**The signing key has no lifecycle.** Already logged as OPEN-5, so this is their own
finding rather than ours, and it is unowned and unscheduled. It matters more than its
one-line entry suggests: the whole architecture rests on the agent never holding the
key, and a compromise of that one key invalidates every receipt at once. Their OPEN-3
has the same shape for timestamps, where the replay claim depends on a source nobody
has picked yet.

One correction we owe them in return. The contract is careful to record that
Dilithium5 equals ML-DSA-87 as an inference from the round-3 parameter sets, since
FIPS 204 does not use the Dilithium names. This repository says ML-DSA-87 throughout
and the measured sizes are the FIPS 204 ones, but the equivalence is an inference
rather than a quotation, and it is recorded here as such rather than stated as fact.

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

A question raised on the thread and still open: when should a delegation's
status be judged, at grant time, at invocation, or at completion? `boundary.py` does not pretend to settle it. It
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

## The resume basis, and the edge that was missing

The thread's live question is what a resume should rest on. Signature verification
is an authenticity check: it says who signed, not whether the condition that
caused the halt still holds. If a valid signature is sufficient for RESUMED, then
a run where the condition was verified restored and a run where someone accepted
the risk produce identical records, and an auditor cannot tell them apart.

`resume.py` implements the proposed answer: a resume carries a basis drawn from a
closed set, `evidence` or `exemption`, with two boundaries that are the load
bearing part.

An exemption does not cover `authority_revoked`, because revocation is the issuing
authority's decision and a manager on the executing side cannot un-revoke someone
else's authority. An exemption does not cover `authority_not_determined`, because
that is an absence of information and a signature cannot convert "we do not know"
into "we know".

Building this exposed a defect in our own state machine, which is finding F7. The
`REVERIFY` to `RESUMED` transition was not declared in the transition table at
all; `resume()` reached RESUMED by assigning the attribute directly, bypassing the
table. So the one edge a governing regime needs to withdraw was the one edge the
machine did not model, while the harness claimed to enforce only legal
transitions. The edge is now declared, and an irreversible revocation withdraws it
rather than inventing a terminal state, so the state space stays finite and
enumerable.

That defect is worth stating plainly because it is the useful part: publishing a
harness that checks other implementations is easy to do while leaving a hole in
the place the argument is actually about.

## Three more holes, found and closed

An independent security review of this harness on 30 October 2026 found two more
places where a property the harness claims to enforce could be bypassed. A third
was found by the scanner written from the lesson of the first two, which is the
argument for turning a lesson into a check rather than a paragraph. All three are
recorded here in the same spirit as the missing edge above, because the useful part
of publishing a checker is saying where the checker was itself wrong. Each was
reproduced before the change and is now pinned by a test that fails against the old
code and passes against the new.

**An empty `evidence` basis reached RESUMED.** `resume.py` validated the restore
evidence only when an evidence object was present, so a basis of `evidence`
carrying no evidence at all constructed cleanly and resumed on the signature
alone, reporting the restore condition as "verified in full" while nothing had
been checked. That is exactly the signature-only resume F8 exists to refuse,
wearing the evidence label; the T-7.1 check missed it because it exercises only a
`None` basis, not an empty-but-present one. An evidence basis now requires a
complete evidence object at construction, and an empty one is refused before it
can reach the decision layer or the lifecycle.

**A non-membership proof was forgeable for a live capability.** The revocation
registry's `verify_absence` checked that a proof's predecessor and successor sat
under the root and bracketed the capability by hash, but not that they were
*adjacent* leaves. Two live leaves can bracket a third, so a proof naming
non-adjacent neighbours could present a still-live capability as absent and forge
its revocation status, the opposite of the soundness F16 relies on. Adjacency is
now enforced from the Merkle-verified indices: two neighbours must be
consecutive, a successor-only proof must point at the first leaf, and a
predecessor-only proof at the last. Honest proofs are unaffected; the forged one
is refused.

**A lifecycle resume with no basis reached RESUMED.** `Lifecycle.resume` enforced
the basis only when one was supplied, so calling the lifecycle directly walked
PAUSE to ROLLBACK to REVERIFY to RESUMED having recorded nothing about why the halt
was lifted. The docstring claimed a resume could not bypass the basis by calling
the lifecycle directly, and the code did exactly that whenever the argument was
omitted. A resume with no basis is now refused, T-7.5 pins it, and F8 drives the
lifecycle path as well as the decision layer, because F8 was silent about the one
path that was open.

The first two changed no state, wire value or public finding: they closed the gap
between what the harness enforced and what it already claimed. The third did change
a claim, and honestly so. F8 asserted that a resume must carry a complete basis
while the lifecycle accepted none, so the finding was false on that path until the
code was fixed; its wording now names the lifecycle, and T-7.5 makes the assertion
testable rather than aspirational.

## Validated on VM2

The wheel is built and validated in a clean-room Docker container on VM2, with no
network during install, so the artefact set has to be self sufficient. Thirteen
stages, all passing: offline install, import confirmed to resolve to the wheel
rather than a staged source tree, 160 tests collected and 160 passing, the twenty
one check self test, the evidence findings re-derived from the installed wheel, sdist
cleanliness, `pip check`, no runtime dependencies, and the ML-DSA core signing and
refusing an empty payload.

The negative control matters most. After a green run, the installed wheel is
patched back to the old behaviour, removing the declared edge and restoring the
direct assignment. Two tests fail, then the wheel is restored and the suite is
green again. A harness that cannot be made to fail is not evidence of anything.

```bash
# reproduce
scp dist/*.whl dist/*.tar.gz vm2:/root/ube-conformance/artefacts/
scp -r tests vectors vm2:/root/ube-conformance/
scp scripts/cleanroom.sh vm2:/root/ube-conformance/
ssh vm2 'docker run -d --name ube-conformance-clean -v /root/ube-conformance:/work python:3.12-slim sleep infinity'
ssh vm2 'docker exec ube-conformance-clean sh /work/cleanroom.sh'
```

## Voluntary Oblivious Compliance and the agent grader

Issue 21 asks for the VOC model: a `compliance_mode` caveat that is `STRICT` or
`VOC`, a signed `justification_receipt`, and an automated grader that holds the
authority to accept the risk. The reason it exists is stated best by the person
who raised it. A human in the loop for every exception produces "Mother, may I"
fatigue, and a human who approves everything is not a control.

`voc.py` implements the flow. `STRICT` fails closed on a violation with no pause
and no receipt. `VOC` raises ANOMALY, pauses, and requests an exemption. The
grader signs a receipt, the protocol verifies the signature, and the protocol
deliberately does not read the opinion inside the receipt. Recording that it did
not form a view is the point: an unrecorded absence of judgement is invisible to
an auditor.

Three limits are enforced in code rather than in prose, because a boundary that
lives only in documentation is one somebody routes around:

- the receipt schema admits `policy_violation` as the only halt cause, so a
  receipt exempting a revocation cannot be expressed at all;
- the constructor refuses to build one, and the grader refuses to sign one;
- the grader has a ceiling on exemptions per window, so a misconfiguration
  cannot quietly become a blanket waiver, and it logs every refusal.

`schemas/justification_receipt.schema.json` is the published schema. The
signature covers the RFC 8785 canonical form of the receipt, so the same receipt
serialises identically wherever it is verified. `canonical.py` implements that
scheme properly, including ECMAScript number layout, UTF-16 key ordering and
literal non-ASCII, which is the part our earlier JCS-like hasher got wrong.

## The signing core, the registry, and the grader's mandate

Three pieces exist because NTI asks for them by name, and each closes a hole the
protocol would otherwise have.

**ML-DSA-87 in an isolated process.** NTI-1 mandates CRYSTALS-Dilithium5 and the
AIW paper requires the key to sit outside the agent's context, on the argument
that an agent holding the private key is an agent whose attacker holds it. A
Python `sign()` function does not satisfy that, so `rust/nti-signer` is a separate
binary: it generates the key, uses it, and never writes it anywhere. Python drives
it over a line protocol and can ask for a signature or check one, nothing more.
Measured sizes are the FIPS 204 ones, 2592 byte verifying key and 4627 byte
signature, and the core refuses to sign an empty payload because a signature over
nothing is the defect F2 records.

**A Merkle revocation registry.** The paper describes a root that updates on
revocation and tokens verified against the *latest* root, so a token issued
mid-chain is rejected at the boundary. `registry.py` implements that as an
accumulator, deliberately separate from the audit chain, because one grows and the
other is replaced. Inclusion and absence proofs, domain separated leaves, and a
proof built before a revocation fails against the current root while still
verifying against the pinned historical one.

**The grader's mandate.** This is the hole the receipt does not close. A signature
proves which grader signed, not that it was ever entitled to. So `mandate.py` adds
a bounded, signed, revocable authorisation, and a grader cannot issue its own: self
authorisation is not authority. The mandate names the policies it may exempt, the
principals it may act for, a value ceiling, an expiry and an exemption count, all
checked at the moment of signing. Revoking it stops the next signature. The
receipt carries `mandate_id` and the signed mandate itself, so an auditor can
answer "who allowed this automation to say yes" without reading prose.

## Licence

Apache-2.0. The NTI-1 specification text is CC BY 4.0 and is not reproduced
here; only small quoted fragments for clause references.
