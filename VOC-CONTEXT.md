# Where VOC sits in an NTI deployment

**Date:** 30 October 2026
**Context:** NTI issue 21, Voluntary Oblivious Compliance and the automated agent grader
**Reference implementation measured:** `ube-foundation` 0.1.7

This note is about how VOC should work inside NTI as NTI is actually described,
not about whether one package passes one test. The distinction turned out to
matter, and getting it wrong first is why this document exists in this shape.

## The thing I got wrong, and what corrected it

I ran the reference implementation against NTI's three testable requirements that
involve `evaluate`. It answered Allow for an unsigned request, an expired
capability and a threshold failure. I wrote that up as the reference failing its
own tests.

That was the wrong frame. The AIW paper is explicit about where enforcement lives:

> While an LLM can evaluate policy and signal a `PAUSE`, it cannot be trusted to
> enforce it. The NTI sidecar is the deterministic enforcement layer. It
> intercepts the execution loop, blocks the socket connection, and signs the
> `PAUSE` or `ROLLBACK` receipt using Dilithium5.

`TrustEngine.evaluate` is the policy evaluator. The **sidecar** is the bouncer. A
policy function returning Allow for a request that carries no signature is not
necessarily a defect, because requiring the signature is the sidecar's job before
it ever asks the engine.

So the measurements stand and the interpretation was wrong. That is worth writing
down rather than quietly correcting, because the same mistake is sitting in the
specification for anyone else to make.

## The specification gap

NTI-1 section 5 lists five testable requirements. It does not say which component
must satisfy any of them:

| Test | Wording | Which component is being tested? |
| --- | --- | --- |
| T-1.1 | Submit action with no signature. Result: MUST be Deny | Unstated |
| T-2.1 | Submit action with expired capability. Result: MUST be Deny | Unstated |
| T-3.1 | Multi-agent action without threshold. Result: MUST be Deny | Unstated |
| T-4.1 | Execute 100 actions. Chain length MUST equal 100 | Unstated |
| T-5.1 | Restart system. Audit chain MUST be preserved | Unstated |

In an architecture with a sidecar, an engine, a Rust crypto core and a registry,
"submit action" is ambiguous between at least two of them. Our harness assumed the
engine, which is why it produced a finding that reads as alarming and is probably
not. The fix is not to pick a component: it is for the specification to say, per
test, which layer is under test and therefore what a passing harness must drive.

**Concretely: T-1.1 should name the sidecar, because signature verification before
policy evaluation is described in the paper as the sidecar's first act.**

## How VOC fits, component by component

VOC is not a feature of the policy engine. It is a property of the path through a
halt, and that path crosses four components. NTI issue 21 asks for the schema and
the rules; this is where each rule has to live for the flow to be enforceable at
all.

### 1. The capability carries the mode

`compliance_mode = STRICT | VOC` belongs on the capability, beside `Expires` and
`MaxExecutions`, because it is a property of what was granted rather than of what
was requested. The sidecar reads it at the sub-call boundary.

This is also where the reference implementation's caveat handling becomes
relevant, and it is a real constraint rather than a criticism: `grant` stores a
capability string carrying caveats, but `evaluate` matches only a plain capability
id, so caveats cannot currently travel from grant to decision. VOC needs the same
channel, so whatever carries `Expires` has to carry `compliance_mode`. That is a
requirement on the wire shape, not on any one package.

### 2. The sidecar decides whether to halt or pause

The engine says Deny. Under `STRICT` the sidecar refuses and stops. Under `VOC` it
raises ANOMALY and enters PAUSE, at the sub-call boundary, so the atomic call in
flight finishes. That ordering matters: the halt is never mid tool call, which is
the paper's safe interruption point and is now checked as T-9.1.

### 3. The grader signs; the sidecar verifies without reading

The automated agent grader holds the authority to sign the exemption. The sidecar
verifies the signature and records the receipt. It does not read the reason,
because judging it is the accountability layer's job.

The protocol records that it formed no view. That is the whole point of
`resume_basis`: an auditor must be able to separate a resume on evidence from a
resume on exemption, and the second only exists because someone accepted a risk
deliberately.

### 4. The registry bounds what may be exempted

The Merkle revocation registry answers a different question from the policy engine:
is this capability live at the current root? VOC must not be able to touch that
answer. Hence the two boundaries, which hold because they are structural rather
than advisory:

- `exemption_covers = policy_violation` only. The schema's `halt.cause`
  enumeration contains no other value, so a receipt exempting a revocation cannot
  be expressed.
- `authority_revoked` and `authority_not_determined` are refused by the receipt
  constructor and by the grader, and a stale-root proof is refused at the boundary
  regardless of any receipt.

The revocation registry and the exemption path are therefore independent. A
manager on the executing side can accept a policy violation; no signature can
re-open a revoked authority or convert "we do not know" into "we know".

## What the receipt has to contain

Enough to be recomputed by a party who trusts nobody in the chain:

- the request it binds to, so it cannot be replayed onto another call
- the policy that denied, and the halt cause, drawn from a closed set
- the resume basis, fixed to `exemption` by construction
- the grader's identity and role, since a compliance officer and a release manager
  are different authorities
- the principal and delegation the action was taken under, so a reader can check
  the delegation's state at resume time
- a validity end, because an exemption without an end is a permanent waiver
- a signature over the RFC 8785 canonical form, so two verifiers using different
  JSON libraries agree on the bytes

That is `schemas/justification_receipt.schema.json` in this repository, and the
signature is ML-DSA-87 produced in an isolated process, because the paper requires
the key never to enter the agent's context.

## What an honest claim about this looks like

What can be said:

> A harness exists that runs VOC against a target: it drives the four components,
> checks that the two exemption boundaries are enforced structurally, and verifies
> receipts signed with the mandated scheme in an isolated core. It runs today
> against the reference implementation's policy engine, and it measures that
> engine returning Allow for unsigned and expired requests. Under the paper's
> division of labour that is the sidecar's call, not the engine's, which is why the
> specification should name the component each test targets.

What cannot be said:

> The reference implementation is non-compliant.

The second claim is not supported. It assumes the engine is the enforcement layer,
and the paper says it is not. Anyone reading the first claim gets an accurate
picture and a specific question to put to the thread; anyone reading the second
gets a fight about a misreading.

## The question this puts to the thread

One sentence, worth putting to the authors rather than to a commit message:

**Should NTI-1 section 5 name the component under test for each requirement, or
should a conformance harness be free to choose? If it is free, two harnesses can
disagree about the same implementation and both be right, which makes the test
suite unable to settle anything.**

That is a specification question, it is cheap to answer, and it decides whether
any conformance claim about NTI-1 means anything at all.
