# Superseded: reference implementation baseline

**This interpretation was withdrawn on 30 October 2026.** The measurements below
are accurate; the conclusions drawn from them were not, because they assumed the
policy engine is the enforcement layer. The AIW paper says the sidecar is. The
corrected reading is in `VOC-CONTEXT.md`.

The engine returning Allow for an unsigned, expired or under-threshold request is
not demonstrably a defect: requiring the signature before the engine is consulted
is the sidecar's job. What the measurements do establish, and what matters for VOC,
is that a capability's caveats cannot travel from `grant` to `evaluate`, which is
the same channel `compliance_mode` will need.

## Original record, kept so the correction is traceable

**Date:** 30 October 2026
**Package:** `ube_foundation` 0.1.7, wheel `cp310-abi3-win_amd64`, installed from PyPI in an isolated venv
**Harness:** this repository at `79990c2` plus the uncommitted VOC/ML-DSA work
**Adapter:** `scripts/baseline_reference.py`

The conformance procedure says to run the reference implementation before making
any claim about our own code, because a suite's behaviour against the reference is
what tells you the harness works. This is that run, recorded whether or not the
result is flattering to anyone.

## What the reference implementation is

A single compiled extension exposing three names:

- `TrustEngine` with `evaluate`, `grant`, `revoke_token`, `register_voter_key`
- `PqcKeyPair` with `sign`, `sign_bytes`, `verify`, plus Kyber encryption helpers
- `ube_foundation`, the module itself

Signature sizes are correct for the mandate: a `PqcKeyPair` publishes a 2592 byte
public key and produces 4627 byte signatures, which are the FIPS 204 ML-DSA-87
sizes. The post-quantum claim is therefore genuine at the primitive level.

## The request shape is not in the specification

`evaluate` takes a JSON string whose required fields are
`id`, `action`, `actor`, `capability`, `input`, plus `nonce` and `timestamp`, with
`signature` as a list of integers rather than a hex string. None of this appears in
NTI-1, whose section 5 describes `(voter_id, request_id, decision, outcome_hash,
signature)` for votes and nothing at all for an action request.

The fields here were found by feeding requests and reading the validator's
`missing field` errors one at a time. An implementer working from the published
specification cannot construct a valid request without doing the same, which is a
specification gap rather than a defect in the package.

## Result against the three testable requirements that exercise `evaluate`

| Check | Requirement | Result |
| --- | --- | --- |
| T-1.1 | An action submitted with no signature MUST be denied | **Allow** |
| T-2.1 | An action under an expired capability MUST be denied | **Allow** |
| T-3.1 | A multi-agent action without threshold agreement MUST be denied | **Allow** |

Run directly, with the same capability live and only the signature varied, so the
result cannot be an artefact of how the adapter builds a request:

```
no signature field at all    {"decision":"Allow","reason":"granted"}
empty signature list         {"decision":"Allow","reason":"granted"}
garbage signature            {"decision":"Allow","reason":"granted"}
valid signature              {"decision":"Allow","reason":"granted"}
```

A signature of 4627 zero bytes is accepted exactly as a real ML-DSA-87 signature
is. The allow decision is unaffected by the signature in every case tested.

## Two further observations

**Caveats cannot be carried.** `grant(actor, capability)` takes a capability as a
string. Passing a capability that carries caveats, for example
`{"id":"cap-x","expires":1}`, is accepted and stored, but `evaluate` then reports
`no cap` for that same string, because it only matches a plain capability id. So
`Expires` and `MaxExecutions` cannot be expressed in a way that both grants and
evaluates. This is consistent with T-2.1 failing.

**Revocation does not affect evaluation.** `revoke_token` accepts any string and
returns `None` without error. After revoking a capability id that was just granted,
`evaluate` still answers `Allow`. That is the property Pillar 1 requires ("identity
claims MUST NOT be revocable without an auditable record") and the runtime halt in
section 6 depends on.

## What this does not prove

It does not prove our harness is correct. Ours is the instrument, and an
instrument that is wrong about the reference is wrong about everything.

It does not prove the package is broken in general: this exercises `evaluate`
through the shape the adapter discovered, which is one path among several. A
different deployment may populate fields this adapter does not, and the
maintainers may have a configuration in which signature and expiry are enforced.

It says nothing about `sign`, `verify`, the Kyber helpers or the voter-key path,
which were not exercised.

It is one version, 0.1.7, on one platform, on one day.

## What follows for us

Two things, and the first is uncomfortable.

Our own T-1.1 currently passes against our own harness. That is not evidence, and
this run shows why: the same check against the reference fails, which means the
check is capable of failing and our pass is therefore meaningful. That is the
useful outcome of a baseline.

But our checks also passed the reference **by accident** in the first attempt,
because the adapter omitted the capability and everything denied for `no cap`.
That is the exact failure the skill warns about, caught and fixed here rather than
reported as a result.

The claim worth making publicly is narrow: a harness exists that runs against a
third-party implementation, and this is what it measured today. The claim not worth
making is that NTI-1 is or is not implemented, because the specification does not
define the request it is supposed to test.
