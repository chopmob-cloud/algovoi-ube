# NTI-1 issue #18 conformance vectors

Shared test vectors for [abisheakp197/nti-spec#18](https://github.com/abisheakp197/nti-spec/issues/18):
preimage reproducibility, tamper detection, truncation, and the duplicate-vote
case.

These are generated, not hand-written. Regenerate and verify that the committed
tree is current:

```bash
python scripts/gen_issue18_vectors.py           # write the vectors
python scripts/gen_issue18_vectors.py --check    # fail if the tree is stale
```

`tests/test_issue18_vectors.py` regenerates them to a temporary directory,
asserts the committed files are byte-identical, and checks each vector against
the harness itself (chain verification, JCS canonicalization).

Licensed under Apache-2.0, the same as the rest of this repository (see
[../../LICENSE](../../LICENSE)).
