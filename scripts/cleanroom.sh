#!/bin/sh
# Clean-room validation for algovoi-ube on VM2.
#
# Runs inside a fresh python:3.12-slim container with no network during install,
# so the artefact set has to be self-sufficient. Every stage captures its own
# exit code on the line after the command, because `cmd | tail` hands the pipe's
# status to the verdict and turns a failure into a pass.

set -u
FAILED=0
VENV=/work/venv
ART=/work/artefacts

verdict() {
    rc=$1
    name=$2
    if [ "$rc" -eq 0 ]; then
        echo "  PASS  $name"
    else
        echo "  FAIL  $name (exit $rc)"
        FAILED=1
    fi
}

echo "=== 0. environment ==="
python -V
echo "  container has no pytest and no algovoi_ube before install:"
python -c "import pytest" 2>&1 | tail -1
python -c "import algovoi_ube" 2>&1 | tail -1

echo
echo "=== 1. create venv ==="
python -m venv "$VENV"
verdict $? "venv creation"

echo
echo "=== 2. offline install of the wheel plus test runner ==="
"$VENV"/bin/pip install --no-index --find-links "$ART" \
    "$ART"/algovoi_ube-0.1.0-py3-none-any.whl "$ART"/pytest-9.2.0-py3-none-any.whl \
    > /work/install.log 2>&1
RC=$?
verdict "$RC" "offline wheel install"
if [ "$RC" -ne 0 ]; then
    tail -20 /work/install.log
fi

echo
echo "=== 3. the wheel is what gets imported ==="
"$VENV"/bin/python -c "
import algovoi_ube, sys
p = algovoi_ube.__file__
print('  imported from:', p)
assert 'site-packages' in p, 'imported the source tree, not the wheel'
assert '/work/src' not in p, 'imported from a staged source tree'
assert '/work/tests' not in p, 'imported from the staged tests dir'
print('  wheel import confirmed')
" > /work/import.log 2>&1
RC=$?
verdict "$RC" "import resolves to the installed wheel"
cat /work/import.log

echo
echo "=== 4. test collection count (a skip reads as a pass in a summary) ==="
cd /work && "$VENV"/bin/python -m pytest /work/tests --collect-only -q > /work/collect.log 2>&1
RC=$?
verdict "$RC" "test collection"
grep -E "tests collected|error" /work/collect.log | tail -3

echo
echo "=== 5. full suite against the installed wheel ==="
cd /work && "$VENV"/bin/python -m pytest /work/tests -q > /work/tests.log 2>&1
RC=$?
verdict "$RC" "pytest suite"
tail -3 /work/tests.log
echo "  skipped count:"
grep -c "skipped" /work/tests.log || true

echo
echo "=== 6. harness self test from the wheel ==="
cd /tmp && "$VENV"/bin/python -c "
import sys
from algovoi_ube.runner import self_test
sys.exit(self_test())
" > /work/selftest.log 2>&1
RC=$?
verdict "$RC" "conformance self test"
grep -E "checks passed|FAIL|declared in the table|withdraws the edge" /work/selftest.log | tail -6

echo
echo "=== 7. evidence collector regenerates every finding ==="
mkdir -p /work/evidence
cd /work && cp -r /work/vectors /work/vectors.bak 2>/dev/null
"$VENV"/bin/python -c "
import sys, json
sys.path.insert(0, '/work')
from algovoi_ube.resume import BASES, WIRE_VALUES, decide_resume
from algovoi_ube.failclosed import LEGAL, State
# Re-derive the four resume findings from the installed wheel alone.
from algovoi_ube.resume import ResumeBasis, Basis, RestoreEvidence, ResumeRefused
bare = decide_resume(signature_valid=True, basis=None)
assert bare.allowed is False and bare.wire_value == 'pause', bare
on_ev = decide_resume(signature_valid=True, basis=ResumeBasis(
    basis=Basis.EVIDENCE.value,
    evidence=RestoreEvidence(conditions=['restored'], verifier_role='officer',
                             valid_until='2026-10-30T17:00:00Z')))
assert on_ev.allowed is True, on_ev
assert State.RESUMED in LEGAL[State.REVERIFY]
for bad in ('authority_revoked', 'authority_not_determined'):
    try:
        ResumeBasis(basis=Basis.EXEMPTION.value, covers=bad)
        raise SystemExit('exemption wrongly covered ' + bad)
    except ResumeRefused:
        pass
print('  F7 to F10 re-derived from the wheel: pass')
" > /work/evidence.log 2>&1
RC=$?
verdict "$RC" "resume findings re-derived from the wheel"
cat /work/evidence.log

echo
echo "=== 8. sdist cleanliness ==="
"$VENV"/bin/python -c "
import tarfile, glob
p = glob.glob('/work/artefacts/*.tar.gz')[0]
names = tarfile.open(p).getnames()
bad = [n for n in names if '__pycache__' in n or '.pytest_cache' in n or '/build/' in n
       or '/dist/' in n or n.endswith('.pyc') or n.endswith('.log')]
assert not bad, bad
print('  SDIST_CLEAN_OK', len(names), 'entries')
" > /work/sdist.log 2>&1
RC=$?
verdict "$RC" "sdist cleanliness"
cat /work/sdist.log

echo
echo "=== 9. pip check on the installed wheel ==="
"$VENV"/bin/pip check > /work/pipcheck.log 2>&1
RC=$?
verdict "$RC" "pip check"
cat /work/pipcheck.log

echo
echo "=== 10. stdlib only, no runtime dependencies ==="
"$VENV"/bin/python -c "
import importlib.metadata as md
reqs = md.requires('algovoi-ube') or []
hard = [r for r in reqs if 'extra ==' not in r]
print('  runtime requirements:', hard or 'none')
assert not hard, hard
" > /work/deps.log 2>&1
RC=$?
verdict "$RC" "no runtime dependencies"
cat /work/deps.log

echo
echo "=== 11. negative control: withdraw the edge, suite must go red ==="
cp -r "$VENV"/lib/python3.12/site-packages/algovoi_ube /work/ube_backup
"$VENV"/bin/python - <<'PY'
import pathlib
p = pathlib.Path("/work/venv/lib/python3.12/site-packages/algovoi_ube/failclosed.py")
t = p.read_text(encoding="utf-8")
t = t.replace("    State.REVERIFY: {State.RESUMED},\n", "")
t = t.replace("        self.to(State.RESUMED)\n        return self.state",
              "        self.state = State.RESUMED\n        self.history.append(State.RESUMED)\n        return self.state")
p.write_text(t, encoding="utf-8")
print("  installed wheel patched back to the old bypass")
PY
cd /work && "$VENV"/bin/python -m pytest /work/tests -q > /work/negative.log 2>&1
RC=$?
FAILS=$(grep -c "^FAILED" /work/negative.log || true)
RAN=$(grep -cE "passed|failed" /work/negative.log || true)
if [ "$RC" -ne 0 ] && [ "$FAILS" -gt 0 ] && [ "$RAN" -gt 0 ]; then
    echo "  PASS  negative control went red as required ($FAILS test(s) failed)"
    grep "^FAILED" /work/negative.log | sed "s/^/    /"
else
    echo "  FAIL  negative control did not fail for the right reason"
    echo "        exit=$RC failed_lines=$FAILS summary_lines=$RAN"
    echo "        (exit 4 with no failures means no tests ran, which is not a control)"
    FAILED=1
fi
rm -rf "$VENV"/lib/python3.12/site-packages/algovoi_ube
cp -r /work/ube_backup "$VENV"/lib/python3.12/site-packages/algovoi_ube

echo
echo "=== 12. restored, green again ==="
cd /work && "$VENV"/bin/python -m pytest /work/tests -q > /work/restored.log 2>&1
RC=$?
verdict "$RC" "suite green after restoring the wheel"
tail -2 /work/restored.log

echo
if [ "$FAILED" -eq 0 ]; then
    echo "ALL STAGES PASSED"
    exit 0
fi
echo "ONE OR MORE STAGES FAILED"
exit 1
