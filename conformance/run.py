"""Convenience entry point: python conformance/run.py --self-test"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from algovoi_ube.runner import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
