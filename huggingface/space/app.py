"""HuggingFace Space entry point — re-exports the local dashboard.

The actual dashboard lives at examples/dashboard.py in the upstream repo;
this thin shim lets the Space deployment use the same source without
duplicating it. When deploying the Space, copy or symlink
``examples/dashboard.py`` next to this file as ``dashboard.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the bulwark package importable when this file runs from a Space root.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Run the dashboard as if it were the entry point.
from examples.dashboard import main  # noqa: E402

if __name__ == "__main__":
    main()
else:
    # When Streamlit imports this module (its standard pattern) just call main().
    main()
