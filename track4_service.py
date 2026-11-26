"""Track 4 stdin/stdout adapter."""
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

from kig_core.judge import dispatch


def main():
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("expected object")
        root = Path(os.environ.get("TRACK4_STATE_DIR") or
                    Path(tempfile.gettempdir()) / f"track4-judge-{os.getuid()}")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        result = dispatch(root / "judge.sqlite", request)
    except (ValueError, UnicodeError):
        result = {"error": "invalid_request"}
    except ImportError:
        print("Required Track 4 crypto dependency could not be loaded.", file=sys.stderr)
        result = {"error": "service_unavailable"}
    except (OSError, sqlite3.Error):
        result = {"error": "service_unavailable"}
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
