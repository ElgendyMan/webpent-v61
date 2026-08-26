"""Validate the checked-in target-adapter review packet contract."""
from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.target_adapter_review import (
    validate_target_adapter_review_packet,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = PROJECT_ROOT / "docs" / "target_adapter_review_packet_template_v1.json"


def main() -> int:
    try:
        packet = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "errors": [f"packet:read_failed:{exc}"]}))
        return 1
    errors = validate_target_adapter_review_packet(packet)
    result = {"passed": not errors, "errors": list(errors), "path": str(TEMPLATE_PATH)}
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
