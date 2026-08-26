"""Validate a target-adapter review packet without target I/O."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from webpent.shared.target_adapter_review import validate_target_adapter_review_packet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = PROJECT_ROOT / "docs" / "target_adapter_review_packet_template_v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "packet",
        nargs="?",
        type=Path,
        default=TEMPLATE_PATH,
        help="JSON review packet to validate (defaults to the checked-in template)",
    )
    args = parser.parse_args()
    packet_path = args.packet.resolve()
    try:
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "errors": [f"packet:read_failed:{exc}"]}))
        return 1
    errors = validate_target_adapter_review_packet(packet)
    result = {"passed": not errors, "errors": list(errors), "path": str(packet_path)}
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
