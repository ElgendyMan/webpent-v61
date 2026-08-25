from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from webpent.benchmark.juice_shop_oracles import JUICE_ORACLE_CONTRACTS
from webpent.benchmark.juice_shop_safe_cases import JUICE_SHOP_SAFE_CASES


def digest(value: object) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(serialized).hexdigest()}"


def main() -> None:
    cases = [asdict(case) for case in JUICE_SHOP_SAFE_CASES]
    oracles = [asdict(JUICE_ORACLE_CONTRACTS[key]) for key in sorted(JUICE_ORACLE_CONTRACTS)]
    in_scope = [case for case in cases if case["safe_to_execute"]]
    categories = sorted({case["category"] for case in in_scope})
    output = {
        "mapping_sha256": digest(cases),
        "oracle_contract_sha256": digest(oracles),
        "case_count": len(cases),
        "safe_case_count": len(in_scope),
        "safe_class_count": len(categories),
        "safe_classes": categories,
        "approval_created": False,
        "results_included": False,
        "raw_data_included": False,
    }
    print(json.dumps(output, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
