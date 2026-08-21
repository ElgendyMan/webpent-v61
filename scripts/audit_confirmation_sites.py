from pathlib import Path

for path in sorted(Path("src/webpent").rglob("*.py")):
    lines = path.read_text(errors="ignore").splitlines()
    for index, line in enumerate(lines):
        if '"Tool-Confirmed"' not in line and "'Tool-Confirmed'" not in line:
            continue
        print(f"--- {path}:{index + 1} ---")
        for number in range(max(0, index - 12), min(len(lines), index + 13)):
            print(f"{number + 1}: {lines[number]}")
        print()
