from pathlib import Path

needles = ("Tool-Confirmed", "Confidence.CONFIRMED")
for path in sorted(Path("src/webpent/agents").rglob("*.py")):
    lines = path.read_text(errors="ignore").splitlines()
    for i, line in enumerate(lines):
        if any(n in line for n in needles):
            print(f"{path}:{i+1}:{line.strip()}")
