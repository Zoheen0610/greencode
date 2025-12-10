GreenCode Analyzer

Energy-aware static + hybrid Python analyzer that detects inefficient patterns (loops, allocations, I/O, complexity) and estimates runtime energy/CO₂ impact.

Use it locally or as a GitHub Action in any repository.

Features

Static analysis (loops, nested depth, heavy allocations, cyclomatic complexity)

Optional dynamic execution

--trace (in-process tracing)

--safe-subprocess (safer energy-only mode)

Energy & CO₂ estimation

JSON output for CI pipelines

Reusable GitHub Action (Zoheen0610/greencode@v1)

📦 Local Usage
Static Analyzer

python src/static_analyzer.py path/to/file.py

Hybrid Analyzer
# safest mode (no in-process execution)
python src/hybrid_full_analyzer.py file.py --safe-subprocess --json

# full tracing (runs code inside analyzer – trusted code only)
python src/hybrid_full_analyzer.py file.py --trace --json

Analyze an entire folder
python src/hybrid_full_analyzer.py .


☁️ GitHub Action (for other repos)

Any project can use GreenCode in CI by adding this workflow:

name: GreenCode Check
on: [push, pull_request]

jobs:
  green:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Zoheen0610/greencode@v1
        with:
          path: "${{ github.workspace }}"   # analyze whole repo
          mode: "safe-subprocess"           # recommended for CI
          json: "true"

Users control what is analyzed:

A single file:
path: "script.py"

A folder:
path: "src/"

Entire repo:
path: "${{ github.workspace }}"

📤 Outputs

Green Score (heuristic efficiency score)

Optional greencode_action_output.json containing:

per-file + per-function scores

loop hotspots

I/O sites

dynamic call counts (if trace mode)

energy & CO₂ estimate

Useful for CI gates or PR annotations.

🔒 Safety Notes

Use safe-subprocess for untrusted code (public CI).

--trace executes user code inside the runner → only safe for private projects.

📌 Release

To make your action usable as @v1, run:

git tag v1
git push origin v1
