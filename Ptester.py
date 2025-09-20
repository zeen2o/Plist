name: Run Ptester (Ubuntu batches)

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  run-ptester:
    runs-on: ubuntu-latest
    timeout-minutes: 400    # 400 minutes = 6h40m

    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
          fetch-depth: 0

      - name: Install curl
        run: sudo apt-get update && sudo apt-get install -y curl

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run proxy tester batches (guarded with timeout)
        id: run_ptester
        continue-on-error: true
        run: |
          # Run script; guard it with timeout 24000s (6h40m)
          timeout 24000s python Ptester.py --count 100 --max-workers 200 --timeout 3 --overall-timeout 24000 || rc=$?
          echo "script_rc=${rc:-0}" >> $GITHUB_OUTPUT

      - name: Ensure results summary exists
        run: |
          mkdir -p results
          echo "Action run at $(date -u)" >> results/summary.txt || true

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ptester-results
          path: results/**

      - name: Commit & push results
        run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add results || true
          git commit -m "Add Ptester results [skip ci]" || echo "No changes to commit"
          git push origin HEAD:${{ github.ref_name }} || echo "Push failed"
