#!/usr/bin/env python3
"""
Reproduce the whole-library experiment on a REAL binary via Ghidra.

This script:
  1. Invokes Ghidra headless on test_cases/libz.so
  2. Enumerates all functions
  3. Deep-extracts features for each non-trivial function
  4. Saves the combined output as examples/libz_live_corpus.json
  5. Runs the identifiability experiment on it

Usage:
    python experiments/run_on_real_binary.py
    python experiments/run_on_real_binary.py --binary test_cases/libcrypto.so
    python experiments/run_on_real_binary.py --min-size 80 --max-functions 100
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.config import Config
from modules.ghidra_runner import GhidraRunner
from experiments.whole_binary_experiment import (
    run_experiment, print_per_function_table,
    print_distribution, print_matching_ratio,
    print_best_cases, print_unidentifiable,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="test_cases/libz.so",
                        help="Path to the binary to analyze.")
    parser.add_argument("--output-corpus", default="examples/libz_live_corpus.json",
                        help="Where to save the Ghidra-extracted corpus.")
    parser.add_argument("--min-size", type=int, default=40,
                        help="Skip functions smaller than this many bytes (default: 40).")
    parser.add_argument("--max-functions", type=int, default=None,
                        help="Cap the number of functions to process (default: all).")
    parser.add_argument("--skip-extraction", action="store_true",
                        help="Skip Ghidra; just run the experiment on the existing corpus file.")
    parser.add_argument("--report", default=None,
                        help="Optional path for the final JSON identifiability report.")
    args = parser.parse_args()

    corpus_path = os.path.abspath(args.output_corpus)

    # ── Phase 1: Extract via Ghidra ─────────────────────────────
    if not args.skip_extraction:
        config = Config.load()
        if not config.ghidra_home:
            print("[ERROR] ghidra_home not set. Configure config.json.")
            sys.exit(1)

        binary_path = os.path.abspath(args.binary)
        if not os.path.isfile(binary_path):
            print(f"[ERROR] Binary not found: {binary_path}")
            sys.exit(1)

        print(f"[*] Binary:      {binary_path}")
        print(f"[*] Ghidra:      {config.ghidra_home}")
        print(f"[*] Output:      {corpus_path}")

        runner = GhidraRunner(
            ghidra_path=config.ghidra_home,
            project_dir=config.project_dir,
        )

        # Step 1: Enumerate functions
        print(f"\n[*] Step 1: Enumerating all functions (30-90s)...")
        t0 = time.time()
        ghidra_data = runner.run_analysis(binary_path)
        functions = ghidra_data.get("functions", [])
        elapsed = time.time() - t0
        print(f"    Found {len(functions)} functions in {elapsed:.1f}s")

        # Filter: skip tiny functions (PLT stubs, trampolines)
        functions = [f for f in functions if f.get("size", 0) >= args.min_size]
        print(f"    After size filter (>={args.min_size} bytes): {len(functions)} functions")

        if args.max_functions:
            functions = functions[:args.max_functions]
            print(f"    Capped at --max-functions: {len(functions)}")

        # Step 2: Deep-extract features for each function
        print(f"\n[*] Step 2: Deep-extracting features for {len(functions)} functions...")
        print(f"    This takes ~1-3 seconds per function.")
        full_functions = []

        for i, func in enumerate(functions, 1):
            addr = func["address"]
            name = func.get("name", "unknown")
            try:
                print(f"    [{i}/{len(functions)}] {name} @ {addr}...", end=" ", flush=True)
                features = runner.extract_function_features(binary_path, addr)
                full_functions.append(features)
                n_const = len(features.get("constants", []))
                n_str = len(features.get("strings", []))
                print(f"constants={n_const} strings={n_str}")
            except Exception as e:
                print(f"FAILED: {e}")
                continue

        # Step 3: Save the combined corpus
        corpus = {
            "binary": binary_path,
            "total_functions": len(ghidra_data.get("functions", [])),
            "displayed_functions": len(full_functions),
            "extracted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "functions": full_functions,
        }
        os.makedirs(os.path.dirname(corpus_path), exist_ok=True)
        with open(corpus_path, "w") as f:
            json.dump(corpus, f, indent=2)
        print(f"\n[*] Corpus saved: {corpus_path}")

    # ── Phase 2: Run the identifiability experiment ─────────────
    print(f"\n[*] Step 3: Running identifiability experiment...")
    with open(corpus_path) as f:
        data = json.load(f)

    results = run_experiment(data)

    print_per_function_table(results)
    print_distribution(results)
    print_matching_ratio(results)
    print_best_cases(results)
    print_unidentifiable(results)

    # Optional JSON report
    if args.report:
        from collections import Counter
        from dataclasses import asdict
        report = {
            "source_binary": data.get("binary"),
            "total_functions_in_binary": data.get("total_functions"),
            "functions_analyzed": len(results),
            "distribution": dict(Counter(r.tier for r in results)),
            "functions": [asdict(r) for r in results],
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Report saved: {args.report}")


if __name__ == "__main__":
    main()
