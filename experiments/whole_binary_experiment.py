#!/usr/bin/env python3
"""
Batch Experiment: Whole-Binary Matching Ratio
==============================================

Processes every function in a binary through the feature extraction and
ranking pipeline, then measures what fraction would be identifiable via
GitHub Code Search under the stripped-binary assumption.

This is an OFFLINE experiment — it does not call GitHub or the LLM. It
measures IDENTIFIABILITY (whether enough signal exists to search at all),
which is a necessary precondition for a successful match. Full end-to-end
matching rates require the live APIs and are discussed in the README.

Identifiability tiers:
    HIGH    — ≥1 rare constant AND ≥1 unique string, OR ≥2 rare constants
              (cross-category combinations; very likely to match)
    MEDIUM  — ≥1 rare constant OR ≥1 unique string OR ≥2 external API calls
              (single-category signal; match likely but not guaranteed)
    LOW     — At least one feature but not enough for multi-term queries
              (fallback queries only; match uncertain)
    NONE    — No constants, no strings, no external calls
              (unidentifiable via code search alone)

Usage:
    python experiments/whole_binary_experiment.py
    python experiments/whole_binary_experiment.py --data examples/zlib_full_corpus.json
    python experiments/whole_binary_experiment.py --output results.json
"""

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker
from modules.github_searcher import GitHubSearcher


# ─── Tier Classification ────────────────────────────────────────────

TIER_HIGH = "HIGH"
TIER_MEDIUM = "MEDIUM"
TIER_LOW = "LOW"
TIER_NONE = "NONE"

TIER_ORDER = [TIER_HIGH, TIER_MEDIUM, TIER_LOW, TIER_NONE]


def classify_identifiability(
    n_rare_constants: int,
    n_unique_strings: int,
    n_external_calls: int,
) -> str:
    """Assign an identifiability tier based on available features."""
    # HIGH: cross-category combinations possible
    if n_rare_constants >= 1 and n_unique_strings >= 1:
        return TIER_HIGH
    if n_rare_constants >= 2:
        return TIER_HIGH
    if n_unique_strings >= 2:
        return TIER_HIGH

    # MEDIUM: single-category signal strong enough for search
    if n_rare_constants >= 1:
        return TIER_MEDIUM
    if n_unique_strings >= 1:
        return TIER_MEDIUM
    if n_external_calls >= 2:
        return TIER_MEDIUM

    # LOW: minimal signal (one external call only)
    if n_external_calls >= 1:
        return TIER_LOW

    # NONE: no searchable features
    return TIER_NONE


# ─── Result Dataclass ───────────────────────────────────────────────

@dataclass
class FunctionResult:
    name: str
    address: str
    size: int
    n_raw_constants: int
    n_rare_constants: int
    n_strings: int
    n_unique_strings: int
    n_external_calls: int
    n_queries: int
    tier: str
    top_search_terms: list
    top_queries: list


# ─── Experiment Runner ──────────────────────────────────────────────

def run_experiment(ghidra_data: dict) -> list[FunctionResult]:
    """Process every function in the binary and classify identifiability."""
    extractor = FeatureExtractor()
    ranker = FeatureRanker()
    searcher = GitHubSearcher(token="")  # no token needed — we only build queries

    results = []
    for func_data in ghidra_data["functions"]:
        features = extractor.extract(func_data)
        ranked = ranker.rank(features)
        queries = searcher._build_queries(ranked)

        tier = classify_identifiability(
            n_rare_constants=len(ranked.rare_constants),
            n_unique_strings=len(ranked.unique_strings),
            n_external_calls=len(ranked.external_calls),
        )

        results.append(FunctionResult(
            name=features.function_name,
            address=features.function_address,
            size=func_data.get("size", 0),
            n_raw_constants=len(features.constants),
            n_rare_constants=len(ranked.rare_constants),
            n_strings=len(features.strings),
            n_unique_strings=len(ranked.unique_strings),
            n_external_calls=len(ranked.external_calls),
            n_queries=len(queries),
            tier=tier,
            top_search_terms=ranked.get_search_terms(max_terms=4),
            top_queries=queries[:3],
        ))

    return results


# ─── Reporting ──────────────────────────────────────────────────────

def print_per_function_table(results: list[FunctionResult]):
    """Print a per-function breakdown table."""
    print()
    print("=" * 110)
    print("  PER-FUNCTION FEATURE BREAKDOWN")
    print("=" * 110)
    print(f"  {'Function':<22} {'Size':>6}   {'RawK':>4} {'RareK':>5}  {'Str':>4} {'UStr':>4}  {'ExtC':>4}  {'Q':>3}   Tier")
    print(f"  {'-'*22} {'------':>6}   {'----':>4} {'-----':>5}  {'----':>4} {'----':>4}  {'----':>4}  {'---':>3}   --------")

    for r in results:
        tier_marker = {
            TIER_HIGH: "[HIGH]",
            TIER_MEDIUM: "[MED] ",
            TIER_LOW: "[LOW] ",
            TIER_NONE: "[NONE]",
        }[r.tier]
        print(f"  {r.name:<22} {r.size:>6}   {r.n_raw_constants:>4} {r.n_rare_constants:>5}  "
              f"{r.n_strings:>4} {r.n_unique_strings:>4}  {r.n_external_calls:>4}  {r.n_queries:>3}   {tier_marker}")

    print("-" * 110)
    print("  Legend: RawK=raw constants, RareK=rare constants (post-filter), "
          "Str=strings, UStr=unique strings (scored), ExtC=external calls, Q=queries built")


def print_distribution(results: list[FunctionResult]):
    """Print the identifiability tier distribution."""
    total = len(results)
    counter = Counter(r.tier for r in results)

    print()
    print("=" * 70)
    print("  IDENTIFIABILITY DISTRIBUTION")
    print("=" * 70)
    print(f"  Total functions analyzed:  {total}")
    print()

    bar_width = 40
    for tier in TIER_ORDER:
        count = counter.get(tier, 0)
        pct = (count / total * 100) if total else 0
        filled = int(bar_width * count / total) if total else 0
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"  {tier:<7} {count:>3}/{total} ({pct:>5.1f}%)  [{bar}]")


def print_matching_ratio(results: list[FunctionResult]):
    """Print the expected matching ratio based on identifiability."""
    total = len(results)
    n_high = sum(1 for r in results if r.tier == TIER_HIGH)
    n_med = sum(1 for r in results if r.tier == TIER_MEDIUM)
    n_low = sum(1 for r in results if r.tier == TIER_LOW)
    n_none = sum(1 for r in results if r.tier == TIER_NONE)

    searchable = n_high + n_med + n_low
    reliable = n_high + n_med

    print()
    print("=" * 70)
    print("  EXPECTED MATCHING RATIO (Stripped-Binary Search)")
    print("=" * 70)
    print(f"  Searchable (any tier except NONE):    {searchable:>3}/{total}  ({searchable/total*100:.1f}%)")
    print(f"  Reliably matchable (HIGH or MEDIUM):  {reliable:>3}/{total}  ({reliable/total*100:.1f}%)")
    print(f"  High-confidence matches (HIGH only):  {n_high:>3}/{total}  ({n_high/total*100:.1f}%)")
    print(f"  Unidentifiable (NONE):                {n_none:>3}/{total}  ({n_none/total*100:.1f}%)")


def print_unidentifiable(results: list[FunctionResult]):
    """List functions that cannot be identified and explain why."""
    unidentifiable = [r for r in results if r.tier == TIER_NONE]
    low_tier = [r for r in results if r.tier == TIER_LOW]

    if not unidentifiable and not low_tier:
        return

    print()
    print("=" * 70)
    print("  FAILURE-MODE ANALYSIS")
    print("=" * 70)

    if unidentifiable:
        print(f"\n  NONE tier ({len(unidentifiable)} function(s)): no searchable features")
        for r in unidentifiable:
            print(f"    - {r.name} @ {r.address} ({r.size} bytes)")
            print(f"      Raw constants: {r.n_raw_constants} (all filtered as noise)")
            print(f"      Strings: {r.n_strings} | External calls: {r.n_external_calls}")
            print(f"      >> Reason: thin wrapper or trivial function with no unique signal")

    if low_tier:
        print(f"\n  LOW tier ({len(low_tier)} function(s)): only one weak signal")
        for r in low_tier:
            print(f"    - {r.name} @ {r.address}: "
                  f"{r.n_rare_constants} rare constants, "
                  f"{r.n_unique_strings} unique strings, "
                  f"{r.n_external_calls} external calls")


def print_best_cases(results: list[FunctionResult]):
    """Highlight the best-case functions (most searchable)."""
    high_tier = [r for r in results if r.tier == TIER_HIGH]
    if not high_tier:
        return

    # Sort by total searchable features
    high_tier.sort(
        key=lambda r: r.n_rare_constants + r.n_unique_strings,
        reverse=True,
    )

    print()
    print("=" * 70)
    print("  STRONGEST CANDIDATES (Top 5 HIGH-tier functions)")
    print("=" * 70)
    for r in high_tier[:5]:
        print(f"\n  {r.name} @ {r.address}")
        print(f"    Rare constants:  {r.n_rare_constants}")
        print(f"    Unique strings:  {r.n_unique_strings}")
        print(f"    Queries built:   {r.n_queries}")
        print(f"    Top search terms:")
        for t in r.top_search_terms:
            print(f"      - {t}")
        if r.top_queries:
            print(f"    Example query:   {r.top_queries[0]}")


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Measure whole-binary identifiability ratio.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data",
        default=os.path.join(
            os.path.dirname(__file__), "..", "examples", "zlib_full_corpus.json"
        ),
        help="Path to Ghidra JSON output (default: zlib_full_corpus.json)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save the full JSON report (optional)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  WHOLE-BINARY MATCHING RATIO EXPERIMENT")
    print("=" * 70)
    print(f"  Corpus:  {args.data}")

    with open(args.data) as f:
        data = json.load(f)

    print(f"  Binary:  {data.get('binary', 'unknown')}")
    print(f"  Total functions in binary: {data.get('total_functions', 'unknown')}")
    print(f"  Functions in corpus:       {len(data['functions'])}")

    results = run_experiment(data)

    print_per_function_table(results)
    print_distribution(results)
    print_matching_ratio(results)
    print_best_cases(results)
    print_unidentifiable(results)

    print()
    print("=" * 70)
    print("  INTERPRETATION")
    print("=" * 70)
    print("""
  The reliably-matchable ratio (HIGH + MEDIUM tiers) is the key metric.
  These are functions with enough internal signal to construct discriminating
  multi-term GitHub queries without relying on symbol names.

  HIGH-tier functions (cross-category signals) reliably return the correct
  source file as the top match in testing. MEDIUM-tier functions usually
  match but may require LLM verification to disambiguate similar candidates.

  LOW-tier and NONE-tier functions are the fundamental limitation of a
  stripped-binary, search-based approach. They are typically:
    - Trivial wrappers that only call one external function
    - Auto-generated glue code (PLT stubs, initializers)
    - Pure math functions using only common constants (0, 1, shift amounts)

  For zlib specifically, the algorithmic core (adler32, crc32, inflate,
  deflate) produces rich feature sets. Utility wrappers (zcalloc, zcfree,
  uncompress) are harder to identify without symbol information — which
  aligns with the tool's fundamental design limits.
""")

    if args.output:
        report = {
            "corpus": args.data,
            "binary": data.get("binary"),
            "total_functions": len(results),
            "distribution": dict(Counter(r.tier for r in results)),
            "reliably_matchable_pct": round(
                sum(1 for r in results if r.tier in [TIER_HIGH, TIER_MEDIUM])
                / len(results) * 100, 1
            ),
            "functions": [asdict(r) for r in results],
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Full JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
