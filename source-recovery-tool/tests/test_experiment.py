"""
Tests for the whole-binary experiment's identifiability classifier.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from whole_binary_experiment import classify_identifiability, TIER_HIGH, TIER_MEDIUM, TIER_LOW, TIER_NONE


class TestIdentifiabilityClassifier:
    """Test the tier classification logic."""

    def test_high_tier_constant_and_string(self):
        """One rare constant + one unique string = HIGH (cross-category)."""
        assert classify_identifiability(n_rare_constants=1, n_unique_strings=1, n_external_calls=0) == TIER_HIGH

    def test_high_tier_two_constants(self):
        """Two rare constants = HIGH (like SHA256_Init)."""
        assert classify_identifiability(n_rare_constants=2, n_unique_strings=0, n_external_calls=0) == TIER_HIGH

    def test_high_tier_two_strings(self):
        """Two unique strings = HIGH (like zError)."""
        assert classify_identifiability(n_rare_constants=0, n_unique_strings=2, n_external_calls=0) == TIER_HIGH

    def test_high_tier_adler32_profile(self):
        """adler32 has 2 constants and 2 strings — should be HIGH."""
        assert classify_identifiability(n_rare_constants=2, n_unique_strings=2, n_external_calls=0) == TIER_HIGH

    def test_medium_tier_one_constant(self):
        """One rare constant alone = MEDIUM (like crc32)."""
        assert classify_identifiability(n_rare_constants=1, n_unique_strings=0, n_external_calls=0) == TIER_MEDIUM

    def test_medium_tier_one_string(self):
        """One unique string alone = MEDIUM (like gzopen)."""
        assert classify_identifiability(n_rare_constants=0, n_unique_strings=1, n_external_calls=0) == TIER_MEDIUM

    def test_medium_tier_two_callees(self):
        """Two external API calls = MEDIUM (wrapper functions)."""
        assert classify_identifiability(n_rare_constants=0, n_unique_strings=0, n_external_calls=2) == TIER_MEDIUM

    def test_low_tier_one_callee(self):
        """Single external call = LOW (like zcalloc → calloc)."""
        assert classify_identifiability(n_rare_constants=0, n_unique_strings=0, n_external_calls=1) == TIER_LOW

    def test_none_tier_no_features(self):
        """No features at all = NONE (like uncompress wrapper)."""
        assert classify_identifiability(n_rare_constants=0, n_unique_strings=0, n_external_calls=0) == TIER_NONE

    def test_rich_function_is_high(self):
        """Functions with many features of each type are clearly HIGH."""
        assert classify_identifiability(n_rare_constants=5, n_unique_strings=10, n_external_calls=3) == TIER_HIGH


class TestExperimentEndToEnd:
    """Smoke test that the experiment runs on the real corpus."""

    def test_corpus_loads_and_processes(self):
        """The full corpus processes without errors."""
        import json
        from whole_binary_experiment import run_experiment

        corpus_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "zlib_full_corpus.json"
        )
        with open(corpus_path) as f:
            data = json.load(f)

        results = run_experiment(data)
        assert len(results) == 25

    def test_adler32_classified_high(self):
        """adler32 (our showcase function) must land in HIGH tier."""
        import json
        from whole_binary_experiment import run_experiment

        corpus_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "zlib_full_corpus.json"
        )
        with open(corpus_path) as f:
            data = json.load(f)

        results = run_experiment(data)
        adler = next(r for r in results if r.name == "adler32")
        assert adler.tier == TIER_HIGH

    def test_reliably_matchable_ratio_meets_threshold(self):
        """For zlib, reliably-matchable (HIGH+MEDIUM) should be ≥ 60%."""
        import json
        from whole_binary_experiment import run_experiment

        corpus_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "zlib_full_corpus.json"
        )
        with open(corpus_path) as f:
            data = json.load(f)

        results = run_experiment(data)
        reliable = sum(1 for r in results if r.tier in [TIER_HIGH, TIER_MEDIUM])
        ratio = reliable / len(results)
        assert ratio >= 0.60, f"Reliably-matchable ratio is only {ratio:.1%}"
