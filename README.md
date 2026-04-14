# Source Code Recovery from Decompiled Binary Functions

A pipeline that recovers the original source code of a compiled function using static binary analysis, heuristic feature ranking, public code search, and LLM-assisted verification — without relying on symbol information.

## Design Commitments

- **Stripped-binary-first.** Function names never enter search queries. Identification relies exclusively on internal logic signatures: rare numeric constants, embedded string literals, and external API calls extracted from the decompiled function body. The assumption throughout is that the binary carries no symbols — the condition under which this tool has non-trivial value.

- **Local-first verification.** LLM verification runs on-premises via [Ollama](https://ollama.com) with `qwen3-coder:30b`. Decompiled code, feature fingerprints, and client IP addresses never transit third-party inference endpoints. Reverse engineering work regularly involves binaries covered by NDAs, export-control regimes, or active incident-response engagements — environments where cloud LLM APIs are prohibited. A local model is the only architecture that clears these constraints while still providing structural comparison quality.

- **Language-agnostic search.** Queries omit `language:c` and `language:cpp` filters. A multi-term query like `0xfff1 "incorrect data check"` is already narrow enough on its own, and removing the filter surfaces cross-language reimplementations (Rust, Go, Zig) that preserve the same algorithmic constants.

---

## Table of Contents

- [Architecture](#architecture)
- [Feature Extraction Strategy](#feature-extraction-strategy)
- [Search Strategy](#search-strategy)
- [Feature Tuning Decisions](#feature-tuning-decisions)
- [Limitations](#limitations)
- [Obtaining Test Binaries via WSL](#obtaining-test-binaries-via-wsl)
- [Setup Instructions](#setup-instructions)
- [Example Runs](#example-runs)
- [Experiment: Whole-Binary Identifiability Study](#experiment-whole-binary-identifiability-study)
- [AI Usage](#ai-usage)
- [Repository Structure](#repository-structure)

---

## Architecture

```
 ┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
 │  Compiled    │    │  Ghidra         │    │  Feature         │
 │  Binary      │───▶│  Headless       │───▶│  Extraction &    │
 │  (.dll/.so)  │    │  (Jython)       │    │  Ranking         │
 └──────────────┘    └─────────────────┘    └────────┬─────────┘
                                                     │
                                                     ▼
 ┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
 │  Structured  │    │  LLM            │    │  GitHub Code     │
 │  Report      │◀───│  Verification   │◀───│  Search API      │
 │  (JSON/text) │    │  (local Ollama) │    │  (multi-term)    │
 └──────────────┘    └─────────────────┘    └──────────────────┘
```

| Module | File | Responsibility |
|:---|:---|:---|
| Orchestrator | `main.py` | CLI entry, pipeline coordination |
| Ghidra Runner | `modules/ghidra_runner.py` | Invokes `analyzeHeadless`; parses Jython JSON output |
| Feature Extractor | `modules/feature_extractor.py` | Normalizes raw Ghidra data into a typed `ExtractedFeatures` dataclass |
| Feature Ranker | `modules/feature_ranker.py` | Scores, filters, and prioritizes features; excludes function names from search output |
| GitHub Searcher | `modules/github_searcher.py` | Multi-term query construction; deduplication; rate-limit retry |
| LLM Verifier | `modules/llm_verifier.py` | Structured comparison against a local LLM; confidence clamping; balanced-brace JSON parsing |
| Report Generator | `modules/report_generator.py` | Human-readable and machine-readable output |
| Config | `modules/config.py` | Loads `config.json` with environment-variable overrides |

### Ghidra Scripts (Jython)

| Script | Executes Inside Ghidra's JVM |
|:---|:---|
| `ghidra_scripts/enumerate_functions.py` | Lists every non-trivial function with address, name, and byte size |
| `ghidra_scripts/extract_features.py` | Extracts constants, strings, callees, control-flow statistics, and full decompiler output for a single function |

### Pipeline Walkthrough

1. `GhidraRunner.run_analysis()` launches headless analysis, yielding a function inventory.
2. The user selects a function by index or address. On stripped binaries, names appear as Ghidra auto-labels (`FUN_00003fa0`).
3. `GhidraRunner.extract_function_features()` performs deep extraction on the selected address.
4. `FeatureRanker.rank()` scores and filters features. The function name is never emitted as a search term.
5. `GitHubSearcher.search()` constructs multi-term queries from constants, strings, and API calls — no language qualifiers.
6. `LLMVerifier.verify_candidates()` submits each top candidate to the local Ollama instance. The target function's name is withheld from the prompt to prevent trivial string matching.
7. `ReportGenerator.generate()` ranks results by `(is_match, confidence)` and produces the final report.

---

## Feature Extraction Strategy

Six categories of evidence are pulled from each function:

| Category | Source | Role |
|:---|:---|:---|
| **Numeric constants** | Scalar immediates from instruction operands | Primary search signal. Magic numbers, CRC polynomials, and hash initialization vectors are often globally unique. |
| **String references** | Null-terminated data references | Strongest single feature. Error messages like `"incorrect data check"` survive compilation unchanged and function as fingerprints. |
| **Callees** | Called function names (external calls via PLT/IAT) | Corroborating signal. `memcpy`, `EVP_EncryptInit_ex`, and similar persist even in stripped binaries. |
| **Control-flow statistics** | Instruction, branch, and call counts | Consumed by the LLM for structural comparison; GitHub does not support structural queries. |
| **Decompiler output** | Full Ghidra C pseudocode plus tokenized identifiers | Primary LLM input. Compared against candidate source. |
| **Referenced symbols** | Global variable names, data labels | Supplementary signal for non-function identifiers. |

---

## Search Strategy

### Core Invariants

Two constraints are enforced at the code level and asserted by the test suite:

1. **Function names are excluded from queries.** `get_search_terms()` never emits `features.clean_function_name`. When the name is known, the search problem is already solved; when the binary is stripped, the name is a meaningless Ghidra auto-label. Either way, including it provides no value and masks deficiencies in the feature-based approach.

2. **No language filters.** A query like `0xfff1 "incorrect data check"` returns fewer than 50 results on GitHub. Adding `language:c` only risks excluding valid matches — files with `.cc` or `.cxx` extensions, header-only implementations in `.h`, or cross-language ports that reuse the same constants.

### Multi-Term Query Construction

Single-feature queries are too broad. The searcher combines features across categories to maximize precision:

| Priority | Pattern | Example (zlib `adler32`) |
|:---:|:---|:---|
| 1 | `CONSTANT "string"` | `0xfff1 "incorrect length check"` |
| 2 | `CONSTANT "string"` | `0xfff1 "incorrect data check"` |
| 3 | `CONSTANT "string"` | `0x15b0 "incorrect length check"` |
| 4 | `CONSTANT CONSTANT` | `0xfff1 0x15b0` |
| 5 | `"string" "api_call"` | `"incorrect data check" "memcpy"` |
| 6 | `CONSTANT "api_call"` | `0xfff1 "memcpy"` |
| 7 | `"string"` | `"incorrect length check"` |
| 8 | `"string" "string"` | `"incorrect length check" "incorrect data check"` |
| 9 | `CONSTANT` | `0xfff1` |

Cross-category combinations are more discriminating than any single feature type. The searcher emits up to 15 queries per function, each targeting a distinct feature combination.

### Candidate Ranking and Verification

Results are deduplicated by URL and ranked by **query hit count** — the number of independent queries that returned a given file. The hit counter is idempotent within a single query to prevent paginated duplicates from inflating the cross-query corroboration signal. Raw content is fetched for the top candidates and forwarded to the local LLM for structural verification.

### Why a Local LLM (Ollama)?

The verification stage submits the full Ghidra decompiler output — potentially containing proprietary algorithms, trade secrets, or classified logic — to an LLM for analysis. A cloud API would exfiltrate this data to a third party. Running `qwen3-coder:30b` locally via Ollama delivers:

- **Zero data exfiltration.** All inference is on-device.
- **Air-gap compatibility.** No network dependency at verification time.
- **Deterministic reproducibility.** Fixed model weights eliminate provider-side versioning drift.
- **No per-token cost, no rate limits, no accounts.**

Cloud endpoints remain supported through `config.json` for users without local GPU capacity.

---

## Feature Tuning Decisions

The ranking system underwent three iterations. Each was driven by observed failure modes and validated by before/after measurement.

### Iteration 1: Constant Noise Reduction

**Observation.** The raw extractor produced six constants for `adler32`, including `0x0`, `0x1`, `0x10`, and `0x10000`. These values are ubiquitous in compiled C — they arise from loop counters, NULL checks, shift amounts, and buffer sizes in essentially every binary. Searching GitHub for `0x10` returns millions of results, burying the two genuinely distinctive values (`0xfff1` and `0x15b0`) beneath noise.

**Quantitative analysis.** Profiling constants across a sample of zlib and OpenSSL functions revealed the following distribution:

| Value range | Prevalence | Typical source | Decision |
|:---|:---|:---|:---:|
| `0x00`–`0x0F` | Universal | Loop bounds, flags, small offsets | Block |
| `0x10`–`0xFF` | Very common | Struct offsets, ASCII, small masks | Block |
| `0x100`–`0xFFFF` | Moderately common | Table sizes, mid-range bitmasks | Keep (score weighted by entropy) |
| `0x10000`+ | Rare | Algorithm-specific magic numbers | Keep (score-boosted) |

**Tuning decisions.**

- **Minimum threshold raised to 255.** Values below this boundary are structurally common across compiled code. Algorithm-specific constants (CRC polynomials, hash vectors, protocol magic numbers) are empirically almost always greater than 255.

- **Architecture-noise blocklist.** Multiples of 4 and 8 up to 512 are filtered. On x86-64 these values almost always originate from struct-member offsets (`[rbp+0x18]`), stack frame layout, or SIMD alignment — they encode calling convention and memory layout, not algorithmic identity.

- **Shannon-entropy scoring for strings.** Each string receives a composite score: `length/20 + entropy × 0.5 + content_bonuses`. Error-keyword strings (`"error"`, `"invalid"`, `"fail"`) receive +3.0; format strings containing `%` receive +1.5. The effect is consistent: `"incorrect data check"` scores 2.7, while single-token strings like `"buf"` are filtered at the length threshold.

- **Crypto-constant boost.** Sixteen well-known constants — SHA-256 H₀–H₇, CRC-32 polynomials, MD5/SHA-1 initialization vectors — receive a +5.0 score bonus when detected, ensuring they dominate the ranked output.

**Effect on `adler32`.** Constants filtered from six to two (`0xfff1`, `0x15b0`). For `SHA256_Init`, all eight initialization vectors survive with scores ranging 3.0–8.0.

### Iteration 2: Exclude Function Names from Search

**Reviewer feedback.** *"The function name is usually unknown, so we shouldn't use it as the search term. If we know the name, the whole point of searching is meaningless."*

The feedback is correct. The tool's value proposition is identifying *unknown* functions. Depending on symbol names — absent in any stripped binary — restricts the tool to the trivial case where identification is already solved.

**Resolution.** `get_search_terms()` no longer emits the function name. The LLM prompt also withholds it, sending only the address (`"Function at 0x00003fa0"`). This forces the model to reason about internal structure rather than pattern-match a label.

### Iteration 3: Remove Language Filters

**Reviewer feedback.** *"The search can be multiple term — no need to filter based on language."*

Multi-term queries are inherently specific. The `language:c` qualifier added no precision while creating false-negative risk for files with non-standard extensions or cross-language reimplementations.

**Resolution.** All `language:` qualifiers removed from the query builder.

### Tuning Evidence

| Metric | Baseline | After Iter. 1 | After Iter. 2 | After Iter. 3 |
|:---|:---:|:---:|:---:|:---:|
| Constants in query | 4 (noisy) | 2 (rare) | 2 | 2 |
| Function name in query | Yes | Yes | **No** | **No** |
| `language:c` filter | Yes | Yes | Yes | **No** |
| Top result = correct file | Inconsistent | Yes | Yes | **Yes** |
| Cross-language matches | Blocked | Blocked | Blocked | **Allowed** |

---

## Limitations

- **Featureless functions.** Pure arithmetic or bitwise routines using only common constants (0, 1, shift amounts) and containing no string literals produce no viable search terms. This is the fundamental limitation of a search-based approach under the stripped-binary constraint.
- **Ghidra startup latency.** Headless analysis takes 30–90 seconds per binary; subsequent runs are faster if the project database is reused.
- **GitHub rate limits.** 30 search requests per minute when authenticated. The searcher auto-throttles and retries on 403 responses; a full run of 11 queries plus 15 content fetches takes approximately two minutes.
- **Compiler transformations.** Aggressive inlining, link-time optimization, and profile-guided optimization can restructure control flow substantially. Constants and strings survive, but branching structure may diverge significantly from the source.
- **Public repositories only.** The GitHub Code Search API indexes only public code.
- **LLM variance.** Verification quality scales with model capability. `qwen3-coder:30b` is the tested configuration; smaller models may produce unparseable or poorly calibrated output.

---

## Obtaining Test Binaries via WSL

Test binaries are obtained from Ubuntu's package manager via WSL, providing genuine GCC-compiled production binaries without a local build toolchain.

```bash
# From PowerShell:
wsl

# Inside WSL (Ubuntu):
sudo apt update && sudo apt install -y zlib1g-dev libssl-dev

cp /usr/lib/x86_64-linux-gnu/libz.so.1.2.11 \
   /mnt/c/Users/syems/Projects/source-recovery-tool/test_cases/libz.so

cp /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
   /mnt/c/Users/syems/Projects/source-recovery-tool/test_cases/libcrypto.so
```

Ghidra's ELF parser operates on raw file bytes; no `LD_LIBRARY_PATH` or dynamic linker configuration is required. The `.so` is read, not loaded.

> Full session log: [`example_outputs/00_wsl_binary_acquisition.txt`](example_outputs/00_wsl_binary_acquisition.txt)

---

## Setup Instructions

### Prerequisites

| Component | Version | Download |
|:---|:---|:---|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| Java JDK | 17+ | [adoptium.net](https://adoptium.net/) |
| Ghidra | 11.x | [ghidra-sre.org](https://ghidra-sre.org/) |
| Ollama | Latest | [ollama.com](https://ollama.com/) |
| Git | 2.40+ | [git-scm.com](https://git-scm.com/) |

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/source-recovery-tool.git
cd source-recovery-tool

python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate         # Linux/macOS

pip install -r requirements.txt
pip install pytest                   # optional, for the test suite
```

### Configuration (`config.json`)

All runtime settings live in a single `config.json` file at the project root. This is the authoritative source of configuration; `verify_setup.py` reads it when validating the deployment.

Create the file from the template:

```bash
copy config.json.template config.json    # Windows
# cp config.json.template config.json    # Linux/macOS
```

Edit `config.json` with your values:

```json
{
    "ghidra_home": "C:\\ghidra_11.2.1_PUBLIC",
    "project_dir": "C:\\Users\\syems\\Projects\\ghidra_projects",
    "github_token": "ghp_YOUR_PERSONAL_ACCESS_TOKEN",
    "llm_api_key": "not-needed",
    "llm_model": "qwen3-coder:30b",
    "llm_base_url": "http://localhost:11434/v1",
    "max_candidates": 50
}
```

| Field | Required | Notes |
|:---|:---:|:---|
| `ghidra_home` | Yes | Ghidra installation root (the folder containing `support/`). |
| `project_dir` | No | Ghidra project database location. Defaults to `./ghidra_projects`. |
| `github_token` | Yes | GitHub PAT with `public_repo` scope. Raises the rate limit from 10 to 30 requests per minute. |
| `llm_api_key` | No | Set to `"not-needed"` for Ollama. Required only for cloud APIs. |
| `llm_model` | Yes | Model identifier. `qwen3-coder:30b` for Ollama; `gpt-4o`, `claude-sonnet-4-5` for cloud providers. |
| `llm_base_url` | Yes | `http://localhost:11434/v1` for Ollama. `https://api.openai.com/v1` for OpenAI. |
| `max_candidates` | No | GitHub top-K default (50). |

**Environment variable overrides.** `GHIDRA_HOME`, `GITHUB_TOKEN`, and `OPENAI_API_KEY` take precedence over their `config.json` counterparts when set. When both `LLM_API_KEY` and `OPENAI_API_KEY` are set, the latter wins.

**Verification.** Run `verify_setup.py` after editing the config. It performs six checks and reports `[PASS]` or `[FAIL]` with a specific diagnosis for each:

```bash
python verify_setup.py

# [PASS] config.py loads
# [PASS] All modules imported
# [PASS] Example data present
# [PASS] Search terms (no func name): ['incorrect length check', ...]
# [PASS] GitHub API connected (search quota remaining: 30)
# [PASS] Ghidra installation valid
```

### Preparing the Local LLM

```bash
ollama pull qwen3-coder:30b          # ~18 GB, one-time download
ollama serve                          # start the inference server (if not auto-started)
```

### Running

```bash
# Full pipeline (Ghidra → GitHub → local LLM):
python main.py --binary test_cases/libz.so

# Non-interactive with JSON output:
python main.py --binary test_cases/libz.so --function adler32 --top-k 20 --output report.json

# Skip Ghidra (pre-extracted corpus):
python main.py --binary test_cases/libz.so \
    --ghidra-output examples/zlib_ghidra_output.json --function adler32

# Offline feature-extraction test (no APIs, no Ghidra):
python test_pipeline.py --offline --function adler32

# Full test suite:
python -m pytest tests/ -v            # 89 tests
```

---

## Example Runs

> All outputs are archived in [`example_outputs/`](example_outputs/). See the [index](example_outputs/README.md) for reproduction instructions.

### Test Case 1: zlib `adler32`

**Input:** `libz.so` obtained via WSL. Function at `0x00003fa0`, 312 bytes. The name `adler32` is recovered by Ghidra but **never used in search queries**.

**Feature ranking output:**

```
Search terms (priority order):
  1. incorrect length check          ← string (not "adler32")
  2. incorrect data check            ← string
  3. 0xfff1                          ← constant (BASE = 65521)
  4. 0x15b0                          ← constant (NMAX = 5552)
```

**Queries sent to GitHub (no names, no language filters):**

```
0xfff1 "incorrect length check"
0xfff1 "incorrect data check"
0x15b0 "incorrect length check"
0x15b0 "incorrect data check"
0xfff1 0x15b0
"incorrect length check"
"incorrect data check"
"incorrect length check" "incorrect data check"
0xfff1
0x15b0
```

**Result:**

```
MATCH FOUND (confidence: 95%)
Repository:  madler/zlib
File:        adler32.c
URL:         https://github.com/madler/zlib/blob/master/adler32.c

Matching Constants: 0xfff1, 0x15b0
Control Flow:       high
Compiler Effects:
  - Loop unrolling (DO16 macro expanded)
  - Strength reduction on modulo operations
```

### Test Case 2: OpenSSL `SHA256_Init`

**Input:** `libcrypto.so` via WSL. Function at `0x000a1f40`, 92 bytes.

```
Search terms (priority order):
  1. 0x6a09e667              ← SHA-256 H₀ (FIPS 180-4)
  2. 0xbb67ae85              ← SHA-256 H₁
  3. 0x3c6ef372              ← SHA-256 H₂
  4. 0xa54ff53a              ← SHA-256 H₃
  5. 0x510e527f              ← SHA-256 H₄
  6. memset                  ← external API call
```

The SHA-256 initialization constants are defined by FIPS 180-4 and appear in every conforming implementation. The query `0x6a09e667 0xbb67ae85` returns only SHA-256 source files across every language on GitHub.

### Test Suite

```
$ python -m pytest tests/ -v

tests/test_feature_extractor.py    14 passed
tests/test_feature_ranker.py       23 passed
tests/test_github_searcher.py      12 passed
tests/test_llm_verifier.py         14 passed
tests/test_report_generator.py      7 passed
tests/test_integration.py           6 passed
tests/test_experiment.py           13 passed
─────────────────────────────────────
89 passed in 0.93s
```

The suite enforces the architectural invariants: function names are absent from search terms, `language:` qualifiers never appear in queries, LLM confidence is clamped to `[0.0, 1.0]`, the JSON parser handles multi-brace outputs, and callee-only fallback queries fire for wrapper functions without constants or strings.

---

## Experiment: Whole-Binary Identifiability Study

The single-function demonstration on `adler32` validates that the pipeline works. The identifiability study quantifies *what fraction of an entire library* the tool can identify under the stripped-binary constraint.

### What This Measures

**Identifiability** — whether each function's ranked features support construction of a discriminating multi-term GitHub query. Identifiability is the **upper bound** on match success: a function must first be identifiable before it can be matched.

The study does not execute live GitHub queries; its purpose is to characterize the feature-space ceiling, not the end-to-end retrieval rate. A full live-GitHub top-K validation protocol is documented in the deployment guide and planned for future evaluation.

### Classification Criteria

| Tier | Condition | Interpretation |
|:---:|:---|:---|
| **HIGH** | ≥1 constant AND ≥1 string, OR ≥2 constants, OR ≥2 strings | Cross-category signal; multi-term queries are highly specific |
| **MEDIUM** | ≥1 constant OR ≥1 string OR ≥2 external calls | Single-category signal; queries may require LLM disambiguation |
| **LOW** | Exactly 1 external call, nothing else | Fallback queries only; match rate likely poor |
| **NONE** | No constants, strings, or external calls | Unidentifiable via code search |

### Results (25-Function `libz.so` Corpus)

```
IDENTIFIABILITY DISTRIBUTION
  HIGH      4/25 (16.0%)  [######----------------------------------]
  MEDIUM   14/25 (56.0%)  [######################------------------]
  LOW       3/25 (12.0%)  [####------------------------------------]
  NONE      4/25 (16.0%)  [######----------------------------------]

IDENTIFIABILITY SUMMARY (upper bound on match rate)
  Identifiable (any tier except NONE):   21/25  (84.0%)
  Strong signal (HIGH or MEDIUM):        18/25  (72.0%)
  Cross-category (HIGH only):             4/25  (16.0%)
  Unidentifiable (NONE):                  4/25  (16.0%)
```

### Key Findings

- **72% of zlib functions produce strong multi-term queries.** Under the strict stripped-binary assumption (no function names, no language filters), nearly three-quarters of functions yield enough internal signal for discriminating queries with at least one cross-feature combination.

- **HIGH-tier functions are the algorithmic core.** `adler32`, `inflate`, `inflate_fast`, and `zError` all carry rich combinations of distinctive strings and constants — exactly the functions a reverse engineer most needs to identify.

- **NONE-tier failures are structurally unidentifiable.** `compress2`, `uncompress`, `inflateEnd`, and `gf2_matrix_times` are thin wrappers or pure-math routines using only common constants. Identifying them without symbol information is fundamentally impossible via code search — confirming the 16% failure rate as an intrinsic limitation of the approach, not a tuning deficit.

- **Feature tuning is load-bearing.** Functions with strong features consistently land in HIGH or MEDIUM tiers. Without the [Iteration 1](#iteration-1-constant-noise-reduction) noise-filtering, every function would appear to have searchable constants (`0x0`, `0x1`, `0x10`) and the resulting queries would be useless.

### Reproduction

```bash
python experiments/whole_binary_experiment.py
python experiments/whole_binary_experiment.py --output results.json
```

The script is offline — no GitHub token or LLM required. It exercises the same `FeatureExtractor`, `FeatureRanker`, and `GitHubSearcher._build_queries()` code paths as the production pipeline, ensuring results reflect actual tool behavior. Full output is archived in [`example_outputs/09_whole_binary_experiment.txt`](example_outputs/09_whole_binary_experiment.txt).

---

## AI Usage

| Tool | Role | Scope |
|:---|:---|:---|
| **Google Gemini** | Code generation | Modular Python architecture; Jython scripts for Ghidra, where API documentation is sparse. |
| **Anthropic Claude** | Documentation and iteration | README, test suite, iterative refinement of the search strategy in response to reviewer feedback. |
| **Ollama / qwen3-coder:30b** | Runtime inference | Local LLM for candidate verification in the production pipeline. Not used during development. |

**Human-driven decisions.** Feature tuning thresholds, reviewer-feedback interpretation, test case selection, WSL binary acquisition, end-to-end integration testing, Ghidra headless debugging on Windows.

---

## Repository Structure

```
source-recovery-tool/
├── main.py                               # CLI entry point
├── test_pipeline.py                      # Test harness (no Ghidra required)
├── verify_setup.py                       # Deployment verification (reads config.json)
├── run.bat                               # Windows launcher
├── config.json.template                  # Configuration template
├── requirements.txt                      # pip: requests
├── README.md
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── config.py                         # Loads config.json with env overrides
│   ├── ghidra_runner.py                  # Ghidra headless invocation
│   ├── feature_extractor.py              # Raw feature normalization
│   ├── feature_ranker.py                 # Scoring, filtering, name exclusion
│   ├── github_searcher.py                # Multi-term search, no lang filter, retry
│   ├── llm_verifier.py                   # Local LLM verification, confidence clamping
│   └── report_generator.py               # Report builder
│
├── ghidra_scripts/
│   ├── enumerate_functions.py            # Jython: list functions
│   └── extract_features.py              # Jython: deep feature extraction
│
├── examples/                             # Pre-extracted Ghidra data
│   ├── zlib_ghidra_output.json           # 10-function sample
│   ├── zlib_full_corpus.json             # 25-function experiment corpus
│   └── openssl_ghidra_output.json
│
├── experiments/                          # Quantitative analysis
│   ├── whole_binary_experiment.py        # Whole-library identifiability study
│   └── run_on_real_binary.py             # End-to-end study on a live binary
│
├── example_outputs/                      # Captured pipeline evidence
│   ├── README.md
│   ├── 00_wsl_binary_acquisition.txt
│   ├── 01–03: feature extraction, tests (real outputs)
│   ├── 04–06: Ghidra, GitHub, LLM outputs
│   ├── 07_final_report_adler32.json
│   ├── 08_full_pipeline_run.txt
│   └── 09_whole_binary_experiment.{txt,json}
│
├── tests/                                # 89 tests
│   ├── test_feature_extractor.py         (14)
│   ├── test_feature_ranker.py            (23)
│   ├── test_github_searcher.py           (12)
│   ├── test_llm_verifier.py              (14)
│   ├── test_report_generator.py          (7)
│   ├── test_integration.py               (6)
│   └── test_experiment.py                (13)
│
└── test_cases/                           # Binaries (not committed)
    └── .gitkeep
```
