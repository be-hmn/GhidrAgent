# Evaluation

This project uses small reverse-engineering challenges as regression benchmarks
for the JSON extraction pipeline.

## Scoring

Each benchmark case is scored on a 0.0 to 1.0 scale.

| Result | Score | Meaning |
|---|---:|---|
| correct | 1.0 | Final answer is correct and the JSON contains enough evidence to justify it. |
| partial | 0.5 | Useful evidence is present, but answer has ordering, omission, or minor reconstruction errors. |
| wrong | 0.0 | Answer is wrong or JSON does not contain enough evidence. |

Primary metric:

```text
accuracy = sum(case.score) / number_of_cases
```

Current baseline:

```text
Dataset: reversing.kr simple crackme baseline
Cases: 3
Correct: 3
Partial: 0
Wrong: 0
Accuracy: 100%
```

## Baseline Cases

| Case | Category | Result | Notes |
|---|---|---:|---|
| Easy Crack | simple_string_and_char_validation | correct | Requires short DAT data and character constraints. |
| Easy ELF | simple_elf_validation | correct | Solved from static JSON evidence. |
| Easy Keygen | simple_keygen_validation | correct | Solved from static JSON evidence. |

## What Counts As Pipeline Success

A case should only be marked `correct` when the JSON output contains the evidence
needed to justify the answer. If an LLM guesses correctly from outside context,
that should not be counted as extractor success.

Useful evidence fields include:

```text
decompiled_code
strings
resolved_data
validation_constraints
call_sequence
```

## Updating The Benchmark

Add new cases to:

```text
benchmarks/reversing_kr_baseline.json
```

Then run:

```powershell
.\.venv\Scripts\python.exe scripts\score_benchmark.py benchmarks\reversing_kr_baseline.json
```
