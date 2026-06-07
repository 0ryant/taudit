# arXiv taudit FP/FN labeling protocol

Date: 2026-06-01
Status: protocol draft; no correctness claim yet

## Purpose

The arXiv scanner paper reports detection behavior over a shared corpus, but it
does not provide a verified ground-truth label set. taudit must therefore keep
detection volume separate from correctness.

## Minimum protocol

1. Select a stratified sample from the benchmark corpus, covering every mapped
   weakness class with at least one positive candidate where available.
2. Add seeded fixtures for rare or missing classes so each class can be judged.
3. Have two independent reviewers label each workflow/weakness pair.
4. Use a written rubric per weakness class before labeling starts.
5. Adjudicate disagreements and retain disagreement counts.
6. Mark parser partiality and unknowable provider state as `unjudgeable`, not
   as a true negative.
7. Report confidence intervals and sample coverage beside any precision or
   recall number.

## Label values

| Label | Meaning |
| --- | --- |
| `true_positive` | The finding identifies a real weakness under the rubric. |
| `false_positive` | The finding is emitted but the rubric says the weakness is absent. |
| `false_negative` | The rubric says the weakness is present and taudit emits no mapped finding. |
| `true_negative` | The rubric says the weakness is absent and taudit emits no mapped finding. |
| `unjudgeable` | Static YAML evidence is insufficient or provider/runtime state is required. |

## Stop conditions

Do not publish FP/FN numbers if:

- fewer than two reviewers complete the labeling;
- the rubric changes after labels are collected without a relabel pass;
- inter-reviewer disagreement remains unresolved;
- a class has too few examples to support the stated metric;
- parser partiality dominates the sample for a class.

## Evidence ceiling

Until this protocol is executed, the only safe correctness statement is:
`taudit has detection-volume evidence only`.
