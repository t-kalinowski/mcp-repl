# Eval suite ideas: measuring whether `mcp-repl` helps

This document sketches a harness-agnostic eval design for answering two questions:

1. Does access to `mcp-repl` measurably accelerate an agent on R-centric tasks?
2. Do different `mcp-repl` tool descriptions measurably change outcomes?

The goal is a numeric benchmark that you can track over time and across tool/description variants.

## What we measure (per run)

- **Time to completion**: wall-clock time until the agent submits its final answer/artifacts.
- **Final quality grade**: a numeric score from a task-specific grader (often 0–1 or 0–100).
- **Token efficiency**: total tokens consumed for the run (optionally split by “model tokens” vs “tool output tokens” if your harness supports it).
- **Cached tokens**: tracked, but treated as a harness-level attribute (useful for interpreting results, not for optimizing the tool itself).

## Ablations (what to compare)

To isolate the value of `mcp-repl`, run the same tasks under controlled conditions:

- **No console**: the agent cannot call `mcp-repl` (baseline).
- **Console enabled**: the agent can call `mcp-repl` with the default tool description.
- **Console + description variants**: keep code identical, but swap the tool description text:
  - **Minimal**: “stateful R REPL; send code; state persists.”
  - **Operational**: include pager semantics, docs commands, debugger tips.
  - **Behavioral**: explicitly encourage “inspect-first”, browser-driven development, and private iteration before reporting.

This is effectively an ablation over *capability* (tool present) and *policy* (how well the agent knows to use it).

## Task design principles (so the console matters)

Good eval tasks for `mcp-repl` have three properties:

- **Statefulness is an advantage**: repeated iteration benefits from keeping objects resident (large data, intermediate transforms, model fits).
- **Inspection is required**: the agent must discover types/shapes/classes, error paths, or invariants; guessing is punished.
- **Evidence beats eloquence**: grading depends on computed results or verified artifacts, not on persuasive narrative.

Avoid tasks where a one-shot static answer is likely to do fine (purely conceptual questions, trivial scripts, tiny datasets).

## A simple task format: Markdown + YAML front matter

Treat each eval as a standalone Markdown file. The body is the prompt. The front matter declares inputs and expected outputs.

If you add a starter task catalog (for example under `eval/tasks/`), keep it in this format.

Example schema (illustrative; adjust to your eventual framework):

```md
---
id: eda-messy-csv-001
title: "EDA on a messy dataset"
tags: [r, eda, types, visualization]
difficulty: medium
time_limit_s: 900
resources:
  files:
    - path: data/messy_customers.csv
      description: "CSV with mixed types, missingness, inconsistent encodings"
artifacts:
  - path: artifacts/report.md
    description: "Concise findings + key tables"
  - path: artifacts/plot.png
    description: "One plot supporting the main finding"
grading:
  type: "script"
  entrypoint: graders/eda-messy-csv-001.R
  outputs:
    score_range: [0, 1]
tooling:
  mcp_repl:
    enabled: true
    description_variant: operational
---

You are helping a user analyze `data/messy_customers.csv`.

Goals:
1) Identify the top 3 predictors of churn (binary column `churn`).
2) Produce one plot that supports your conclusion.
3) Write a short report in `artifacts/report.md` and save the plot to `artifacts/plot.png`.

Constraints:
- Be robust to missing values and inconsistent types.
- Explain any assumptions.
```

## Concrete eval task proposals

Each proposal below is designed so that (a) inspection beats guessing and (b) persistence reduces repeated setup cost.

If you build concrete task stubs, place them in a directory like `eval/tasks/`.

### 1) “Messy CSV EDA + plot” (types + visualization)

**Prompt**: Given a CSV with mixed types (numeric stored as strings, factor levels with whitespace, missingness, date parsing issues), produce a small set of summary results and one plot, plus a short written report.

**Why `mcp-repl` helps**:
- Quickly inspect `str()`, `summary()`, `table()`, factor levels, missingness patterns.
- Iterate on cleaning steps without reloading.
- Generate a plot and visually verify it before reporting.

**Grader**:
- Checks report exists and includes required numeric values (within tolerance).
- Validates plot file exists and is a non-empty image.
- Optionally runs a hidden reference analysis and scores correlation / agreement on top predictors.

### 2) “Debug and fix” (browser-driven development)

**Prompt**: A small R package/project contains a failing function and a minimal test suite. Fix the bug without changing the tests. (Provide the project files in the eval resources.)

**Why `mcp-repl` helps**:
- Reproduce the failure and use `debugonce()`/`browser()` to inspect local state.
- Iterate quickly: patch code → reload/source → rerun minimal repro.

**Grader**:
- Runs the test suite; score is proportional to passing tests.
- Bonus points for avoiding regressions (hidden tests) and for minimal diff size if you want to penalize thrashing.

### 3) “Port a function” (reference objects + behavioral parity)

**Prompt**: Port a small function from Python (or C++) to R with provided fixtures. The function is subtle around edge cases (NA handling, integer overflow-ish behavior, floating precision, factor levels).

**Why `mcp-repl` helps**:
- Keep reference fixtures loaded; repeatedly compare outputs.
- Use small probes to verify parity before finalizing.

**Grader**:
- Runs the R implementation against a set of public + hidden fixtures; scores % of cases correct.

### 4) “Long-running with checkpoints” (interrupt/restart + progress)

**Prompt**: Run an analysis that includes a moderately long computation (e.g., bootstrap, simulation, cross-validation) with intermediate checkpoints. If it exceeds the time budget, produce partial results plus a plan to finish (as defined by the task).

**Why `mcp-repl` helps**:
- The agent can start the run, inspect partial output, adjust parameters, and continue without losing context.
- Best-effort interrupt/restart supports recovery from wedged runs.

**Grader**:
- Scores correctness of partials + the completeness/consistency of checkpoint outputs.
- Penalizes wasted time (e.g., restarting from scratch repeatedly) if you include time-aware grading.

### 5) “Visualization refinement” (preview-and-iterate)

**Prompt**: Produce a plot that must satisfy concrete requirements (labels, scales, colorblind-safe palette, faceting rules, annotation, and a specified size). The dataset and the spec are provided; the plot must match the spec.

**Why `mcp-repl` helps**:
- The agent can render and visually verify the result, then adjust iteratively.

**Grader**:
- Verifies the plot exists and matches basic properties (dimensions, number of panels, presence of labels).
- If you want stronger grading, compare against a reference image using an image-diff metric with tolerance.

### 6) “Manual lookup in huge docs” (pager navigation + targeted extraction)

**Prompt**: Use `RShowDoc("R-exts")` (or another large local manual), find specific technical facts (for example, exact API names, required flags, and caveats), and write a short answer with references to the matched sections.

**Why `mcp-repl` helps**:
- The agent can traverse very large output incrementally instead of reloading docs repeatedly.
- Pager navigation commands (`:/`, `:n`, `:seek`, `:skip`, `:where`) reduce search latency in long manuals.

**Grader**:
- Checks that required facts are present and correct.
- Penalizes hallucinated identifiers and unsupported claims.
- Optionally verifies that quoted identifiers actually appear in the source manual.

## How to turn runs into a benchmark number

Keep the primary metrics separate (time, grade, tokens), but it’s useful to also define a composite for quick tracking.

One simple approach:

- **Quality-first**: require `grade >= threshold` for a run to count as “completed”.
- Among completed runs, report:
  - median time-to-completion
  - median tokens
  - completion rate

If you still want a single scalar score, consider an “efficiency-adjusted quality” metric such as:

- `score = grade / (1 + α * time_s + β * tokens)`

Pick α/β so that changes are interpretable (e.g., “30 seconds is worth ~X grade points”).

## Comparing tool description variants

When evaluating descriptions, keep everything else fixed:

- Same tasks, same model, same temperature/seed policy.
- Randomize the assignment of description variants to runs to reduce drift.

What you’re testing is not only whether the tool *can* help, but whether the agent is reliably guided into:

- inspect-first behavior (types/shapes before transformations),
- browser-driven debugging (reproduce → break → inspect → fix),
- plot preview and iteration,
- state reuse across steps instead of redoing setup.
