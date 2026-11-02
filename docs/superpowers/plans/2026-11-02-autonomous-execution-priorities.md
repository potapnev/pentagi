# Autonomous Execution Priorities Implementation Plan

> **For agentic workers:** Implement this plan inline. Validate with the isolated replay cases listed below.

**Goal:** Bound repeated administrative work and report completion only when technical objectives have evidence-backed coverage.

**Architecture:** Add a flow-scoped work guard over normalized administrative/delegation tool calls, use existing tool-call and subtask records to distinguish technical progress, and derive a terminal assessment state before writing the final result. No schema or version changes.

**Tech Stack:** Go 1.26, existing PostgreSQL `toolcalls`/`subtasks` records, embedded Go templates.

**Spec:** User request, 2026-11-02.

## Global Constraints

- Keep PentAGI 2.2.0 and preserve existing database/history.
- Preserve scope and safety controls; do not run a live external assessment.
- Terminal states: `COMPLETED`, `PARTIAL`, `BLOCKED`, `FAILED`.
- Suppress repeated work only within the same Flow and only absent new substantive evidence.
- Keep work targeted; no durability or infrastructure redesign.

## Review Focus

- Identical inspections across chains/subtasks are bounded and reuse prior output.
- New technical evidence permits one relevant follow-up without opening an unlimited loop.
- Conflicting counts and repeated reports do not advance technical progress.
- A completed report cannot override untested primary objectives.
- Missing scope/safety prerequisites remain a blocker and never trigger target actions.

## Task 1: Work repetition and plan refinement

**Files:** `backend/pkg/providers/performer.go`, new guard helper/tests, `backend/pkg/controller/subtasks.go`, `backend/pkg/templates/prompts/refiner.tmpl`.

- Test a repeated file inspection and repeated delegation across distinct subtasks; assert one execution absent new evidence, one bounded follow-up after new evidence, and no duplicate administrative subtask recreation.
- Implement flow-wide canonical signatures, evidence-generation gating, and bounded planner filtering.
- Include technical-action/admin-progress counts in refiner instructions; fallback/delegation errors must preserve the existing plan and not recursively replan.

## Task 2: Evidence-backed terminal outcomes

**Files:** `backend/pkg/tools/args.go`, `backend/pkg/controller/task.go`, task result tests, `backend/pkg/templates/prompts/reporter.tmpl`.

- Test conflicting request-count reconciliation, repeated reporting, all four terminal states, and reporter success with untested objective subtasks.
- Derive `COMPLETED` only when all non-administrative objectives have successful target-action evidence; use `PARTIAL` for incomplete coverage with some progress, `BLOCKED` for unmet scope/safety prerequisites before testing, and `FAILED` for execution failure.
- Persist terminal state in the task result and map only `COMPLETED` to the existing successful lifecycle status.

## Regression and stop rule

Replay sanitized completed Flow 81 aggregates plus five isolated synthetic cases. Report baseline vs fixed duplicate executions, administrative share, objective coverage, and final status. Stop once all cases pass; do not initiate target testing or additional infrastructure work.
