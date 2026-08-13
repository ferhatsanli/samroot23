# CHECKPOINT_PROTOCOL.md

## Why
Do not rely on Codex getting a graceful final turn when quota is exhausted. OpenAI says an active turn *may* continue after a usage limit is reached, subject to fair-use limits; therefore persistence must already exist before the cutoff.

## Files
- `ROADMAP.md`: durable checklist; mark items only when evidence supports completion.
- `CHECKPOINT.md`: short live resume state; overwrite frequently.
- `NEXT_TASK.md`: smallest bounded current objective.
- `PROJECT_STATE.md`: compact durable verified knowledge.
- `EVIDENCE_LEDGER.csv`: one-line durable claims with evidence pointers.
- Detailed reports: `codex_context/reports/`.

## Update protocol
At the START of every atomic objective:
1. Ensure `CHECKPOINT.md` names the objective and files being used.
2. If about to launch a long/high-output command, save checkpoint first.

After every meaningful result:
1. Save detailed evidence to a report.
2. Update/add one concise row in `EVIDENCE_LEDGER.csv`.
3. Mark corresponding `ROADMAP.md` item `[x]` or `[~]`.
4. Compactly update `PROJECT_STATE.md` only for durable verified conclusions.
5. Replace `CHECKPOINT.md` with the new current state.
6. Replace `NEXT_TASK.md` with the next highest-value bounded task.
7. Continue automatically.

## No-bloat rules
- Never append transcript-like history to `CHECKPOINT.md`.
- `CHECKPOINT.md` target: <= 1200 words, preferably <= 700.
- `PROJECT_STATE.md` target: compact; remove superseded hypotheses.
- `NEXT_TASK.md` target: one objective, not a project history.
- Detailed disassembly goes only into reports.
- `ROADMAP.md` changes should mostly be checkbox/status edits.
- `EVIDENCE_LEDGER.csv` claims must be one line each.

## Before risky context-expensive work
Checkpoint BEFORE:
- large recursive scans,
- multi-minute analyses,
- rebuilding extractors,
- large binary diff jobs,
- any operation expected to produce large logs.

## On blocker
If blocked:
- mark roadmap item `[!]`;
- state exact blocker in `CHECKPOINT.md`;
- document the cheapest discriminating next test;
- continue to another independent high-value unresolved item if one exists.

## On quota return / new week
Start a fresh Codex session. Read only:
1. `AGENTS.md`
2. `CHECKPOINT.md`
3. `NEXT_TASK.md`
4. the relevant unchecked roadmap section
5. targeted evidence identified in the checkpoint

Do not load the long archive by default.

## Completion
Only stop normally when:
- `DEVICE_UNLOCK_PLAN.md` is sufficiently supported, OR
- offline evidence is exhausted and the minimum physical-device experiment set is documented.
