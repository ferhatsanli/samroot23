# Install checkpoint system

From:
`/Users/ferhatsanli/Desktop/samroot/bl_packs`

Extract/copy these files directly into the workspace root:
- ROADMAP.md
- CHECKPOINT.md
- EVIDENCE_LEDGER.csv
- CHECKPOINT_PROTOCOL.md
- CODEX_CONTINUE_PROMPT_CHECKPOINTED.txt

Append the contents of `AGENTS_CHECKPOINT_ADDITION.md` to the existing `AGENTS.md` once.

Then paste `CODEX_CONTINUE_PROMPT_CHECKPOINTED.txt` into the current Codex session.

For future quota-reset sessions, use a much shorter resume prompt:

Use $s23-firmware-analysis. Resume strictly from CHECKPOINT.md and NEXT_TASK.md, following CHECKPOINT_PROTOCOL.md and ROADMAP.md. Do not redo completed items. Continue autonomously toward DEVICE_UNLOCK_PLAN.md.
