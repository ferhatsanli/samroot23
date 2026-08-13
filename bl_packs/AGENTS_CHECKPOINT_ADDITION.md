## Persistent checkpoint protocol
This project uses `ROADMAP.md`, `CHECKPOINT.md`, `NEXT_TASK.md`, and `EVIDENCE_LEDGER.csv` for quota-safe continuation.

Before every atomic objective, keep `CHECKPOINT.md` current. Save it before any long/high-output command. After every meaningful result, update evidence/report + roadmap + checkpoint + next task before continuing.

Never depend on a graceful final response at quota exhaustion. A new session must be able to resume from `AGENTS.md`, `CHECKPOINT.md`, and `NEXT_TASK.md` without reading the long archive.
