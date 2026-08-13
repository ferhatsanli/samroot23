# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-bootstrap-001
STATUS: READY

## Objective
Bootstrap a persistent GitHub coordination loop for this existing S23 bootloader reverse-engineering project, synchronize the meaningful current local project state to GitHub, and leave the worktree clean and resumable.

## One-time protocol installation
Update the local `AGENTS.md` with a compact persistent section named `GitHub coordination loop` containing these rules:

1. When the user sends only `continue`, `devam`, `updated`, or equivalent continuation wording, treat it as authorization to execute the newest unprocessed command in `CODEX_INBOX.md`.
2. At the start of such a run, if the worktree is clean, run `git pull --ff-only` so the newest inbox is available. If the worktree is unexpectedly dirty, do not overwrite or discard changes; inspect them and preserve checkpoint state before proceeding.
3. Read `CODEX_INBOX.md`. Compare its `COMMAND_ID` with the last processed command recorded in `CODEX_STATUS.md`. Never execute the same command twice.
4. Follow the existing checkpoint/token-efficiency rules in `AGENTS.md`, `CHECKPOINT_PROTOCOL.md`, `CHECKPOINT.md`, `ROADMAP.md`, and `NEXT_TASK.md`.
5. After each meaningful milestone, keep checkpoint/state/evidence files current as already required.
6. At the END of every processed inbox command, always replace `CODEX_STATUS.md` with a concise handoff containing exactly these sections:
   - `COMMAND_ID`
   - `RESULT`: COMPLETE / BLOCKED / NEEDS_INPUT / PARTIAL
   - `VERIFIED`
   - `INFERENCE`
   - `UNKNOWN`
   - `FILES_CHANGED`
   - `NEXT_RECOMMENDED_ACTION`
   Keep this report short (roughly 10-30 lines) and point to detailed reports rather than copying them.
7. Before committing, inspect `git status --short` and `git diff`. Stage only meaningful project files created or modified by the current investigation. Do not add caches, virtual environments, temporary files, build junk, `.pyc`, `__pycache__`, or unrelated user files. Update `.gitignore` if useful.
8. Commit all intended current-run analysis/report/checkpoint/status changes with a short descriptive English commit message of 3-5 words.
9. Push the current branch to its configured GitHub remote without waiting for the user. If push is rejected solely because the remote inbox commit is ahead, integrate safely with `git pull --rebase` and push. Never discard user changes or resolve a real merge conflict by guessing.
10. A processed run is not complete until `CODEX_STATUS.md`, checkpoint files, the relevant detailed reports, and the commit have been pushed successfully. If authentication/network/push fails, set `RESULT: BLOCKED` locally and report the exact failure.

## Bootstrap actions for this command
- Preserve all current meaningful reverse-engineering work already produced locally, including current checkpoint/roadmap/state/evidence files and detailed analysis reports.
- Review the current untracked/modified set rather than blindly using `git add -A`.
- Add the GitHub coordination-loop rules above to `AGENTS.md` compactly.
- Create/replace `CODEX_STATUS.md` using the required format and summarize the CURRENT project state, including the latest verified EZB6 hard-disabled Download-Mode gate and the exact missing FZDP/B9 comparison input.
- Commit and push the meaningful current project state.
- Use a short 3-5 word commit message.
- Do not perform new firmware modification or flashing work in this bootstrap command.

## Context management
Do not try to invoke Codex slash commands from shell/model instructions. Keep checkpoint files current so client-side/manual/automatic compaction is safe. If context is compacted, resume from `CHECKPOINT.md` + `NEXT_TASK.md` + the newest unprocessed `CODEX_INBOX.md` without re-reading the long archive unless necessary.
