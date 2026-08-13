# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-bootstrap-002
STATUS: READY

## Starting point already reviewed by ChatGPT
The latest user-pushed project state was reviewed before issuing this command. Treat it as authoritative current state; do not restart from an earlier checkpoint.

Latest reviewed evidence:
- `codex_context/reports/B9_ENTRY_PATH_INVENTORY.md`
- `codex_context/DEVICE_UNLOCK_PLAN.md`
- `CHECKPOINT.md`
- `NEXT_TASK.md`

Current verified state:
- EZB6 Download-Mode interactive unlock entry is hard-disabled: replacement helper `0xCA790` always returns false and skips the retained long-press/confirmation path.
- EZB6 LinuxLoader has only two recovered direct/tail callers of transition `0x26020`: blocked interactive `0xD4BAC` and boot-time EM reconciliation `0x9324`.
- EZB6 Odin contains a privileged Samsung EM-token install/verification mechanism with issuer/device/expiry/validity/mode checks, but no local evidence establishes a consumer-unlock token mode or permitted end-user workflow.
- No FZDP or other alternate SM-S911B binary-B9 ABL/LinuxLoader/Odin input exists locally. The next comparison input remains an unmodified `SM-S911BXXU9FZDP` BL archive / `abl.elf`, at minimum LinuxLoader PE and preferably Odin PE.

Additional physical-device evidence not yet incorporated into the project state:
```text
ro.boot.kg=0x1
ro.boot.kg.bit=00
ro.boot.flash.locked=1
ro.boot.vbmeta.device_state=locked
ro.oem_unlock_supported=<unset>
ro.frp.pst=/dev/block/persistent
settings get global oem_unlock_enabled=null
persistent_data_block: writable=true
FRP enforcement enabled=true
FRP state=false
Has FRP credential handle=false
Verified boot state=green
No apparent OEM/FRP/enterprise restriction was found in the targeted device-policy grep.
```
This Android-policy evidence may characterize the missing OEM-unlock UI, but it does not change the already-verified unconditional-false EZB6 Download-Mode gate.

## Objective
Bootstrap the persistent GitHub coordination loop from this exact current state, incorporate the new physical-device evidence, and synchronize the meaningful state to GitHub. Do not perform broad new firmware analysis in this bootstrap run.

## One-time protocol installation
Update local `AGENTS.md` with a compact section named `GitHub coordination loop` containing these rules:

1. When the user sends only `continue`, `devam`, `updated`, or equivalent continuation wording, execute the newest unprocessed command in `CODEX_INBOX.md`.
2. At the start, if the worktree is clean, run `git pull --ff-only`. If unexpectedly dirty, preserve and inspect changes; never discard or overwrite them blindly.
3. Compare `CODEX_INBOX.md` `COMMAND_ID` with the last processed ID in `CODEX_STATUS.md`; never execute the same command twice.
4. Follow `CHECKPOINT_PROTOCOL.md`, `CHECKPOINT.md`, `ROADMAP.md`, `NEXT_TASK.md`, and existing token-efficiency rules.
5. Keep checkpoint/state/evidence files current after meaningful milestones.
6. At the END of every processed command, replace `CODEX_STATUS.md` with a concise handoff containing exactly:
   - `COMMAND_ID`
   - `RESULT`: COMPLETE / BLOCKED / NEEDS_INPUT / PARTIAL
   - `VERIFIED`
   - `INFERENCE`
   - `UNKNOWN`
   - `FILES_CHANGED`
   - `NEXT_RECOMMENDED_ACTION`
   Keep it roughly 10-30 lines and reference detailed reports instead of copying them.
7. Before committing, inspect `git status --short` and `git diff`. Stage only meaningful current project changes. Exclude caches, venvs, temporary/build files, `.pyc`, `__pycache__`, and unrelated user files. Improve `.gitignore` if appropriate.
8. Commit intended changes with a short descriptive English message of 3-5 words.
9. Push the current branch automatically. If rejected only because remote is ahead, integrate safely (`git pull --rebase` when appropriate) and retry. Never guess through real merge conflicts.
10. A run is complete only when status/checkpoint/reports intended for that run are committed and pushed. If push/auth/network fails, preserve local state and report the exact blocker.

## Bootstrap actions
- Pull and preserve the latest user-pushed state; note that commit `6e00b499` contains the latest analysis state reviewed by ChatGPT, and this inbox commit is newer.
- Add the coordination-loop rules to `AGENTS.md` once, without duplicating existing checkpoint rules.
- Incorporate the physical-device Android-policy evidence above into the most appropriate compact state/evidence/device-plan files, clearly separating VERIFIED observations from interpretation.
- Do not redo the B9 entry-path inventory or the verified `0xCA790` analysis.
- Create/replace `CODEX_STATUS.md` summarizing the CURRENT state and the exact FZDP/B9 input blocker.
- Review the local worktree and include any meaningful current analysis/checkpoint files that were not already in the user's manual push; do not blindly stage everything.
- Commit and push all intended bootstrap changes using a short 3-5 word English commit message.
- Do not flash, patch, downgrade, install EM tokens, or modify trusted device state.

## Context management
Do not attempt to invoke Codex slash commands from shell/model instructions. Keep persistent files current so manual/automatic compaction is safe. After compaction or a fresh session, resume from `CHECKPOINT.md` + `NEXT_TASK.md` + the newest unprocessed `CODEX_INBOX.md`; read the long archive only if compact state is insufficient.
