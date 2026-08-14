# AGENTS.md — S23 firmware reverse engineering

## Scope
Offline analysis of Samsung Galaxy S23 SM-S911B/DS bootloader/OEM-unlock behavior in this `bl_packs` workspace.

## Start-of-session
Read only:
1. `PROJECT_STATE.md`
2. `NEXT_TASK.md`
3. `REPORT_INDEX.md` only if you need to locate evidence.

Do **not** read `codex_context/archive/CODEX_HANDOFF_S23_BOOTLOADER_LONG.md` unless the compact state is insufficient or contradictory.

## Token discipline
- Default to one agent. Do not spawn subagents unless the task is independently parallelizable and the expected benefit clearly outweighs extra token use.
- Prefer local files and shell tools. Do not browse the web unless a missing external fact materially blocks the analysis.
- Do not recursively dump/cat large directories or reports. Use `find`, `rg`, `grep`, `sed -n`, `head`, targeted Python, and byte/address ranges.
- Read the smallest relevant report section first; expand only when necessary.
- Reuse existing scripts/reports before generating new analyses.
- Keep terminal output summarized. Put verbose disassembly/logs in report files, not chat.
- Keep final responses concise: VERIFIED, INFERENCE, UNKNOWN, next step.

## Analysis rules
- Distinguish current bootloader state, Android OEM-toggle exposure, and locked→unlocked transition capability.
- Zero simple XREFs do not prove unused code/strings; consider indirect/relocation/table references.
- Do not re-prove established findings unless resolving a contradiction.
- Do not label BLDP/DDI, KG CHECKING, VaultKeeper, or tz_kg as the gate without direct evidence.
- Prefer structural/function/caller/global-access evidence over string presence alone.
- Maintain old/new CXDF↔EZB6 mappings when discovering addresses.

## Safety / device operations
- Offline firmware analysis is the default.
- Do not flash, patch, unlock, or modify the physical device unless the user explicitly asks for that separate step.
- Do not install the binary-A OTA during this investigation.
- Do not propose forging Samsung signatures.

## Environment
This Codex workspace is macOS and the working directory is expected to be:
`/Users/ferhatsanli/Desktop/samroot/bl_packs`

Use macOS commands here unless the user explicitly changes environment.

## Local firmware inputs
- All user-supplied bootloader firmware archives/components are centralized under `/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/`.
- Check `BL_FILES/` first and do not scan `Downloads`, `Desktop`, legacy `FZDP/`, `CYB4/`, or `firmware_inputs/` locations unless a task explicitly says the centralized directory is incomplete.
- Treat `BL_FILES/` as local-only binary input. Do not stage or commit firmware archives, extracted binaries, or temporary extraction outputs from it.
- Prefer exact filename lookup inside `BL_FILES/` over broad recursive filesystem searches.

## Autonomous goal loop
- The project objective is broader than any single `CODEX_INBOX.md` command. An inbox command is a starting objective, not an instruction to stop after one intermediate milestone.
- After completing an atomic objective, immediately choose and execute the next highest-information local/read-only step toward the project objective when it is supported by existing evidence and available local inputs.
- Continue chaining bounded objectives in the same run without waiting for another `continue` merely because a report, comparison, firmware sample, or checkpoint milestone completed.
- Update checkpoint/state/evidence files between atomic objectives so quota exhaustion remains recoverable.
- Prefer already-available files in `BL_FILES/` and existing reports/scripts before asking for input or doing external research.
- Stop only when at least one of these is true:
  1. the actual investigation objective has been reached with evidence sufficient for a defensible conclusion;
  2. the next useful step genuinely requires missing user/external input that is not already local;
  3. the next step would cross the safety/device-operation boundary (flash, patch, token installation, destructive write, signature forgery, etc.);
  4. a real ambiguity requires a user decision rather than an evidence-driven choice;
  5. tool/auth/network/quota failure prevents further progress.
- Do not stop merely to report a next recommended local action that can already be performed safely. Perform it instead.
- When several historical firmware samples are locally available, adaptively analyze the minimum sequence needed to narrow the policy boundary; do not artificially limit a run to one sample.
- Once an intermediate boundary question is resolved, pivot to the next evidence-supported question that advances the overall legitimate bootloader-unlock investigation, while remaining offline/read-only unless the user separately authorizes device operations.

## State maintenance
After a meaningful milestone:
- update `PROJECT_STATE.md` with only durable verified facts;
- replace `NEXT_TASK.md` with the next bounded objective;
- keep both compact;
- put detailed evidence in `codex_context/reports/` or the analysis tool's existing report directory.
## Persistent checkpoint protocol
This project uses `ROADMAP.md`, `CHECKPOINT.md`, `NEXT_TASK.md`, and `EVIDENCE_LEDGER.csv` for quota-safe continuation.

Before every atomic objective, keep `CHECKPOINT.md` current. Save it before any long/high-output command. After every meaningful result, update evidence/report + roadmap + checkpoint + next task before continuing.

Never depend on a graceful final response at quota exhaustion. A new session must be able to resume from `AGENTS.md`, `CHECKPOINT.md`, and `NEXT_TASK.md` without reading the long archive.

## GitHub coordination loop
- When the user sends only `continue`, `conti`, `devam`, `updated`, or equivalent continuation wording, first run `git fetch origin main`, then inspect `git show origin/main:bl_packs/CODEX_INBOX.md` and compare its `COMMAND_ID` with `CODEX_STATUS.md`.
- Treat the remote inbox as authoritative even when the worktree is dirty; unrelated `.DS_Store` or `.gitignore` changes must not prevent discovery or execution of a newer command. Never discard local changes merely to sync.
- Never execute the same remote inbox `COMMAND_ID` twice. Before final commit/push, integrate remote history safely while preserving unrelated local changes; stop on real conflicts rather than guessing.
- Follow the autonomous goal loop, persistent checkpoint/state/evidence protocol, and existing token-efficiency rules.
- At the end of each processed command/run, replace `CODEX_STATUS.md` with a concise 10–30-line handoff containing exactly `COMMAND_ID`, `RESULT`, `VERIFIED`, `INFERENCE`, `UNKNOWN`, `FILES_CHANGED`, and `NEXT_RECOMMENDED_ACTION`.
- `NEXT_RECOMMENDED_ACTION` is for the first action that could not be completed in the current run; never use it as a reason to stop when that action is local, safe, and executable now.
- Before committing, inspect `git status --short` and `git diff`; stage only meaningful project changes. Exclude caches, venvs, temporary/build files, `.pyc`, `__pycache__`, and unrelated user files; improve `.gitignore` when appropriate.
- Commit intended changes with a short 3–5-word English message and push the current branch. If only remote advancement rejects the push, safely integrate with `git pull --rebase` and retry; never guess through real merge conflicts.
- A run is complete only when the autonomous goal loop reaches a legitimate stop condition and its intended status/checkpoint/reports are committed and pushed. If push/auth/network fails, preserve local state and report the exact blocker.
