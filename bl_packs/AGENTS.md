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
