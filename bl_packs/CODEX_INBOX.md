# CODEX_INBOX.md

COMMAND_ID: 2026-08-14-autonomous-boundary-009
STATUS: READY

## Objective
Resume from completed CYB4 B8 analysis and continue autonomously toward the overall offline/read-only bootloader-unlock investigation objective. Do not stop after one intermediate firmware comparison when another useful local action is already available.

Authoritative local firmware-input directory:
`/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/`

First, perform one concise shallow inventory of firmware filenames under `BL_FILES/` (including its immediate build subdirectories) so the available historical samples are known. Do not scan Downloads/Desktop or the wider filesystem, and do not hash every file.

Established boundary:
- CXDF B5: dynamic/reachable native Download-Mode unlock entry.
- CYB4 B8: dynamic/reachable native Download-Mode unlock entry.
- FZDP B9: hard-disabled native entry.
- EZB6 B9: hard-disabled native entry.

### Autonomous boundary loop
1. If late-B8 `S911BXXS8EZA1` is local, analyze it next.
2. Otherwise choose the locally available sample with the highest information value for narrowing the CYB4-B8 → B9 boundary.
3. After each sample, immediately choose the next useful local sample if it can narrow the boundary further. Do not wait for another user `continue` between samples.
4. Reuse existing extraction, UEFI, LinuxLoader, and comparison scripts. Keep raw binaries/extractions ignored and local-only.
5. For each analyzed build, classify the entry-policy helper as dynamic/reachable, unconditional-false hard-disabled, or materially rewired; map its two normal event-loop gates, long-press/confirmation route, and persistent transition topology.
6. Maintain concise checkpoint/evidence/state updates between atomic samples so quota exhaustion is recoverable.

### After the boundary is narrowed as far as local samples permit
Do not stop merely because the historical classification milestone is complete. Compare the nearest dynamic and hard-disabled builds around the boundary to characterize the policy change itself:
- normalized helper/function differences;
- callers and policy-structure field accesses;
- nearby OEM/FRP/OEM-lock initialization/diagnostic removals or rewiring;
- whether the hard-disable is an isolated helper replacement or accompanies a broader request-generation/policy-layer change;
- any evidence-supported relation to the retained transition, VaultKeeper/KG, or EM-token reconciliation path, without asserting unsupported causality.

Then continue to the next evidence-supported local/read-only question that advances the legitimate current-B9 unlock investigation. Do not re-prove settled findings. Stop only under the `Autonomous goal loop` stop conditions in `AGENTS.md` — e.g. genuine missing input, safety/device-operation boundary, user decision, tool/quota failure, or an evidence-sufficient final conclusion.

Update as appropriate:
- `codex_context/reports/UNLOCK_ENTRY_BOUNDARY.md`
- a focused boundary-diff report if warranted
- `PROJECT_STATE.md`
- `CHECKPOINT.md`
- `NEXT_TASK.md`
- `ROADMAP.md`
- `EVIDENCE_LEDGER.csv`
- `REPORT_INDEX.md`
- `CODEX_STATUS.md`

Offline static analysis only. Never flash, downgrade, patch firmware, install tokens, forge signatures, write RPMB/trusted state, or modify the physical device. Preserve unrelated local changes and never commit firmware binaries.
