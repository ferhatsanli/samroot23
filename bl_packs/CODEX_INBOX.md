# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-bl-files-path-008
STATUS: READY

## Objective
Resolve the discrepancy between the user's report that all BL firmware files are under `bl_packs/BL_FILES/` and the previous run seeing only `.DS_Store`, then continue CYB4 analysis immediately if the input is found.

Expected repository root:
`/Users/ferhatsanli/Desktop/samroot`

Expected authoritative BL input directory:
`/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/`

Do not perform broad filesystem searches or web searches.

### Step 1 — cheap path verification
From anywhere in the repo, record only concise output for:
- `git rev-parse --show-toplevel`
- `pwd -P`
- `ls -la /Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/`
- `find /Users/ferhatsanli/Desktop/samroot -maxdepth 4 -type d -name BL_FILES -print`

For every `BL_FILES` directory returned, perform only a depth-1 filename listing with file sizes. Do not hash every firmware file.

Also check these two likely accidental nesting variants only if needed:
- `/Users/ferhatsanli/Desktop/samroot/BL_FILES/`
- `/Users/ferhatsanli/Desktop/samroot/bl_packs/bl_packs/BL_FILES/`

### Step 2 — CYB4 discovery
Locate CYB4 only from the shallow BL_FILES listings. Expected identifying substring:
`S911BXXU8CYB4`

Expected historical filename if unchanged:
`BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`

If found anywhere in the verified BL_FILES location:
- record exact path, filename, size, and SHA-256 for CYB4 only;
- keep firmware/extracted binaries local-only and Git-ignored;
- reuse the existing extraction/UEFI/LinuxLoader workflow;
- map the CYB4 counterpart of the CXDF/FZDP/EZB6 entry-policy helper and its two event-loop gates;
- classify CYB4 as dynamic/reachable, hard-disabled, or materially rewired;
- update `codex_context/reports/UNLOCK_ENTRY_BOUNDARY.md`, `PROJECT_STATE.md`, `CHECKPOINT.md`, `NEXT_TASK.md`, `ROADMAP.md`, `EVIDENCE_LEDGER.csv`, `REPORT_INDEX.md`, and `CODEX_STATUS.md` concisely;
- inspect the other filenames already present in the same BL_FILES directory only to choose the next minimum-information historical sample. Do not analyze additional builds in this same run unless necessary to resolve an ambiguity in CYB4.

If CYB4 is still absent after these bounded checks, set `RESULT: NEEDS_INPUT` and report exactly which BL_FILES directories were found and their shallow filenames. Do not search Downloads/Desktop generally and do not attempt external acquisition.

Offline static analysis only. Do not flash, patch, install tokens, or modify the physical device. Preserve unrelated local changes and never commit firmware binaries.