# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-cyb4-probe-006
STATUS: READY

## Objective
Continue the existing offline historical firmware comparison from `UNLOCK_ENTRY_BOUNDARY.md` using the next B8 sample if it is available locally.

Preferred local input:
`BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`

First search only these locations for that archive or an already-extracted CYB4 ABL/LinuxLoader input:
- `/Users/ferhatsanli/Desktop/samroot/bl_packs/firmware_inputs/`
- `/Users/ferhatsanli/Desktop/samroot/bl_packs/CYB4/`
- `/Users/ferhatsanli/Downloads/`
- `/Users/ferhatsanli/Desktop/`

If absent, set `RESULT: NEEDS_INPUT`, report the exact filename above, and stop without repeating broad download searches.

If present:
- record filename, size, and SHA-256;
- keep binary inputs local-only and Git-ignored;
- reuse the existing extraction workflow;
- map the CYB4 counterpart of the previously compared entry-policy helper and its matching event-loop call sites;
- classify the CYB4 behavior relative to CXDF B5, FZDP B9, and EZB6 B9;
- update `UNLOCK_ENTRY_BOUNDARY.md`, `PROJECT_STATE.md`, `CHECKPOINT.md`, `NEXT_TASK.md`, `ROADMAP.md`, `EVIDENCE_LEDGER.csv`, `REPORT_INDEX.md`, and `CODEX_STATUS.md` with concise VERIFIED / INFERENCE / UNKNOWN findings.

Adaptive next sample:
- if CYB4 matches the later B9 behavior, next target `S911BXXS7CXL2` B7;
- if CYB4 matches the earlier B5 behavior, next target `S911BXXS8EZA1` B8.

Use only the minimum historical BL samples needed. Offline static analysis only; do not flash or modify the physical device. Preserve unrelated local changes and never commit firmware binaries.
