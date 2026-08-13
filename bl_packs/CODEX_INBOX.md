# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-cyb4-probe-007
STATUS: READY

## Objective
Continue the offline historical unlock-entry boundary comparison with CYB4 B8, using the user's centralized local BL input directory.

Authoritative local firmware-input directory:
`/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/`

The user reports that CYB4 and all other BL files they currently possess have been moved into this directory. Do not search `Downloads`, `Desktop`, `FZDP/`, `CYB4/`, or `firmware_inputs/` first.

Expected CYB4 input:
`/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES/BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`

Start with an exact existence check for that path. If the exact name differs, perform only one shallow filename listing of `BL_FILES/` to locate the CYB4 archive; do not perform broad filesystem searches.

If CYB4 is present:
- record its exact filename, size, and SHA-256;
- keep all firmware binaries and extraction outputs local-only and Git-ignored;
- reuse the existing extraction workflow and existing analysis scripts/reports;
- map the CYB4 counterpart of the previously compared entry-policy helper and its matching event-loop call sites;
- classify CYB4 as dynamic/reachable, hard-disabled, or materially rewired relative to CXDF B5, FZDP B9, and EZB6 B9;
- update `UNLOCK_ENTRY_BOUNDARY.md`, `PROJECT_STATE.md`, `CHECKPOINT.md`, `NEXT_TASK.md`, `ROADMAP.md`, `EVIDENCE_LEDGER.csv`, `REPORT_INDEX.md`, and `CODEX_STATUS.md` concisely.

Adaptive next sample:
- if CYB4 matches the later B9 behavior, choose the next useful earlier sample from the BL files already present in `BL_FILES/` before requesting or searching for anything externally;
- if CYB4 matches the earlier B5 behavior, choose the next useful later sample from `BL_FILES/` first.

Also remove/replace stale state text claiming that no B6/B7/B8 input is local, once local presence is verified.

Offline static analysis only. Do not flash or modify the physical device. Preserve unrelated local changes and never commit firmware binaries.
