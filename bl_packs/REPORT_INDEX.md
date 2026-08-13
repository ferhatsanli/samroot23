# REPORT_INDEX.md

Use targeted reads; do not `cat` all large reports unless necessary.

## Highest priority
### `unlock_entry_trace/summary.txt`
Compact result proving:
- CXDF `0x25EE0` ↔ EZB6 `0x26020` = 100% normalized similarity;
- EZB6 new direct caller at `0x9324`;
- D5D90/C7CF0/C5A10 target/caller summary.

### `unlock_entry_trace/report.txt`
Detailed disassembly/caller contexts for the above.

### `state_source_trace/summary.txt`
Next-stage compact report, if already generated.

### `state_source_trace/report.txt`
Next-stage detailed report, if already generated.

### `codex_context/reports/longpress_gate_report.txt`
Targeted CXDF/EZB6 disassembly and caller contexts for the Download-Mode entry-policy divergence. It proves CXDF `0xC6ED0` is replaced at the corresponding EZB6 gate by unconditional-false `0xCA790`.

### `codex_context/reports/B9_ENTRY_PATH_INVENTORY.md`
Local B9 inventory, exact missing FZDP component requirement, and the constrained EZB6 EM-token authorization-route conclusion.

### `codex_context/reports/token_channel_report.txt`
Targeted Odin/LinuxLoader EM-token string/xref contexts and complete direct/tail caller inventory for LinuxLoader transition `0x26020`.

### `codex_context/reports/FZDP_B9_ENTRY_COMPARISON.md`
Archive-identified FZDP B9 extraction and three-way CXDF/FZDP/EZB6 conclusion: FZDP already uses the same unconditional-false Download-Mode entry policy as EZB6.

## Earlier unlock-path work
### `unlock_path_analysis/unlock_string_diff.txt`
Old/new OEM/FRP string presence and removal.

### `unlock_path_analysis/unlock_xref_report.txt`
Direct xrefs and contexts for unlock-related strings/functions.

### `oem_unlock_trace/trace_summary.txt`
Compact direct/indirect target trace.

### `oem_unlock_trace/trace_report.txt`
Detailed target/xref contexts.

## Useful existing scripts
- `trace_unlock_entry.sh`
- `trace_state_sources.sh`
- earlier `unlock_path_analysis/*` scripts if present.

## Firmware/component inputs
Find rather than assume exact nested paths:
- `uefi_abl_compare/**/LinuxLoader/1 PE32 image section/body.bin`
- `uefi_abl_compare/**/Odin/1 PE32 image section/body.bin`
- `cxdf_vaultkeeper.mbn`
- `ezb6_vaultkeeper.mbn`
- `cxdf_tz_kg.mbn`
- `ezb6_tz_kg.mbn`
- CXDF/EZB6 `abl.elf`

## Archive
`codex_context/archive/CODEX_HANDOFF_S23_BOOTLOADER_LONG.md`
contains the long historical handoff. Read only when compact state lacks necessary context.
