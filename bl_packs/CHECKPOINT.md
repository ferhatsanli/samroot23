# CHECKPOINT.md — LIVE RESUME STATE

## Project goal
Prepare a justified device-side bootloader-unlock procedure for SM-S911B/DS on `S911BXXS9EZB6`, or reduce the blocker to the minimum required physical-device experiments.

## Status
COMPLETE — remote command `2026-08-13-fzdp-b9-004` resolved the FZDP B9 comparison.

## FZDP result
- FZDP archive SHA-256: `9c8508eee373e9ae69a4979aa7f7868bea4a984d1f705dd2707a66137edd505f`.
- FZDP `0xCABE0` is 100%-normalized to EZB6 `0xCA790` and always returns false.
- FZDP gates `0x707A8`/`0x707F0` skip retained long press `0x710D0` and confirmation `0xD74E0`; the latter would call unchanged transition `0x26020` at `0xD75AC`.
- Hard-disable predates EZB6 within B9 and is code policy, not device KG/FRP runtime state.
- FZDP retains the same privileged EM-token service surface; no consumer unlock mode/workflow identified.

## Safety
FZDP remains ignored/local-only. No flash, downgrade, patch, trusted-state modification, or EM-token operation is justified.

## Evidence
`codex_context/reports/FZDP_B9_ENTRY_COMPARISON.md`, detailed `fzdp_entry_probe.txt`, ledger `E021–E022`.
