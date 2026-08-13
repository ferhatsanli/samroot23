# CHECKPOINT.md — LIVE RESUME STATE

## Project goal
Prepare a justified device-side bootloader-unlock procedure for SM-S911B/DS on `S911BXXS9EZB6`, or reduce the blocker to the minimum required physical-device experiments.

## Status
BLOCKED ON SPECIFIC LOCAL INPUT — bootstrap `2026-08-13-bootstrap-002` processed; no alternate SM-S911B B9 firmware component is available for comparison.

## Durable facts
- EZB6 Download-Mode long-press is hard-disabled by `0xCA790` returning false unconditionally; the physical no-op is explained.
- Android baseline: OEM-support property unset and OEM setting null; FRP is enforced but inactive/no credential, persistent-data-block writable, and no targeted enterprise restriction was observed. This does not change the ABL gate.
- Local inventory has only CXDF B5 and EZB6 B9 ABL images. No `S911BXXU9FZDP`/other B9 archive, `abl.elf`, LinuxLoader, or Odin body exists.
- Odin has privileged EM-token installation/verification; consumer-unlock mode and authorized user workflow are unknown. Do not install tokens.

## Exact next input
Unmodified `SM-S911BXXU9FZDP` (or other verified SM-S911B B9) BL archive / `abl.elf`, or at minimum extracted UEFI LinuxLoader PE body; matching Odin PE preferred. Supply exact archive/build identity. Offline analysis only; this is not flash authorization.

## Evidence
`codex_context/reports/B9_ENTRY_PATH_INVENTORY.md`, `token_channel_report.txt`; ledger `E018–E020`.
