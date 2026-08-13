# CHECKPOINT.md — LIVE RESUME STATE

## Project goal
Prepare a justified device-side bootloader-unlock procedure for SM-S911B/DS on `S911BXXS9EZB6`, or reduce the blocker to the minimum required physical-device experiments.

## Status
BLOCKED ON SPECIFIC LOCAL INPUT — no alternate SM-S911B B9 firmware component is available for comparison.

## Resolved facts
- EZB6 Download-Mode long-press is hard-disabled by `0xCA790` returning false unconditionally; the physical no-op is explained.
- Local inventory has only CXDF B5 and EZB6 B9 ABL images. No `S911BXXU9FZDP`/other B9 archive, `abl.elf`, LinuxLoader, or Odin body exists.
- EZB6 LinuxLoader has only two direct/tail `0x26020` callers: blocked interactive `0xD4BAC` and boot-time `0x9324` (`BLInitToken` → EM bit 3).
- Odin has a privileged EM-token install/verification protocol. Its consumer-unlock mode and authorized user workflow remain unknown; do not install tokens.

## Exact next input
Unmodified `SM-S911BXXU9FZDP` (or another verified `SM-S911B` binary-B9) **BL archive / `abl.elf`**, or at minimum its extracted UEFI **LinuxLoader PE body**. Include exact archive/build identity. The matching Odin PE body is preferred to compare EM-token handling. This is for offline analysis only, not flash authorization.

## Evidence
`codex_context/reports/B9_ENTRY_PATH_INVENTORY.md`, `token_channel_report.txt`, ledger `E018–E019`.
