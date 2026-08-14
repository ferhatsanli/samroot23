# CHECKPOINT.md — LIVE RESUME STATE

## Status
CYB4 B8 is classified by remote command `2026-08-13-bl-files-path-008`: its Download-Mode entry policy remains dynamic/reachable. The hard-disable was introduced after CYB4 B8 and no later than FZDP B9.

## Verified CYB4 chain
`0xC6ED0` dynamically evaluates policy/runtime fields and has a reachable true return. Gates `0x701A4` and `0x701EC` can pass to `0x70228 → 0x70A50` (4,000-ms long press), then `0x70238 → 0xCFCC0` (confirmation), which calls `0x25EE0` at `0xCFD8C`. CYB4 policy and transition are each 100.00% normalized to CXDF equivalents.

## Current objective
Await an unmodified late-B8 `S911BXXS8EZA1` BL tar/archive, or archive-identified `abl.elf` / LinuxLoader PE, in `BL_FILES/`. Map the same helper/gates to determine whether removal occurred within B8 or after it. No EZA1 input is currently local.

## Safety
Firmware/extracted binaries stay local-only; never stage them. Offline static analysis only: no flashing, downgrade, patch, token installation, or device modification.
