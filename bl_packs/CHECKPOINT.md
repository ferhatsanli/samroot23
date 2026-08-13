# CHECKPOINT.md — LIVE RESUME STATE

## Project goal
Locate the historical boundary where SM-S911B Download-Mode consumer unlock entry changed from dynamic to hard-disabled, without flashing or modifying a device.

## Status
NEEDS INPUT — remote command `2026-08-13-boundary-search-005` classified no new binary because normal BL-only CYB4 acquisition was unavailable.

## Proven boundary
- CXDF B5 is dynamic/reachable.
- FZDP B9 and EZB6 B9 are 100%-matching unconditional-false policy implementations.
- Boundary is after B5 and no later than B9; it is code policy, not KG/FRP runtime state.

## Exact required input
`BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`, unmodified. Extracted `abl.elf` / LinuxLoader PE plus archive identity is acceptable. Put it under ignored `firmware_inputs/`; do not flash it.

## Adaptive next step
If CYB4 is hard-disabled, request/classify B7 `S911BXXS7CXL2`; if dynamic, use late B8 `S911BXXS8EZA1`.
