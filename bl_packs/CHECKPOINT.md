# CHECKPOINT.md — LIVE RESUME STATE

## Status
NEEDS INPUT — remote command `2026-08-13-cyb4-probe-007` checked centralized `BL_FILES/`; it contains only `.DS_Store`.

## Exact required input
`BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`, unmodified. An extracted `abl.elf` / LinuxLoader PE with archive identity is acceptable.

## Proven boundary
CXDF B5 dynamic; FZDP B9 and EZB6 B9 hard-disabled. The policy boundary is after B5 and no later than B9. If CYB4 is supplied and hard-disabled, test B7 `S911BXXS7CXL2`; if dynamic, test B8 `S911BXXS8EZA1`.

## Safety
Place input in ignored `BL_FILES/`; offline analysis only, never flash.
