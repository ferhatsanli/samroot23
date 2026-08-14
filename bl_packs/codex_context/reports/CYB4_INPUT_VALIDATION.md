# CYB4 B8 input validation

## Command 2026-08-13-bl-files-path-008

- Repository top level: `/Users/ferhatsanli/Desktop/samroot`.
- Working directory: `/Users/ferhatsanli/Desktop/samroot/bl_packs`.
- Authoritative input directory: `/Users/ferhatsanli/Desktop/samroot/bl_packs/BL_FILES`.
- It contains build directories `CXDF`, `CYB4`, `EZB6`, and `FZDP` (plus `.DS_Store`).

## Identified CYB4 input

`BL_FILES/CYB4/BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`

- ZIP size: 97 MB (filesystem display).
- SHA-256: `7e1231842645dfbf01fe313755bbabbb507c86abae2c458c18b248b877dcc89e`.
- ZIP listing contains expected BL tar `BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5` (124,149,872 bytes), plus a 719-byte firmware-info text file.

This authenticates the local analysis input by exact expected name and content shape. It does not assert provenance beyond the supplied artifact. Firmware and extracted binaries remain local-only.
