# Download-Mode unlock-entry policy boundary

## Verified analyzed builds

| Build | Binary | Entry-policy classification | Evidence |
| --- | ---: | --- | --- |
| `S911BXXS5CXDF` | B5 | Dynamic/reachable | `0xC6ED0` evaluates policy/state; normal long-press path can be entered. |
| `S911BXXU9FZDP` | B9 | Hard-disabled | `0xCABE0` returns false unconditionally; both normal gates skip retained long-press/confirmation. |
| `S911BXXS9EZB6` | B9 | Hard-disabled | `0xCA790` returns false unconditionally; both normal gates skip retained long-press/confirmation. |

Current evidence-supported interval: **the consumer Download-Mode entry hard-disable was introduced after CXDF B5 and no later than FZDP B9.** FZDP/EZB6 prove the effect is code policy, not this handset's KG/FRP runtime state.

## Highest-value unprocessed probe

`S911BXXU8CYB4` is an independently listed SM-S911B/EUX Android 14 binary-B8 build (build date 2025-02-07; security patch 2025-02-01). The exact BL child archive required is:

`BL_S911BXXU8CYB4_S911BXXU8CYB4_MQB92281678_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`

No B6/B7/B8 input exists locally. A public firmware index lists the BL child as approximately 97.32 MB, but its available controls require browser/login flow and no normal direct CLI download URL was exposed. Per acquisition constraints, no restricted-flow retrieval or full 13.66 GB firmware download was attempted.

Remote command `2026-08-13-cyb4-probe-006` then searched only the designated local locations (`firmware_inputs/`, `CYB4/`, Downloads, and Desktop). No CYB4 archive, `abl.elf`, or LinuxLoader input was present; only already-analyzed CXDF/EZB6/FZDP artifacts were found.

Remote command `2026-08-13-cyb4-probe-007` checked the centralized authoritative `BL_FILES/` directory exactly as directed. Its only shallow file entry is `.DS_Store`; the exact CYB4 BL archive and any CYB4 extracted ABL/LinuxLoader input are absent.

## Next decision

Supply the exact unmodified CYB4 BL child archive above (or extracted `abl.elf` / LinuxLoader PE plus archive identity). It is the single highest-information first probe:

- If CYB4 is hard-disabled, next compare verified `S911BXXS7CXL2` B7.
- If CYB4 remains dynamic, next compare late B8 `S911BXXS8EZA1`.

No historical firmware is authorized for flashing; this is offline boundary analysis only.
