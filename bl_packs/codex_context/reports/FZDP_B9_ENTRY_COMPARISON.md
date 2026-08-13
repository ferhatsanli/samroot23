# FZDP B9 Download-Mode entry comparison

## Input identity — VERIFIED

- Archive: `BL_S911BXXU9FZDP_S911BXXU9FZDP_MQB109002558_REV00_user_low_ship_MULTI_CERT.tar.md5`
- SHA-256: `9c8508eee373e9ae69a4979aa7f7868bea4a984d1f705dd2707a66137edd505f`
- Archive contents supplied `abl.elf.lz4`. It was decompressed locally, its UEFI FV (offset `0x1000`, length `0x252000`) was extracted, and UEFIExtract recovered LinuxLoader and Odin PE bodies. These binary artifacts remain under ignored `FZDP/` and are not Git inputs.

## FZDP LinuxLoader result — VERIFIED

FZDP is binary B9 but **does not retain a dynamically reachable native Download-Mode unlock entry path**.

- FZDP entry-policy helper: `0xCABE0`.
- It calls `0xC2480`, obtains/logs policy field `+0xF0`, then unconditionally executes `mov w0, wzr; ret` at `0xCAC44..0xCAC4C`.
- FZDP normal Download-Mode event loop calls it twice at `0x707A8` and `0x707F0`. Both test its zero result and branch away (`0x707B0 → 0x709B0`; `0x707F8 → 0x70840`) before the long-press route.
- The retained long-press helper is `0x710D0`, called with `w0=0xFA0` (4,000 ms) at `0x7082C`; successful return would call confirmation handler `0xD74E0` at `0x7083C`. These calls are unreachable in normal flow because of the false policy helper.
- FZDP confirmation `0xD74E0` directly calls persistent transition `0x26020` at `0xD75AC`. FZDP `0x26020` has exactly two direct/tail callers: boot-time EM reconciliation `0x9324` and dormant interactive `0xD75AC`.

## Three-way comparison — VERIFIED

| Property | CXDF B5 | FZDP B9 | EZB6 B9 |
| --- | --- | --- | --- |
| Entry helper | `0xC6ED0`, dynamic policy fields/state | `0xCABE0`, unconditional false | `0xCA790`, unconditional false |
| Event-loop gates | `0x70194`, `0x701DC` | `0x707A8`, `0x707F0` | `0x70474`, `0x704BC` |
| Long press | `0x70A40` may be reached | `0x710D0` retained but skipped | `0x70D20` retained but skipped |
| Confirmation | `0xCFAA0 → 0x25EE0` | `0xD74E0 → 0x26020` dormant | `0xD4AE0 → 0x26020` dormant |
| Transition callers | interactive plus boot behavior | `0x9324`, `0xD75AC` | `0x9324`, `0xD4BAC` |
| OEM/FRP/OEM-LOCK diagnostics | old OEM/FRP diagnostics present historically | absent; long-press diagnostic retained | absent; long-press diagnostic retained |

FZDP `0xCABE0` and EZB6 `0xCA790` are both 28 instructions and have **100.00% normalized similarity**. Their `0x26020` transition functions are likewise both 136 instructions and **100.00% normalized similarity**. The relevant hard-disable therefore predates FZDP→EZB6; it is an earlier code-policy boundary than the two B9 builds, not a KG/FRP runtime prerequisite difference.

## FZDP Odin / EM token channel — VERIFIED / UNKNOWN

FZDP Odin retains `BL_EM_CMD_INSTALL_TOKEN`, `BLWriteToken`, `Process_EMTOKEN`, and issuer/device/validity/mode token parsers, matching the privileged EZB6 service-token surface. No FZDP-only consumer-unlock mode, command, or end-user issuance workflow was identified from targeted static evidence.

- **VERIFIED:** both B9 builds have the hard-disabled interactive route and privileged EM-token processing.
- **INFERENCE:** the hard-disable was already deliberate in FZDP, before EZB6, and is code policy rather than the target's KG/FRP Android state.
- **UNKNOWN:** the pre-FZDP build boundary where dynamic consumer entry was removed; any authorized consumer-unlock token mode or issuer workflow.

Detailed FZDP disassembly/caller contexts: `codex_context/reports/fzdp_entry_probe.txt`.
