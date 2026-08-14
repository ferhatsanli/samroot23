# CYB4 B8 → FZDP B9 entry-policy boundary diff

## Scope

Nearest available dynamic and hard-disabled local samples were compared: CYB4 B8 and FZDP B9. No late-B8 EZA1 or other intermediate build is in the shallow `BL_FILES` inventory, so this identifies the implemented policy change but cannot date its exact build.

## VERIFIED: dynamic evaluator was replaced by a false-return stub

| Property | CYB4 B8 | FZDP B9 |
| --- | --- | --- |
| Entry helper | `0xC6ED0` | `0xCABE0` |
| Instructions | 71 | 28 |
| Normalized similarity | 54.55% | 54.55% versus CYB4 |
| Common structure | 19-instruction prologue/logging prefix, shared epilogue | 19-instruction prologue/logging prefix, shared epilogue |
| Decision body | Reads policy `+0xF0`, runtime fields near `0x1AA000+0xBC0/+0xBC4`, and policy `+0x154/+0x15C`; conditionally returns true | Omitted; `mov w0,wzr; ret` at `0xCAC44..0xCAC4C` |

FZDP still calls its policy accessor (`0xC2480`) and logs the analogous policy `+0xF0` field before returning false. Therefore the structure remains observable, but no value it supplies can authorize native entry through this helper.

## VERIFIED: caller topology retains the UI but gates it off

CYB4 calls `0xC6ED0` at `0x701A4` and `0x701EC`; successful results can reach `0x70228 → 0x70A50` (4,000-ms long press) and `0x70238 → 0xCFCC0` (confirmation), then `0xCFD8C → 0x25EE0`.

FZDP calls `0xCABE0` at `0x707A8` and `0x707F0`. Both immediately test zero and branch around the preserved long press (`0x710D0`) and confirmation (`0xD74E0`), which would call unchanged transition `0x26020`. This is an isolated authorization/entry-policy replacement above retained UI and transition code.

## OEM/FRP-adjacent diagnostics

Targeted string checks of LinuxLoader found these diagnostics in CYB4 but not FZDP:

- `[FRP][OEM] init succeed!`
- `[OEM]Oem unlock value is %d`
- `[OEM]PLC:%x`

This supports a broader OEM/FRP policy-layer cleanup/removal across the boundary. It does not establish that any one missing diagnostic was an authorization decision or that KG, VaultKeeper, or EM-token state caused the hard-disable.

## Relation to retained transition and B9 EM reconciliation

CYB4 has only the interactive direct call to `0x25EE0` (`0xCFD8C`), while FZDP retains the blocked interactive call and adds the already-established boot-time EM-reconciliation caller at `0x9324 → 0x26020`. This shows B9 has a non-interactive privileged transition source alongside the disabled native consumer route. Static evidence still does not identify an end-user EM-token mode, issuer, or permitted workflow.

## Conclusion

**VERIFIED:** the B9 no-op is caused by deliberate replacement of the dynamic native entry-policy decision with a hard false result; it is not contingent on the target phone’s observed KG/FRP/OEM runtime values.

**UNKNOWN:** exact intermediate build/change, the higher-level product/policy actor that selected this replacement, and any legitimate consumer authorization path into the B9 EM-token channel. The only next boundary input is late B8 `S911BXXS8EZA1` ABL/LinuxLoader.
