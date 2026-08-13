# EZB6 state-source trace resolution

Scope: `D5D90`, `0x18DB94`, `C7CF0`, and `C5A10` in EZB6 LinuxLoader only.  Analysis uses the existing extracted PE body and corrected offline trace tooling.

## VERIFIED

### `0x5C4B0(0x18DB80)` — CCIC ADC acquisition, excluded as `0x18DB94` producer

- `0x6EE50` is the sole direct caller of EZB6 `0x5C4B0` and passes the global address `0x18DB80` in `x0`.
- `0x5C4B0` first locates the CCIC protocol and invokes its first interface method with that supplied buffer.  Its referenced diagnostic strings are `Error locating the CCIC protocol`, `Error CcicReadAdc`, and `ReadAdc: %d`.
- The wrapper itself performs no store through `x20` (the supplied `0x18DB80`); the only direct load from the supplied buffer is `ldr w2,[x20]` for an error log.  Thus it can populate the ADC result at the buffer start only through the CCIC interface callback, not field `+0x14` itself.
- The remainder of `0x6EE50` independently processes fields `0x18DB84`, `0x18DB88`, and `0x18DB8C` through battery/fuel-gauge helpers.  It does not read or write `0x18DB94`.
- The closest CXDF structural match is `0x5C2E0` (91.18% normalized similarity), so this hardware/ADC wrapper is retained rather than an EZB6 replacement for an unlock request source.

Conclusion: the apparent `0x18DB80` block relationship is spatial only.  `0x5C4B0` does not furnish evidence for an authoritative producer of `0x18DB94` or bitmap bit 3.

### `0x61` readers — retained recovery/SAPA control, not unlock-request control

- The `0x707D4` access belongs to a recovery-key/BootChecker routine beginning at `0x706F8`; its closest CXDF equivalent is `0x70418` (92.0% normalized similarity).  Its referenced messages include `[KEY] Recovery Mode, Reset param!`, `Block [KEY] Recovery Mode. Restart after BOTA update!`, `SkipRecovery misc read failed`, and `[BootChecker]RebootRecoveryWithKey`.
- The `0x71290` access belongs to a SAPA RTC/power-on routine beginning at `0x7105C`; its closest CXDF equivalent is `0x70D7C` (90.4% normalized similarity).  Its messages include `[SAPA] RTC`, `[SAPA] cable or reboot case`, `Invalid RTC power on -> off`, and `[SAPA] power on!`.
- Both old counterparts compare the analogue field `0x19BFDC` to the same `0x61` value in the corresponding branch.  Therefore this special value and both use sites predate EZB6 and are not an EZB6-specific OEM-unlock removal.
- Bounded direct-call traversal from these two routines (four edges) reaches neither `D5D90`, the retained state transition `0x26020`, `C7CF0`, nor the unlock getter.  No OEM, FRP, VaultKeeper, or KG diagnostic appears in their routine-level referenced strings.

Conclusion: `0x18DB94` is a retained boot/recovery/power-state field used to suppress or alter recovery/SAPA behavior for special value `0x61`.  This proves its observed readers are independent of the locked-to-unlocked request chain.  The exact enum label and its producer remain UNKNOWN, but this field should no longer be prioritized as a likely unlock-request source.

### Bitmap root `0x1A8120` — EM-token result vector; not a local persistent-state producer

- The vector lives in zero-filled `.data` in both images (`EZB6 0x1A8120`, CXDF `0x1B2320`), so bit 3 is runtime-supplied rather than a firmware-default bit.
- Exact static references to the root are reads only: `D5D90` is its indexed bit getter, and nearby `D5E90` exposes indexed 64-bit entries.  No direct store to root or its first word was found in the executable code.  This excludes a simple local constant or direct local writer.
- The enclosing subsystem identifies itself in diagnostics as EM: `D9560` sends EM command `0x19` (`BL_EM_CMD_INIT`), via `D95F0` (`BLEmProcess` / `BLEmMakeReq`).  `D60F0` is explicitly logged as `BLInitToken`; it calls `D9560` immediately before the boot entry queries bit 3 and supplies that result to `0x26020`.
- The root is also used by other EM policy/test queries (bits 0, 1, 3, 4, 0xA, 0xB, 0x15, 0x25, 0x26, 0x3D).  Bit 3 is therefore one flag in an externally processed EM-token result vector, not a standalone OEM-unlock state.
- The EM wrappers are substantially retained: `D5D90` ↔ CXDF `D0D50` (94.7%), `D5E90` ↔ `D0E00` (93.8%), `D9560` has closest CXDF match `D44D0` (90.6%), and `D95F0` ↔ `D4560` (88.1%).  No EZB6-only producer divergence was established here.

Conclusion: the closest upstream source recoverable inside LinuxLoader is the external EM-token processing interface reached by `BLInitToken`, not the bitmap.  The token transport/response consumer that actually fills bit 3 is still UNKNOWN; it must be traced through the EM request handlers or observed on a device.  This is not evidence that an arbitrary bitmap edit can make a legitimate trusted unlock transition.

## Follow-up: CXDF OEM diagnostic and interactive transition topology

### OEM/FRP diagnostics are retained but unreferenced data

- A PE-wide literal/relocation scan covered CXDF Odin and LinuxLoader for `[FRP][OEM] init succeed!`, `[OEM]Oem unlock value is %d`, `[OEM]PLC:%x`, `[OEM]Unlock buffer Allocate fail`, and `OEM LOCK : ...`.
- Every target has zero static 32/64-bit RVA/VA pointer occurrences and zero base-relocation targets.  Earlier ADR/ADRP direct-reference scans were also zero.
- Therefore these strings cannot, by themselves, identify a live CXDF OEM request function.  They are retained unreferenced diagnostic data in the examined images.

### Interactive lock/unlock confirmation loop survives into EZB6

- CXDF direct caller `0xCFAA0` reads `IsUnlocked`, waits for confirmation/event status through `0x31F20`, then repeatedly calls `0x25EE0(w0=current_state, w1=1)` when the event result is `1` or `2`.
- Its closest EZB6 equivalent is `0xD4AE0` (93.33% normalized similarity).  EZB6 performs the same sequence and directly calls `0x26020` at `0xD4BAC`; this is the second direct caller, in addition to boot-time `0x9324`.
- The respective enclosing event loops are also retained: CXDF call site `0x70228` → `0xCFAA0`; EZB6 `0x70508` → `0xD4AE0`.  They share the same poll/timeout layout and precede the confirmation handler with equivalent helper calls.

Conclusion: the exact user-visible wording and entry gesture remain to be confirmed on-device, but static code verifies that an interactive event-driven legitimate transition path still exists in EZB6.  This corrects the earlier incomplete claim that `0x9324` was the sole direct caller of `0x26020`.

### EZB6 interactive entry gate is a four-second Volume-Up long press

- Before calling `0xD4AE0`, EZB6 event loop `0x70508` calls `0x70D20` with `w0=0xFA0` (4,000 ms).  If it returns nonzero, it reaches `0xD4AE0` immediately.
- `0x70D20` contains diagnostics `[%d] +LongPressVolUpkeyCheck Start!` and `LongPressVolUpkeyCheck Failed!`; its CXDF counterpart is `0x70A40` (91.7% normalized similarity).
- `0xD4AE0` then reads keyboard/event status through retained input helper `0x32060` (CXDF `0x31F20`, 90.0%); event values 1 and 2 loop into direct `0x26020` calls.
- Supporting retained event setup includes `0x70AB0` (creates Odin device-type/power events; CXDF `0x707D0`, 85.4%) and `0x70C00` (Vbus/power-event check; CXDF `0x70920`, 90.0%).
- No call from this interactive long-press/confirmation chain reaches `BLInitToken`, `D5D90`, or the EM token bitmap before `0x26020`.  Bit 3 is therefore a boot-time reconciliation input, not the authorization gate for the interactive native request.

Conclusion: a legitimate EZB6 native request path is statically supported as Download Mode → hold Volume Up for four seconds → native confirmation event → retained state transition.  Device observation is still required to establish whether current OEM/FRP/KG/account policy exposes or rejects that path on this particular locked phone.

### Native transition persists state and wipes data; it is not cosmetic

- `0x26020` takes the state-change branch into `0x26240` (CXDF `0x26100`, 91.0%).  That routine dispatches unlock state `1` to `0x26950`, whose diagnostic is `Unable set the unlock value: %r`.
- `0x26950` writes the desired lock-state byte into the persistent-state structure and invokes `0x18E70` (CXDF `0x18D30`, 90.9%).
- `0x18E70` locates the VB protocol and calls its device-write method; diagnostics identify the operation as `VBRwDevice failed with: %r`.  This is direct evidence of persistent block-device service use, not only an in-memory flag.
- After state write, `0x26240` calls the device-state reset flow, locates the `userdata` partition, invokes the erase-block protocol, and waits for erase completion.  It reports `Unable to erase userdata Partition: %r` on failure.
- `0x26020` then calls its recovery/reboot helper.  The whole sequence is retained from CXDF.

Conclusion: a successfully confirmed interactive request writes persistent boot state and deliberately wipes userdata before recovery reboot.  Static LinuxLoader evidence does not expose the inner implementation of the VB service or prove a direct VaultKeeper/KG call from this routine, so trusted-app persistence linkage remains UNKNOWN rather than assumed.

### CXDF→EZB6 long-press policy divergence — the confirmation path is deliberately unreachable in EZB6

Physical-device observation on the exact target is consistent with a newly recovered predecessor gate, rather than with a missed 4-second gesture: locked EZB6 has no Android OEM-unlocking option and a Volume-Up hold in Download Mode has no result.

- In CXDF, the event loop calls `0xC6ED0` before it polls/starts the long-press sequence.  Its return value is tested at `0x70198` and `0x701E0`; zero skips the long press/confirmation.  `0xC6ED0` obtains a policy structure from `0xC1800`, reads field `+0xF0`, and combines it with runtime state at `0x1A9BC0/+0x1A9BC4` and fields `+0x154/+0x15C`.  It can return one, so CXDF conditionally exposes the path.
- EZB6 preserves the same two call-site gates at `0x70474` and `0x704BC`, but replaces the callee with `0xCA790`.  `0xCA790` obtains the corresponding structure through `0xC2040` and logs its `+0xF0` field, then executes `mov w0,wzr; ret` at `0xCA7F4..0xCA7FC` on every non-fault return path.  It does not branch on `+0xF0`, KG, FRP, OEM, account, or an ADB-visible runtime field before returning.
- The second EZB6 gate is immediate: `0x704BC: bl 0xCA790; 0x704C0: tst w0,#0xff; 0x704C4: b.eq 0x7050C`.  Therefore it always branches around `0x704F8: bl 0x70D20` and `0x70508: bl 0xD4AE0`.  The first gate has the same false-return branch to `0x7067C`.
- `0x70D20` and `0xD4AE0` are still present but dead through the normal event-loop route on EZB6.  Their presence does not imply the path is currently registered/reachable.

Conclusion (**VERIFIED**): the missing confirmation is caused by an EZB6 LinuxLoader entry-policy replacement that deterministically disables the native long-press route.  `KG CHECKING (00)` may independently control Android OEM-toggle policy, but it is not a runtime value capable of making this specific long-press gate true: the replacement ignores all policy values and returns false unconditionally.  No read-only Android property can distinguish or satisfy this already-resolved ABL gate.

Detailed disassembly/caller contexts: `codex_context/reports/longpress_gate_report.txt` (generated by `longpress_gate_trace.py`).

### `D5D90` — generic indexed bit-test, preserved from CXDF

- Both versions place it in executable PE `.text`:
  - EZB6 `0xD5D90`, 19 instructions.
  - CXDF `0xD0D50`, 19 instructions.
- Their normalized instruction sequence is identical.  The only changed operands are image/global addresses.
- EZB6 computes `word = w0 >> 6`, loads `u64` from the `.data` bit-vector rooted at `0x1A8120`, shifts by the original `w0`, masks bit 0, and returns that Boolean.  CXDF does exactly the same from `0x1B2320`.
- The three direct EZB6 callers query bit numbers `3` (`0x9314`), `0x15` (`0x2C184`), and `0x26` (`0x5B7B8`).  No strings or calls occur inside the helper.
- At `0x9314`, result of bit 3 directly becomes the `w0` lock-state input to retained unlock transition `0x26020` (`0` when clear, `1` when set).

This establishes the mechanism as a generic bitmap query; it does not establish what policy/state bit 3 denotes.

### `0x18DB94` — read-only field in a boot-state block, with CXDF analogue

- `0x6EE10` is a 15-instruction getter that returns the 32-bit field at `0x18DB94`.
- Its exact CXDF structural equivalent is `0x6EBA0`, which returns `0x19BFDC`.
- Direct executable-code accesses found in the corrected full `.text` decode are reads only:
  - `0x6EE28` getter;
  - `0x707D4`, comparison with `0x61`;
  - `0x71290`, branches on zero and `0x61`.
- No direct `str*` to the exact field was found.  The `±0x100` neighborhood is a larger mutable boot-state/configuration block, so indirect initialization remains possible.
- Adjacent routine `0x6EE50` passes the block base `0x18DB80` to `0x5C4B0` before reading neighboring fields.  This is a concrete indirect-producer lead, not proof that `0x5C4B0` writes `+0x14`.

### `C7CF0` — BLDP in-memory data dispatcher, not a direct RPMB/UEFI-variable writer

- The function contains the log name `bldp_set_data` and the string `[BLDP] %a : data_type = %d`.
- It dispatches on `w0` data type `0..4`; `x1` is the data/payload pointer.  Call at `0x9338` uses type `1` and points to the stack copy of the `0x18DB94` value.
- Its type-0 path stores the payload byte at `0x19F50E`, then calls BLDP-local helpers (`0xC89D0`, `0xC8B60`).  Other paths similarly operate on the `0x19Fxxx` BLDP state block.
- The target function itself has no direct RPMB, UEFI variable-service, or DDI transport call.  The evidence supports publication into BLDP in-memory state; whether a later BLDP consumer persists or exports it is outside this function.

### `C5A10` — BLDP state-block initializer

- Its log strings are `[BLDP] %a : Setting initial values` and `bldp_init`.
- It initializes/fills the block at `0x19F494` and defaults many byte fields to `0xFF` or zero.
- `0x19F50E` written by `C7CF0` is offset `0x7A` within that same initialized block, directly linking the two targets.
- Its only direct caller is the EZB6 boot flow at `0x9248`, before the `D5D90(3)` → `0x26020` sequence.

## INFERENCE

- The `0x9338` call publishes the old/new analogue boot-state field to BLDP after LinuxLoader applies its retained transition.  It is bookkeeping/state publication, not the source of the transition request.
- The exact comparison value `0x61` around `0x18DB94` likely belongs to a boot-state/configuration enum, but no semantic name is assigned from these observations.

## UNKNOWN / next bounded evidence

- Which producer initializes `0x18DB94` (including whether `0x5C4B0(0x18DB80)` writes it indirectly).
- Meaning and origin of bitmap bit 3 queried by `D5D90(3)`.
- Whether a later BLDP consumer persists or exports the type-1 field.

## Tooling correction

`trace_state_sources.sh` previously called Capstone linearly over `.text`; an embedded invalid/data word caused decoding to stop before all priority functions.  It now enables `skipdata` and avoids dependency downloads when its offline venv already has `pefile` and `capstone`.  Full report regeneration exceeded the terminal cell time limit after the expanded decode, so the conclusions above were extracted directly from the corrected analyzer against the same bodies.
