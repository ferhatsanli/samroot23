# PROJECT_STATE.md

## Device / baselines
- Device: Samsung Galaxy S23 `SM-S911B/DS`; firmware search model `SM-S911B`; CSC `EUX/OXM`.
- Current firmware: `S911BXXS9EZB6` = **EZB6**, Android 16 / One UI 8 era, bootloader binary B9.
- Historical offline baseline: `S911BXXS5CXDF` = **CXDF**, Android 14, bootloader binary B5.
- CXDF cannot be flashed to current B9 device because of anti-rollback.
- Offered binary-A OTA `S911BXXSAFZG1/...` was intentionally not installed.

## Current physical-device state — VERIFIED
Observed:
- `ro.boot.flash.locked=1`
- `ro.boot.other.locked=1`
- `ro.boot.vbmeta.device_state=locked`
- `ro.boot.verifiedbootstate=green`
- Download Mode: `KG STATUS: CHECKING (00)`, `RP SWREV: B9`, secure boot enabled, RPMB provisioned.
Therefore the device is genuinely locked; this is not merely Settings hiding a toggle.
`KG CHECKING` is not proven to be the cause.

Additional read-only Android-policy observations:
- `ro.oem_unlock_supported` is unset; `settings get global oem_unlock_enabled` is `null`.
- `ro.frp.pst=/dev/block/persistent`; persistent-data-block is writable; FRP enforcement is enabled, but FRP state is false and no FRP credential handle exists.
- Targeted `device_policy` output contains no apparent OEM/FRP/enterprise restriction.
These facts characterize the absent Android OEM-unlock UI. They do not alter the separately verified unconditional-false EZB6 Download-Mode gate.

## ABL / UEFI structure — VERIFIED
- `abl.elf` old/new are 4,194,304 bytes.
- It is an ELF32 ARM outer container holding a UEFI PI Firmware Volume.
- UEFI inner AArch64 apps include `Odin` and `LinuxLoader`.
- LinuxLoader bodies:
  - CXDF: 1,794,048 bytes
  - EZB6: 1,753,088 bytes
- Existing extracted paths live under `uefi_abl_compare/`.

## OEM-specific UI/init changes — VERIFIED
CXDF-only strings removed in EZB6 include:
- `[FRP][OEM] init succeed!`
- `[OEM]Oem unlock value is %d`
- `[OEM]PLC:%x`
- `[OEM]Unlock buffer Allocate fail`
- `OEM LOCK : %a (%a%x)`
- `OEM LOCK : %a (%a)`
This correlates with the physical One UI 8 Download Mode no longer showing an `OEM LOCK` line.

## Generic unlock machinery — VERIFIED
EZB6 still retains:
- `GetUnlockCount`
- `IsUnlocked`
- `IsUnlockCritical`
- `androidboot.vbmeta.device_state`
- unlocked AVB handling
- `device_unlock.jpg`
- lock/unlock transition/error strings.

Key LinuxLoader mappings:
- `GetUnlockCount`: CXDF ~`0x25CD0`; EZB6 ~`0x25E10`
- `IsUnlocked`: CXDF `0x25D80`; EZB6 `0x25EC0`
- `IsUnlockCritical`: CXDF `0x25E30`; EZB6 `0x25F70`

Global state layout:
- CXDF `IsUnlocked=0x199F65`, `IsUnlockCritical=0x199F66`, `UnlockCount=0x19ABF8`
- EZB6 `IsUnlocked=0x18BB0D`, `IsUnlockCritical=0x18BB0E`, `UnlockCount=0x18C7A0`
Read/write patterns are strongly preserved.

## Core lock/unlock transition — VERIFIED, HIGH IMPORTANCE
LinuxLoader transition function:
- CXDF: `0x25EE0`
- EZB6: `0x26020`
- both 136 instructions
- normalized similarity: **100.00%**

Equivalent strings include:
`Lock`, `Unlock`, `LOCK`, `UNLOCK`,
`Device already %a keep booting step(%d)`,
`ERROR!!! Flash Value %a Failed..!!(%d)`,
`Device reboot to recovery due to change from %a to %a(%d)`.

Conclusion: the core ABL/LinuxLoader transition implementation was not removed.

## VaultKeeper — VERIFIED
Analyzed `cxdf_vaultkeeper.mbn` and `ezb6_vaultkeeper.mbn`.
EZB6 is substantially smaller, but OEM-related handling remains, including equivalent paths around:
- OEM flag
- OEM software fuse
- bootloader command handling
Thus VaultKeeper OEM handling was not simply deleted.

## tz_kg — VERIFIED
Analyzed `cxdf_tz_kg.mbn` and `ezb6_tz_kg.mbn`.
`KG_unlock` remains:
- CXDF `0x909C`
- EZB6 `0x9188`
- equal function size
- **100% normalized match**

`KG_lock` and KG-checking paths also remain strongly matched.
EZB6 adds trusted-state hardening including strings such as:
- `KG_TA : rpmb hmac mismatch : %d`
- `KG_TA : Rejecting dev cert.`
These are not proven to be the OEM-unlock gate.

## New EZB6 boot-time state path — VERIFIED, CURRENT FOCUS
From `unlock_entry_trace`:

```asm
0x9310: mov w0,#3
0x9314: bl  0xD5D90
0x9318: tst w0,#0xff
0x931C: mov w1,wzr
0x9320: cset w0,ne
0x9324: bl  0x26020
0x9328: bl  0x6EE10
0x932C: str w0,[sp,#0xc]
0x9330: add x1,sp,#0xc
0x9334: mov w0,#1
0x9338: bl  0xC7CF0
```

EZB6 `0x26020` has one direct caller (`0x9324`); the corresponding CXDF setter had no direct `BL` caller detected by that analysis.

`0x6EE10` is a small getter for 32-bit global `0x18DB94`; its exact CXDF equivalent is `0x6EBA0` reading `0x19BFDC`. Three direct code reads were found (`0x6EE28`, `0x707D4`, `0x71290`), but no direct store. Exact semantic meaning remains unknown.

Known direct callers:
- `D5D90`: `0x9314`, `0x2C184`, `0x5B7B8`
- `C7CF0`: `0x89A8`, `0x9338`, `0x813C8`, `0x81410`
- `C5A10`: `0x9248`

`0x9688` is not a 91-instruction function. The actual local wrapper is:
```asm
add  x1,sp,#0x30
mov  w0,wzr
strb w8,[sp,#0x30]
b    0xC7CF0
```
It tail-calls `C7CF0` with state-byte values observed as 2, 3, and 4.

`trace_state_sources.sh` decoding defect is fixed: embedded data made Capstone stop its linear `.text` decode. Corrected decode shows:
- `D5D90` = 19-instruction generic indexed bit-test over EZB6 `.data` bit-vector `0x1A8120`, structurally identical to CXDF `0xD0D50` / `0x1B2320`. Calls query bits 3, 0x15, and 0x26. It does not establish the meaning of bit 3.
- `C7CF0` is BLDP `bldp_set_data`: a type-0..4 dispatcher writing/publishing into the `0x19Fxxx` BLDP in-memory block. The `0x9338` call uses type 1 and the `0x18DB94` value. No direct RPMB, UEFI-variable, DDI, or trusted-storage call occurs in this function.
- `C5A10` is BLDP `bldp_init`, initializing the block at `0x19F494`; the `C7CF0` byte destination `0x19F50E` is its offset `+0x7A`. Its sole direct caller is boot flow `0x9248`.

Detailed evidence: `codex_context/reports/EZB6_STATE_SOURCE_RESOLUTION.md`.

`0x5C4B0`, previously suspected because `0x6EE50` passes it `0x18DB80`, is a retained CCIC-protocol ADC wrapper (closest CXDF analogue `0x5C2E0`, 91.18% normalized similarity).  Its callback buffer is not evidence of a write to `0x18DB94` (`+0x14`), and the wrapper itself only reads buffer offset zero for logging.  It is excluded as the authoritative unlock-state producer.

The two non-getter `0x18DB94` readers belong to retained BootChecker recovery-key (`0x706F8`, CXDF `0x70418`, 92.0%) and SAPA RTC/power-on (`0x7105C`, CXDF `0x70D7C`, 90.4%) control routines.  Their same `0x61` comparison is preserved from CXDF; bounded call traversal does not reach `D5D90`, `0x26020`, or the unlock layer.  Thus the field’s observed role is independent boot/recovery/power-state control, not an authoritative unlock request.

The bit-vector queried by `D5D90` is runtime-zeroed `.data` and is not directly written by LinuxLoader code.  Its enclosing EM token subsystem runs `BLInitToken` → `BL_EM_CMD_INIT` → `BLEmProcess` immediately before the bit-3-to-transition call.  Bit 3 is consequently an externally processed EM-token result flag, not an independently authoritative bitmap.  Its exact response producer/meaning remains unknown; no EZB6-only divergence was found in the retained EM wrappers.

The interactive LinuxLoader transition code survives: CXDF `0xCFAA0` directly invokes `0x25EE0`; its EZB6 equivalent `0xD4AE0` (93.33% normalized similarity) directly invokes `0x26020` at `0xD4BAC`.  The embedded EZB6 event-loop body contains `LongPressVolUpkeyCheck(4,000 ms)` followed by `0xD4AE0`; that confirmation handler has no path through `BLInitToken`, `D5D90`, or bit 3.  Thus EM bit 3 is boot-time reconciliation state, not the authorization input of the dormant interactive code.

## Long-press entry policy — VERIFIED
The physical device has no Android OEM-unlocking option and its Download-Mode Volume-Up hold has no visible effect. Static comparison resolves why: CXDF calls dynamic policy helper `0xC6ED0`, which reads a policy structure (`+0xF0/+0x154/+0x15C`) and runtime state at `0x1A9BC0/+0x1A9BC4`, before conditionally returning true. EZB6 replaces it with `0xCA790`: this logs the analogous structure's `+0xF0`, then unconditionally returns zero (`0xCA7F4`). At both preserved EZB6 event-loop gates (`0x70474`, `0x704BC`), zero branches around `0x70D20` and `0xD4AE0`. Therefore the native long-press confirmation route is deliberately unreachable on EZB6 normal flow, regardless of KG/FRP/OEM/runtime values. `KG CHECKING (00)` may independently explain Android UI policy but cannot enable this ABL gate.

## B9 comparison availability and alternate EM channel — VERIFIED
The local workspace contains no `S911BXXU9FZDP` or any other SM-S911B B9 ABL/LinuxLoader/Odin input—only CXDF B5 and EZB6 B9. The minimum comparison input is an unmodified FZDP (or other verified B9) `abl.elf` / extracted LinuxLoader PE; the companion Odin PE is useful. Same binary revision is not enough authorization to flash it.

EZB6 LinuxLoader has exactly two direct/tail callers of `0x26020`: blocked interactive `0xD4BAC` and boot-time `0x9324`, which runs `BLInitToken` then EM bit 3 reconciliation. EZB6 Odin implements a privileged EM-token protocol (`BL_EM_CMD_INSTALL_TOKEN`, `BLWriteToken`, `Process_EMTOKEN`) with issuer, device, validity, expiry, and mode checks; LinuxLoader retains matching token parsing/mode paths. This establishes a Samsung-authorized service-token mechanism feeding the only alternative transition caller, but no local evidence identifies a consumer-unlock token mode, a user-accessible issuer/workflow, or permission to install a token.

## FZDP B9 comparison — VERIFIED
Unmodified `S911BXXU9FZDP` B9 ABL was extracted locally (archive SHA-256 `9c8508eee373e9ae69a4979aa7f7868bea4a984d1f705dd2707a66137edd505f`). FZDP already hard-disables the normal Download-Mode route: helper `0xCABE0` is a 28-instruction, 100%-normalized equivalent of EZB6 `0xCA790`, logging policy `+0xF0` then returning false unconditionally. Its two gates (`0x707A8`, `0x707F0`) skip retained long press `0x710D0` and confirmation `0xD74E0`; confirmation would otherwise call its unchanged 136-instruction transition `0x26020` at `0xD75AC`. FZDP has the same two transition callers (boot-time `0x9324`, dormant interactive `0xD75AC`) and the same privileged Odin EM-token surface, with no identified consumer-unlock mode. Thus hard-disable predates EZB6 and is code policy, not the observed device's KG/FRP runtime state. No flashing implication follows from same B9.

The interactive `0x26020` path is persistent and destructive by design: it reaches retained `set unlock value` → VB-protocol device-write, resets device state, erases `userdata`, then reboots to recovery.  It is not a cosmetic ABL bitmap change.  Static evidence does not yet expose the VB service’s internal trusted-app linkage, so VaultKeeper/KG connection is not asserted.

`codex_context/DEVICE_UNLOCK_PLAN.md` now records the supported result: no firmware patch/downgrade procedure is justified offline; the next physical work is a minimal read-only OEM-unlock visibility/prerequisite and Download-Mode observation set.

## New BLDP/DDI layer — VERIFIED PRESENCE, ROLE UNKNOWN
EZB6 adds many DDI/BLDP-related strings/functions, including:
`ClearDdiPreviousBldpData`, `CopyDdiData`, `SetDdiBootMode`,
`SetDdiKernelType`, `SetDdiRebootReason`, `GetKGFuseFromBL`,
and BLDP fields for KG state/fuse, secure boot, unlock count, vbmeta type.
This proves new boot-state tracking/synchronization but not that it is the gate.

## Current architectural conclusion
The hypothesis “Samsung deleted unlock support” is weak.

Strongest model:
```text
Android OEM/FRP user request
        ↓
policy / request-entry layer      ← EZB6 Download-Mode long-press entry is hard-disabled
        ↓
ABL LinuxLoader transition       ← retained
        ↓
VaultKeeper OEM handling         ← retained
        ↓
tz_kg KG_unlock                  ← retained
        ↓
RPMB / trusted state
```

Central question:
**Where does EZB6 stop, replace, or fail to generate the user-triggered locked→unlocked request before the still-present unlock engine?**
