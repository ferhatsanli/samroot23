# SM-S911B/DS — EZB6 device unlock plan

## FINAL STATUS

**No supported native bootloader-unlock procedure exists for this exact EZB6 build.** The retained transition and confirmation code is not enough: EZB6 hard-disables the only recovered Download-Mode entry route before it reads a key hold. Do not patch, flash, downgrade, or modify trusted state.

## VERIFIED CHAIN

```text
CXDF: event loop → dynamic policy helper 0xC6ED0 → Volume-Up 4-second check
      → confirmation handler → unlock transition

EZB6: event loop → replacement helper 0xCA790 → always returns false
      → branch around Volume-Up check 0x70D20 and confirmation 0xD4AE0
```

- CXDF `0xC6ED0` reads policy-structure fields `+0xF0/+0x154/+0x15C` and state at `0x1A9BC0/+0x1A9BC4`; it can return true.
- EZB6 `0xCA790` obtains/logs the analogous `+0xF0` field, then always executes `mov w0,wzr; ret`. The preserved call sites at `0x70474` and `0x704BC` branch on this false result.
- `0x70D20`, `0xD4AE0`, and persistent transition `0x26020` remain in the image but are unreachable via the normal Download-Mode loop.
- The observed device behavior (no OEM option, no four-second Volume-Up result) exactly matches this entry-policy replacement.

## ROOT CAUSE

**VERIFIED:** EZB6 replaces the CXDF runtime-dependent Download-Mode unlock-entry policy with an unconditional-false helper. This is not a currently satisfiable KG, FRP, OEM, account, or Android property predicate in that route.

`KG STATUS: CHECKING (00)` and missing Android OEM-unlocking UI remain relevant to Android policy, but they are not the gate that makes the recovered long-press path fail: `0xCA790` ignores runtime policy values when choosing its return.

## OTHER AUTHORIZATION CHANNELS

EZB6 Odin and LinuxLoader contain a privileged EM-token installation/verification mechanism (`BL_EM_CMD_INSTALL_TOKEN`, `BLWriteToken`, issuer/device/expiry/mode validation). LinuxLoader's only alternative transition caller is boot-time EM bit-3 reconciliation after `BLInitToken`.

This is **VERIFIED as a Samsung service-token mechanism**, but **UNKNOWN as a consumer unlock channel**: no local evidence identifies an unlock token mode, a permitted end-user issuer, or a safe user procedure. Do not install, request, reuse, or fabricate tokens. A future local B9 image can be compared statically; it must not be flashed merely because it shares B9.

## DEVICE PRECONDITIONS

The phone is genuinely locked: `flash.locked=1`, vbmeta locked, verified boot green, `KG CHECKING (00)`, secure boot enabled, RPMB provisioned, binary B9. CXDF/B5 cannot be flashed because of anti-rollback.

Additional read-only Android evidence: `ro.oem_unlock_supported` is unset and `oem_unlock_enabled=null`; FRP storage is `/dev/block/persistent`, persistent-data-block is writable, FRP enforcement is enabled, but FRP state is false with no FRP credential handle. Targeted device-policy output reports no apparent OEM/FRP/enterprise restriction. These observations explain neither a user-set OEM flag nor the ABL hard-disable; they only rule out the inspected FRP/enterprise indicators as an obvious Android-side explanation.

## DEVICE-SIDE PROCEDURE

There is no authorized device-side unlock action to perform on this build. Do not repeat the long-press test as an unlock method; it is statically gated off. Preserve normal firmware and user data.

## EXPECTED OBSERVATIONS

- Android has no OEM-unlocking item or reports it unavailable.
- Download Mode has no OEM LOCK line and a long Volume-Up hold makes no confirmation appear.
- These observations are expected from the EZB6 hard-disabled entry gate, not evidence that the hold was too short.

## FAILURE BRANCHES

- **A future update changes the UI or Download-Mode behavior:** capture its exact firmware build and screens before analysis; do not assume this result applies to a new image.
- **An unmodified FZDP/other B9 archive becomes available:** provide its `abl.elf` or extracted LinuxLoader PE (and Odin PE if possible) for offline comparison. Do not flash it pending model/CSC/rollback and legitimate-path verification.
- **Android exposes OEM unlocking after a policy change:** record it read-only, but do not infer that Download Mode can unlock until the new firmware's gate is inspected.
- **A KG/FRP/enterprise warning appears:** preserve it. It can explain Android policy but does not override the verified false ABL gate.

## RISK / IRREVERSIBILITY

- A legitimate transition, if ever reached on another build, wipes userdata and changes security/warranty state.
- Current B9 anti-rollback prevents CXDF/B5 downgrade.
- Never write ABL bitmap, DDI/BLDP, RPMB, UEFI variables, or trusted-app data; no static finding authorizes bypassing the disabled policy.

## VERIFIED / INFERENCE / UNKNOWN

- **VERIFIED:** normal EZB6 Download-Mode flow calls `0xCA790`; it returns false unconditionally; both call sites skip the long-press/confirmation code. The phone's observed no-op is therefore explained.
- **INFERENCE:** `KG CHECKING` likely contributes to Android OEM-toggle exposure, independently of the Download-Mode hard-disable.
- **UNKNOWN:** the exact semantic label of the old CXDF policy structure fields; whether an EM token mode is a legitimate consumer-unlock authorization; and any permitted end-user issuer/workflow. No supported user channel is recovered locally.

## MINIMUM REQUIRED DEVICE EXPERIMENTS

These read-only commands can characterize the separate Android policy state; **none can enable or distinguish the already-resolved Download-Mode false gate**:

```sh
adb shell 'getprop ro.boot.kg; getprop ro.boot.kg.bit; getprop ro.boot.flash.locked; getprop ro.boot.vbmeta.device_state; getprop ro.oem_unlock_supported; getprop ro.frp.pst'
adb shell settings get global oem_unlock_enabled
adb shell dumpsys persistent_data_block
adb shell dumpsys device_policy | grep -i -E 'oem|frp|factory|restriction'
```

Interpretation: an OEM-unlock flag, persistent-data-block “OEM unlock allowed” result, or an enterprise restriction can explain the absent Android setting. A different result does not alter the Download-Mode conclusion unless firmware itself changes.
