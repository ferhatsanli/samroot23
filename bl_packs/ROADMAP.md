# ROADMAP.md — S23 Bootloader Unlock Investigation

Goal: prepare a technically justified, executable bootloader-unlock procedure for the exact SM-S911B/DS on EZB6, or reduce the unresolved blocker to the smallest possible set of device experiments.

Status legend:
- [x] VERIFIED / completed
- [~] partially resolved; evidence exists but upstream/downstream meaning remains
- [ ] not resolved
- [!] blocked / requires device or unavailable evidence

## A. Baseline and lower-chain survival
- [x] Confirm physical device is genuinely locked (`flash.locked=1`, vbmeta locked, green verified boot).
- [x] Establish CXDF (`S911BXXS5CXDF`) and EZB6 (`S911BXXS9EZB6`) comparison baselines.
- [x] Extract ABL UEFI and LinuxLoader/Odin bodies.
- [x] Verify generic unlock handling remains in EZB6.
- [x] Verify `IsUnlocked`, `IsUnlockCritical`, `GetUnlockCount` remain.
- [x] Verify LinuxLoader lock/unlock transition survives:
  - CXDF `0x25EE0`
  - EZB6 `0x26020`
  - 136 instructions, 100% normalized match.
- [x] Verify VaultKeeper OEM-related paths remain.
- [x] Verify `tz_kg` `KG_unlock` remains and matches old implementation.
- [x] Establish old OEM/FRP-specific UI/init strings disappear in EZB6.

## B. New EZB6 boot-state path
- [x] Resolve `D5D90` as unchanged indexed `.data` bitmap bit-test.
- [x] Verify bitmap bit 3 directly supplies retained unlock-transition input.
- [x] Resolve `C5A10` as `bldp_init`.
- [x] Resolve `C7CF0` as `bldp_set_data`.
- [x] Establish BLDP path is bookkeeping/publication, not direct transition-request source.
- [x] Identify `0x6EE10` as getter reading EZB6 global `0x18DB94`.
- [x] Identify CXDF analogue of `0x18DB94` as `0x19BFDC`.
- [~] Determine producer and exact semantics of EZB6 global `0x18DB94` (retained boot/recovery/SAPA consumer role established; producer/enum label remains unknown).
- [~] Determine producer and exact semantics of bitmap bit 3 (identified as runtime EM-token result-vector flag; exact token response/meaning remains unknown).

## C. Trace authoritative unlock-state producer upstream
- [x] Resolve `0x5C4B0(0x18DB80)` path noted by current analysis.
- [x] Resolve relevant `0x61` readers and their relationship to bitmap/global state.
- [~] Enumerate all writers/initializers/copies feeding the bitmap containing bit 3 (no direct local writer; `BLInitToken` → EM command interface is closest upstream source).
- [ ] Determine whether bit 3 is loaded from:
  - [ ] OEM/FRP state
  - [ ] VaultKeeper response
  - [ ] KG state/fuse
  - [ ] persistent partition/param
  - [ ] UEFI variable
  - [ ] shared memory / protocol structure
  - [~] another source: external EM-token processing interface (response field still unresolved)
- [ ] Find CXDF analogue of the producer path and compare old/new behavior.
- [ ] Identify the first semantically meaningful CXDF↔EZB6 divergence upstream of the retained transition setter.

## D. Recover user-triggered request path
- [ ] Locate CXDF implementation associated with removed OEM/FRP behavior:
  - [ ] `[FRP][OEM] init succeed!`
  - [ ] `[OEM]Oem unlock value is %d`
  - [ ] `[OEM]PLC:%x`
  - [ ] `[OEM]Unlock buffer Allocate fail`
  - [ ] `OEM LOCK : ...`
- [ ] Use relocation-aware / indirect-reference analysis where simple ADR/ADRP XREFs fail.
- [~] Reconstruct CXDF request chain from OEM/FRP input to LinuxLoader transition (interactive event-loop → dynamic policy gate `0xC6ED0` → confirmation handler → setter recovered; OEM/FRP prerequisite issuer remains unresolved).
- [x] Identify EZB6 equivalent/replacement/deletion for the Download-Mode request-entry stage. (CXDF dynamic `0xC6ED0` is replaced by `0xCA790`, an unconditional-false return; both EZB6 gates skip long-press/confirmation.)
- [~] Determine whether user-triggered request is:
  - [ ] hidden only at Android/UI layer (REJECTED for the Download-Mode route),
  - [x] rejected by ABL policy (EZB6 `0xCA790` returns false unconditionally before `LongPressVolUpkeyCheck`),
  - [x] no longer generated (REJECTED: native Download-Mode long-press request path remains),
  - [ ] rejected downstream by trusted policy,
  - [ ] dependent on a new prerequisite/state.

## E. Trusted transition and persistence verification
- [ ] Connect recovered request path explicitly to VaultKeeper command handling.
- [ ] Connect VaultKeeper path explicitly to `KG_unlock`.
- [ ] Determine what trusted state is authenticated/persisted when a legitimate unlock occurs.
- [x] Determine whether changing only ABL bitmap/state would be cosmetic/transient or capable of initiating legitimate trusted transition. (Bitmap alone is not the interactive input; native transition uses VB persistent write, reset, userdata erase, recovery reboot.)
- [ ] Identify all required authoritative preconditions for locked→unlocked transition.

## E2. Same-binary comparison and alternate authorization routes
- [x] Inventory local SM-S911B binary-B9 inputs. (Only EZB6 B9 exists; no FZDP/other B9 ABL component is local.)
- [x] Compare CXDF/EZB6 entry-policy replacement with FZDP B9. (FZDP `0xCABE0` is 100%-normalized to EZB6 unconditional-false `0xCA790`; both FZDP gates skip long press/confirmation.)
- [x] Enumerate EZB6 direct/tail LinuxLoader transition callers. (Only `0x9324` EM boot reconciliation and blocked interactive `0xD4BAC`.)
- [x] Search EZB6 for a separate legitimate authorization protocol. (Odin EM-token install/verification exists.)
- [~] Determine whether an EM token mode legitimately authorizes consumer bootloader unlock. (FZDP and EZB6 retain the same privileged protocol; no consumer mode/authorized issuer workflow identified; do not install tokens.)

## E3. Historical hard-disable boundary
- [x] Establish initial interval: CXDF B5 dynamic; FZDP B9 and EZB6 B9 hard-disabled.
- [x] Acquire/classify earliest B8 `S911BXXU8CYB4`. (Dynamic/reachable `0xC6ED0`; both gates can reach the 4,000 ms long-press and confirmation route.)
- [!] If B8 hard-disabled, classify late B7 `S911BXXS7CXL2`; if B8 dynamic, classify late B8 `S911BXXS8EZA1`. (CYB4 is dynamic; EZA1 ABL/LinuxLoader is the next exact input and is not local.)

## F. Device-side plan
- [x] Determine whether a complete offline-derived unlock procedure is possible. (No: the normal EZB6 Download-Mode entry route is hard-disabled.)
- [x] If YES: produce exact ordered device procedure. (Not applicable; prior long-press procedure is superseded.)
- [x] If NO: reduce uncertainty to minimum device experiments. (Read-only Android policy/KG/FRP checks can characterize the missing OEM setting but cannot enable the ABL-false gate.)
- [x] Define read-only/low-risk experiments first.
- [x] Define expected observations for every experiment.
- [x] Define failure branches and interpretation.
- [x] Define anti-rollback/wipe/fuse/RPMB risks.
- [x] Create/update `codex_context/DEVICE_UNLOCK_PLAN.md`.

## G. Final acceptance criteria
Project is complete only when one of these is true:

### Success
- [ ] A verified or strongly justified locked→unlocked chain is reconstructed end-to-end.
- [x] `DEVICE_UNLOCK_PLAN.md` contains a concrete procedure for when the phone is connected.
- [x] Preconditions, expected observations, failure branches, and irreversible risks are documented.

### Offline-analysis exhaustion
- [x] All locally available high-value firmware evidence for the observed missing confirmation policy has been exhausted.
- [x] Remaining unknowns are explicitly listed.
- [x] `DEVICE_UNLOCK_PLAN.md` contains the smallest ordered set of device experiments needed to finish the investigation.

## Resume rule
On a new Codex session:
1. Read `CHECKPOINT.md`.
2. Read only the first unchecked/partial section of this roadmap relevant to `CHECKPOINT.md`.
3. Read `NEXT_TASK.md`.
4. Use `REPORT_INDEX.md` only to locate evidence.
5. Do not reread completed stages unless resolving a contradiction.
