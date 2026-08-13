# Samsung Galaxy S23 SM-S911B/DS — Codex Handoff

## Mission

Continue the ongoing offline reverse-engineering investigation of Samsung Galaxy S23 bootloader / OEM Unlock behavior across old and new firmware. Work from:

```text
/Users/ferhatsanli/Desktop/samroot/bl_packs
```

You have terminal access to everything under `bl_packs`. Read existing reports/scripts before regenerating work.

The central question is now:

> Where, between the Android OEM/FRP request layer and the still-present ABL/VaultKeeper/KG unlock machinery, does EZB6 stop or replace the user-triggered locked→unlocked request?

Do not assume the unlock engine was removed: current evidence says the core lower-level machinery still exists.

---

## 1. Device / firmware

Device:

```text
Samsung Galaxy S23
Model: SM-S911B/DS
Firmware lookup model: SM-S911B
CSC: EUX / OXM
```

The user previously rooted this exact physical device before One UI 8 using Odin + Magisk.

Current installed firmware:

```text
S911BXXS9EZB6
Android 16 / One UI 8 era
Bootloader binary B9
```

Previous installed:

```text
S911BXXU9FZDP
B9
```

Historical comparison baseline:

```text
S911BXXS5CXDF
Android 14
B5
```

Short names:

```text
CXDF = S911BXXS5CXDF
EZB6 = S911BXXS9EZB6
```

OTA offered but intentionally not installed:

```text
S911BXXSAFZG1/S911BOXMAFZG1/S911BXXSAFZE1
Binary A / 10
```

Reason: installing it would close B9 downgrade space.

Important limitation: CXDF/B5 cannot be flashed to current B9 due anti-rollback. It is an offline comparison baseline only. There is no known public pre-One-UI-8 B9 baseline available in this project.

---

## 2. Current physical device evidence

Download Mode:

```text
KG STATUS: CHECKING (00)
WARRANTY VOID: 0X1 (0X303)
RP SWREV: B9 (9,9,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0)
SECURE DOWNLOAD: ENABLE
CURRENT BINARY: Samsung Official
QUALCOMM SECUREBOOT : ENABLE
LCS STATE : PROD(3)
RPMB fuse Set
RPMB PROVISIONED
SPU: 5, AR: 1
HDM STATUS : NONE
```

ADB/getprop evidence:

```text
[init.svc.kgtaserv]: [running]
[knox.kg.state]: [Checking]
[ro.boot.bootloader]: [S911BXXS9EZB6]
[ro.boot.flash.locked]: [1]
[ro.boot.kg]: [0x1]
[ro.boot.kg.ap]: [AAAA00000000000000000437FC0DDBED]
[ro.boot.kg.bit]: [00]
[ro.boot.other.locked]: [1]
[ro.boot.vbmeta.device_state]: [locked]
[ro.boot.verifiedbootstate]: [green]
[sys.pdp.action]: [cekeyunlock]
```

Interpretation:

- The physical device is genuinely locked.
- This is not merely Settings hiding a toggle.
- Keep separate:
  1. actual current bootloader state,
  2. Android OEM Unlock toggle exposure,
  3. locked→unlocked transition capability/policy.
- `sys.pdp.action=cekeyunlock` is unrelated.
- `KG CHECKING` is not proven to be the root cause.
- Do not claim permanent impossibility without evidence.

---

## 3. Signing / flashing conclusions already settled

Do not waste time trying to “re-sign” Samsung firmware.

Known:

- Magisk AP flashing requires unlocked bootloader.
- Repacking `.tar.md5` is not Samsung cryptographic signing.
- Official Samsung signatures cannot be produced without Samsung private keys.
- Do not propose signature forgery as the route forward.

---

## 4. BL packages and core files

CXDF BL:

```text
BL_S911BXXS5CXDF_S911BXXS5CXDF_MQB80280092_REV00_user_low_ship_MULTI_CERT.tar.md5
```

EZB6 BL:

```text
BL_S911BXXS9EZB6_S911BXXS9EZB6_MQB106572656_REV00_user_low_ship_MULTI_CERT.tar.md5
```

Important components:

```text
abl.elf.lz4
vaultkeeper.mbn.lz4
tz_kg.mbn.lz4
vbmeta.img.lz4
```

Already decompressed/analyzed counterparts may exist under the working tree.

---

## 5. ABL outer structure

Both decompressed `abl.elf` files are exactly 4,194,304 bytes.

SHA256:

```text
CXDF d5587c4b5699e7f8026f400350663336b0c16722c84c41bf07bb302f0ac3fed2
EZB6 b092b4e808bc56703af441b812379de38fea37ec25cfb7939828311365df7da3
```

Raw diff:

```text
825,872 bytes differ
19.6903%
206 / 1024 4K blocks changed
```

Critical structural discovery:

`abl.elf` is an ELF32 ARM outer container holding a UEFI PI Firmware Volume, not simply raw ARM32 code.

Outer ELF:

```text
Entry: 0x9FA00000
PT_LOAD offset 0x1000
vaddr 0x9FA00000
filesz/memsz 0x252000
```

Firmware Volume:

```text
_FVH file offset 0x1028
FV starts 0x1000
Filesystem GUID 8C8CE578-8A3D-4F1C-9935-896185C32DD3
FV length 0x252000
FV end 0x253000
```

A prior ~99% changed region was misleading because it contained compressed UEFI content.

---

## 6. UEFI extraction

LongSoft UEFIExtract was used successfully. Warning:

```text
parse: not a single Volume Top File is found, the image may be corrupted
```

was nonfatal.

Inner structure:

```text
Volume image GUID: 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792
Compressed GUID-defined section: EE4E5898-3914-4259-9D6E-DC7BD79403CF
Inner FV: 046FAE99-CF2E-49ED-A6A8-A1488B7E80D3
```

Important inner AArch64 EFI applications:

```text
Odin
LinuxLoader
Cryptest
QuestSOD
QuestUSB
```

Relevant body paths generally resemble:

```text
uefi_abl_compare/.../Odin/1 PE32 image section/body.bin
uefi_abl_compare/.../LinuxLoader/1 PE32 image section/body.bin
```

LinuxLoader sizes:

```text
CXDF 1,794,048 bytes
EZB6 1,753,088 bytes
```

Odin sizes:

```text
CXDF 1,146,880 bytes
EZB6 1,196,032 bytes
```

---

## 7. Critical OEM/FRP string changes

CXDF Odin strings removed in EZB6 include:

```text
OEM LOCK : %a (%a%x)
OEM LOCK : %a (%a)
[FRP][OEM] init succeed!
[OEM]Oem unlock value is %d
[OEM]PLC:%x
[OEM]Unlock buffer Allocate fail
]vbmeta
```

CXDF LinuxLoader strings removed in EZB6 include:

```text
[FMM]QseecomStartApp (vk) call Failed, status=%d, vaultkeeperappid=%d
[FMM]QseecomStartApp (vk) call success status=%d, vaultkeeperappid=%d
[FRP][OEM] init succeed!
[OEM]Oem unlock value is %d
[OEM]PLC:%x
[OEM]Unlock buffer Allocate fail
```

EZB6 generalized the FMM strings to `%a` app-name forms.

Important correction: do NOT claim EZB6 still contains exact `[OEM]Oem unlock value is %d`; it does not.

This correlates with the physical observation that One UI 8 Download Mode no longer displays an `OEM LOCK` line.

---

## 8. Generic unlock support remains

EZB6 LinuxLoader still contains active generic unlock machinery, including:

```text
GetUnlockCount
androidboot.vbmeta.device_state
unlocked
Unlock
device_unlock.jpg
IsUnlockCritical
Unable set the unlock value: %r
Unable set the unlock critical value: %r
IsUnlocked
For device unlock, Draw UnLock Img
Device is unlocked, Skipping boot verification
```

Conclusion:

> Handling/booting an already-unlocked device remains supported.

Do not conflate this with the user-triggered locked→unlocked request path.

---

## 9. Unlock state globals

Previously identified globals:

CXDF:

```text
IsUnlocked       0x199F65
IsUnlockCritical 0x199F66
UnlockCount      0x19ABF8
```

EZB6:

```text
IsUnlocked       0x18BB0D
IsUnlockCritical 0x18BB0E
UnlockCount      0x18C7A0
```

Observed access patterns were structurally the same:

```text
IsUnlocked:       reads=2 writes=3
IsUnlockCritical: reads=2 writes=3
UnlockCount:      reads=4 writes=2
```

This strongly supports survival of the core state machinery.

---

## 10. Function-level matches

Important old/new mappings:

```text
GetUnlockCount
CXDF function ~0x25CD0, xref ~0x25D24
EZB6 function ~0x25E10, xref ~0x25E64

IsUnlocked
CXDF 0x25D80
EZB6 0x25EC0

IsUnlockCritical
CXDF 0x25E30
EZB6 0x25F70
```

`androidboot.vbmeta.device_state` propagation also remains semantically near-identical.

---

## 11. Strongest ABL result: lock/unlock transition setter survives

CXDF transition function:

```text
0x25EE0
```

EZB6 transition function:

```text
0x26020
```

Latest report measured:

```text
Normalized similarity: 100.00%
Instruction count: 136 vs 136
```

Equivalent strings in both include:

```text
Lock
Unlock
Device already %a keep booting step(%d)
ERROR!!! Flash Value %a Failed..!!(%d)
LOCK
UNLOCK
Device reboot to recovery due to change from %a to %a(%d)
```

Conclusion:

> The LinuxLoader lock/unlock transition function itself was not removed or materially rewritten in EZB6.

---

## 12. Major new EZB6 boot-time sequence

Read these first if present:

```text
unlock_entry_trace/summary.txt
unlock_entry_trace/report.txt
```

Critical EZB6 sequence:

```asm
0x00009310: mov  w0, #3
0x00009314: bl   #0xd5d90
0x00009318: tst  w0, #0xff
0x0000931C: mov  w1, wzr
0x00009320: cset w0, ne
0x00009324: bl   #0x26020
0x00009328: bl   #0x6ee10
0x0000932C: str  w0, [sp, #0xc]
0x00009330: add  x1, sp, #0xc
0x00009334: mov  w0, #1
0x00009338: bl   #0xc7cf0
```

Semantically:

```text
D5D90(3)
   ↓
booleanize result
   ↓
0x26020(boolean, 0)    ← existing 100%-matched unlock-state setter
   ↓
6EE10()
   ↓
C7CF0(1, &value)
```

Latest report also showed:

```text
CXDF setter direct callers: 0
EZB6 setter direct callers: 1
```

EZB6 direct caller:

```text
0x9324
```

This new boot-time state source is now a primary investigation target.

---

## 13. D5D90 / C7CF0 / C5A10 status

Previous analyzer returned 0 decoded instructions for:

```text
D5D90
C7CF0
C5A10
```

Do NOT interpret this as “they do not exist.”

The analyzer only disassembled `.text`; these targets may reside in another executable/nonstandard PE section.

Known references:

D5D90:

```text
0x9314
0x2C184
0x5B7B8
```

C7CF0:

```text
0x89A8
0x9338
0x813C8
0x81410
```

C5A10:

```text
0x9248
```

The next intended script was:

```text
trace_state_sources.sh
```

Its intended outputs:

```text
state_source_trace/summary.txt
state_source_trace/report.txt
```

If they exist, read them before doing anything else. If not, inspect/fix/run the script.

---

## 14. Global getter 0x6EE10

Disassembly:

```asm
0x0006EE10: sub  sp, sp, #0x20
0x0006EE14: str  x30, [sp, #0x10]
0x0006EE18: adrp x8, #0x13e000
0x0006EE1C: adrp x9, #0x18d000
0x0006EE20: ldr  x8, [x8, #8]
0x0006EE24: str  x8, [sp, #8]
0x0006EE28: ldr  w0, [x9, #0xb94]
...
0x0006EE48: ret
```

Therefore it reads:

```text
0x18D000 + 0xB94 = 0x18DB94
```

Working interpretation:

```text
0x6EE10 = simple getter for global 0x18DB94
```

Still unknown:

- who writes `0x18DB94`,
- exact semantic meaning of the field.

Finding all writers/readers is high priority.

---

## 15. C7CF0 wrapper clue

A previous analyzer incorrectly treated `0x9688` as a 91-instruction function.

Actual local block:

```asm
0x00009688: add  x1, sp, #0x30
0x0000968C: mov  w0, wzr
0x00009690: strb w8, [sp, #0x30]
0x00009694: b    #0xc7cf0
```

This is a tail-call wrapper:

```text
state byte in w8
   ↓
stack byte
   ↓
C7CF0(0, &state)
```

It is invoked with at least:

```text
2
3
4
```

There is also:

```text
C7CF0(1, &value)
```

at `0x9338`.

Current hypothesis (not verified): C7CF0 is a generic state/event sink, possibly DDI/BLDP-related.

---

## 16. New BLDP / DDI state tracking in EZB6

EZB6 added strings such as:

```text
ClearDdiPreviousBldpData
CopyDdiData
GetKGFuseFromBL
SetDdiBootMode
SetDdiKernelType
SetDdiRebootReason

[BLDP] bootloader_mode = %d
[BLDP] bootloader_rp = 0x%x
[BLDP] kg_fuse = 0x%x
[BLDP] kg_state = 0x%x
[BLDP] secure_boot = 0x%x
[BLDP] unlock_count = %d
[BLDP] vbmeta_type = 0x%x

bldp_internal_set_kg_info
bldp_internal_set_secure_boot_info
bldp_internal_set_vbmeta_type
```

This proves new security/boot state synchronization/hardening exists.

Do NOT yet claim BLDP/DDI is itself the unlock gate.

---

## 17. VaultKeeper findings

Files analyzed:

```text
cxdf_vaultkeeper.mbn
ezb6_vaultkeeper.mbn
```

Sizes:

```text
CXDF 1,491,544 bytes
EZB6 1,069,656 bytes
```

Dynamic symbol counts:

```text
CXDF 285
EZB6 204
```

Many removed functions were vault/crypto infrastructure, not clear OEM unlock removal.

Crucially, equivalent OEM-related paths remain in both:

```text
Failed to get oem flag(%d)
Failed to check oem_sw_fuse(%d)
Command from bootloader is invalid (%d)
RPMB Key provisioning not yet. Skip.
```

Compared OEM flag / OEM software fuse code paths matched at or near 100% in earlier analysis.

Conclusion:

> VaultKeeper OEM-related handling was not simply removed.

---

## 18. tz_kg findings

Files analyzed:

```text
cxdf_tz_kg.mbn
ezb6_tz_kg.mbn
```

Both size:

```text
1,561,176 bytes
```

Major result:

```text
KG_unlock remains present in both.
CXDF KG_unlock: 0x909C
EZB6 KG_unlock: 0x9188
size: 1124 bytes both
normalized similarity: 100%
```

Strings still present in both:

```text
KG_unlock
KG_TA : KG unlock
KG_TA : RPMB is not available when unlocking
```

`KG_lock` and KG checking paths also matched strongly.

Conclusion:

> Secure-world KG unlock engine itself was not removed from EZB6.

New EZB6 hardening observed:

```text
KG_TA : rpmb hmac mismatch : %d
KG_TA : Rejecting dev cert.
```

Symbol changes included:

```text
removed:
KG_private_decrypt
clear_rpmb_keep_certs

added:
get_hotp_key
clear_rpmb_keep_persistent_data
```

This suggests stronger RPMB/certificate/persistent-state handling, but does not yet prove the OEM unlock blocker.

---

## 19. Current strongest architectural model

Old hypothesis:

```text
Samsung removed unlock functionality from ABL / VaultKeeper / KG
```

is now poorly supported.

Stronger current model:

```text
Android Settings OEM Unlock
        │
        ▼
OEM / FRP / policy request layer
        │
        │   <<< MOST SUSPICIOUS REGION
        ▼
ABL / LinuxLoader unlock-state setter
        │
        ▼
VaultKeeper
        │
        ▼
tz_kg KG_unlock
        │
        ▼
RPMB / trusted state
```

The lower half remains demonstrably present.

---

## 20. Current flow diagram

```text
Android Settings
"OEM Unlock"
      │
      │  EZB6: toggle absent
      ▼
OEM / FRP / policy request layer
      │
      │  old OEM-specific strings removed
      ▼
ABL / LinuxLoader
      │
      ├── IsUnlocked            present
      ├── IsUnlockCritical      present
      ├── GetUnlockCount        present
      ├── unlock setter         present
      ├── device_unlock.jpg     present
      └── AVB unlocked handling present
      │
      ▼
Lock/Unlock Setter
CXDF 0x25EE0
EZB6 0x26020
100% normalized match
      │
      ▼
VaultKeeper
OEM flag / OEM SW fuse / bootloader command logic retained
      │
      ▼
tz_kg
KG_lock / KG_unlock / KG checking retained
KG_unlock old/new = 100% normalized match
      │
      ▼
RPMB / trusted state
```

New EZB6 side chain:

```text
EZB6 boot
   │
   ▼
D5D90(3)
   │
   ▼
boolean
   │
   ▼
0x26020(boolean, 0)
unlock-state setter
   │
   ▼
0x6EE10()
   │
   ▼
global 0x18DB94
   │
   ▼
C7CF0(1, &value)
```

Additional:

```text
state 2 ─┐
state 3 ─┼──> wrapper 0x9688 ──tail-call──> C7CF0
state 4 ─┘
```

---

## 21. Reports/scripts to discover first

Start with:

```bash
pwd
find . -maxdepth 4 -type f | sort
```

Then prioritize files containing:

```text
unlock
oem
xref
trace
state
global
vault
kg
bldp
ddi
compare
```

Known paths from this project may include:

```text
unlock_path_analysis/unlock_string_diff.txt
unlock_path_analysis/unlock_xref_report.txt

oem_unlock_trace/trace_summary.txt
oem_unlock_trace/trace_report.txt

unlock_entry_trace/summary.txt
unlock_entry_trace/report.txt

state_source_trace/summary.txt
state_source_trace/report.txt

trace_unlock_entry.sh
trace_state_sources.sh
```

Confirm existence; do not blindly assume every path exists.

---

## 22. Immediate next task — Priority 1: resolve D5D90

Goal:

```text
What exactly does D5D90(3) query/read?
```

Actions:

1. Identify PE section containing `0xD5D90`.
2. Disassemble it even if outside `.text`.
3. Enumerate all direct/tail callers:
   - `0x9314`
   - `0x2C184`
   - `0x5B7B8`
4. Compare arguments passed by each caller.
5. Resolve nearby strings/globals/protocols.
6. Find best structural CXDF equivalent.
7. Determine what selector/value `3` means only from evidence.

Possible candidates (do not assume): KG state, OEM state, DDI/BLDP field, boot mode, fuse, persistent property.

---

## 23. Priority 2: resolve global 0x18DB94

Goal:

```text
Who writes 0x18DB94 and what does it represent?
```

Known read:

```text
0x6EE28: ldr w0, [x9, #0xB94]
ADRP x9 = 0x18D000
=> 0x18DB94
```

Actions:

1. Find every exact read/write reference.
2. Inspect neighbors ±0x100 or wider if it is part of a struct.
3. Trace writer functions backward through callers.
4. Resolve referenced strings.
5. Compare analogous CXDF global/function.

---

## 24. Priority 3: resolve C7CF0

Goal:

```text
What state/event/data does C7CF0 persist or publish?
```

Known refs:

```text
0x89A8
0x9338
0x813C8
0x81410
tail call from 0x9688
```

Known call forms:

```text
C7CF0(1, &value)
C7CF0(0, &state_byte)
```

with state byte values 2/3/4.

Identify storage destination: DDI, shared IMEM, BLDP, UEFI variable, RPMB, or merely in-memory record.

---

## 25. Priority 4: resolve C5A10

EZB6 added:

```text
0x9248 -> 0xC5A10
```

Determine whether it participates in DDI/BLDP, KG synchronization, unlock-state initialization, or unrelated boot telemetry.

---

## 26. Priority 5: reconstruct exact user request chain

After the new state plumbing is understood, return to CXDF-only OEM strings:

```text
[FRP][OEM] init succeed!
[OEM]Oem unlock value is %d
[OEM]PLC:%x
[OEM]Unlock buffer Allocate fail
OEM LOCK : ...
```

Simple ADR/ADRP scanners found zero direct refs. Do not conclude they are unused.

Potential missing mechanisms:

- relocation-backed pointers,
- pointer tables,
- ADRP+LDR indirect refs,
- MOVZ/MOVK address construction,
- protocol tables,
- data-driven log structures.

Relocation-aware PE analysis may be needed.

---

## 27. Dead ends / already solved facts

Do not spend time re-proving:

- current device is locked,
- generic unlocked-device handling exists,
- `KG_unlock` exists,
- ABL lock/unlock setter exists,
- `IsUnlocked` exists,
- `androidboot.vbmeta.device_state` propagation exists.

Do not equate “zero simple xrefs” with unused code/data.

Do not assume BLDP/DDI is the gate merely because it is new.

Do not assume KG CHECKING is the gate.

---

## 28. User workflow preferences

User prefers:

- Turkish,
- terminal-first,
- concise but technically precise,
- one comprehensive main `.sh` script per major stage,
- not many tiny scripts,
- after a script, one single command to collect reports.

On macOS typical report collection:

```bash
cat <reports...> | pbcopy
```

Before writing **any new script**, ask exactly:

```text
1 = macOS, 2 = Termux — hangisindesin?
```

Wait for answer before generating the script.

---

## 29. Operational rule

Until the gating/request path is understood:

- prefer offline firmware analysis,
- do not automatically modify the physical device,
- do not flash experimental bootloader components,
- do not advance the phone to binary A firmware,
- do not blindly patch branches and flash them.

Current objective is understanding the request/trusted-state chain first.

---

## 30. Suggested autonomous Codex workflow

From `bl_packs`:

```bash
pwd
find . -maxdepth 4 -type f | sort > /tmp/bl_packs_files.txt
```

Then:

1. Read this handoff fully.
2. Inspect existing reports listed above.
3. Inspect `trace_unlock_entry.sh`.
4. Inspect/run/fix `trace_state_sources.sh` if appropriate.
5. Resolve D5D90 / C7CF0 / C5A10 across all PE executable/code sections.
6. Trace all accesses to `0x18DB94`.
7. Structurally compare each relevant EZB6 function against CXDF.
8. Produce one concise findings report and one detailed technical report.
9. Separate VERIFIED from INFERENCE explicitly.
10. Do not redo solved work unless validating an inconsistency.
11. Preserve new mappings in a machine-readable mapping file if practical.

Suggested mapping format:

```text
symbol_or_role,firmware,address,status,evidence
```

Seed entries:

```text
UnlockStateSetter,CXDF,0x25EE0,verified,100% match with EZB6 0x26020
UnlockStateSetter,EZB6,0x26020,verified,136 instruction function
IsUnlocked,CXDF,0x25D80,verified,xrefs/global reads
IsUnlocked,EZB6,0x25EC0,verified,matched structure
KG_unlock,CXDF,0x909C,verified,tz_kg function
KG_unlock,EZB6,0x9188,verified,100% normalized match
GlobalBootState,EZB6,0x18DB94,unknown,read by 0x6EE10
D5D90,EZB6,0xD5D90,unknown,new boot-time state source candidate
C7CF0,EZB6,0xC7CF0,unknown,state/event sink candidate
C5A10,EZB6,0xC5A10,unknown,new boot-flow call
```

---

## 31. Final focus

The project is no longer primarily asking:

```text
Did Samsung delete unlock support?
```

Evidence says the core unlock engine remains.

Current focus:

```text
Where is the user-generated locked→unlocked request prevented, replaced, or no longer generated in EZB6?
```

Highest-priority newly discovered chain:

```text
D5D90(3)
   ↓
0x26020
   ↓
0x18DB94
   ↓
C7CF0
```

Resolve that chain before broadening the search.
