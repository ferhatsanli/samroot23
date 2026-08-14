# CYB4 B8 Download-Mode entry comparison

## Input and extraction

The validated CYB4 archive is identified in `CYB4_INPUT_VALIDATION.md` (ZIP SHA-256 `7e1231842645dfbf01fe313755bbabbb507c86abae2c458c18b248b877dcc89e`). Its `abl.elf.lz4` decompresses to a 4,194,304-byte ELF32 ARM container. The UEFI FV begins at `0x1000`, has declared length `0x252000`, and was locally unpacked to recover the LinuxLoader PE. Binary inputs and extracted content remain local-only.

## CYB4 result — VERIFIED: dynamic/reachable policy

CYB4 has not adopted the B9 unconditional-false entry helper. It retains the dynamic policy helper at `0xC6ED0`:

- 71 instructions, ending `0xC6FEC`; 100.00% normalized similarity to CXDF `0xC6ED0`.
- It obtains a policy structure through `0xC1800`, reads `+0xF0`, and conditionally evaluates runtime globals near `0x1AA000 + 0xBC0/+0xBC4` plus structure fields `+0x154/+0x15C`.
- It has a reachable `mov w0,#1` return at `0xC6F6C` and other conditional returns; it is not an unconditional false stub.

The normal Download-Mode event loop calls it twice:

```asm
0x701A4: bl  0xC6ED0
0x701A8: tst w0,#0xFF
0x701AC: b.eq 0x703AC
...
0x701EC: bl  0xC6ED0
0x701F0: tst w0,#0xFF
0x701F4: b.eq 0x7023C
...
0x70224: mov w0,#0xFA0
0x70228: bl  0x70A50   ; LongPressVolUpkeyCheck(4,000 ms)
0x7022C: cbz w0,0x7023C
0x70238: bl  0xCFCC0   ; confirmation UI/handler
```

`0xCFCC0` directly calls the retained transition at `0xCFD8C → 0x25EE0`. CYB4 `0x25EE0` is 136 instructions and 100.00% normalized to CXDF’s transition. The direct confirmation route is therefore alive when the dynamic entry policy permits it.

## Comparison and boundary

| Build | Binary | Policy helper | Result |
| --- | ---: | --- | --- |
| CXDF | B5 | `0xC6ED0` | Dynamic/reachable |
| CYB4 | B8 | `0xC6ED0` | Dynamic/reachable |
| FZDP | B9 | `0xCABE0` | Unconditional false |
| EZB6 | B9 | `0xCA790` | Unconditional false |

**VERIFIED:** the hard-disable was introduced after CYB4 B8 and no later than FZDP B9. CYB4 demonstrates that a native consumer entry route still existed in this earlier build family; it does not authorize flashing or downgrading a B9 handset.

## Next minimum-information sample

CYB4 is dynamic, so the next sample is late B8 `S911BXXS8EZA1`: supply its unmodified BL tar/archive, or archive-identified `abl.elf` / extracted LinuxLoader PE, for the same static comparison. The local `BL_FILES` build folders contain only CXDF, CYB4, FZDP, and EZB6 inputs; no EZA1 sample is available.

Detailed targeted disassembly: `codex_context/reports/cyb4_entry_probe.txt`.
