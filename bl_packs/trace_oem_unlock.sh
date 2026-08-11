#!/bin/bash

set -euo pipefail

BASE="$(pwd)"
ROOT="$BASE/uefi_abl_compare"
OUT="$BASE/oem_unlock_trace"
VENV="$BASE/unlock_path_analysis/venv"

mkdir -p "$OUT"

OLD_ROOT="$ROOT/CXDF_abl_fv.bin.dump"
NEW_ROOT="$ROOT/EZB6_abl_fv.bin.dump"

find_module() {
    find "$1" \
        -type f \
        -path "*$2/1 PE32 image section/body.bin" \
        -print \
        | head -n 1
}

OLD_ODIN="$(find_module "$OLD_ROOT" Odin)"
NEW_ODIN="$(find_module "$NEW_ROOT" Odin)"
OLD_LINUX="$(find_module "$OLD_ROOT" LinuxLoader)"
NEW_LINUX="$(find_module "$NEW_ROOT" LinuxLoader)"

for f in "$OLD_ODIN" "$NEW_ODIN" "$OLD_LINUX" "$NEW_LINUX"; do
    if [ ! -f "$f" ]; then
        echo "Missing module: $f"
        exit 1
    fi
done

# ------------------------------------------------------------
# Python environment
# ------------------------------------------------------------

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

python -m pip install --quiet pefile capstone

# ------------------------------------------------------------
# Analyzer
# ------------------------------------------------------------

python \
    - "$OLD_ODIN" "$NEW_ODIN" \
      "$OLD_LINUX" "$NEW_LINUX" \
      "$OUT/trace_report.txt" <<'PY'

import sys
import struct
import pefile

from capstone import *
from capstone.arm64_const import *

old_odin, new_odin, old_linux, new_linux, output = sys.argv[1:]

TARGETS = [

    # Removed OEM path
    "[OEM]Oem unlock value is %d",
    "[FRP][OEM] init succeed!",
    "[OEM]PLC:%x",
    "[OEM]Unlock buffer Allocate fail",

    # Download mode OEM state
    "OEM LOCK : %a (%a%x)",
    "OEM LOCK : %a (%a)",

    # Generic unlock path
    "[OEM]LOCK:%d",
    "Unable set the unlock value: %r",
    "Unable set the unlock critical value: %r",
    "For device unlock, Draw UnLock Img",
    "Device is unlocked, Skipping boot verification",
    "GetUnlockCount",
    "IsUnlockCritical",
    "IsUnlocked",
    "setOEMFlags",
    "androidboot.vbmeta.device_state",
    "device_unlock.jpg",

    # New One UI 8 state tracking
    "[BLDP] unlock_count = %d",
    "[BLDP] kg_state = 0x%x",
    "[BLDP] kg_fuse = 0x%x",
    "[BLDP] secure_boot = 0x%x",
    "[BLDP] vbmeta_type = 0x%x",
    "ClearDdiPreviousBldpData",
    "CopyDdiData",
    "SetDdiBootMode",
    "SetDdiKernelType",
    "SetDdiRebootReason",
    "GetKGFuseFromBL",
]


def load(path):

    blob = open(path, "rb").read()
    pe = pefile.PE(data=blob)

    return blob, pe


def raw_to_va(pe, raw):

    for s in pe.sections:

        start = s.PointerToRawData
        end = start + s.SizeOfRawData

        if start <= raw < end:

            rva = s.VirtualAddress + (raw - start)

            return pe.OPTIONAL_HEADER.ImageBase + rva

    return None


def va_to_raw(pe, va):

    rva = va - pe.OPTIONAL_HEADER.ImageBase

    for s in pe.sections:

        start = s.VirtualAddress
        end = start + max(
            s.Misc_VirtualSize,
            s.SizeOfRawData
        )

        if start <= rva < end:

            return (
                s.PointerToRawData
                + (rva - s.VirtualAddress)
            )

    return None


def disassemble(blob, pe):

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    result = []

    for s in pe.sections:

        if not (s.Characteristics & 0x20000000):
            continue

        raw = s.PointerToRawData
        data = blob[raw:raw + s.SizeOfRawData]

        va = (
            pe.OPTIONAL_HEADER.ImageBase
            + s.VirtualAddress
        )

        result.extend(md.disasm(data, va))

    return result


def find_string(blob, text):

    needle = text.encode()

    positions = []
    start = 0

    while True:

        pos = blob.find(needle, start)

        if pos < 0:
            break

        positions.append(pos)
        start = pos + 1

    return positions


def find_raw_pointers(blob, value):

    hits = []

    candidates = [
        struct.pack("<I", value & 0xffffffff),
        struct.pack("<Q", value),
    ]

    for width, needle in ((4, candidates[0]), (8, candidates[1])):

        start = 0

        while True:

            p = blob.find(needle, start)

            if p < 0:
                break

            hits.append((p, width))

            start = p + 1

    return hits


def reg_name(insn, op):

    try:
        return insn.reg_name(op.reg)
    except:
        return None


def find_code_refs(insns, target):

    refs = []

    target_page = target & ~0xfff

    # --------------------------------------------------------
    # ADR
    # --------------------------------------------------------

    for i, ins in enumerate(insns):

        if ins.id != ARM64_INS_ADR:
            continue

        ops = ins.operands

        if (
            len(ops) >= 2
            and ops[1].type == ARM64_OP_IMM
            and ops[1].imm == target
        ):

            refs.append(
                (i, "ADR", target)
            )

    # --------------------------------------------------------
    # ADRP + ADD
    # ADRP + LDR
    # --------------------------------------------------------

    for i, ins in enumerate(insns):

        if ins.id != ARM64_INS_ADRP:
            continue

        ops = ins.operands

        if len(ops) < 2:
            continue

        if (
            ops[0].type != ARM64_OP_REG
            or ops[1].type != ARM64_OP_IMM
        ):
            continue

        base_reg = reg_name(ins, ops[0])
        page = ops[1].imm

        if page != target_page:
            continue

        for j in range(i + 1, min(i + 12, len(insns))):

            n = insns[j]
            nops = n.operands

            # ADD register, register, immediate
            if (
                n.id == ARM64_INS_ADD
                and len(nops) >= 3
                and nops[0].type == ARM64_OP_REG
                and nops[1].type == ARM64_OP_REG
                and nops[2].type == ARM64_OP_IMM
            ):

                src = reg_name(n, nops[1])

                if src == base_reg:

                    resolved = page + nops[2].imm

                    if resolved == target:

                        refs.append(
                            (i, "ADRP+ADD", resolved)
                        )

            # LDR [register, immediate]
            if (
                n.id == ARM64_INS_LDR
                and len(nops) >= 2
                and nops[1].type == ARM64_OP_MEM
            ):

                src = n.reg_name(
                    nops[1].mem.base
                )

                if src == base_reg:

                    resolved = (
                        page
                        + nops[1].mem.disp
                    )

                    if resolved == target:

                        refs.append(
                            (i, "ADRP+LDR", resolved)
                        )

    # de-duplicate

    result = []
    seen = set()

    for x in refs:

        key = (x[0], x[1], x[2])

        if key not in seen:
            seen.add(key)
            result.append(x)

    return result


def context(insns, index, radius=18):

    lo = max(0, index - radius)
    hi = min(len(insns), index + radius + 1)

    result = []

    for n in range(lo, hi):

        ins = insns[n]

        mark = ">>" if n == index else "  "

        result.append(
            f"{mark} "
            f"0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} "
            f"{ins.op_str}"
        )

    return "\n".join(result)


def analyze(name, path):

    blob, pe = load(path)
    insns = disassemble(blob, pe)

    lines = []

    lines.append("=" * 100)
    lines.append(name)
    lines.append("=" * 100)
    lines.append(f"File: {path}")
    lines.append(
        f"Instructions: {len(insns)}"
    )
    lines.append("")

    for target in TARGETS:

        positions = find_string(blob, target)

        if not positions:
            continue

        lines.append("")
        lines.append("#" * 100)
        lines.append(f"TARGET: {target}")
        lines.append("#" * 100)

        for raw in positions:

            va = raw_to_va(pe, raw)

            lines.append(
                f"String raw : 0x{raw:X}"
            )
            lines.append(
                f"String VA  : "
                + (
                    f"0x{va:X}"
                    if va is not None
                    else "N/A"
                )
            )

            if va is None:
                continue

            # ------------------------------------------------
            # direct references
            # ------------------------------------------------

            direct = find_code_refs(
                insns,
                va
            )

            lines.append(
                f"Direct code refs: {len(direct)}"
            )

            for idx, typ, resolved in direct:

                lines.append("")
                lines.append(
                    f"[DIRECT {typ}] "
                    f"@ 0x{insns[idx].address:X}"
                )

                lines.append(
                    context(insns, idx)
                )

            # ------------------------------------------------
            # pointer table references
            # ------------------------------------------------

            pointer_hits = find_raw_pointers(
                blob,
                va
            )

            valid_pointer_hits = []

            for ptr_raw, width in pointer_hits:

                ptr_va = raw_to_va(
                    pe,
                    ptr_raw
                )

                if ptr_va is None:
                    continue

                # Ignore the string itself accidentally
                # containing matching bytes.
                if abs(ptr_raw - raw) < 16:
                    continue

                valid_pointer_hits.append(
                    (ptr_raw, ptr_va, width)
                )

            lines.append(
                f"Pointer-table candidates: "
                f"{len(valid_pointer_hits)}"
            )

            for number, (
                ptr_raw,
                ptr_va,
                width
            ) in enumerate(
                valid_pointer_hits[:20],
                1
            ):

                lines.append("")
                lines.append(
                    f"[PTR {number}] "
                    f"raw=0x{ptr_raw:X} "
                    f"VA=0x{ptr_va:X} "
                    f"width={width}"
                )

                refs = find_code_refs(
                    insns,
                    ptr_va
                )

                lines.append(
                    f"Code refs to pointer: "
                    f"{len(refs)}"
                )

                for idx, typ, resolved in refs:

                    lines.append(
                        f"[INDIRECT {typ}] "
                        f"@ 0x{insns[idx].address:X}"
                    )

                    lines.append(
                        context(insns, idx)
                    )

    return "\n".join(lines)


modules = [
    ("CXDF ODIN", old_odin),
    ("EZB6 ODIN", new_odin),
    ("CXDF LINUXLOADER", old_linux),
    ("EZB6 LINUXLOADER", new_linux),
]

reports = []

for name, path in modules:

    print(
        f"Analyzing {name}...",
        file=sys.stderr
    )

    reports.append(
        analyze(name, path)
    )

with open(output, "w") as f:

    f.write(
        "\n\n".join(reports)
    )

print()
print("Created:")
print(output)

PY

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

REPORT="$OUT/trace_report.txt"
SUMMARY="$OUT/trace_summary.txt"

{
    grep -E \
        '^(TARGET:|String raw|String VA|Direct code refs|Pointer-table candidates|\[DIRECT|\[INDIRECT|\[PTR)' \
        "$REPORT" || true
} > "$SUMMARY"

echo
echo "============================================"
echo "Done"
echo "============================================"
echo
echo "Full:"
echo "$REPORT"
echo
echo "Summary:"
echo "$SUMMARY"
