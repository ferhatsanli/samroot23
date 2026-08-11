#!/bin/bash

set -euo pipefail

BASE="$(pwd)"
ROOT="$BASE/uefi_abl_compare"
OUT="$BASE/unlock_globals"
VENV="$BASE/unlock_path_analysis/venv"

mkdir -p "$OUT"

OLD_ROOT="$ROOT/CXDF_abl_fv.bin.dump"
NEW_ROOT="$ROOT/EZB6_abl_fv.bin.dump"

find_linuxloader() {
    find "$1" \
        -type f \
        -path "*LinuxLoader/1 PE32 image section/body.bin" \
        -print | head -n 1
}

OLD="$(find_linuxloader "$OLD_ROOT")"
NEW="$(find_linuxloader "$NEW_ROOT")"

if [ ! -f "$OLD" ] || [ ! -f "$NEW" ]; then
    echo "[ERROR] LinuxLoader not found"
    exit 1
fi

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

python -m pip install --quiet pefile capstone

python - "$OLD" "$NEW" "$OUT" <<'PY'

import os
import sys
import pefile

from capstone import *
from capstone.arm64_const import *

old_path, new_path, outdir = sys.argv[1:]

TARGETS = {
    "CXDF": {
        "IsUnlocked":        0x199F65,
        "IsUnlockCritical":  0x199F66,
        "UnlockCount":       0x19ABF8,
    },

    "EZB6": {
        "IsUnlocked":        0x18BB0D,
        "IsUnlockCritical":  0x18BB0E,
        "UnlockCount":       0x18C7A0,
    }
}


# ============================================================
# Load image
# ============================================================

def load(path):

    blob = open(path, "rb").read()
    pe = pefile.PE(data=blob)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []

    for section in pe.sections:

        if not (
            section.Characteristics & 0x20000000
        ):
            continue

        raw = section.PointerToRawData
        size = section.SizeOfRawData

        data = blob[raw:raw+size]

        va = (
            pe.OPTIONAL_HEADER.ImageBase
            + section.VirtualAddress
        )

        insns.extend(
            md.disasm(data, va)
        )

    return blob, pe, insns


# ============================================================
# Helpers
# ============================================================

def rname(ins, reg):

    if not reg:
        return None

    return ins.reg_name(reg)


def is_write(ins):

    return ins.id in (
        ARM64_INS_STR,
        ARM64_INS_STRB,
        ARM64_INS_STRH,
        ARM64_INS_STUR,
        ARM64_INS_STURB,
        ARM64_INS_STURH,
    )


def is_read(ins):

    return ins.id in (
        ARM64_INS_LDR,
        ARM64_INS_LDRB,
        ARM64_INS_LDRH,
        ARM64_INS_LDUR,
        ARM64_INS_LDURB,
        ARM64_INS_LDURH,
        ARM64_INS_LDRSW,
    )


def source_register(ins):

    if not ins.operands:
        return None

    op = ins.operands[0]

    if op.type == ARM64_OP_REG:
        return rname(ins, op.reg)

    return None


def memory_operand(ins):

    for op in ins.operands:

        if op.type == ARM64_OP_MEM:
            return op

    return None


# ============================================================
# Lightweight symbolic address tracker
# ============================================================

def scan_memory_accesses(insns, targets):

    target_by_addr = {
        addr: name
        for name, addr in targets.items()
    }

    registers = {}

    hits = []

    for idx, ins in enumerate(insns):

        ops = ins.operands

        # ----------------------------------------------------
        # ADRP xN, absolute_page
        # ----------------------------------------------------

        if (
            ins.id == ARM64_INS_ADRP
            and len(ops) >= 2
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_IMM
        ):

            dst = rname(
                ins,
                ops[0].reg
            )

            registers[dst] = ops[1].imm
            continue


        # ----------------------------------------------------
        # ADR xN, absolute
        # ----------------------------------------------------

        if (
            ins.id == ARM64_INS_ADR
            and len(ops) >= 2
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_IMM
        ):

            dst = rname(
                ins,
                ops[0].reg
            )

            registers[dst] = ops[1].imm
            continue


        # ----------------------------------------------------
        # ADD xD, xS, #imm
        # ----------------------------------------------------

        if (
            ins.id == ARM64_INS_ADD
            and len(ops) >= 3
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_REG
            and ops[2].type == ARM64_OP_IMM
        ):

            dst = rname(
                ins,
                ops[0].reg
            )

            src = rname(
                ins,
                ops[1].reg
            )

            if src in registers:

                registers[dst] = (
                    registers[src]
                    + ops[2].imm
                )

            else:
                registers.pop(
                    dst,
                    None
                )

            continue


        # ----------------------------------------------------
        # MOV xD, xS
        # ----------------------------------------------------

        if (
            ins.id == ARM64_INS_MOV
            and len(ops) >= 2
            and ops[0].type == ARM64_OP_REG
        ):

            dst = rname(
                ins,
                ops[0].reg
            )

            if ops[1].type == ARM64_OP_REG:

                src = rname(
                    ins,
                    ops[1].reg
                )

                if src in registers:
                    registers[dst] = registers[src]
                else:
                    registers.pop(
                        dst,
                        None
                    )

            else:
                registers.pop(
                    dst,
                    None
                )

            continue


        # ----------------------------------------------------
        # Memory access
        # ----------------------------------------------------

        if is_read(ins) or is_write(ins):

            mem = memory_operand(ins)

            if mem is not None:

                base = rname(
                    ins,
                    mem.mem.base
                )

                if base in registers:

                    address = (
                        registers[base]
                        + mem.mem.disp
                    )

                    if address in target_by_addr:

                        name = target_by_addr[address]

                        access = (
                            "WRITE"
                            if is_write(ins)
                            else "READ"
                        )

                        hits.append({
                            "index": idx,
                            "address": ins.address,
                            "target": name,
                            "target_address": address,
                            "access": access,
                            "source": source_register(ins),
                            "instruction": (
                                f"{ins.mnemonic} "
                                f"{ins.op_str}"
                            )
                        })


        # ----------------------------------------------------
        # Unconditional control flow:
        # tracked register values are no longer reliable.
        # ----------------------------------------------------

        if ins.id in (
            ARM64_INS_B,
            ARM64_INS_RET,
            ARM64_INS_BR,
        ):

            registers.clear()
            continue


        # ----------------------------------------------------
        # Function call:
        # ARM64 caller-saved x0-x18 may be destroyed.
        # ----------------------------------------------------

        if ins.id in (
            ARM64_INS_BL,
            ARM64_INS_BLR,
        ):

            for n in range(19):

                registers.pop(
                    f"x{n}",
                    None
                )

            continue


        # ----------------------------------------------------
        # Clear destination registers for instructions that
        # overwrite them in ways we don't symbolically track.
        # ----------------------------------------------------

        if ops:

            first = ops[0]

            if first.type == ARM64_OP_REG:

                dst = rname(
                    ins,
                    first.reg
                )

                SAFE = {
                    ARM64_INS_CMP,
                    ARM64_INS_TST,
                    ARM64_INS_CBZ,
                    ARM64_INS_CBNZ,
                    ARM64_INS_TBZ,
                    ARM64_INS_TBNZ,
                }

                if (
                    dst
                    and ins.id not in SAFE
                    and not is_read(ins)
                    and not is_write(ins)
                ):

                    registers.pop(
                        dst,
                        None
                    )

    return hits


# ============================================================
# Function boundary heuristic
# ============================================================

def is_prologue(ins):

    if (
        ins.mnemonic == "sub"
        and ins.op_str.startswith(
            "sp, sp, #"
        )
    ):
        return True

    if ins.mnemonic == "stp":

        text = ins.op_str.replace(
            " ",
            ""
        )

        if (
            text.startswith(
                "x29,x30,[sp,#-"
            )
            and text.endswith("]!")
        ):
            return True

    return False


def function_start_index(
    insns,
    idx
):

    for i in range(
        idx,
        max(-1, idx-1000),
        -1
    ):

        if is_prologue(
            insns[i]
        ):
            return i

        if (
            i < idx
            and insns[i].id
            == ARM64_INS_RET
        ):

            return i + 1

    return max(
        0,
        idx-100
    )


def function_end_index(
    insns,
    start
):

    for i in range(
        start,
        min(
            len(insns),
            start+1500
        )
    ):

        if (
            insns[i].id
            == ARM64_INS_RET
        ):
            return i

    return min(
        len(insns)-1,
        start+500
    )


# ============================================================
# Find direct BL callers
# ============================================================

def direct_callers(
    insns,
    address
):

    result = []

    for idx, ins in enumerate(insns):

        if (
            ins.id
            != ARM64_INS_BL
        ):
            continue

        if not ins.operands:
            continue

        op = ins.operands[0]

        if (
            op.type
            == ARM64_OP_IMM
            and op.imm
            == address
        ):

            result.append(idx)

    return result


# ============================================================
# Context
# ============================================================

def context(
    insns,
    idx,
    radius=20
):

    lines = []

    lo = max(
        0,
        idx-radius
    )

    hi = min(
        len(insns),
        idx+radius+1
    )

    for i in range(
        lo,
        hi
    ):

        ins = insns[i]

        mark = (
            ">>"
            if i == idx
            else "  "
        )

        lines.append(
            f"{mark} "
            f"0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} "
            f"{ins.op_str}"
        )

    return "\n".join(
        lines
    )


def function_dump(
    insns,
    start,
    end
):

    lines = []

    for i in range(
        start,
        end+1
    ):

        ins = insns[i]

        lines.append(
            f"0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} "
            f"{ins.op_str}"
        )

    return "\n".join(
        lines
    )


# ============================================================
# Strings referenced inside a function
# ============================================================

def raw_to_va(
    pe,
    raw
):

    for s in pe.sections:

        rs = s.PointerToRawData
        re = rs + s.SizeOfRawData

        if rs <= raw < re:

            return (
                pe.OPTIONAL_HEADER.ImageBase
                + s.VirtualAddress
                + (raw-rs)
            )

    return None


def printable_strings(
    blob,
    minimum=6
):

    results = []

    start = None
    current = bytearray()

    for i, b in enumerate(blob):

        if 32 <= b <= 126:

            if start is None:
                start = i

            current.append(b)

        else:

            if (
                start is not None
                and len(current)
                >= minimum
            ):

                results.append(
                    (
                        start,
                        current.decode(
                            "ascii",
                            errors="ignore"
                        )
                    )
                )

            start = None
            current = bytearray()

    return results


# ============================================================
# Analyze
# ============================================================

def analyze(
    label,
    path
):

    blob, pe, insns = load(
        path
    )

    hits = scan_memory_accesses(
        insns,
        TARGETS[label]
    )

    strings = printable_strings(
        blob
    )

    report = []

    report.append(
        "=" * 100
    )

    report.append(
        f"{label} GLOBAL ACCESS ANALYSIS"
    )

    report.append(
        "=" * 100
    )

    report.append(
        f"File: {path}"
    )

    report.append("")

    for target_name, target_addr in TARGETS[label].items():

        relevant = [
            h for h in hits
            if h["target"]
            == target_name
        ]

        reads = [
            h for h in relevant
            if h["access"]
            == "READ"
        ]

        writes = [
            h for h in relevant
            if h["access"]
            == "WRITE"
        ]

        report.append("")
        report.append(
            "#" * 100
        )

        report.append(
            f"{target_name} @ "
            f"0x{target_addr:X}"
        )

        report.append(
            "#" * 100
        )

        report.append(
            f"READS : {len(reads)}"
        )

        report.append(
            f"WRITES: {len(writes)}"
        )

        report.append("")

        for number, hit in enumerate(
            relevant,
            1
        ):

            idx = hit["index"]

            fs = function_start_index(
                insns,
                idx
            )

            fe = function_end_index(
                insns,
                fs
            )

            faddr = insns[fs].address
            fend = insns[fe].address

            callers = direct_callers(
                insns,
                faddr
            )

            report.append(
                "-" * 90
            )

            report.append(
                f"ACCESS {number}: "
                f"{hit['access']}"
            )

            report.append(
                f"Instruction : "
                f"0x{hit['address']:X} "
                f"{hit['instruction']}"
            )

            report.append(
                f"Source reg  : "
                f"{hit['source']}"
            )

            report.append(
                f"Function    : "
                f"0x{faddr:X}-"
                f"0x{fend:X}"
            )

            report.append(
                f"Direct callers: "
                f"{len(callers)}"
            )

            report.append("")
            report.append(
                "ACCESS CONTEXT"
            )

            report.append(
                context(
                    insns,
                    idx,
                    24
                )
            )

            report.append("")
            report.append(
                "FUNCTION CALLERS"
            )

            for cnum, caller_idx in enumerate(
                callers[:30],
                1
            ):

                report.append("")
                report.append(
                    f"CALLER {cnum}: "
                    f"0x"
                    f"{insns[caller_idx].address:X}"
                )

                report.append(
                    context(
                        insns,
                        caller_idx,
                        16
                    )
                )

            report.append("")
            report.append(
                "ENCLOSING FUNCTION"
            )

            report.append(
                function_dump(
                    insns,
                    fs,
                    fe
                )
            )

            report.append("")

    return (
        report,
        hits
    )


old_report, old_hits = analyze(
    "CXDF",
    old_path
)

new_report, new_hits = analyze(
    "EZB6",
    new_path
)


# ============================================================
# Summary
# ============================================================

summary = []

summary.append(
    "=" * 100
)

summary.append(
    "UNLOCK GLOBAL ACCESS SUMMARY"
)

summary.append(
    "=" * 100
)

summary.append("")


def summarize(
    label,
    hits
):

    summary.append(
        label
    )

    summary.append(
        "-" * len(label)
    )

    for name, addr in TARGETS[label].items():

        rel = [
            h for h in hits
            if h["target"] == name
        ]

        reads = [
            h for h in rel
            if h["access"] == "READ"
        ]

        writes = [
            h for h in rel
            if h["access"] == "WRITE"
        ]

        summary.append(
            f"{name:<20} "
            f"0x{addr:X}  "
            f"reads={len(reads):2d} "
            f"writes={len(writes):2d}"
        )

        for h in writes:

            summary.append(
                f"    WRITE "
                f"0x{h['address']:X}: "
                f"{h['instruction']}"
            )

    summary.append("")


summarize(
    "CXDF",
    old_hits
)

summarize(
    "EZB6",
    new_hits
)


# ============================================================
# Write files
# ============================================================

full_path = os.path.join(
    outdir,
    "global_access_full.txt"
)

summary_path = os.path.join(
    outdir,
    "global_access_summary.txt"
)

with open(
    full_path,
    "w"
) as f:

    f.write(
        "\n".join(old_report)
    )

    f.write(
        "\n\n"
    )

    f.write(
        "\n".join(new_report)
    )


with open(
    summary_path,
    "w"
) as f:

    f.write(
        "\n".join(summary)
    )


print()
print(
    "Generated:"
)

print(
    summary_path
)

print(
    full_path
)

PY

echo
echo "Analysis complete."
echo
echo "Reports:"
echo "  $OUT/global_access_summary.txt"
echo "  $OUT/global_access_full.txt"
