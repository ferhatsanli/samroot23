#!/bin/bash

set -euo pipefail

BASE="$(pwd)"
ROOT="$BASE/uefi_abl_compare"
OUT="$BASE/boot_caller_compare"
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
import re
import difflib

import pefile

from capstone import *
from capstone.arm64_const import *

OLD_PATH, NEW_PATH, OUTDIR = sys.argv[1:]

# Boot-time unlock-state initializer discovered previously.
OLD_INIT = 0x26A70
NEW_INIT = 0x26BB0


# ============================================================
# PE / disassembly
# ============================================================

def load_image(path):

    blob = open(path, "rb").read()
    pe = pefile.PE(data=blob)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    instructions = []

    for section in pe.sections:

        if not (
            section.Characteristics & 0x20000000
        ):
            continue

        raw = section.PointerToRawData
        size = section.SizeOfRawData

        data = blob[raw:raw + size]

        va = (
            pe.OPTIONAL_HEADER.ImageBase
            + section.VirtualAddress
        )

        instructions.extend(
            md.disasm(data, va)
        )

    addr_index = {
        ins.address: i
        for i, ins in enumerate(instructions)
    }

    return blob, pe, instructions, addr_index


# ============================================================
# Helpers
# ============================================================

def is_bl_to(ins, target):

    if ins.id != ARM64_INS_BL:
        return False

    if not ins.operands:
        return False

    op = ins.operands[0]

    return (
        op.type == ARM64_OP_IMM
        and op.imm == target
    )


def find_callers(insns, target):

    return [
        i for i, ins in enumerate(insns)
        if is_bl_to(ins, target)
    ]


def looks_like_prologue(insns, i):

    ins = insns[i]

    # Typical:
    # stp x29, x30, [sp, #-... ]!
    if ins.mnemonic == "stp":

        text = ins.op_str.replace(" ", "")

        if (
            text.startswith("x29,x30,[sp,#-")
            and text.endswith("]!")
        ):
            return True

    # Samsung/EDK2 often:
    # sub sp, sp, #...
    # str/stp x30 ...
    if (
        ins.mnemonic == "sub"
        and ins.op_str.startswith("sp, sp, #")
    ):

        for j in range(
            i + 1,
            min(i + 8, len(insns))
        ):

            t = insns[j].op_str

            if (
                insns[j].mnemonic in ("str", "stp")
                and "x30" in t
            ):
                return True

    return False


def find_bounds(insns, call_idx):

    # Search far backwards because this appears to be
    # part of a relatively large boot function.

    start = None

    for i in range(
        call_idx,
        max(-1, call_idx - 6000),
        -1
    ):

        if looks_like_prologue(insns, i):
            start = i
            break

    if start is None:

        for i in range(
            call_idx - 1,
            max(-1, call_idx - 6000),
            -1
        ):

            if insns[i].id == ARM64_INS_RET:
                start = i + 1
                break

    if start is None:
        start = max(0, call_idx - 1000)

    end = None

    for i in range(
        call_idx,
        min(len(insns), call_idx + 10000)
    ):

        if insns[i].id == ARM64_INS_RET:
            end = i
            break

    if end is None:
        end = min(len(insns) - 1, call_idx + 3000)

    return start, end


# ============================================================
# Canonical instruction representation
# ============================================================

BRANCHES = {
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
}


def register_name(ins, reg):

    try:
        return ins.reg_name(reg)
    except:
        return "?"


def operand_shape(ins, op):

    if op.type == ARM64_OP_REG:

        return register_name(
            ins,
            op.reg
        )

    if op.type == ARM64_OP_IMM:

        return "#IMM"

    if op.type == ARM64_OP_MEM:

        base = register_name(
            ins,
            op.mem.base
        )

        index = ""

        if op.mem.index:

            index = "+" + register_name(
                ins,
                op.mem.index
            )

        # Ignore raw displacement for structural comparison.
        return f"[{base}{index}+#OFF]"

    return "?"


def shape(ins):

    ops = ",".join(
        operand_shape(ins, op)
        for op in ins.operands
    )

    return (
        f"{ins.mnemonic} {ops}"
    ).strip()


# Less relaxed representation.
# Absolute code/data addresses are hidden,
# ordinary immediates remain visible.

def semi_normal(ins):

    text = ins.op_str

    if ins.id in BRANCHES:

        text = re.sub(
            r"#-?0x[0-9a-fA-F]+",
            "#ADDR",
            text
        )

        text = re.sub(
            r"#-?\d+",
            "#ADDR",
            text
        )

    return (
        f"{ins.mnemonic} {text}"
    ).strip()


# ============================================================
# VA -> file mapping
# ============================================================

def va_to_raw(pe, va):

    rva = (
        va
        - pe.OPTIONAL_HEADER.ImageBase
    )

    for section in pe.sections:

        start = section.VirtualAddress

        end = (
            start
            + max(
                section.Misc_VirtualSize,
                section.SizeOfRawData
            )
        )

        if start <= rva < end:

            return (
                section.PointerToRawData
                + rva
                - start
            )

    return None


# ============================================================
# String extraction
# ============================================================

def c_string_at(blob, raw, limit=300):

    if raw is None:
        return None

    if raw < 0 or raw >= len(blob):
        return None

    result = bytearray()

    for b in blob[
        raw:min(len(blob), raw + limit)
    ]:

        if b == 0:
            break

        if not (
            b == 9
            or 32 <= b <= 126
        ):
            return None

        result.append(b)

    if len(result) < 5:
        return None

    try:
        return result.decode(
            "ascii",
            errors="ignore"
        )
    except:
        return None


def referenced_strings(
    blob,
    pe,
    insns,
    start,
    end
):

    found = []

    # ARM64 strings are usually:
    #
    # adrp xN, PAGE
    # add  xN, xN, OFFSET

    for i in range(
        start,
        min(end + 1, len(insns))
    ):

        ins = insns[i]

        if ins.id != ARM64_INS_ADRP:
            continue

        if len(ins.operands) < 2:
            continue

        if (
            ins.operands[0].type != ARM64_OP_REG
            or ins.operands[1].type != ARM64_OP_IMM
        ):
            continue

        reg = register_name(
            ins,
            ins.operands[0].reg
        )

        page = ins.operands[1].imm

        for j in range(
            i + 1,
            min(i + 8, end + 1)
        ):

            nxt = insns[j]

            if nxt.id != ARM64_INS_ADD:
                continue

            if len(nxt.operands) < 3:
                continue

            ops = nxt.operands

            if not (
                ops[0].type == ARM64_OP_REG
                and ops[1].type == ARM64_OP_REG
                and ops[2].type == ARM64_OP_IMM
            ):
                continue

            dst = register_name(
                nxt,
                ops[0].reg
            )

            src = register_name(
                nxt,
                ops[1].reg
            )

            if dst != reg or src != reg:
                continue

            va = page + ops[2].imm

            raw = va_to_raw(
                pe,
                va
            )

            text = c_string_at(
                blob,
                raw
            )

            if text:

                found.append({
                    "address": nxt.address,
                    "string_va": va,
                    "text": text
                })

            break

    # Remove duplicate text/address pairs.

    result = []
    seen = set()

    for item in found:

        key = (
            item["address"],
            item["text"]
        )

        if key not in seen:

            seen.add(key)
            result.append(item)

    return result


# ============================================================
# Function dump
# ============================================================

def dump_function(insns, start, end):

    return [
        (
            f"0x{insns[i].address:08X}: "
            f"{insns[i].mnemonic:<8} "
            f"{insns[i].op_str}"
        )
        for i in range(start, end + 1)
    ]


# ============================================================
# Direct calls in function
# ============================================================

def calls_inside(insns, start, end):

    result = []

    for i in range(start, end + 1):

        ins = insns[i]

        if ins.id != ARM64_INS_BL:
            continue

        if not ins.operands:
            continue

        op = ins.operands[0]

        if op.type != ARM64_OP_IMM:
            continue

        result.append({
            "index": i,
            "address": ins.address,
            "target": op.imm,
        })

    return result


# ============================================================
# Compare two caller functions
# ============================================================

def compare():

    old_blob, old_pe, old_ins, old_map = load_image(
        OLD_PATH
    )

    new_blob, new_pe, new_ins, new_map = load_image(
        NEW_PATH
    )

    old_callers = find_callers(
        old_ins,
        OLD_INIT
    )

    new_callers = find_callers(
        new_ins,
        NEW_INIT
    )

    if not old_callers:
        raise RuntimeError(
            "CXDF initializer caller not found"
        )

    if not new_callers:
        raise RuntimeError(
            "EZB6 initializer caller not found"
        )

    old_call = old_callers[0]
    new_call = new_callers[0]

    old_start, old_end = find_bounds(
        old_ins,
        old_call
    )

    new_start, new_end = find_bounds(
        new_ins,
        new_call
    )

    OLD_FUNC = old_ins[
        old_start:old_end + 1
    ]

    NEW_FUNC = new_ins[
        new_start:new_end + 1
    ]

    old_shapes = [
        shape(x)
        for x in OLD_FUNC
    ]

    new_shapes = [
        shape(x)
        for x in NEW_FUNC
    ]

    old_semi = [
        semi_normal(x)
        for x in OLD_FUNC
    ]

    new_semi = [
        semi_normal(x)
        for x in NEW_FUNC
    ]

    relaxed_ratio = difflib.SequenceMatcher(
        None,
        old_shapes,
        new_shapes,
        autojunk=False
    ).ratio()

    semi_ratio = difflib.SequenceMatcher(
        None,
        old_semi,
        new_semi,
        autojunk=False
    ).ratio()

    matcher = difflib.SequenceMatcher(
        None,
        old_shapes,
        new_shapes,
        autojunk=False
    )

    old_strings = referenced_strings(
        old_blob,
        old_pe,
        old_ins,
        old_start,
        old_end
    )

    new_strings = referenced_strings(
        new_blob,
        new_pe,
        new_ins,
        new_start,
        new_end
    )

    old_string_set = {
        x["text"]
        for x in old_strings
    }

    new_string_set = {
        x["text"]
        for x in new_strings
    }

    removed_strings = sorted(
        old_string_set
        - new_string_set
    )

    added_strings = sorted(
        new_string_set
        - old_string_set
    )

    old_calls = calls_inside(
        old_ins,
        old_start,
        old_end
    )

    new_calls = calls_inside(
        new_ins,
        new_start,
        new_end
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = []

    summary.append(
        "=" * 100
    )

    summary.append(
        "BOOT CALLER COMPARISON"
    )

    summary.append(
        "=" * 100
    )

    summary.append("")

    summary.append(
        f"CXDF initializer call : "
        f"0x{old_ins[old_call].address:X}"
    )

    summary.append(
        f"EZB6 initializer call : "
        f"0x{new_ins[new_call].address:X}"
    )

    summary.append("")

    summary.append(
        f"CXDF caller function  : "
        f"0x{old_ins[old_start].address:X}"
        f"-0x{old_ins[old_end].address:X}"
    )

    summary.append(
        f"EZB6 caller function  : "
        f"0x{new_ins[new_start].address:X}"
        f"-0x{new_ins[new_end].address:X}"
    )

    summary.append("")

    summary.append(
        f"CXDF instructions     : "
        f"{len(OLD_FUNC)}"
    )

    summary.append(
        f"EZB6 instructions     : "
        f"{len(NEW_FUNC)}"
    )

    summary.append(
        f"Instruction delta     : "
        f"{len(NEW_FUNC) - len(OLD_FUNC):+d}"
    )

    summary.append("")

    summary.append(
        f"Relaxed similarity    : "
        f"{relaxed_ratio * 100:.2f}%"
    )

    summary.append(
        f"Semi-strict similarity: "
        f"{semi_ratio * 100:.2f}%"
    )

    summary.append("")

    summary.append(
        f"CXDF direct BL calls  : "
        f"{len(old_calls)}"
    )

    summary.append(
        f"EZB6 direct BL calls  : "
        f"{len(new_calls)}"
    )

    summary.append("")

    summary.append(
        "REMOVED REFERENCED STRINGS"
    )

    summary.append(
        "-" * 100
    )

    if removed_strings:

        summary.extend(
            removed_strings
        )

    else:

        summary.append(
            "(none)"
        )

    summary.append("")
    summary.append(
        "ADDED REFERENCED STRINGS"
    )

    summary.append(
        "-" * 100
    )

    if added_strings:

        summary.extend(
            added_strings
        )

    else:

        summary.append(
            "(none)"
        )

    # --------------------------------------------------------
    # Interesting string filter
    # --------------------------------------------------------

    regex = re.compile(
        r"unlock|lock|oem|kg|vault|ddi|bldp|"
        r"bootloader|secure|vbmeta|frp|fuse|"
        r"warranty|device.?state",
        re.I
    )

    summary.append("")
    summary.append(
        "INTERESTING NEW STRINGS"
    )

    summary.append(
        "-" * 100
    )

    interesting = [
        x
        for x in added_strings
        if regex.search(x)
    ]

    if interesting:

        summary.extend(
            interesting
        )

    else:

        summary.append(
            "(none)"
        )

    # --------------------------------------------------------
    # Full structural differences
    # --------------------------------------------------------

    full = list(summary)

    full.append("")
    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "STRUCTURAL DIFFERENCES"
    )

    full.append(
        "=" * 100
    )

    diff_number = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():

        if tag == "equal":
            continue

        diff_number += 1

        full.append("")
        full.append(
            "#" * 100
        )

        full.append(
            f"DIFF {diff_number}: {tag}"
        )

        full.append(
            f"OLD instructions {i1}-{i2}"
        )

        full.append(
            f"NEW instructions {j1}-{j2}"
        )

        full.append(
            "#" * 100
        )

        full.append("")
        full.append(
            "--- CXDF ---"
        )

        for item in OLD_FUNC[i1:i2]:

            full.append(
                f"0x{item.address:08X}: "
                f"{item.mnemonic:<8} "
                f"{item.op_str}"
            )

        full.append("")
        full.append(
            "+++ EZB6 +++"
        )

        for item in NEW_FUNC[j1:j2]:

            full.append(
                f"0x{item.address:08X}: "
                f"{item.mnemonic:<8} "
                f"{item.op_str}"
            )

    # --------------------------------------------------------
    # Referenced strings with addresses
    # --------------------------------------------------------

    full.append("")
    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "CXDF REFERENCED STRINGS"
    )

    full.append(
        "=" * 100
    )

    for x in old_strings:

        full.append(
            f"CODE=0x{x['address']:X} "
            f"STRING=0x{x['string_va']:X} "
            f"{x['text']}"
        )

    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "EZB6 REFERENCED STRINGS"
    )

    full.append(
        "=" * 100
    )

    for x in new_strings:

        full.append(
            f"CODE=0x{x['address']:X} "
            f"STRING=0x{x['string_va']:X} "
            f"{x['text']}"
        )

    # --------------------------------------------------------
    # BL calls
    # --------------------------------------------------------

    full.append("")
    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "CXDF DIRECT CALLS"
    )

    full.append(
        "=" * 100
    )

    for x in old_calls:

        full.append(
            f"0x{x['address']:08X} "
            f"-> 0x{x['target']:08X}"
        )

    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "EZB6 DIRECT CALLS"
    )

    full.append(
        "=" * 100
    )

    for x in new_calls:

        full.append(
            f"0x{x['address']:08X} "
            f"-> 0x{x['target']:08X}"
        )

    # --------------------------------------------------------
    # Complete function disassembly
    # --------------------------------------------------------

    full.append("")
    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "CXDF CALLER FULL DISASSEMBLY"
    )

    full.append(
        "=" * 100
    )

    full.extend(
        dump_function(
            old_ins,
            old_start,
            old_end
        )
    )

    full.append("")
    full.append(
        "=" * 100
    )

    full.append(
        "EZB6 CALLER FULL DISASSEMBLY"
    )

    full.append(
        "=" * 100
    )

    full.extend(
        dump_function(
            new_ins,
            new_start,
            new_end
        )
    )

    # --------------------------------------------------------
    # Files
    # --------------------------------------------------------

    summary_file = os.path.join(
        OUTDIR,
        "boot_caller_summary.txt"
    )

    full_file = os.path.join(
        OUTDIR,
        "boot_caller_full.txt"
    )

    with open(
        summary_file,
        "w"
    ) as f:

        f.write(
            "\n".join(summary)
        )

    with open(
        full_file,
        "w"
    ) as f:

        f.write(
            "\n".join(full)
        )

    print(
        "Generated:"
    )

    print(
        summary_file
    )

    print(
        full_file
    )


compare()

PY

echo
echo "Analysis complete."
echo
echo "Reports:"
echo "  $OUT/boot_caller_summary.txt"
echo "  $OUT/boot_caller_full.txt"
