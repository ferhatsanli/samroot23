#!/bin/bash

set -euo pipefail

BASE="$(pwd)"
ROOT="$BASE/uefi_abl_compare"
OUT="$BASE/unlock_callgraph"
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
    echo "[ERROR] LinuxLoader not found."
    exit 1
fi

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

python -m pip install --quiet pefile capstone

python - "$OLD" "$NEW" "$OUT" <<'PY'

import sys
import os
import re
import hashlib
import pefile

from capstone import *
from capstone.arm64_const import *

old_path, new_path, outdir = sys.argv[1:]

TARGETS = [
    "Unable set the unlock value: %r",
    "Unable set the unlock critical value: %r",
    "GetUnlockCount",
    "IsUnlocked",
    "IsUnlockCritical",
    "Device is unlocked, Skipping boot verification",
    "setOEMFlags",
    "androidboot.vbmeta.device_state",
]

# ------------------------------------------------------------
# PE helpers
# ------------------------------------------------------------

def load_image(path):
    blob = open(path, "rb").read()
    pe = pefile.PE(data=blob)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []

    for section in pe.sections:

        if not (section.Characteristics & 0x20000000):
            continue

        raw = section.PointerToRawData
        size = section.SizeOfRawData

        data = blob[raw:raw+size]

        va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        insns.extend(md.disasm(data, va))

    return blob, pe, insns


def raw_to_va(pe, raw):

    for section in pe.sections:

        rs = section.PointerToRawData
        re = rs + section.SizeOfRawData

        if rs <= raw < re:

            return (
                pe.OPTIONAL_HEADER.ImageBase
                + section.VirtualAddress
                + (raw - rs)
            )

    return None


def find_string(blob, pe, text):

    needle = text.encode()
    result = []

    start = 0

    while True:

        raw = blob.find(needle, start)

        if raw < 0:
            break

        va = raw_to_va(pe, raw)

        if va is not None:
            result.append((raw, va))

        start = raw + 1

    return result


# ------------------------------------------------------------
# Find ADR/ADRP references
# ------------------------------------------------------------

def rname(ins, reg):
    return ins.reg_name(reg)


def find_string_xrefs(insns, target):

    result = []

    target_page = target & ~0xFFF

    for i, ins in enumerate(insns):

        ops = ins.operands

        # ADR
        if (
            ins.id == ARM64_INS_ADR
            and len(ops) >= 2
            and ops[1].type == ARM64_OP_IMM
            and ops[1].imm == target
        ):
            result.append(i)

        # ADRP + ADD
        if (
            ins.id == ARM64_INS_ADRP
            and len(ops) >= 2
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_IMM
            and ops[1].imm == target_page
        ):

            reg = rname(ins, ops[0].reg)

            for j in range(i+1, min(i+10, len(insns))):

                n = insns[j]
                nops = n.operands

                if (
                    n.id == ARM64_INS_ADD
                    and len(nops) >= 3
                    and nops[0].type == ARM64_OP_REG
                    and nops[1].type == ARM64_OP_REG
                    and nops[2].type == ARM64_OP_IMM
                    and rname(n, nops[1].reg) == reg
                ):

                    resolved = target_page + nops[2].imm

                    if resolved == target:
                        result.append(i)
                        break

    return sorted(set(result))


# ------------------------------------------------------------
# Function boundary heuristics
# ------------------------------------------------------------

def is_prologue(insns, i):

    ins = insns[i]

    # sub sp, sp, #...
    if ins.mnemonic == "sub":
        if ins.op_str.startswith("sp, sp, #"):
            return True

    # stp x29, x30, [sp, #-...]!
    if ins.mnemonic == "stp":
        s = ins.op_str.replace(" ", "")

        if s.startswith("x29,x30,[sp,#-") and s.endswith("]!"):
            return True

    return False


def find_function_start(insns, xref_idx):

    # Look up to ~2KB backwards.
    lower = max(0, xref_idx - 512)

    candidates = []

    for i in range(xref_idx, lower-1, -1):

        if is_prologue(insns, i):
            candidates.append(i)

            # nearest reasonable prologue
            if xref_idx - i < 160:
                return i

    if candidates:
        return candidates[0]

    # fallback: after previous RET
    for i in range(xref_idx-1, lower-1, -1):

        if insns[i].mnemonic == "ret":
            return i + 1

    return max(0, xref_idx - 40)


def find_function_end(insns, start_idx, xref_idx):

    maximum = min(len(insns), start_idx + 800)

    for i in range(max(xref_idx, start_idx), maximum):

        if insns[i].mnemonic == "ret":
            return i

    return min(len(insns)-1, start_idx + 300)


# ------------------------------------------------------------
# Function callers
# ------------------------------------------------------------

def get_branch_target(ins):

    if ins.id != ARM64_INS_BL:
        return None

    if not ins.operands:
        return None

    op = ins.operands[0]

    if op.type == ARM64_OP_IMM:
        return op.imm

    return None


def find_callers(insns, function_start):

    callers = []

    for i, ins in enumerate(insns):

        target = get_branch_target(ins)

        if target == function_start:
            callers.append(i)

    return callers


# ------------------------------------------------------------
# Normalization for old/new structural comparison
# ------------------------------------------------------------

def normalize_operand(ins, op):

    if op.type == ARM64_OP_REG:
        return ins.reg_name(op.reg)

    if op.type == ARM64_OP_IMM:

        # Absolute addresses change when the binary layout changes.
        if ins.id in (
            ARM64_INS_B,
            ARM64_INS_BL,
            ARM64_INS_ADR,
            ARM64_INS_ADRP
        ):
            return "<ADDR>"

        return f"#{op.imm}"

    if op.type == ARM64_OP_MEM:

        base = ins.reg_name(op.mem.base)

        index = ""
        if op.mem.index:
            index = "+" + ins.reg_name(op.mem.index)

        return f"[{base}{index}+{op.mem.disp}]"

    return "<OP>"


def normalized_function(insns, start, end):

    result = []

    for ins in insns[start:end+1]:

        ops = ",".join(
            normalize_operand(ins, op)
            for op in ins.operands
        )

        result.append(
            f"{ins.mnemonic} {ops}".strip()
        )

    return result


def context(insns, idx, radius=16):

    result = []

    for i in range(
        max(0, idx-radius),
        min(len(insns), idx+radius+1)
    ):

        ins = insns[i]

        marker = ">>" if i == idx else "  "

        result.append(
            f"{marker} 0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} {ins.op_str}"
        )

    return "\n".join(result)


def function_dump(insns, start, end):

    lines = []

    for i in range(start, end+1):

        ins = insns[i]

        lines.append(
            f"0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} {ins.op_str}"
        )

    return "\n".join(lines)


# ------------------------------------------------------------
# Analyze one firmware
# ------------------------------------------------------------

def analyze(label, path):

    blob, pe, insns = load_image(path)

    report = []
    functions = {}

    report.append("=" * 100)
    report.append(label)
    report.append("=" * 100)
    report.append(f"File: {path}")
    report.append(f"Instructions: {len(insns)}")
    report.append("")

    for target in TARGETS:

        locations = find_string(blob, pe, target)

        if not locations:
            continue

        for raw, va in locations:

            refs = find_string_xrefs(insns, va)

            if not refs:
                continue

            report.append("")
            report.append("#" * 100)
            report.append(f"TARGET: {target}")
            report.append(f"String VA: 0x{va:X}")
            report.append("#" * 100)

            # Only first useful xref for this analysis.
            for ref_idx in refs[:3]:

                ref_addr = insns[ref_idx].address

                start = find_function_start(
                    insns,
                    ref_idx
                )

                end = find_function_end(
                    insns,
                    start,
                    ref_idx
                )

                function_start = insns[start].address
                function_end = insns[end].address

                norm = normalized_function(
                    insns,
                    start,
                    end
                )

                norm_hash = hashlib.sha256(
                    "\n".join(norm).encode()
                ).hexdigest()

                key = target

                if key not in functions:

                    functions[key] = {
                        "xref": ref_addr,
                        "start": function_start,
                        "end": function_end,
                        "norm": norm,
                        "norm_hash": norm_hash,
                    }

                report.append(
                    f"XREF             : 0x{ref_addr:X}"
                )

                report.append(
                    f"Function start   : 0x{function_start:X}"
                )

                report.append(
                    f"Function end     : 0x{function_end:X}"
                )

                report.append(
                    f"Instruction count: {end-start+1}"
                )

                report.append(
                    f"Normalized SHA256: {norm_hash}"
                )

                callers = find_callers(
                    insns,
                    function_start
                )

                report.append(
                    f"Direct callers   : {len(callers)}"
                )

                for n, caller_idx in enumerate(
                    callers[:30],
                    1
                ):

                    report.append("")
                    report.append(
                        f"CALLER {n}: "
                        f"0x{insns[caller_idx].address:X}"
                    )

                    report.append(
                        context(
                            insns,
                            caller_idx,
                            radius=20
                        )
                    )

                report.append("")
                report.append(
                    "--- ENCLOSING FUNCTION ---"
                )

                report.append(
                    function_dump(
                        insns,
                        start,
                        end
                    )
                )

                report.append("")

    return report, functions


old_report, old_functions = analyze(
    "CXDF LINUXLOADER",
    old_path
)

new_report, new_functions = analyze(
    "EZB6 LINUXLOADER",
    new_path
)

# ------------------------------------------------------------
# Structural comparison
# ------------------------------------------------------------

compare = []

compare.append("=" * 100)
compare.append("CXDF <-> EZB6 FUNCTION COMPARISON")
compare.append("=" * 100)
compare.append("")

for target in TARGETS:

    old = old_functions.get(target)
    new = new_functions.get(target)

    if not old or not new:
        continue

    compare.append(target)
    compare.append("-" * len(target))

    compare.append(
        f"OLD xref     : 0x{old['xref']:X}"
    )

    compare.append(
        f"NEW xref     : 0x{new['xref']:X}"
    )

    compare.append(
        f"XREF delta   : {new['xref'] - old['xref']:+#x}"
    )

    compare.append(
        f"OLD function : "
        f"0x{old['start']:X}-0x{old['end']:X}"
    )

    compare.append(
        f"NEW function : "
        f"0x{new['start']:X}-0x{new['end']:X}"
    )

    compare.append(
        f"Function delta: "
        f"{new['start'] - old['start']:+#x}"
    )

    identical = (
        old["norm_hash"]
        == new["norm_hash"]
    )

    compare.append(
        f"Normalized identical: {identical}"
    )

    compare.append(
        f"OLD normalized hash: {old['norm_hash']}"
    )

    compare.append(
        f"NEW normalized hash: {new['norm_hash']}"
    )

    # Find first structural difference if any.
    if not identical:

        limit = min(
            len(old["norm"]),
            len(new["norm"])
        )

        first = None

        for i in range(limit):

            if old["norm"][i] != new["norm"][i]:
                first = i
                break

        if first is None:

            first = limit

        compare.append(
            f"First normalized difference: instruction {first}"
        )

        lo = max(0, first - 8)
        hi = first + 16

        compare.append("")
        compare.append("OLD:")

        for i in range(
            lo,
            min(hi, len(old["norm"]))
        ):
            compare.append(
                f"{i:04d}: {old['norm'][i]}"
            )

        compare.append("")
        compare.append("NEW:")

        for i in range(
            lo,
            min(hi, len(new["norm"]))
        ):
            compare.append(
                f"{i:04d}: {new['norm'][i]}"
            )

    compare.append("")
    compare.append("")


# ------------------------------------------------------------
# Write reports
# ------------------------------------------------------------

full_path = os.path.join(
    outdir,
    "callgraph_full.txt"
)

comparison_path = os.path.join(
    outdir,
    "function_comparison.txt"
)

with open(full_path, "w") as f:

    f.write("\n".join(old_report))
    f.write("\n\n")
    f.write("\n".join(new_report))


with open(comparison_path, "w") as f:

    f.write("\n".join(compare))


print("Generated:")
print(full_path)
print(comparison_path)

PY

echo
echo "Analysis complete."
echo
echo "Reports:"
echo "  $OUT/function_comparison.txt"
echo "  $OUT/callgraph_full.txt"
