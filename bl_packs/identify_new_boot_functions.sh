#!/bin/bash

set -euo pipefail

BASE="$(pwd)"
ROOT="$BASE/uefi_abl_compare"
OUT="$BASE/new_boot_functions"
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

import sys
import os
import difflib
import hashlib
from collections import Counter

import pefile

from capstone import *
from capstone.arm64_const import *

OLD_PATH, NEW_PATH, OUTDIR = sys.argv[1:]

TARGETS = {
    "new_call_C5A10": 0xC5A10,
    "new_call_D5D90": 0xD5D90,
    "new_call_26020": 0x26020,
    "new_call_6EE10": 0x6EE10,
    "new_state_function_C7CF0": 0xC7CF0,
    "state_wrapper_9688": 0x9688,
}

KEYWORDS = (
    "ddi",
    "bldp",
    "bootloader",
    "boot mode",
    "reboot",
    "kernel",
    "unlock",
    "lock",
    "kg",
    "vault",
    "vbmeta",
    "secure",
    "fuse",
    "device state",
    "event",
    "warranty",
    "frp",
)


# ============================================================
# Load PE
# ============================================================

def load(path):

    blob = open(path, "rb").read()
    pe = pefile.PE(data=blob)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    instructions = []

    text_start = None
    text_end = None

    for sec in pe.sections:

        name = sec.Name.rstrip(b"\x00").decode(errors="ignore")

        if not (sec.Characteristics & 0x20000000):
            continue

        raw = sec.PointerToRawData
        size = sec.SizeOfRawData

        va = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress

        if text_start is None:
            text_start = va

        text_end = max(
            text_end or 0,
            va + sec.Misc_VirtualSize
        )

        instructions.extend(
            md.disasm(
                blob[raw:raw+size],
                va
            )
        )

    addrmap = {
        ins.address: i
        for i, ins in enumerate(instructions)
    }

    return {
        "blob": blob,
        "pe": pe,
        "ins": instructions,
        "addrmap": addrmap,
        "start": text_start,
        "end": text_end,
    }


OLD = load(OLD_PATH)
NEW = load(NEW_PATH)


# ============================================================
# Helpers
# ============================================================

def reg(ins, r):

    try:
        return ins.reg_name(r)
    except:
        return "?"


def is_code_address(image, addr):

    return (
        image["start"] is not None
        and image["start"] <= addr < image["end"]
    )


def immediate_target(ins):

    if ins.id not in (
        ARM64_INS_BL,
        ARM64_INS_B
    ):
        return None

    if not ins.operands:
        return None

    op = ins.operands[0]

    if op.type != ARM64_OP_IMM:
        return None

    return op.imm


# ============================================================
# Candidate function starts
# ============================================================

def looks_like_prologue(ins):

    if (
        ins.mnemonic == "sub"
        and ins.op_str.startswith("sp, sp, #")
    ):
        return True

    if ins.mnemonic == "stp":

        text = ins.op_str.replace(" ", "")

        if (
            text.startswith("x29,x30,[sp,#-")
            and text.endswith("]!")
        ):
            return True

    return False


def candidate_starts(image):

    starts = set()

    insns = image["ins"]

    for ins in insns:

        target = immediate_target(ins)

        if (
            target is not None
            and is_code_address(image, target)
            and target in image["addrmap"]
        ):
            starts.add(target)

        if looks_like_prologue(ins):
            starts.add(ins.address)

    return sorted(starts)


OLD_STARTS = candidate_starts(OLD)
NEW_STARTS = candidate_starts(NEW)


# ============================================================
# Extract function
# ============================================================

def extract_function(image, start, max_ins=700):

    insns = image["ins"]
    amap = image["addrmap"]

    if start not in amap:
        return []

    i = amap[start]

    result = []

    for n in range(i, min(len(insns), i + max_ins)):

        ins = insns[n]
        result.append(ins)

        # Normal return.
        if ins.id == ARM64_INS_RET:
            break

        # Tail call / trampoline:
        # unconditional branch leaving nearby function area.
        if (
            ins.id == ARM64_INS_B
            and len(result) > 1
        ):

            target = immediate_target(ins)

            if (
                target is not None
                and abs(target - start) > 0x1000
            ):
                break

    return result


# ============================================================
# VA/raw/string helpers
# ============================================================

def va_to_raw(image, va):

    pe = image["pe"]

    rva = va - pe.OPTIONAL_HEADER.ImageBase

    for sec in pe.sections:

        vs = sec.VirtualAddress
        ve = vs + max(
            sec.Misc_VirtualSize,
            sec.SizeOfRawData
        )

        if vs <= rva < ve:

            return (
                sec.PointerToRawData
                + (rva - vs)
            )

    return None


def ascii_string_at(blob, raw, limit=500):

    if raw is None:
        return None

    if raw < 0 or raw >= len(blob):
        return None

    data = bytearray()

    for b in blob[raw:raw+limit]:

        if b == 0:
            break

        if b == 9 or 32 <= b <= 126:
            data.append(b)
        else:
            return None

    if len(data) < 4:
        return None

    return data.decode(
        "ascii",
        errors="ignore"
    )


# ============================================================
# Strings referenced from a function
# ============================================================

def referenced_strings(image, function):

    found = []

    blob = image["blob"]

    for i, ins in enumerate(function):

        if ins.id == ARM64_INS_ADR:

            ops = ins.operands

            if (
                len(ops) >= 2
                and ops[1].type == ARM64_OP_IMM
            ):

                va = ops[1].imm
                raw = va_to_raw(image, va)
                text = ascii_string_at(blob, raw)

                if text:

                    found.append(
                        (
                            ins.address,
                            va,
                            text
                        )
                    )

        if ins.id != ARM64_INS_ADRP:
            continue

        ops = ins.operands

        if not (
            len(ops) >= 2
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_IMM
        ):
            continue

        base_reg = reg(
            ins,
            ops[0].reg
        )

        page = ops[1].imm

        for j in range(
            i + 1,
            min(i + 12, len(function))
        ):

            nxt = function[j]
            nops = nxt.operands

            if (
                nxt.id == ARM64_INS_ADD
                and len(nops) >= 3
                and nops[0].type == ARM64_OP_REG
                and nops[1].type == ARM64_OP_REG
                and nops[2].type == ARM64_OP_IMM
            ):

                if (
                    reg(nxt, nops[1].reg)
                    != base_reg
                ):
                    continue

                va = page + nops[2].imm

                raw = va_to_raw(
                    image,
                    va
                )

                text = ascii_string_at(
                    blob,
                    raw
                )

                if text:

                    found.append(
                        (
                            nxt.address,
                            va,
                            text
                        )
                    )

                break

    result = []
    seen = set()

    for item in found:

        key = (
            item[1],
            item[2]
        )

        if key not in seen:

            seen.add(key)
            result.append(item)

    return result


# ============================================================
# Calls
# ============================================================

def calls_from(function):

    result = []

    for ins in function:

        target = immediate_target(ins)

        if target is not None:

            result.append(
                (
                    ins.address,
                    ins.mnemonic,
                    target
                )
            )

    return result


def callers_of(image, target):

    result = []

    for ins in image["ins"]:

        dest = immediate_target(ins)

        if dest == target:

            result.append(
                (
                    ins.address,
                    ins.mnemonic
                )
            )

    return result


# ============================================================
# Function normalization
# ============================================================

def operand_kind(ins, op):

    if op.type == ARM64_OP_REG:
        return "R"

    if op.type == ARM64_OP_IMM:
        return "I"

    if op.type == ARM64_OP_MEM:
        return "M"

    return "?"


def normalized(function):

    result = []

    for ins in function:

        kinds = "".join(
            operand_kind(ins, op)
            for op in ins.operands
        )

        result.append(
            f"{ins.mnemonic}:{kinds}"
        )

    return result


def mnemonic_sequence(function):

    return [
        ins.mnemonic
        for ins in function
    ]


# ============================================================
# Build OLD candidate cache
# ============================================================

OLD_FUNCTIONS = {}

for start in OLD_STARTS:

    fn = extract_function(
        OLD,
        start,
        700
    )

    if len(fn) < 2:
        continue

    OLD_FUNCTIONS[start] = {
        "function": fn,
        "norm": normalized(fn),
        "mnemonic": mnemonic_sequence(fn),
    }


# ============================================================
# Find best old matches
# ============================================================

def best_old_matches(new_function, limit=8):

    new_norm = normalized(
        new_function
    )

    new_mn = mnemonic_sequence(
        new_function
    )

    nlen = len(new_function)

    candidates = []

    for addr, info in OLD_FUNCTIONS.items():

        olen = len(info["function"])

        if nlen <= 3:
            if olen > 20:
                continue
        else:
            ratio = olen / nlen

            if not 0.55 <= ratio <= 1.75:
                continue

        # Fast mnemonic similarity first.
        score1 = difflib.SequenceMatcher(
            None,
            new_mn,
            info["mnemonic"],
            autojunk=False
        ).ratio()

        if score1 < 0.45:
            continue

        score2 = difflib.SequenceMatcher(
            None,
            new_norm,
            info["norm"],
            autojunk=False
        ).ratio()

        score = (
            score1 * 0.45
            + score2 * 0.55
        )

        candidates.append(
            (
                score,
                addr,
                olen
            )
        )

    candidates.sort(
        reverse=True
    )

    return candidates[:limit]


# ============================================================
# Dump
# ============================================================

summary = []
full = []

summary.append(
    "=" * 100
)

summary.append(
    "EZB6 NEW BOOT FUNCTION IDENTIFICATION"
)

summary.append(
    "=" * 100
)

summary.append("")


for name, address in TARGETS.items():

    fn = extract_function(
        NEW,
        address
    )

    summary.append("")
    summary.append(
        "#" * 100
    )

    summary.append(
        f"{name} @ 0x{address:X}"
    )

    summary.append(
        "#" * 100
    )

    if not fn:

        summary.append(
            "FUNCTION NOT FOUND"
        )

        continue

    norm = normalized(fn)

    digest = hashlib.sha256(
        "\n".join(norm).encode()
    ).hexdigest()

    strings = referenced_strings(
        NEW,
        fn
    )

    calls = calls_from(
        fn
    )

    callers = callers_of(
        NEW,
        address
    )

    matches = best_old_matches(
        fn
    )

    summary.append(
        f"Instructions : {len(fn)}"
    )

    summary.append(
        f"End          : 0x{fn[-1].address:X}"
    )

    summary.append(
        f"Norm SHA256  : {digest}"
    )

    summary.append(
        f"Callers      : {len(callers)}"
    )

    summary.append(
        f"Calls out    : {len(calls)}"
    )

    summary.append(
        f"Strings      : {len(strings)}"
    )

    summary.append("")

    summary.append(
        "CALLERS"
    )

    for caller, typ in callers[:50]:

        summary.append(
            f"  0x{caller:X} {typ}"
        )

    summary.append("")

    summary.append(
        "REFERENCED STRINGS"
    )

    interesting_found = False

    for code_addr, string_va, text in strings:

        marker = ""

        if any(
            keyword in text.lower()
            for keyword in KEYWORDS
        ):

            marker = "  <<< IMPORTANT"
            interesting_found = True

        summary.append(
            f"  code=0x{code_addr:X} "
            f"string=0x{string_va:X} "
            f"{text}{marker}"
        )

    if not strings:
        summary.append(
            "  (none detected)"
        )

    summary.append("")

    summary.append(
        "DIRECT / TAIL CALLS"
    )

    for code, typ, dest in calls:

        summary.append(
            f"  0x{code:X} "
            f"{typ} -> 0x{dest:X}"
        )

    summary.append("")

    summary.append(
        "BEST CXDF FUNCTION MATCHES"
    )

    if matches:

        for score, old_addr, old_len in matches:

            summary.append(
                f"  score={score*100:6.2f}% "
                f"CXDF=0x{old_addr:X} "
                f"old_len={old_len}"
            )

    else:

        summary.append(
            "  No convincing CXDF candidate."
        )

    # --------------------------------------------------------
    # full report
    # --------------------------------------------------------

    full.extend(
        summary[-(
            20
            + len(strings)
            + len(calls)
            + len(matches)
        ):]
    )

    full.append("")
    full.append(
        "FULL DISASSEMBLY"
    )

    full.append(
        "-" * 100
    )

    for ins in fn:

        full.append(
            f"0x{ins.address:08X}: "
            f"{ins.mnemonic:<8} "
            f"{ins.op_str}"
        )

    full.append("")
    full.append(
        "BEST OLD MATCH DISASSEMBLY"
    )

    full.append(
        "-" * 100
    )

    if matches:

        best_score, best_addr, old_len = matches[0]

        old_fn = OLD_FUNCTIONS[
            best_addr
        ]["function"]

        full.append(
            f"Similarity: "
            f"{best_score*100:.2f}%"
        )

        full.append(
            f"CXDF address: "
            f"0x{best_addr:X}"
        )

        for ins in old_fn:

            full.append(
                f"0x{ins.address:08X}: "
                f"{ins.mnemonic:<8} "
                f"{ins.op_str}"
            )

    full.append("")
    full.append("")


summary_file = os.path.join(
    OUTDIR,
    "new_functions_summary.txt"
)

full_file = os.path.join(
    OUTDIR,
    "new_functions_full.txt"
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

PY

echo
echo "Analysis complete."
echo
echo "Reports:"
echo "  $OUT/new_functions_summary.txt"
echo "  $OUT/new_functions_full.txt"
