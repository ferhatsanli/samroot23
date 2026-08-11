#!/bin/bash

set -euo pipefail

BASE_DIR="$(pwd)"
ROOT="$BASE_DIR/uefi_abl_compare"

OLD_ROOT="$ROOT/CXDF_abl_fv.bin.dump"
NEW_ROOT="$ROOT/EZB6_abl_fv.bin.dump"

OUT="$BASE_DIR/unlock_path_analysis"
VENV="$OUT/venv"

mkdir -p "$OUT"

echo "============================================================"
echo " Samsung ABL OEM Unlock path analyzer"
echo "============================================================"
echo

# ------------------------------------------------------------
# Locate modules automatically
# ------------------------------------------------------------

find_module() {
    local root="$1"
    local module="$2"

    find "$root" \
        -type f \
        -path "*${module}/1 PE32 image section/body.bin" \
        -print \
        | head -n 1
}

OLD_ODIN="$(find_module "$OLD_ROOT" "Odin")"
NEW_ODIN="$(find_module "$NEW_ROOT" "Odin")"

OLD_LINUX="$(find_module "$OLD_ROOT" "LinuxLoader")"
NEW_LINUX="$(find_module "$NEW_ROOT" "LinuxLoader")"

echo "=== MODULES ==="
echo
echo "OLD Odin:"
echo "$OLD_ODIN"
echo
echo "NEW Odin:"
echo "$NEW_ODIN"
echo
echo "OLD LinuxLoader:"
echo "$OLD_LINUX"
echo
echo "NEW LinuxLoader:"
echo "$NEW_LINUX"
echo

for f in \
    "$OLD_ODIN" \
    "$NEW_ODIN" \
    "$OLD_LINUX" \
    "$NEW_LINUX"
do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Module not found:"
        echo "$f"
        exit 1
    fi
done

# ------------------------------------------------------------
# Basic comparison
# ------------------------------------------------------------

echo "=== MODULE SIZES ==="

stat -f '%N : %z bytes' \
    "$OLD_ODIN" \
    "$NEW_ODIN" \
    "$OLD_LINUX" \
    "$NEW_LINUX"

echo
echo "=== MODULE SHA256 ==="

shasum -a 256 \
    "$OLD_ODIN" \
    "$NEW_ODIN" \
    "$OLD_LINUX" \
    "$NEW_LINUX"

echo

# ------------------------------------------------------------
# Python environment
# ------------------------------------------------------------

echo "=== PYTHON ENVIRONMENT ==="

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

python -m pip install \
    --quiet \
    --upgrade pip

python -m pip install \
    --quiet \
    pefile \
    capstone

echo "Python: $(python --version)"
echo

# ------------------------------------------------------------
# Main analyzer
# ------------------------------------------------------------

python \
    - "$OLD_ODIN" "$NEW_ODIN" \
      "$OLD_LINUX" "$NEW_LINUX" \
      "$OUT" <<'PY'

import sys
import os
import re
import hashlib

import pefile

from capstone import *
from capstone.arm64_const import *

old_odin, new_odin, old_linux, new_linux, outdir = sys.argv[1:]

TARGETS = [
    "[OEM]Oem unlock value is %d",
    "GetUnlockCount",
    "IsUnlockCritical",
    "androidboot.vbmeta.device_state",
    "androidboot.verifiedbootstate=",
    "unlocked",
    "Unlock",
    "device_unlock.jpg",
    "Error Reseting device state",
    "Saving bootloader mode",
    "vaultkeeper",
]

KEYWORD_RE = re.compile(
    r"unlock|oem|vault|device.?state|bootloader|"
    r"flash.?lock|vbmeta|warranty|knox|kg|rmm|"
    r"secure.?boot|ddi",
    re.I
)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def sha256(blob):
    return hashlib.sha256(blob).hexdigest()


def printable_strings(blob, minimum=5):
    result = []

    start = None
    buf = bytearray()

    for i, b in enumerate(blob):

        if 32 <= b <= 126:
            if start is None:
                start = i
            buf.append(b)

        else:
            if len(buf) >= minimum:
                result.append(
                    (start, bytes(buf).decode("ascii", errors="ignore"))
                )

            start = None
            buf = bytearray()

    if len(buf) >= minimum:
        result.append(
            (start, bytes(buf).decode("ascii", errors="ignore"))
        )

    return result


def raw_to_rva(pe, raw_offset):

    for section in pe.sections:

        raw_start = section.PointerToRawData
        raw_size = max(
            section.SizeOfRawData,
            section.Misc_VirtualSize
        )

        raw_end = raw_start + raw_size

        if raw_start <= raw_offset < raw_end:

            return (
                section.VirtualAddress
                + (raw_offset - raw_start)
            )

    return None


def executable_sections(pe):

    IMAGE_SCN_MEM_EXECUTE = 0x20000000

    result = []

    for section in pe.sections:

        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:

            result.append(section)

    return result


def disassemble(pe, blob):

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    image_base = pe.OPTIONAL_HEADER.ImageBase

    instructions = []

    for section in executable_sections(pe):

        start = section.PointerToRawData
        size = section.SizeOfRawData

        data = blob[start:start + size]

        va = image_base + section.VirtualAddress

        for insn in md.disasm(data, va):

            instructions.append(insn)

    return instructions


def get_string_addresses(pe, blob, text):

    needle = text.encode("ascii")

    result = []
    pos = 0

    while True:

        pos = blob.find(needle, pos)

        if pos == -1:
            break

        rva = raw_to_rva(pe, pos)

        if rva is not None:

            va = pe.OPTIONAL_HEADER.ImageBase + rva

            result.append({
                "raw": pos,
                "rva": rva,
                "va": va,
            })

        pos += 1

    return result


def operand_reg_name(insn, operand):

    try:
        return insn.reg_name(operand.reg)
    except Exception:
        return None


def find_xrefs(instructions, target_va, target_len):

    refs = []

    target_end = target_va + target_len

    # --------------------------------------------------------
    # ADR direct references
    # --------------------------------------------------------

    for i, insn in enumerate(instructions):

        if insn.id == ARM64_INS_ADR:

            ops = insn.operands

            if len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:

                dest = ops[1].imm

                if target_va <= dest < target_end:

                    refs.append({
                        "index": i,
                        "kind": "ADR",
                        "resolved": dest,
                    })

    # --------------------------------------------------------
    # ADRP + ADD references
    # --------------------------------------------------------

    for i, insn in enumerate(instructions):

        if insn.id != ARM64_INS_ADRP:
            continue

        ops = insn.operands

        if len(ops) < 2:
            continue

        if ops[0].type != ARM64_OP_REG:
            continue

        if ops[1].type != ARM64_OP_IMM:
            continue

        reg = operand_reg_name(insn, ops[0])
        page = ops[1].imm

        if reg is None:
            continue

        # Check a small forward window.
        for j in range(i + 1, min(i + 8, len(instructions))):

            nxt = instructions[j]

            # Stop when flow leaves the basic local sequence.
            if nxt.id in (
                ARM64_INS_B,
                ARM64_INS_BL,
                ARM64_INS_RET,
            ):
                break

            if nxt.id != ARM64_INS_ADD:
                continue

            nops = nxt.operands

            if len(nops) < 3:
                continue

            if (
                nops[0].type != ARM64_OP_REG or
                nops[1].type != ARM64_OP_REG or
                nops[2].type != ARM64_OP_IMM
            ):
                continue

            dst_reg = operand_reg_name(nxt, nops[0])
            src_reg = operand_reg_name(nxt, nops[1])

            if dst_reg != reg or src_reg != reg:
                continue

            resolved = page + nops[2].imm

            if target_va <= resolved < target_end:

                refs.append({
                    "index": i,
                    "kind": "ADRP+ADD",
                    "resolved": resolved,
                    "add_index": j,
                })

    # Remove duplicate refs.
    unique = []
    seen = set()

    for ref in refs:

        key = (
            ref["index"],
            ref["kind"],
            ref["resolved"]
        )

        if key not in seen:

            seen.add(key)
            unique.append(ref)

    return unique


def format_context(instructions, index, radius=10):

    start = max(0, index - radius)
    end = min(len(instructions), index + radius + 1)

    lines = []

    for i in range(start, end):

        insn = instructions[i]

        marker = ">>" if i == index else "  "

        lines.append(
            f"{marker} "
            f"0x{insn.address:016X}: "
            f"{insn.mnemonic:<8} "
            f"{insn.op_str}"
        )

    return "\n".join(lines)


def analyze_module(label, path):

    blob = read_file(path)
    pe = pefile.PE(data=blob, fast_load=False)

    report = []

    report.append("=" * 78)
    report.append(label)
    report.append("=" * 78)

    report.append(f"Path       : {path}")
    report.append(f"Size       : {len(blob)}")
    report.append(f"SHA256     : {sha256(blob)}")

    report.append(
        f"Machine    : 0x{pe.FILE_HEADER.Machine:04X}"
    )

    report.append(
        f"ImageBase  : 0x{pe.OPTIONAL_HEADER.ImageBase:X}"
    )

    report.append(
        f"Entry RVA  : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
    )

    report.append(
        "Entry VA   : "
        f"0x{pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
    )

    report.append("")
    report.append("SECTIONS")
    report.append("-" * 78)

    for section in pe.sections:

        name = section.Name.rstrip(b"\x00").decode(
            errors="replace"
        )

        report.append(
            f"{name:<12} "
            f"RVA=0x{section.VirtualAddress:08X} "
            f"VSize=0x{section.Misc_VirtualSize:08X} "
            f"Raw=0x{section.PointerToRawData:08X} "
            f"RawSize=0x{section.SizeOfRawData:08X} "
            f"Flags=0x{section.Characteristics:08X}"
        )

    strings = printable_strings(blob)

    report.append("")
    report.append("IMPORTANT STRINGS")
    report.append("-" * 78)

    for raw, text in strings:

        if KEYWORD_RE.search(text):

            rva = raw_to_rva(pe, raw)

            if rva is None:
                address = "N/A"
            else:
                va = pe.OPTIONAL_HEADER.ImageBase + rva
                address = f"0x{va:X}"

            report.append(
                f"RAW=0x{raw:08X} "
                f"VA={address:<18} "
                f"{text[:240]}"
            )

    report.append("")
    report.append("TARGET STRING XREFS")
    report.append("-" * 78)

    instructions = disassemble(pe, blob)

    report.append(
        f"Disassembled instructions: {len(instructions)}"
    )
    report.append("")

    for target in TARGETS:

        locations = get_string_addresses(
            pe,
            blob,
            target
        )

        if not locations:
            continue

        report.append("")
        report.append("#" * 78)
        report.append(f"TARGET: {target}")
        report.append("#" * 78)

        for location in locations:

            report.append(
                f"String raw offset : 0x{location['raw']:X}"
            )

            report.append(
                f"String RVA        : 0x{location['rva']:X}"
            )

            report.append(
                f"String VA         : 0x{location['va']:X}"
            )

            refs = find_xrefs(
                instructions,
                location["va"],
                len(target)
            )

            report.append(
                f"Detected xrefs    : {len(refs)}"
            )

            for number, ref in enumerate(refs, 1):

                report.append("")
                report.append(
                    f"XREF {number} "
                    f"type={ref['kind']} "
                    f"resolved=0x{ref['resolved']:X}"
                )

                report.append(
                    format_context(
                        instructions,
                        ref["index"],
                        radius=12
                    )
                )

    return "\n".join(report), {
        text for _, text in strings
    }


modules = [
    ("CXDF ODIN", old_odin),
    ("EZB6 ODIN", new_odin),
    ("CXDF LINUXLOADER", old_linux),
    ("EZB6 LINUXLOADER", new_linux),
]

all_reports = {}
all_strings = {}

for label, path in modules:

    print(f"Analyzing {label} ...", file=sys.stderr)

    report, strings = analyze_module(
        label,
        path
    )

    all_reports[label] = report
    all_strings[label] = strings


# ------------------------------------------------------------
# Main report
# ------------------------------------------------------------

full_report_path = os.path.join(
    outdir,
    "unlock_xref_report.txt"
)

with open(full_report_path, "w") as f:

    for label, _ in modules:

        f.write(all_reports[label])
        f.write("\n\n")


# ------------------------------------------------------------
# String-set comparison
# ------------------------------------------------------------

comparison_path = os.path.join(
    outdir,
    "unlock_string_diff.txt"
)

with open(comparison_path, "w") as f:

    pairs = [
        ("ODIN", "CXDF ODIN", "EZB6 ODIN"),
        (
            "LINUXLOADER",
            "CXDF LINUXLOADER",
            "EZB6 LINUXLOADER"
        ),
    ]

    for name, old_label, new_label in pairs:

        old_strings = all_strings[old_label]
        new_strings = all_strings[new_label]

        removed = sorted(
            x for x in old_strings - new_strings
            if KEYWORD_RE.search(x)
        )

        added = sorted(
            x for x in new_strings - old_strings
            if KEYWORD_RE.search(x)
        )

        f.write("=" * 78 + "\n")
        f.write(f"{name} IMPORTANT STRING CHANGES\n")
        f.write("=" * 78 + "\n\n")

        f.write("--- REMOVED IN EZB6 ---\n")

        if removed:

            for text in removed:
                f.write(text + "\n")

        else:
            f.write("(none)\n")

        f.write("\n+++ ADDED IN EZB6 +++\n")

        if added:

            for text in added:
                f.write(text + "\n")

        else:
            f.write("(none)\n")

        f.write("\n\n")


print()
print("============================================================")
print(" ANALYSIS FINISHED")
print("============================================================")
print()
print("Generated:")
print()
print(full_report_path)
print(comparison_path)
print()

PY

echo
echo "============================================================"
echo " REPORT SUMMARY"
echo "============================================================"
echo

echo "Interesting string changes:"
echo

cat "$OUT/unlock_string_diff.txt"

echo
echo "============================================================"
echo
echo "Full ARM64 xref report:"
echo
echo "$OUT/unlock_xref_report.txt"
echo
echo "String diff:"
echo
echo "$OUT/unlock_string_diff.txt"
echo
echo "============================================================"
