#!/bin/bash
set -euo pipefail

ROOT="${1:-$PWD}"
OUT="$ROOT/state_source_trace"
VENV="$OUT/venv"

mkdir -p "$OUT"

find_linuxloader() {
    local tag="$1"

    find "$ROOT/uefi_abl_compare" \
        -type f \
        -path "*${tag}*LinuxLoader*PE32 image section/body.bin" \
        -print 2>/dev/null | head -n 1
}

CXDF="$(find_linuxloader CXDF)"
EZB6="$(find_linuxloader EZB6)"

if [[ -z "${CXDF:-}" || -z "${EZB6:-}" ]]; then
    echo "[ERROR] LinuxLoader body.bin bulunamadi."
    echo
    echo "Beklenen ana klasor:"
    echo "  $ROOT/uefi_abl_compare"
    exit 1
fi

echo "[+] CXDF:"
echo "    $CXDF"
echo
echo "[+] EZB6:"
echo "    $EZB6"
echo

if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
fi

# Keep an already-provisioned offline analysis environment usable.  Only
# contact PyPI when the two required modules are actually absent.
if ! "$VENV/bin/python" -c 'import pefile, capstone' >/dev/null 2>&1; then
    "$VENV/bin/python" -m pip install -q pefile capstone
fi

cat > "$OUT/analyze.py" <<'PY'
#!/usr/bin/env python3

import sys
import re
import hashlib
import difflib
from pathlib import Path
from collections import defaultdict

import pefile
import capstone


CXDF_PATH = Path(sys.argv[1])
EZB6_PATH = Path(sys.argv[2])
OUT = Path(sys.argv[3])

SUMMARY = OUT / "summary.txt"
REPORT = OUT / "report.txt"


TARGETS = {
    "D5D90_STATE_SOURCE": 0xD5D90,
    "C7CF0_STATE_SINK":   0xC7CF0,
    "C5A10_NEW_BOOT_CALL": 0xC5A10,

    "UNLOCK_SETTER":      0x26020,
    "GLOBAL_GETTER":      0x6EE10,

    "STATE_WRAPPER":      0x9688,
}

GLOBAL_UNLOCK_BOOT_STATE = 0x18DB94


SECURITY_WORDS = (
    "unlock",
    "lock",
    "oem",
    "frp",
    "kg",
    "vault",
    "rpmb",
    "fuse",
    "ddi",
    "bldp",
    "bootloader",
    "secure",
    "state",
    "policy",
    "warranty",
    "rollback",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def imm_target(ins):
    for op in ins.operands:
        if op.type == capstone.CS_OP_IMM:
            return int(op.imm)
    return None


def regname(ins, op):
    try:
        return ins.reg_name(op.reg)
    except Exception:
        return None


def normalize(ins):
    mn = ins.mnemonic
    op = ins.op_str.lower()

    if mn.startswith("b") or mn in ("adr", "adrp"):
        op = re.sub(
            r'#?-?0x[0-9a-f]+',
            '<ADDR>',
            op
        )
        op = re.sub(
            r'#?-?\d+',
            '<ADDR>',
            op
        )

    op = re.sub(
        r'\[([xw][0-9]+|sp), #(?:-?0x[0-9a-f]+|-?\d+)\]',
        r'[\1,#OFF]',
        op
    )

    return f"{mn} {op}".strip()


class Image:

    def __init__(self, path, label):
        self.path = Path(path)
        self.label = label
        self.data = self.path.read_bytes()

        self.pe = pefile.PE(
            data=self.data,
            fast_load=False
        )

        self.base = int(
            self.pe.OPTIONAL_HEADER.ImageBase
        )

        arch = getattr(
            capstone,
            "CS_ARCH_AARCH64",
            getattr(
                capstone,
                "CS_ARCH_ARM64",
                None
            )
        )

        if arch is None:
            raise RuntimeError(
                "Capstone ARM64/AARCH64 desteklemiyor"
            )

        self.md = capstone.Cs(
            arch,
            capstone.CS_MODE_LITTLE_ENDIAN
        )
        self.md.detail = True
        # LinuxLoader .text contains embedded data/invalid words.  Without
        # skipdata, Capstone stops at the first such word and silently omits
        # every later function (including the three priority targets).
        self.md.skipdata = True

        self.sections = []
        self.exec_sections = []

        self.ins = []
        self.by_addr = {}
        self.section_ins = {}

        self.direct_refs = defaultdict(list)
        self.strings = {}

        self.load_sections()
        self.extract_strings()
        self.disassemble()

    def load_sections(self):

        for sec in self.pe.sections:

            name = sec.Name.rstrip(
                b"\x00"
            ).decode(
                errors="replace"
            )

            va = self.base + int(
                sec.VirtualAddress
            )

            raw_size = int(
                sec.SizeOfRawData
            )

            virtual_size = int(
                sec.Misc_VirtualSize
            )

            characteristics = int(
                sec.Characteristics
            )

            executable = bool(
                characteristics & 0x20000000
            )

            code = bool(
                characteristics & 0x20
            )

            entry = {
                "name": name,
                "va": va,
                "rva": int(sec.VirtualAddress),
                "raw_size": raw_size,
                "virtual_size": virtual_size,
                "size": max(
                    raw_size,
                    virtual_size
                ),
                "characteristics": characteristics,
                "executable": executable,
                "code": code,
                "data": sec.get_data(),
            }

            self.sections.append(entry)

            if executable or code:
                self.exec_sections.append(entry)

    def extract_strings(self):

        for m in re.finditer(
            rb'[\x20-\x7e]{4,300}',
            self.data
        ):

            try:
                text = m.group().decode(
                    "ascii"
                )
            except Exception:
                continue

            try:
                rva = self.pe.get_rva_from_offset(
                    m.start()
                )
            except Exception:
                continue

            va = self.base + int(rva)

            self.strings[va] = text

    def disassemble(self):

        all_ins = []

        for sec in self.exec_sections:

            seq = list(
                self.md.disasm(
                    sec["data"],
                    sec["va"]
                )
            )

            self.section_ins[
                sec["name"] + f"@{sec['va']:X}"
            ] = seq

            all_ins.extend(seq)

        all_ins.sort(
            key=lambda x: x.address
        )

        self.ins = all_ins

        self.by_addr = {
            x.address: i
            for i, x in enumerate(all_ins)
        }

        for x in all_ins:

            if x.mnemonic not in (
                "bl",
                "b"
            ):
                continue

            t = imm_target(x)

            if t is None:
                continue

            self.direct_refs[t].append(
                {
                    "code": x.address,
                    "kind": x.mnemonic,
                }
            )

    def section_for(self, va):

        for sec in self.sections:

            start = sec["va"]
            end = start + sec["size"]

            if start <= va < end:
                return sec

        return None

    def executable_section_for(self, va):

        sec = self.section_for(va)

        if not sec:
            return None

        if sec["executable"] or sec["code"]:
            return sec

        return None

    def context(self, addr, before=20, after=20):

        idx = self.by_addr.get(addr)

        if idx is None:
            return []

        lo = max(
            0,
            idx - before
        )

        hi = min(
            len(self.ins),
            idx + after + 1
        )

        return self.ins[lo:hi]

    def function(self, addr, max_ins=600):

        idx = self.by_addr.get(addr)

        if idx is None:
            return []

        sec = self.executable_section_for(
            addr
        )

        if not sec:
            return []

        sec_end = (
            sec["va"] +
            len(sec["data"])
        )

        result = []

        for x in self.ins[idx:]:

            if x.address >= sec_end:
                break

            result.append(x)

            if x.mnemonic == "ret":
                break

            # Explicit tail-call after at least a small
            # amount of function body.
            if (
                len(result) > 4
                and
                x.mnemonic == "b"
            ):
                t = imm_target(x)

                if t is not None:
                    # Branch outside current local region:
                    # likely tail-call.
                    if abs(t - addr) > 0x1000:
                        break

            if len(result) >= max_ins:
                break

        return result

    def raw_bytes_at_va(
        self,
        va,
        size=64
    ):

        sec = self.section_for(va)

        if not sec:
            return None

        off = va - sec["va"]

        if off >= len(sec["data"]):
            return None

        return sec["data"][
            off:off + size
        ]

    def string_at(self, va):

        if va in self.strings:
            return self.strings[va]

        for start, text in self.strings.items():

            if start <= va < start + len(text):
                return text[va-start:]

        return None

    def referenced_strings(self, seq):

        found = []
        vals = {}

        for x in seq:

            new_val = None
            new_reg = None

            # ADR / ADRP
            if x.mnemonic in (
                "adr",
                "adrp"
            ):

                if (
                    len(x.operands) >= 2
                    and
                    x.operands[0].type
                    == capstone.CS_OP_REG
                    and
                    x.operands[1].type
                    == capstone.CS_OP_IMM
                ):

                    new_reg = regname(
                        x,
                        x.operands[0]
                    )

                    new_val = int(
                        x.operands[1].imm
                    )

            # ADD register, register, immediate
            elif (
                x.mnemonic == "add"
                and
                len(x.operands) >= 3
                and
                x.operands[0].type
                == capstone.CS_OP_REG
                and
                x.operands[1].type
                == capstone.CS_OP_REG
                and
                x.operands[2].type
                == capstone.CS_OP_IMM
            ):

                dst = regname(
                    x,
                    x.operands[0]
                )

                src = regname(
                    x,
                    x.operands[1]
                )

                if src in vals:

                    new_reg = dst
                    new_val = (
                        vals[src]
                        + int(
                            x.operands[2].imm
                        )
                    )

            if new_reg is not None:
                vals[new_reg] = new_val

                s = self.string_at(
                    new_val
                )

                if s:
                    found.append(
                        (
                            x.address,
                            new_val,
                            s
                        )
                    )

            if x.mnemonic in (
                "bl",
                "ret"
            ):
                vals.clear()

        result = []
        seen = set()

        for item in found:

            key = (
                item[0],
                item[1],
                item[2]
            )

            if key not in seen:
                seen.add(key)
                result.append(item)

        return result

    def memory_refs(
        self,
        target,
        radius=0
    ):

        refs = []

        for key, seq in self.section_ins.items():

            for i, ins in enumerate(seq):

                if ins.mnemonic != "adrp":
                    continue

                if (
                    len(ins.operands) < 2
                    or
                    ins.operands[0].type
                    != capstone.CS_OP_REG
                    or
                    ins.operands[1].type
                    != capstone.CS_OP_IMM
                ):
                    continue

                reg = regname(
                    ins,
                    ins.operands[0]
                )

                page = int(
                    ins.operands[1].imm
                )

                vals = {
                    reg: page
                }

                for j in range(
                    i + 1,
                    min(
                        i + 9,
                        len(seq)
                    )
                ):

                    x = seq[j]

                    # Stop at calls / control flow.
                    if x.mnemonic in (
                        "bl",
                        "ret"
                    ):
                        break

                    if (
                        x.mnemonic.startswith("b")
                        and
                        x.mnemonic != "bfi"
                    ):
                        break

                    # ADRP inside window
                    if (
                        x.mnemonic == "adrp"
                        and
                        len(x.operands) >= 2
                        and
                        x.operands[0].type
                        == capstone.CS_OP_REG
                        and
                        x.operands[1].type
                        == capstone.CS_OP_IMM
                    ):

                        r = regname(
                            x,
                            x.operands[0]
                        )

                        vals[r] = int(
                            x.operands[1].imm
                        )

                    # ADD
                    if (
                        x.mnemonic == "add"
                        and
                        len(x.operands) >= 3
                        and
                        x.operands[0].type
                        == capstone.CS_OP_REG
                        and
                        x.operands[1].type
                        == capstone.CS_OP_REG
                        and
                        x.operands[2].type
                        == capstone.CS_OP_IMM
                    ):

                        dst = regname(
                            x,
                            x.operands[0]
                        )

                        src = regname(
                            x,
                            x.operands[1]
                        )

                        if src in vals:
                            vals[dst] = (
                                vals[src]
                                + int(
                                    x.operands[2].imm
                                )
                            )

                    # Memory operations
                    if (
                        x.mnemonic.startswith(
                            (
                                "ldr",
                                "str",
                            )
                        )
                        and
                        len(x.operands) >= 2
                    ):

                        mem = None

                        for op in x.operands:
                            if (
                                op.type
                                == capstone.CS_OP_MEM
                            ):
                                mem = op
                                break

                        if mem is None:
                            continue

                        base = x.reg_name(
                            mem.mem.base
                        )

                        if base not in vals:
                            continue

                        addr = (
                            vals[base]
                            + int(
                                mem.mem.disp
                            )
                        )

                        if (
                            target - radius
                            <= addr
                            <= target + radius
                        ):

                            kind = (
                                "WRITE"
                                if x.mnemonic.startswith(
                                    "str"
                                )
                                else "READ"
                            )

                            refs.append(
                                {
                                    "code":
                                        x.address,
                                    "memory":
                                        addr,
                                    "kind":
                                        kind,
                                    "section":
                                        key,
                                }
                            )

        unique = []
        seen = set()

        for r in refs:

            k = (
                r["code"],
                r["memory"],
                r["kind"]
            )

            if k not in seen:
                seen.add(k)
                unique.append(r)

        return sorted(
            unique,
            key=lambda x: x["code"]
        )

    def function_candidates(self):

        cands = set()

        for target, refs in \
            self.direct_refs.items():

            if self.executable_section_for(
                target
            ):
                cands.add(target)

        for x in self.ins:

            if (
                x.mnemonic == "sub"
                and
                x.op_str.startswith(
                    "sp, sp,"
                )
            ):
                cands.add(
                    x.address
                )

            if (
                x.mnemonic == "stp"
                and
                "x29, x30" in x.op_str
                and
                "[sp" in x.op_str
            ):
                cands.add(
                    x.address
                )

        return sorted(cands)


def similarity(a, b):

    if not a or not b:
        return 0.0

    aa = [
        normalize(x)
        for x in a
    ]

    bb = [
        normalize(x)
        for x in b
    ]

    return difflib.SequenceMatcher(
        None,
        aa,
        bb,
        autojunk=False
    ).ratio()


def best_matches(
    source_seq,
    other,
    limit=10
):

    if not source_seq:
        return []

    slen = len(source_seq)
    matches = []
    # With skipdata enabled, scanning every possible prologue through
    # SequenceMatcher becomes needlessly expensive.  Keep only candidates
    # with the same normalized opening instructions before full comparison.
    # This retains exact/near structural matches while letting the offline
    # report finish in a bounded time.
    prefix = [normalize(x) for x in source_seq[:2]]

    for addr in other.function_candidates():

        idx = other.by_addr.get(addr)

        if idx is None:
            continue

        if (
            len(other.ins) < idx + len(prefix)
            or [normalize(x) for x in other.ins[idx:idx + len(prefix)]]
            != prefix
        ):
            continue

        seq = other.function(
            addr,
            max_ins=min(
                800,
                max(
                    100,
                    slen * 2
                )
            )
        )

        if len(seq) < 3:
            continue

        if slen >= 10:

            if len(seq) < slen * 0.40:
                continue

            if len(seq) > slen * 2.3:
                continue

        score = similarity(
            source_seq,
            seq
        )

        matches.append(
            (
                score,
                addr,
                len(seq)
            )
        )

    matches.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return matches[:limit]


def fmt(seq, highlight=None):

    lines = []

    for x in seq:

        mark = (
            ">>"
            if x.address == highlight
            else "  "
        )

        lines.append(
            f"{mark} "
            f"0x{x.address:08X}: "
            f"{x.mnemonic:<9} "
            f"{x.op_str}"
        )

    return lines


def section_table(img, lines):

    lines.append(
        f"{img.label} PE SECTIONS"
    )
    lines.append("-" * 110)

    for s in img.sections:

        flags = []

        if s["code"]:
            flags.append("CODE")

        if s["executable"]:
            flags.append("EXEC")

        lines.append(
            f"{s['name']:<10} "
            f"VA=0x{s['va']:08X} "
            f"raw=0x{s['raw_size']:X} "
            f"virt=0x{s['virtual_size']:X} "
            f"flags={','.join(flags) or '-'} "
            f"char=0x{s['characteristics']:08X}"
        )

    lines.append("")


def target_report(
    new,
    old,
    name,
    addr,
    lines
):

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        f"EZB6 TARGET: {name} @ 0x{addr:X}"
    )
    lines.append("=" * 110)

    sec = new.section_for(addr)

    if sec is None:

        lines.append(
            "PE section mapping: NOT FOUND"
        )
        return

    lines.append(
        "Section: "
        f"{sec['name']} "
        f"VA=0x{sec['va']:X} "
        f"raw=0x{sec['raw_size']:X} "
        f"virt=0x{sec['virtual_size']:X} "
        f"exec={sec['executable']} "
        f"code={sec['code']}"
    )

    raw = new.raw_bytes_at_va(
        addr,
        32
    )

    if raw is None:

        lines.append(
            "Target is inside virtual section "
            "but has no file-backed raw bytes."
        )

    else:

        lines.append(
            "Bytes: "
            + raw.hex(" ")
        )

    seq = new.function(addr)

    lines.append(
        f"Decoded instructions: {len(seq)}"
    )

    refs = new.direct_refs.get(
        addr,
        []
    )

    lines.append(
        f"Direct BL/B refs: {len(refs)}"
    )

    for r in refs:

        lines.append(
            f"  {r['kind']:<2} "
            f"0x{r['code']:X} "
            f"-> 0x{addr:X}"
        )

    if seq:

        strings = new.referenced_strings(
            seq
        )

        lines.append(
            f"Referenced strings: "
            f"{len(strings)}"
        )

        for code, va, text in strings:

            flag = ""

            if any(
                word in text.lower()
                for word in SECURITY_WORDS
            ):
                flag = " <<< SECURITY"

            lines.append(
                f"  code=0x{code:X} "
                f"str=0x{va:X} "
                f"{text[:180]}"
                f"{flag}"
            )

        calls = []

        for x in seq:

            if x.mnemonic == "bl":

                t = imm_target(x)

                if t is not None:
                    calls.append(
                        (
                            x.address,
                            t
                        )
                    )

        lines.append(
            f"Calls out: {len(calls)}"
        )

        for c, t in calls[:100]:

            lines.append(
                f"  0x{c:X} -> 0x{t:X}"
            )

        lines.append("")
        lines.append(
            "BEST CXDF FUNCTION MATCHES"
        )
        lines.append("-" * 110)

        for score, a, ln in \
            best_matches(
                seq,
                old
            ):

            lines.append(
                f"{score*100:7.2f}% "
                f"CXDF=0x{a:X} "
                f"len={ln}"
            )

        lines.append("")
        lines.append(
            "TARGET DISASSEMBLY"
        )
        lines.append("-" * 110)

        if len(seq) <= 400:

            lines.extend(
                fmt(seq)
            )

        else:

            lines.extend(
                fmt(seq[:200])
            )

            lines.append(
                "... middle omitted ..."
            )

            lines.extend(
                fmt(seq[-200:])
            )

    lines.append("")
    lines.append(
        "CALL / TAIL-CALL CONTEXTS"
    )
    lines.append("-" * 110)

    for r in refs:

        lines.append("")
        lines.append(
            f"{r['kind']} REF "
            f"@ 0x{r['code']:X}"
        )

        lines.extend(
            fmt(
                new.context(
                    r["code"],
                    24,
                    20
                ),
                r["code"]
            )
        )


def global_report(
    img,
    target,
    lines
):

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        f"{img.label} GLOBAL STATE "
        f"@ 0x{target:X}"
    )
    lines.append("=" * 110)

    sec = img.section_for(
        target
    )

    if sec:

        lines.append(
            f"Section: {sec['name']} "
            f"VA=0x{sec['va']:X} "
            f"raw=0x{sec['raw_size']:X} "
            f"virt=0x{sec['virtual_size']:X}"
        )

    else:

        lines.append(
            "Section: NOT FOUND"
        )

    b = img.raw_bytes_at_va(
        target - 0x20,
        0x60
    )

    if b is not None:

        lines.append(
            "Bytes around global:"
        )

        for i in range(
            0,
            len(b),
            16
        ):

            lines.append(
                f"  0x{target-0x20+i:08X}: "
                + b[i:i+16].hex(" ")
            )

    exact = img.memory_refs(
        target,
        0
    )

    near = img.memory_refs(
        target,
        0x100
    )

    lines.append("")
    lines.append(
        f"Exact refs: {len(exact)}"
    )

    for r in exact:

        lines.append(
            f"  {r['kind']:<5} "
            f"code=0x{r['code']:X} "
            f"memory=0x{r['memory']:X}"
        )

        lines.extend(
            fmt(
                img.context(
                    r["code"],
                    16,
                    16
                ),
                r["code"]
            )
        )

    lines.append("")
    lines.append(
        f"Neighbour refs (+/-0x100): "
        f"{len(near)}"
    )

    for r in near:

        lines.append(
            f"  {r['kind']:<5} "
            f"code=0x{r['code']:X} "
            f"memory=0x{r['memory']:X} "
            f"delta={r['memory']-target:+#x}"
        )


def caller_argument_report(
    img,
    target,
    lines
):

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        f"{img.label} ARGUMENT CONTEXTS "
        f"FOR 0x{target:X}"
    )
    lines.append("=" * 110)

    refs = img.direct_refs.get(
        target,
        []
    )

    for r in refs:

        lines.append("")
        lines.append(
            f"{r['kind']} @ 0x{r['code']:X}"
        )

        ctx = img.context(
            r["code"],
            30,
            12
        )

        lines.extend(
            fmt(
                ctx,
                r["code"]
            )
        )


def wrapper_report(img, lines):

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        "STATE WRAPPER 0x9688 — "
        "EXACT LOCAL BLOCK"
    )
    lines.append("=" * 110)

    idx = img.by_addr.get(
        0x9688
    )

    if idx is None:

        lines.append(
            "0x9688 not decoded"
        )
        return

    seq = img.ins[
        idx:min(
            idx + 12,
            len(img.ins)
        )
    ]

    lines.extend(
        fmt(
            seq,
            0x9688
        )
    )


def main():

    old = Image(
        CXDF_PATH,
        "CXDF"
    )

    new = Image(
        EZB6_PATH,
        "EZB6"
    )

    report = []

    report.append(
        "S23 EZB6 STATE SOURCE / SINK TRACE"
    )
    report.append("=" * 110)
    report.append("")

    report.append(
        f"CXDF: {old.path}"
    )
    report.append(
        f"  size={len(old.data):,}"
    )
    report.append(
        f"  sha256={sha256(old.data)}"
    )

    report.append("")

    report.append(
        f"EZB6: {new.path}"
    )
    report.append(
        f"  size={len(new.data):,}"
    )
    report.append(
        f"  sha256={sha256(new.data)}"
    )

    report.append("")

    section_table(
        old,
        report
    )

    section_table(
        new,
        report
    )

    for name, addr in TARGETS.items():

        target_report(
            new,
            old,
            name,
            addr,
            report
        )

    global_report(
        new,
        GLOBAL_UNLOCK_BOOT_STATE,
        report
    )

    caller_argument_report(
        new,
        0xD5D90,
        report
    )

    caller_argument_report(
        new,
        0xC7CF0,
        report
    )

    caller_argument_report(
        new,
        0xC5A10,
        report
    )

    wrapper_report(
        new,
        report
    )

    # -----------------------------------------------------
    # Compact summary
    # -----------------------------------------------------

    summary = []

    summary.append(
        "STATE SOURCE TRACE SUMMARY"
    )
    summary.append("=" * 90)

    summary.append("")
    summary.append(
        "TARGET SECTION MAPPING"
    )
    summary.append("-" * 90)

    for name, addr in TARGETS.items():

        sec = new.section_for(addr)

        if sec is None:

            summary.append(
                f"{name:<24} "
                f"0x{addr:X}  NOT MAPPED"
            )

            continue

        seq = new.function(addr)

        summary.append(
            f"{name:<24} "
            f"0x{addr:X}  "
            f"section={sec['name']} "
            f"exec={sec['executable']} "
            f"code={sec['code']} "
            f"decoded={len(seq)} "
            f"refs={len(new.direct_refs.get(addr, []))}"
        )

        if seq:

            matches = best_matches(
                seq,
                old,
                3
            )

            for score, old_addr, ln \
                in matches:

                summary.append(
                    f"    CXDF match "
                    f"{score*100:7.2f}% "
                    f"0x{old_addr:X} "
                    f"len={ln}"
                )

    summary.append("")
    summary.append(
        f"GLOBAL 0x{GLOBAL_UNLOCK_BOOT_STATE:X}"
    )
    summary.append("-" * 90)

    refs = new.memory_refs(
        GLOBAL_UNLOCK_BOOT_STATE,
        0
    )

    summary.append(
        f"Exact accesses: {len(refs)}"
    )

    for r in refs:

        summary.append(
            f"  {r['kind']:<5} "
            f"code=0x{r['code']:X}"
        )

    summary.append("")
    summary.append(
        "D5D90 DIRECT REFS"
    )
    summary.append("-" * 90)

    for r in new.direct_refs.get(
        0xD5D90,
        []
    ):

        summary.append(
            f"  {r['kind']} "
            f"0x{r['code']:X}"
        )

    summary.append("")
    summary.append(
        "C7CF0 DIRECT / TAIL REFS"
    )
    summary.append("-" * 90)

    for r in new.direct_refs.get(
        0xC7CF0,
        []
    ):

        summary.append(
            f"  {r['kind']} "
            f"0x{r['code']:X}"
        )

    SUMMARY.write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8"
    )

    REPORT.write_text(
        "\n".join(report) + "\n",
        encoding="utf-8"
    )

    print()
    print("[+] Generated:")
    print(f"    {SUMMARY}")
    print(f"    {REPORT}")
    print()


if __name__ == "__main__":
    main()
PY

chmod +x "$OUT/analyze.py"

"$VENV/bin/python" \
    "$OUT/analyze.py" \
    "$CXDF" \
    "$EZB6" \
    "$OUT"
