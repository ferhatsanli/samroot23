#!/usr/bin/env python3

import sys
import re
import hashlib
import difflib
from pathlib import Path
from collections import defaultdict

import pefile
import capstone


OLD_PATH = Path(sys.argv[1])
NEW_PATH = Path(sys.argv[2])
OUT = Path(sys.argv[3])

SUMMARY = OUT / "summary.txt"
REPORT = OUT / "report.txt"


# Known addresses from previous analysis.
TARGETS_OLD = {
    "UnlockStateSetter_old": 0x25EE0,
    "IsUnlocked_old":       0x25D80,
}

TARGETS_NEW = {
    "UnlockStateSetter_new": 0x26020,

    # New boot-flow calls.
    "NewStateSource_D5D90":  0xD5D90,
    "NewStateSink_C7CF0":    0xC7CF0,
    "NewCall_C5A10":         0xC5A10,

    # Reads a global immediately after SetUnlockState.
    "NewGlobalRead_6EE10":   0x6EE10,

    # Wrapper that calls C7CF0 with values 2/3/4.
    "StateWrapper_9688":     0x9688,
}


SECURITY_WORDS = (
    "unlock", "lock", "oem", "frp", "kg", "knox",
    "vault", "rpmb", "ddi", "bldp", "fuse",
    "device", "state", "bootloader", "secure",
    "rollback", "warranty", "auth", "policy",
)


def h(data):
    return hashlib.sha256(data).hexdigest()


def imm_target(ins):
    if not ins.operands:
        return None

    for op in ins.operands:
        if op.type == capstone.CS_OP_IMM:
            return int(op.imm)

    return None


def reg_name(ins, op):
    try:
        return ins.reg_name(op.reg)
    except Exception:
        return None


class PEImage:

    def __init__(self, path, label):
        self.path = Path(path)
        self.label = label
        self.data = self.path.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=False)

        self.image_base = int(
            self.pe.OPTIONAL_HEADER.ImageBase
        )

        self.text = None

        for s in self.pe.sections:
            name = s.Name.rstrip(b"\x00").decode(
                errors="ignore"
            )

            if name == ".text":
                self.text = s
                break

        if self.text is None:
            raise RuntimeError(
                f"{label}: .text bulunamadi"
            )

        self.text_rva = int(
            self.text.VirtualAddress
        )

        self.text_va = (
            self.image_base + self.text_rva
        )

        self.text_data = self.text.get_data()

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

        self.ins = list(
            self.md.disasm(
                self.text_data,
                self.text_va
            )
        )

        self.by_addr = {
            x.address: i
            for i, x in enumerate(self.ins)
        }

        self.callers = defaultdict(list)
        self.call_targets = set()

        for x in self.ins:
            if x.mnemonic == "bl":
                t = imm_target(x)

                if t is not None:
                    self.callers[t].append(
                        x.address
                    )
                    self.call_targets.add(t)

        self.ascii_strings = self._strings()

    def _strings(self):
        result = {}

        for m in re.finditer(
            rb'[\x20-\x7e]{4,300}',
            self.data
        ):
            try:
                s = m.group().decode("ascii")
            except Exception:
                continue

            rva = self.pe.get_rva_from_offset(
                m.start()
            )

            va = self.image_base + rva

            result[va] = s

        return result

    def addr_ok(self, addr):
        return addr in self.by_addr

    def raw_context(
        self,
        addr,
        before=24,
        after=48
    ):
        idx = self.by_addr.get(addr)

        if idx is None:
            return []

        lo = max(0, idx - before)
        hi = min(
            len(self.ins),
            idx + after + 1
        )

        return self.ins[lo:hi]

    def follow_thunk(
        self,
        addr,
        max_depth=8
    ):
        chain = [addr]
        cur = addr

        for _ in range(max_depth):
            idx = self.by_addr.get(cur)

            if idx is None:
                break

            x = self.ins[idx]

            if x.mnemonic != "b":
                break

            t = imm_target(x)

            if t is None:
                break

            if t in chain:
                break

            chain.append(t)
            cur = t

        return chain

    def function_sequence(
        self,
        addr,
        max_ins=1200
    ):
        """
        Address is a BL destination, so treat it as function
        entry even when it has no conventional prologue.
        """

        chain = self.follow_thunk(addr)
        start = chain[-1]

        idx = self.by_addr.get(start)

        if idx is None:
            return start, [], chain

        seq = []

        for x in self.ins[
            idx:min(
                len(self.ins),
                idx + max_ins
            )
        ]:
            seq.append(x)

            if x.mnemonic == "ret":
                break

        return start, seq, chain

    def get_string(self, va):
        if va in self.ascii_strings:
            return self.ascii_strings[va]

        # Also allow pointer in middle of a string.
        for base, s in self.ascii_strings.items():
            if base <= va < base + len(s):
                off = va - base
                return s[off:]

        return None

    def referenced_strings(self, seq):
        found = []

        for i, x in enumerate(seq):

            if x.mnemonic == "adr":
                t = imm_target(x)

                if t is not None:
                    s = self.get_string(t)

                    if s:
                        found.append(
                            (
                                x.address,
                                t,
                                s,
                                "ADR"
                            )
                        )

            if x.mnemonic != "adrp":
                continue

            if len(x.operands) < 2:
                continue

            dst = reg_name(
                x,
                x.operands[0]
            )

            page = imm_target(x)

            if dst is None or page is None:
                continue

            for j in range(
                i + 1,
                min(i + 6, len(seq))
            ):
                y = seq[j]

                if y.mnemonic != "add":
                    continue

                if len(y.operands) < 3:
                    continue

                try:
                    d0 = reg_name(
                        y,
                        y.operands[0]
                    )

                    d1 = reg_name(
                        y,
                        y.operands[1]
                    )

                    if d0 != dst or d1 != dst:
                        continue

                    if (
                        y.operands[2].type
                        != capstone.CS_OP_IMM
                    ):
                        continue

                    va = (
                        page
                        + int(
                            y.operands[2].imm
                        )
                    )

                    s = self.get_string(va)

                    if s:
                        found.append(
                            (
                                x.address,
                                va,
                                s,
                                "ADRP+ADD"
                            )
                        )

                except Exception:
                    continue

        uniq = []
        seen = set()

        for item in found:
            key = (
                item[0],
                item[1],
                item[2]
            )

            if key not in seen:
                seen.add(key)
                uniq.append(item)

        return uniq

    def direct_calls(self, seq):
        result = []

        for x in seq:
            if x.mnemonic == "bl":
                t = imm_target(x)

                if t is not None:
                    result.append(
                        (
                            x.address,
                            t
                        )
                    )

        return result

    def caller_context(self, call_addr):
        return self.raw_context(
            call_addr,
            16,
            12
        )


def normalize_ins(x):
    mn = x.mnemonic

    op = x.op_str.lower()

    # Branch targets.
    if mn.startswith("b") or mn in (
        "bl", "adr", "adrp"
    ):
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

    # Large immediates.
    def repl(m):
        raw = m.group(0)

        try:
            if raw.startswith("#0x"):
                n = int(raw[1:], 16)
            elif raw.startswith("#-0x"):
                n = -int(raw[2:], 16)
            else:
                n = int(raw[1:])
        except Exception:
            return raw

        if n in (
            -1, 0, 1, 2, 3, 4,
            5, 6, 7, 8, 16,
            32, 64, 255
        ):
            return raw

        return "#<IMM>"

    op = re.sub(
        r'#(?:-?0x[0-9a-f]+|-?\d+)',
        repl,
        op
    )

    # Memory offsets.
    op = re.sub(
        r', #(?:-?0x[0-9a-f]+|-?\d+)\]',
        ', #<OFF>]',
        op
    )

    return f"{mn} {op}".strip()


def normalized_seq(seq):
    return [
        normalize_ins(x)
        for x in seq
    ]


def seq_similarity(a, b):
    if not a or not b:
        return 0.0

    return difflib.SequenceMatcher(
        None,
        normalized_seq(a),
        normalized_seq(b),
        autojunk=False
    ).ratio()


def probable_function_candidates(img):

    cands = set(img.call_targets)

    # Add common function prologues missed by direct calls.
    for i, x in enumerate(img.ins):

        if x.mnemonic == "sub" and \
           x.op_str.startswith("sp, sp,"):
            cands.add(x.address)

        if x.mnemonic == "stp" and \
           "x29, x30" in x.op_str and \
           "[sp" in x.op_str:
            cands.add(x.address)

    return sorted(cands)


def best_matches(
    target_seq,
    other,
    limit=12
):
    if not target_seq:
        return []

    target_len = len(target_seq)

    candidates = []

    for addr in probable_function_candidates(
        other
    ):
        _, seq, _ = other.function_sequence(
            addr,
            max_ins=min(
                1400,
                max(
                    80,
                    target_len * 2
                )
            )
        )

        ln = len(seq)

        if ln < 3:
            continue

        if target_len >= 10:
            if ln < target_len * 0.45:
                continue

            if ln > target_len * 2.2:
                continue

        score = seq_similarity(
            target_seq,
            seq
        )

        candidates.append(
            (
                score,
                addr,
                ln
            )
        )

    candidates.sort(
        reverse=True,
        key=lambda x: x[0]
    )

    return candidates[:limit]


def fmt_context(seq, highlight=None):

    out = []

    for x in seq:
        mark = (
            ">>"
            if x.address == highlight
            else "  "
        )

        out.append(
            f"{mark} "
            f"0x{x.address:08X}: "
            f"{x.mnemonic:<9} "
            f"{x.op_str}"
        )

    return out


def describe_target(
    img,
    name,
    addr,
    compare=None
):

    lines = []

    lines.append("=" * 110)
    lines.append(
        f"{img.label}: {name} @ 0x{addr:X}"
    )
    lines.append("=" * 110)

    if not img.addr_ok(addr):
        lines.append(
            "Address executable .text icinde bulunamadi."
        )
        return lines

    start, seq, chain = img.function_sequence(
        addr
    )

    lines.append(
        "Thunk chain : "
        + " -> ".join(
            f"0x{x:X}" for x in chain
        )
    )

    lines.append(
        f"Resolved start: 0x{start:X}"
    )

    lines.append(
        f"Instructions : {len(seq)}"
    )

    if seq:
        lines.append(
            f"End          : "
            f"0x{seq[-1].address:X} "
            f"({seq[-1].mnemonic})"
        )

    callers = img.callers.get(
        addr,
        []
    )

    if start != addr:
        callers += img.callers.get(
            start,
            []
        )

    callers = sorted(set(callers))

    lines.append(
        f"Direct callers: {len(callers)}"
    )

    for c in callers:
        lines.append(
            f"  0x{c:X}"
        )

    strings = img.referenced_strings(
        seq
    )

    lines.append(
        f"Referenced strings: {len(strings)}"
    )

    for code, va, s, typ in strings:
        flag = ""

        if any(
            k in s.lower()
            for k in SECURITY_WORDS
        ):
            flag = "  <<< SECURITY"

        lines.append(
            f"  {typ:10s} "
            f"code=0x{code:X} "
            f"str=0x{va:X} "
            f"{s[:180]}"
            f"{flag}"
        )

    calls = img.direct_calls(seq)

    lines.append(
        f"Direct BL calls: {len(calls)}"
    )

    for code, dst in calls[:120]:
        lines.append(
            f"  0x{code:X} -> 0x{dst:X}"
        )

    if compare is not None and seq:
        lines.append("")
        lines.append(
            f"BEST {compare.label} MATCHES"
        )
        lines.append("-" * 110)

        for score, candidate, ln in \
            best_matches(seq, compare):
            lines.append(
                f"{score*100:7.2f}% "
                f"0x{candidate:X} "
                f"len={ln}"
            )

    lines.append("")
    lines.append(
        "FUNCTION / TARGET DISASSEMBLY"
    )
    lines.append("-" * 110)

    # Avoid multi-thousand line output.
    if len(seq) <= 260:
        lines.extend(
            fmt_context(seq)
        )
    else:
        lines.extend(
            fmt_context(seq[:130])
        )

        lines.append(
            "... <middle omitted> ..."
        )

        lines.extend(
            fmt_context(seq[-130:])
        )

    lines.append("")
    lines.append("CALLER CONTEXTS")
    lines.append("-" * 110)

    for c in callers[:20]:

        lines.append("")
        lines.append(
            f"CALL @ 0x{c:X}"
        )

        lines.extend(
            fmt_context(
                img.caller_context(c),
                c
            )
        )

    return lines


def setter_analysis(
    old,
    new,
    lines
):

    old_addr = 0x25EE0
    new_addr = 0x26020

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        "LOCK / UNLOCK STATE SETTER COMPARISON"
    )
    lines.append("=" * 110)

    _, os, _ = old.function_sequence(
        old_addr
    )

    _, ns, _ = new.function_sequence(
        new_addr
    )

    lines.append(
        f"CXDF 0x{old_addr:X}: "
        f"{len(os)} instructions"
    )

    lines.append(
        f"EZB6 0x{new_addr:X}: "
        f"{len(ns)} instructions"
    )

    lines.append(
        f"Normalized similarity: "
        f"{seq_similarity(os, ns)*100:.2f}%"
    )

    lines.append("")
    lines.append(
        "CXDF DIRECT CALLERS"
    )
    lines.append("-" * 110)

    oc = old.callers.get(
        old_addr,
        []
    )

    if not oc:
        lines.append(
            "(no direct BL caller detected)"
        )

    for c in oc:
        lines.append(
            f"0x{c:X}"
        )

        lines.extend(
            fmt_context(
                old.caller_context(c),
                c
            )
        )

    lines.append("")
    lines.append(
        "EZB6 DIRECT CALLERS"
    )
    lines.append("-" * 110)

    nc = new.callers.get(
        new_addr,
        []
    )

    if not nc:
        lines.append(
            "(no direct BL caller detected)"
        )

    for c in nc:
        lines.append(
            f"0x{c:X}"
        )

        lines.extend(
            fmt_context(
                new.caller_context(c),
                c
            )
        )


def boot_insertion(lines, new):

    lines.append("")
    lines.append("=" * 110)
    lines.append(
        "EZB6 BOOT-TIME UNLOCK STATE INSERTION"
    )
    lines.append("=" * 110)

    for addr in (
        0x9310,
        0x9314,
        0x9324,
        0x9328,
        0x9338,
        0x9370,
        0x93C0,
        0x9594,
    ):

        if not new.addr_ok(addr):
            continue

        lines.append("")
        lines.append(
            f"CONTEXT @ 0x{addr:X}"
        )

        lines.extend(
            fmt_context(
                new.raw_context(
                    addr,
                    10,
                    12
                ),
                addr
            )
        )


def two_hop(img, target, lines):

    lines.append("")
    lines.append(
        f"TWO-HOP CALL GRAPH FOR 0x{target:X}"
    )
    lines.append("-" * 110)

    first = img.callers.get(
        target,
        []
    )

    if not first:
        lines.append(
            "(no direct callers)"
        )
        return

    for c in first:
        lines.append(
            f"CALL 0x{c:X} -> 0x{target:X}"
        )

        # Search probable function starts before caller.
        idx = img.by_addr[c]

        start = None

        for j in range(
            idx,
            max(-1, idx - 600),
            -1
        ):
            x = img.ins[j]

            if (
                x.mnemonic == "sub"
                and
                x.op_str.startswith(
                    "sp, sp,"
                )
            ):
                start = x.address
                break

            if (
                x.mnemonic == "stp"
                and
                "x29, x30" in x.op_str
                and
                "[sp" in x.op_str
            ):
                start = x.address
                break

        if start is None:
            continue

        parents = img.callers.get(
            start,
            []
        )

        lines.append(
            f"  enclosing probable function: "
            f"0x{start:X}"
        )

        for p in parents[:30]:
            lines.append(
                f"    parent call: "
                f"0x{p:X} -> 0x{start:X}"
            )


def main():

    old = PEImage(
        OLD_PATH,
        "CXDF"
    )

    new = PEImage(
        NEW_PATH,
        "EZB6"
    )

    report = []

    report.append(
        "S23 LOCKED -> UNLOCKED REQUEST PATH TRACE"
    )
    report.append("=" * 110)
    report.append("")

    report.append(
        f"CXDF: {old.path}"
    )
    report.append(
        f"  size={len(old.data):,} "
        f"sha256={h(old.data)}"
    )

    report.append(
        f"EZB6: {new.path}"
    )
    report.append(
        f"  size={len(new.data):,} "
        f"sha256={h(new.data)}"
    )

    setter_analysis(
        old,
        new,
        report
    )

    boot_insertion(
        report,
        new
    )

    for name, addr in \
        TARGETS_NEW.items():

        report.append("")

        report.extend(
            describe_target(
                new,
                name,
                addr,
                compare=old
            )
        )

    for name, addr in \
        TARGETS_OLD.items():

        report.append("")

        report.extend(
            describe_target(
                old,
                name,
                addr,
                compare=new
            )
        )

    report.append("")
    report.append("=" * 110)
    report.append(
        "CALL GRAPH EXPANSION"
    )
    report.append("=" * 110)

    two_hop(
        new,
        0x26020,
        report
    )

    two_hop(
        new,
        0xD5D90,
        report
    )

    two_hop(
        new,
        0xC7CF0,
        report
    )

    # Compact summary.
    summary = []

    _, old_set, _ = \
        old.function_sequence(
            0x25EE0
        )

    _, new_set, _ = \
        new.function_sequence(
            0x26020
        )

    summary.append(
        "UNLOCK ENTRY TRACE SUMMARY"
    )
    summary.append("=" * 90)
    summary.append("")

    summary.append(
        f"Unlock setter old/new similarity: "
        f"{seq_similarity(old_set,new_set)*100:.2f}%"
    )

    summary.append(
        f"CXDF setter direct callers: "
        f"{len(old.callers.get(0x25EE0, []))}"
    )

    summary.append(
        f"EZB6 setter direct callers: "
        f"{len(new.callers.get(0x26020, []))}"
    )

    for name, addr in (
        ("D5D90", 0xD5D90),
        ("C7CF0", 0xC7CF0),
        ("C5A10", 0xC5A10),
        ("6EE10", 0x6EE10),
    ):

        start, seq, chain = \
            new.function_sequence(addr)

        summary.append("")
        summary.append(
            f"{name} @ 0x{addr:X}"
        )

        summary.append(
            f"  resolved start : "
            f"0x{start:X}"
        )

        summary.append(
            f"  instructions   : "
            f"{len(seq)}"
        )

        summary.append(
            f"  callers        : "
            f"{len(new.callers.get(addr, []))}"
        )

        strings = \
            new.referenced_strings(seq)

        sec = [
            s for _, _, s, _ in strings
            if any(
                k in s.lower()
                for k in SECURITY_WORDS
            )
        ]

        summary.append(
            f"  security strings: "
            f"{len(sec)}"
        )

        for s in sec[:20]:
            summary.append(
                f"    {s[:160]}"
            )

        matches = \
            best_matches(
                seq,
                old,
                3
            )

        summary.append(
            "  best CXDF matches:"
        )

        for score, a, ln in matches:
            summary.append(
                f"    "
                f"{score*100:7.2f}% "
                f"0x{a:X} "
                f"len={ln}"
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
    print("Generated:")
    print(f"  {SUMMARY}")
    print(f"  {REPORT}")


if __name__ == "__main__":
    main()
