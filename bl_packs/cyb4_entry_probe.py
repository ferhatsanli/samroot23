#!/usr/bin/env python3
"""Targeted read-only CYB4 LinuxLoader entry-route locator."""
import sys
from collections import defaultdict
from pathlib import Path
import capstone
import pefile

source, output = map(Path, sys.argv[1:])
output.parent.mkdir(parents=True, exist_ok=True)
data = source.read_bytes()
pe = pefile.PE(data=data, fast_load=False)
base = pe.OPTIONAL_HEADER.ImageBase
arch = getattr(capstone, "CS_ARCH_AARCH64", capstone.CS_ARCH_ARM64)
md = capstone.Cs(arch, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True
instructions = []
for section in pe.sections:
    if section.Characteristics & 0x20000020:
        instructions.extend(md.disasm(section.get_data(), base + section.VirtualAddress))
instructions.sort(key=lambda ins: ins.address)
by_address = {ins.address: index for index, ins in enumerate(instructions)}
branches = defaultdict(list)
for index, ins in enumerate(instructions):
    if ins.mnemonic in ("b", "bl"):
        for operand in ins.operands:
            if operand.type == capstone.CS_OP_IMM:
                branches[int(operand.imm)].append(index)

def file_offset_to_va(offset):
    try:
        return base + pe.get_rva_from_offset(offset)
    except Exception:
        return None

def string_refs(target):
    if target is None:
        return []
    page = target & ~0xfff
    found = []
    for index, ins in enumerate(instructions):
        if (ins.mnemonic == "adr" and len(ins.operands) > 1 and
                ins.operands[1].type == capstone.CS_OP_IMM and
                ins.operands[1].imm == target):
            found.append(index)
        if (ins.mnemonic == "adrp" and len(ins.operands) > 1 and
                ins.operands[1].type == capstone.CS_OP_IMM and
                ins.operands[1].imm == page):
            reg = ins.operands[0].reg
            for next_ins in instructions[index + 1:index + 6]:
                if (next_ins.mnemonic == "add" and len(next_ins.operands) > 2 and
                        next_ins.operands[0].type == capstone.CS_OP_REG and
                        next_ins.operands[0].reg == reg and
                        next_ins.operands[1].type == capstone.CS_OP_REG and
                        next_ins.operands[1].reg == reg and
                        next_ins.operands[2].type == capstone.CS_OP_IMM):
                    if page + next_ins.operands[2].imm == target:
                        found.append(index)
                    break
    return found

def context(index, before=24, after=48):
    return [f"  0x{ins.address:X}: {ins.mnemonic:<8} {ins.op_str}".rstrip()
            for ins in instructions[max(0, index - before):min(len(instructions), index + after)]]

terms = (
    b"+LongPressVolUpkeyCheck Start!",
    b"LongPressVolUpkeyCheck Failed!",
    b"For device unlock, Draw UnLock Img",
    b"Unable set the unlock value: %r",
    b"setOEMFlags",
)
lines = ["# CYB4 LinuxLoader targeted entry probe", ""]
for term in terms:
    raw = data.find(term)
    target = file_offset_to_va(raw) if raw >= 0 else None
    lines.append(f"## {term.decode(errors='replace')} raw={raw if raw >= 0 else 'none'} va={hex(target) if target else 'none'}")
    for index in string_refs(target):
        lines.append(f"xref context at 0x{instructions[index].address:X}:")
        lines.extend(context(index))

lines.append("\n## Direct branch/call targets near xref contexts")
seen = set()
for term in terms:
    raw = data.find(term)
    target = file_offset_to_va(raw) if raw >= 0 else None
    for index in string_refs(target):
        for ins in instructions[max(0, index - 48):min(len(instructions), index + 80)]:
            if ins.mnemonic in ("b", "bl"):
                for operand in ins.operands:
                    if operand.type == capstone.CS_OP_IMM and int(operand.imm) not in seen:
                        seen.add(int(operand.imm))
                        lines.append(f"target 0x{int(operand.imm):X} from 0x{ins.address:X} ({ins.mnemonic})")
                        for caller in branches.get(int(operand.imm), []):
                            if abs(instructions[caller].address - ins.address) < 0x4000:
                                lines.append(f"  ref 0x{instructions[caller].address:X}")
output.write_text("\n".join(lines) + "\n")
