#!/usr/bin/env python3
"""Targeted static trace of Download-Mode long-press entry predicates."""
import sys
from pathlib import Path
from collections import defaultdict
import pefile, capstone

CX, EZ, OUT = map(Path, sys.argv[1:4])
OUT.mkdir(parents=True, exist_ok=True)

ARCH = getattr(capstone, "CS_ARCH_AARCH64", capstone.CS_ARCH_ARM64)

def load(path):
    pe = pefile.PE(data=path.read_bytes(), fast_load=False)
    md = capstone.Cs(ARCH, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True; md.skipdata = True
    base = pe.OPTIONAL_HEADER.ImageBase
    ins=[]; sections=[]
    for sec in pe.sections:
        if sec.Characteristics & 0x20000020:
            va=base+sec.VirtualAddress; data=sec.get_data()
            sections.append((va, va+len(data)))
            ins += list(md.disasm(data, va))
    ins.sort(key=lambda x:x.address)
    by={x.address:i for i,x in enumerate(ins)}
    refs=defaultdict(list)
    for x in ins:
        if x.mnemonic not in ('b','bl') or not x.operands: continue
        for op in x.operands:
            if op.type == capstone.CS_OP_IMM: refs[int(op.imm)].append(x.address)
    return ins,by,refs

def dump(label, obj, targets):
    ins,by,refs=obj; out=[]
    out.append(f'## {label}')
    for name,addr in targets.items():
        out.append(f'### {name} 0x{addr:X}')
        calls=refs.get(addr,[])
        out.append('direct refs: ' + (', '.join(f'0x{x:X}' for x in calls) or 'none'))
        i=by.get(addr)
        if i is None:
            out.append('not decoded'); continue
        # Context intentionally includes preceding basic-block predicate.
        for x in ins[max(0,i-28):min(len(ins),i+100)]:
            mark='=>' if x.address==addr else '  '
            out.append(f'{mark} 0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
        for call in calls:
            j=by.get(call)
            if j is None: continue
            out.append(f'caller context for 0x{call:X}:')
            for x in ins[max(0,j-18):min(len(ins),j+9)]:
                mark='=>' if x.address==call else '  '
                out.append(f'{mark} 0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
    return '\n'.join(out)

# Mapped gate and helper sites only.  The direct-ref output discovers callers
# without assuming a function name from a string.
cx=load(CX); ez=load(EZ)
report='\n\n'.join((
    dump('CXDF', cx, {'EVENT_LOOP':0x70228, 'ENTRY_POLICY':0xC6ED0, 'LONGPRESS':0x70A40, 'CONFIRM':0xCFAA0}),
    dump('EZB6', ez, {'EVENT_LOOP':0x70508, 'ENTRY_POLICY':0xCA790, 'LONGPRESS':0x70D20, 'CONFIRM':0xD4AE0}),
))+'\n'
(OUT/'longpress_gate_report.txt').write_text(report)
(OUT/'longpress_gate_summary.txt').write_text(
    'Targeted contexts and direct callers written to longpress_gate_report.txt. '\
    'Interpret control-flow manually; do not treat a retained target as unconditional reachability.\n')
