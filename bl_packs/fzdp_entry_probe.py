#!/usr/bin/env python3
"""Targeted read-only FZDP LinuxLoader entry-route locator."""
import sys
from pathlib import Path
from collections import defaultdict
import pefile, capstone

path, out = map(Path, sys.argv[1:]); out.parent.mkdir(parents=True, exist_ok=True)
p=pefile.PE(data=path.read_bytes(),fast_load=False); data=path.read_bytes(); base=p.OPTIONAL_HEADER.ImageBase
arch=getattr(capstone,'CS_ARCH_AARCH64',capstone.CS_ARCH_ARM64); md=capstone.Cs(arch,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True;md.skipdata=True
ins=[]
for s in p.sections:
 if s.Characteristics&0x20000020:ins+=list(md.disasm(s.get_data(),base+s.VirtualAddress))
ins.sort(key=lambda x:x.address); by={x.address:i for i,x in enumerate(ins)}; refs=defaultdict(list)
for i,x in enumerate(ins):
 if x.mnemonic in ('b','bl'):
  for o in x.operands:
   if o.type==capstone.CS_OP_IMM: refs[int(o.imm)].append(i)
def va(off):
 try:return base+p.get_rva_from_offset(off)
 except:return None
def srefs(target):
 page=target&~0xfff; r=[]
 for i,x in enumerate(ins):
  if x.mnemonic=='adr' and len(x.operands)>1 and x.operands[1].type==capstone.CS_OP_IMM and x.operands[1].imm==target:r.append(i)
  if x.mnemonic=='adrp' and len(x.operands)>1 and x.operands[1].type==capstone.CS_OP_IMM and x.operands[1].imm==page:
   reg=x.operands[0].reg
   for y in ins[i+1:i+6]:
    if y.mnemonic=='add' and len(y.operands)>2 and y.operands[0].type==capstone.CS_OP_REG and y.operands[0].reg==reg and y.operands[1].type==capstone.CS_OP_REG and y.operands[1].reg==reg and y.operands[2].type==capstone.CS_OP_IMM:
     if page+y.operands[2].imm==target:r.append(i)
     break
 return r
terms=(b'+LongPressVolUpkeyCheck Start!',b'LongPressVolUpkeyCheck Failed!',b'For device unlock, Draw UnLock Img',b'Unable set the unlock value: %r',b'setOEMFlags')
o=['# FZDP LinuxLoader targeted entry probe','']
for term in terms:
 off=data.find(term); target=va(off) if off>=0 else None
 o.append(f'## {term.decode(errors="replace")} raw={off if off>=0 else "none"} va={hex(target) if target else "none"}')
 for i in srefs(target) if target else []:
  o.append('xref context:')
  for x in ins[max(0,i-18):min(len(ins),i+35)]:o.append(f'  0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
o.append('\n## Direct/tail refs to likely transition candidates')
# Find transition function from error string xref then identify enclosing entry.
err=va(data.find(b'Unable set the unlock value: %r'))
for i in srefs(err) if err else []:
 # nearest prior instructions serve as target address boundary approximation
 addr=ins[i].address
 o.append(f'error-string xref at 0x{addr:X}; direct callers to nearby function require comparison report')
o.append('\n## Gate target caller contexts')
o.append('### ENTRY_POLICY body 0xCABE0')
j=by[0xCABE0]
for x in ins[j:j+100]:
 o.append(f'  0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
 if x.mnemonic=='ret': break
for name,target in (('ENTRY_POLICY',0xCABE0),('LONGPRESS',0x710D0),('CONFIRM',0xD74E0),('TRANSITION',0x26020)):
 o.append(f'### {name} 0x{target:X}')
 for i in refs.get(target,[]):
  o.append(f'caller 0x{ins[i].address:X}:')
  for x in ins[max(0,i-30):min(len(ins),i+18)]:o.append(f'  0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
out.write_text('\n'.join(line.rstrip() for line in o)+'\n')
