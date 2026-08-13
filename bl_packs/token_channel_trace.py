#!/usr/bin/env python3
"""Read-only, targeted EM-token/xref inventory for EZB6 Odin and LinuxLoader."""
import sys, re
from pathlib import Path
from collections import defaultdict
import pefile, capstone

OUT = Path(sys.argv[1]); ODIN=Path(sys.argv[2]); LINUX=Path(sys.argv[3])
OUT.mkdir(parents=True, exist_ok=True)
ARCH=getattr(capstone,'CS_ARCH_AARCH64',capstone.CS_ARCH_ARM64)
TERMS=('BL_EM_CMD_INSTALL_TOKEN','BLWriteToken','Process_EMTOKEN',
       'EM_CMD_REQ_TOKEN_ESS_V1','EM_CMD_INSTALL_TOKEN_ESS_V1',
       'setOEMFlags','em_token_parse_mode_info','em_token_get_mode_information')

def image(path):
 p=pefile.PE(data=path.read_bytes(),fast_load=False); d=path.read_bytes(); b=p.OPTIONAL_HEADER.ImageBase
 md=capstone.Cs(ARCH,capstone.CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 ins=[]
 for s in p.sections:
  if s.Characteristics&0x20000020: ins+=list(md.disasm(s.get_data(),b+s.VirtualAddress))
 ins.sort(key=lambda x:x.address); by={x.address:i for i,x in enumerate(ins)}
 return p,d,b,ins,by
def rawva(p,b,off):
 try:return b+p.get_rva_from_offset(off)
 except:return None
def refs(ins,target):
 out=[]; page=target&~0xfff
 for i,x in enumerate(ins):
  if x.mnemonic=='adr' and len(x.operands)>1 and x.operands[1].type==capstone.CS_OP_IMM and x.operands[1].imm==target: out.append(i)
  if x.mnemonic=='adrp' and len(x.operands)>1 and x.operands[1].type==capstone.CS_OP_IMM and x.operands[1].imm==page:
   # bounded register-preserving followup only
   reg=x.operands[0].reg
   for y in ins[i+1:i+5]:
    if y.mnemonic in ('add','ldr') and len(y.operands)>1 and y.operands[0].type==capstone.CS_OP_REG and y.operands[0].reg==reg:
     if y.mnemonic=='add' and y.operands[1].type==capstone.CS_OP_REG and y.operands[1].reg==reg and y.operands[2].type==capstone.CS_OP_IMM and page+y.operands[2].imm==target: out.append(i)
     break
 return out
def scan(label,path):
 p,d,b,ins,by=image(path); out=[f'## {label} — {path.name}']
 for t in TERMS:
  hits=[]; start=0; needle=t.encode()
  while True:
   k=d.find(needle,start)
   if k<0:break
   hits.append((k,rawva(p,b,k)));start=k+1
  out.append(f'### {t}: occurrences={len(hits)}')
  for raw,va in hits:
   rs=refs(ins,va) if va is not None else []
   out.append(f'string raw=0x{raw:X} va='+(f'0x{va:X}' if va else 'none')+f' refs={len(rs)}')
   for j in rs:
    out.append('context:')
    for x in ins[max(0,j-8):min(len(ins),j+17)]: out.append(f'  0x{x.address:X}: {x.mnemonic:<8} {x.op_str}')
 # Proven transition call inventory for LinuxLoader only.
 if label=='LinuxLoader':
  call=[]
  for x in ins:
   if x.mnemonic in ('b','bl') and any(o.type==capstone.CS_OP_IMM and o.imm==0x26020 for o in x.operands):call.append(x.address)
  out.append('### direct/tail refs to transition 0x26020: '+', '.join(f'0x{x:X}' for x in call))
 return '\n'.join(out)
(OUT/'token_channel_report.txt').write_text(scan('Odin',ODIN)+'\n\n'+scan('LinuxLoader',LINUX)+'\n')
