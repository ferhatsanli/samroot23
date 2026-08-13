---
name: s23-firmware-analysis
description: Analyze this Samsung S23 CXDF/EZB6 bootloader, OEM-unlock, ABL/LinuxLoader, VaultKeeper, tz_kg, DDI/BLDP reverse-engineering project. Use for firmware comparison, ARM64 PE/ELF disassembly, xrefs, globals, caller tracing, and updating project findings. Do not trigger for unrelated coding.
---

# S23 firmware analysis workflow

1. Treat `PROJECT_STATE.md` as the compact source of established project facts.
2. Treat `NEXT_TASK.md` as the only current objective.
3. Use `REPORT_INDEX.md` to locate evidence; then read only targeted sections of large reports.
4. Prefer existing extracted `body.bin`/MBN/ELF inputs and existing scripts before repeating extraction.
5. For address investigation:
   - map address to PE/ELF section first;
   - disassemble all executable/code sections, not only `.text`;
   - inspect direct `BL` and tail `B` refs;
   - inspect ADR/ADRP+ADD/ADRP+LDR and data-table/relocation possibilities;
   - trace exact global reads/writes and nearby struct fields;
   - compare old/new normalized instruction structure and caller topology.
6. String presence is supporting evidence, not proof of behavior.
7. Classify every conclusion as VERIFIED, INFERENCE, or UNKNOWN.
8. Do not revisit solved lower-chain facts (`0x26020`, VaultKeeper OEM path, `KG_unlock`) unless a contradiction requires it.
9. Keep chat output short. Save verbose disassembly in a report file.
10. After a milestone, compactly update `PROJECT_STATE.md` and `NEXT_TASK.md`; do not append indefinitely.

Current focus should normally come from `NEXT_TASK.md`, not from this skill.
