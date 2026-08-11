#!/bin/bash

set -u

CXDF="CXDF/abl.elf"
EZB6="EZB6/abl.elf"

echo "========================================"
echo " Samsung ABL comparison report"
echo "========================================"
echo

# ---------- basic checks ----------
for f in "$CXDF" "$EZB6"; do
  if [ ! -f "$f" ]; then
    echo "[ERROR] File not found: $f"
    exit 1
  fi
done

echo "=== BASIC FILE INFO ==="
file "$CXDF"
file "$EZB6"
echo

echo "=== SIZE ==="
stat -f '%N : %z bytes' "$CXDF" "$EZB6"
echo

echo "=== SHA-256 ==="
shasum -a 256 "$CXDF" "$EZB6"
echo

echo "=== BINARY EQUALITY ==="
if cmp -s "$CXDF" "$EZB6"; then
  echo "Files are byte-for-byte IDENTICAL"
else
  echo "Files are DIFFERENT"
fi
echo

# ---------- first differing byte ----------
echo "=== FIRST BINARY DIFFERENCE ==="
cmp -l "$CXDF" "$EZB6" 2>/dev/null | head -n 10 || true
echo

# ---------- tool detection ----------
READELF=""
OBJDUMP=""

if command -v greadelf >/dev/null 2>&1; then
  READELF="greadelf"
elif command -v readelf >/dev/null 2>&1; then
  READELF="readelf"
fi

if command -v gobjdump >/dev/null 2>&1; then
  OBJDUMP="gobjdump"
elif command -v objdump >/dev/null 2>&1; then
  OBJDUMP="objdump"
fi

echo "=== TOOL DETECTION ==="
echo "readelf tool : ${READELF:-NOT FOUND}"
echo "objdump tool : ${OBJDUMP:-NOT FOUND}"
echo "otool        : $(command -v otool 2>/dev/null || echo NOT_FOUND)"
echo
echo

# ---------- ELF headers ----------
if [ -n "$READELF" ]; then
  echo "=== CXDF ELF HEADER ==="
  "$READELF" -h "$CXDF" 2>&1
  echo

  echo "=== EZB6 ELF HEADER ==="
  "$READELF" -h "$EZB6" 2>&1
  echo

  echo "=== ELF HEADER DIFF ==="
  "$READELF" -h "$CXDF" > /tmp/cxdf_hdr.txt 2>&1
  "$READELF" -h "$EZB6" > /tmp/ezb6_hdr.txt 2>&1
  diff -u /tmp/cxdf_hdr.txt /tmp/ezb6_hdr.txt || true
  echo

  echo "=== SECTION TABLE DIFF ==="
  "$READELF" -S "$CXDF" > /tmp/cxdf_sections.txt 2>&1
  "$READELF" -S "$EZB6" > /tmp/ezb6_sections.txt 2>&1
  diff -u /tmp/cxdf_sections.txt /tmp/ezb6_sections.txt || true
  echo

  echo "=== PROGRAM HEADER DIFF ==="
  "$READELF" -l "$CXDF" > /tmp/cxdf_program.txt 2>&1
  "$READELF" -l "$EZB6" > /tmp/ezb6_program.txt 2>&1
  diff -u /tmp/cxdf_program.txt /tmp/ezb6_program.txt || true
  echo
else
  echo "=== ELF ANALYSIS ==="
  echo "No readelf/greadelf found."
  echo "Skipping ELF header/section analysis."
  echo
fi

# ---------- strings ----------
echo "=== INTERESTING STRINGS: CXDF ==="
strings -a "$CXDF" |
grep -iE 'unlock|locked|lock|oem|flash|fastboot|vault|knox|kg|verified|vbmeta|device.state|bootloader|secure|warranty|download' |
sort -u |
head -n 200
echo

echo "=== INTERESTING STRINGS: EZB6 ==="
strings -a "$EZB6" |
grep -iE 'unlock|locked|lock|oem|flash|fastboot|vault|knox|kg|verified|vbmeta|device.state|bootloader|secure|warranty|download' |
sort -u |
head -n 200
echo

echo "=== UNIQUE INTERESTING STRING DIFFERENCES ==="
strings -a "$CXDF" | sort -u > /tmp/cxdf_strings.txt
strings -a "$EZB6" | sort -u > /tmp/ezb6_strings.txt

diff -u /tmp/cxdf_strings.txt /tmp/ezb6_strings.txt |
grep -iE '^[+-].*(unlock|locked|lock|oem|flash|fastboot|vault|knox|kg|verified|vbmeta|device.state|bootloader|secure|warranty|download)' |
head -n 300 || true
echo

# ---------- section hashes ----------
if [ -n "$OBJDUMP" ]; then
  echo "=== OBJDUMP SECTION HEADERS: CXDF ==="
  "$OBJDUMP" -h "$CXDF" 2>&1 | head -n 120
  echo

  echo "=== OBJDUMP SECTION HEADERS: EZB6 ==="
  "$OBJDUMP" -h "$EZB6" 2>&1 | head -n 120
  echo

  echo "=== OBJDUMP SECTION HEADER DIFF ==="
  "$OBJDUMP" -h "$CXDF" > /tmp/cxdf_objdump_sections.txt 2>&1
  "$OBJDUMP" -h "$EZB6" > /tmp/ezb6_objdump_sections.txt 2>&1
  diff -u /tmp/cxdf_objdump_sections.txt /tmp/ezb6_objdump_sections.txt || true
  echo
fi

# ---------- hex headers ----------
echo "=== FIRST 256 BYTES: CXDF ==="
xxd -l 256 "$CXDF"
echo

echo "=== FIRST 256 BYTES: EZB6 ==="
xxd -l 256 "$EZB6"
echo

echo "=== FIRST 256 BYTE DIFF ==="
xxd -l 256 "$CXDF" > /tmp/cxdf_hex.txt
xxd -l 256 "$EZB6" > /tmp/ezb6_hex.txt
diff -u /tmp/cxdf_hex.txt /tmp/ezb6_hex.txt || true
echo

# ---------- rough difference density ----------
echo "=== DIFFERENCE DENSITY SAMPLE ==="

python3 - "$CXDF" "$EZB6" <<'PY'
import sys

a_path, b_path = sys.argv[1], sys.argv[2]

with open(a_path, "rb") as f:
    a = f.read()

with open(b_path, "rb") as f:
    b = f.read()

size = min(len(a), len(b))
diffs = sum(x != y for x, y in zip(a[:size], b[:size]))

print(f"Compared bytes : {size}")
print(f"Differing bytes: {diffs}")
print(f"Difference rate: {(diffs / size * 100):.4f}%")

block = 4096
changed_blocks = 0
total_blocks = 0

for offset in range(0, size, block):
    aa = a[offset:offset+block]
    bb = b[offset:offset+block]

    total_blocks += 1

    if aa != bb:
        changed_blocks += 1

print(f"Changed 4K blocks: {changed_blocks}/{total_blocks}")
PY

echo
echo "========================================"
echo " END OF REPORT"
echo "========================================"
