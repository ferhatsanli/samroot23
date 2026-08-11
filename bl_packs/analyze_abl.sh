#!/bin/bash

set -u

OLD="CXDF/abl.elf"
NEW="EZB6/abl.elf"
OUT="abl_analysis"

mkdir -p "$OUT"

echo "=================================================="
echo " Samsung ABL focused binary analysis"
echo " OLD: $OLD"
echo " NEW: $NEW"
echo "=================================================="
echo

for f in "$OLD" "$NEW"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Missing file: $f"
        exit 1
    fi
done

echo "[1] Basic ELF information"
echo "-------------------------"
file "$OLD"
file "$NEW"
echo

# --------------------------------------------------
# Find objdump
# --------------------------------------------------

OBJDUMP=""

if command -v gobjdump >/dev/null 2>&1; then
    OBJDUMP="gobjdump"
elif command -v objdump >/dev/null 2>&1; then
    OBJDUMP="objdump"
fi

echo "[2] Tool detection"
echo "------------------"
echo "objdump: ${OBJDUMP:-NOT FOUND}"
echo "python3: $(command -v python3 || echo NOT_FOUND)"
echo

# --------------------------------------------------
# Python binary-range analysis
# --------------------------------------------------

echo "[3] Locating changed regions"
echo "----------------------------"

python3 - "$OLD" "$NEW" "$OUT" <<'PY'
import sys
import os
import hashlib

old_path, new_path, outdir = sys.argv[1:4]

with open(old_path, "rb") as f:
    old = f.read()

with open(new_path, "rb") as f:
    new = f.read()

size = min(len(old), len(new))

BASE = 0x9FA00000
BLOCK = 4096

changed = []

for off in range(0, size, BLOCK):
    a = old[off:off+BLOCK]
    b = new[off:off+BLOCK]

    if a != b:
        count = sum(x != y for x, y in zip(a, b))
        changed.append((off, min(off+BLOCK, size), count))

print(f"Image size      : {size} bytes")
print(f"Changed blocks  : {len(changed)}")
print()

# Merge adjacent changed blocks
regions = []

for start, end, diffcount in changed:
    if not regions:
        regions.append([start, end, diffcount])
        continue

    prev = regions[-1]

    if start == prev[1]:
        prev[1] = end
        prev[2] += diffcount
    else:
        regions.append([start, end, diffcount])

print(f"Merged regions  : {len(regions)}")
print()

region_file = os.path.join(outdir, "changed_regions.txt")

with open(region_file, "w") as f:

    for i, (start, end, diffcount) in enumerate(regions, 1):

        length = end - start

        va_start = BASE + start
        va_end   = BASE + end

        pct = (diffcount / length) * 100

        line = (
            f"REGION {i:03d} "
            f"FILE=0x{start:08X}-0x{end:08X} "
            f"VA=0x{va_start:08X}-0x{va_end:08X} "
            f"SIZE={length} "
            f"DIFF={diffcount} "
            f"RATE={pct:.2f}%"
        )

        print(line)
        f.write(line + "\n")

print()
print("Top regions by number of differing bytes:")
print()

top = sorted(
    enumerate(regions, 1),
    key=lambda x: x[1][2],
    reverse=True
)[:20]

for idx, (start, end, diffcount) in top:

    length = end-start
    pct = diffcount / length * 100

    print(
        f"REGION {idx:03d}: "
        f"offset 0x{start:08X}-0x{end:08X} "
        f"VA 0x{BASE+start:08X} "
        f"diff={diffcount}/{length} "
        f"({pct:.2f}%)"
    )


# --------------------------------------------------
# Fine-grained ranges
# --------------------------------------------------

fine_ranges = []

inside = False
start = None
last = None

for i in range(size):

    different = old[i] != new[i]

    if different and not inside:
        start = i
        inside = True

    if different:
        last = i

    if inside and not different:

        # merge tiny equal gaps <= 16 bytes
        gap_start = i
        j = i

        while j < size and old[j] == new[j] and j-gap_start <= 16:
            j += 1

        if j < size and old[j] != new[j] and j-gap_start <= 16:
            continue

        fine_ranges.append((start, last+1))
        inside = False


if inside:
    fine_ranges.append((start, last+1))


with open(os.path.join(outdir, "fine_ranges.txt"), "w") as f:

    for start, end in fine_ranges:

        f.write(
            f"0x{start:08X}-0x{end:08X} "
            f"VA=0x{BASE+start:08X} "
            f"LEN={end-start}\n"
        )


# --------------------------------------------------
# Compare executable area separately
# ELF PT_LOAD from previous objdump:
# file offset 0x1000
# length      0x252000
# --------------------------------------------------

exec_start = 0x1000
exec_end   = exec_start + 0x252000

exec_old = old[exec_start:exec_end]
exec_new = new[exec_start:exec_end]

exec_diff = sum(a != b for a,b in zip(exec_old,exec_new))

print()
print("Executable PT_LOAD:")
print(
    f"  differing bytes: {exec_diff}/{len(exec_old)} "
    f"({exec_diff/len(exec_old)*100:.3f}%)"
)

# --------------------------------------------------
# Search printable strings near changed regions
# --------------------------------------------------

keywords = [
    b"unlock",
    b"lock",
    b"oem",
    b"flash",
    b"fastboot",
    b"secure",
    b"device",
    b"verified",
    b"vault",
    b"knox",
    b"warranty",
]

def printable_strings(blob, minimum=6):

    result = []
    current = bytearray()
    start = None

    for i,b in enumerate(blob):

        if 32 <= b <= 126:

            if start is None:
                start = i

            current.append(b)

        else:

            if len(current) >= minimum:
                result.append((start, bytes(current)))

            current = bytearray()
            start = None

    if len(current) >= minimum:
        result.append((start, bytes(current)))

    return result


print()
print("Keyword-like strings in OLD:")
for off,s in printable_strings(old):

    lower = s.lower()

    if any(k in lower for k in keywords):
        print(f"  0x{off:08X}: {s[:160].decode(errors='replace')}")


print()
print("Keyword-like strings in NEW:")
for off,s in printable_strings(new):

    lower = s.lower()

    if any(k in lower for k in keywords):
        print(f"  0x{off:08X}: {s[:160].decode(errors='replace')}")

PY

echo

# --------------------------------------------------
# Generate full disassembly
# --------------------------------------------------

if [ -n "$OBJDUMP" ]; then

    echo "[4] Generating ARM disassembly"
    echo "------------------------------"

    "$OBJDUMP" \
        -D \
        --architecture=arm \
        "$OLD" \
        > "$OUT/cxdf_disassembly.txt" 2>&1 || true

    "$OBJDUMP" \
        -D \
        --architecture=arm \
        "$NEW" \
        > "$OUT/ezb6_disassembly.txt" 2>&1 || true

    echo "CXDF disassembly:"
    wc -l "$OUT/cxdf_disassembly.txt"

    echo "EZB6 disassembly:"
    wc -l "$OUT/ezb6_disassembly.txt"

    echo

    echo "[5] Disassembly diff statistics"
    echo "--------------------------------"

    diff \
        -u \
        "$OUT/cxdf_disassembly.txt" \
        "$OUT/ezb6_disassembly.txt" \
        > "$OUT/disassembly.diff" || true

    echo "Diff lines:"
    wc -l "$OUT/disassembly.diff"

    echo

    echo "First meaningful disassembly differences:"
    echo

    grep -E '^[+-][[:space:]]*[0-9a-f]+:' \
        "$OUT/disassembly.diff" \
        | head -n 120 || true

else

    echo "[WARNING]"
    echo "No usable objdump detected."
    echo "Binary range analysis completed anyway."

fi


# --------------------------------------------------
# Hex dumps around first changed area
# --------------------------------------------------

echo
echo "[6] First changed region context"
echo "--------------------------------"

FIRST_OFFSET=$(
    cmp -l "$OLD" "$NEW" 2>/dev/null \
    | head -1 \
    | awk '{print $1}'
)

if [ -n "${FIRST_OFFSET:-}" ]; then

    # cmp offsets are 1-based
    FIRST_OFFSET=$((FIRST_OFFSET - 1))

    START=$((FIRST_OFFSET - 128))

    if [ "$START" -lt 0 ]; then
        START=0
    fi

    echo "First difference offset: $(printf '0x%X' "$FIRST_OFFSET")"
    echo

    echo "--- CXDF ---"

    xxd \
        -s "$START" \
        -l 512 \
        "$OLD"

    echo
    echo "--- EZB6 ---"

    xxd \
        -s "$START" \
        -l 512 \
        "$NEW"

fi


echo
echo "=================================================="
echo " SUMMARY FILES"
echo "=================================================="

ls -lh "$OUT"

echo
echo "Most useful report for next step:"
echo
echo "    $OUT/changed_regions.txt"
echo
echo "Also useful:"
echo
echo "    $OUT/disassembly.diff"
echo
echo "=================================================="
