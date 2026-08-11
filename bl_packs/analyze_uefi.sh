#!/bin/bash

set -u

OLD="CXDF/abl.elf"
NEW="EZB6/abl.elf"

OUT="$(pwd)/uefi_abl_compare"
TOOLS="$OUT/tools"

mkdir -p "$OUT" "$TOOLS"

echo "============================================================"
echo " Samsung ABL / UEFI Firmware Volume Analyzer"
echo "============================================================"
echo

# ------------------------------------------------------------
# 0. Input validation
# ------------------------------------------------------------

for f in "$OLD" "$NEW"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Missing: $f"
        exit 1
    fi
done

OLD_ABS="$(cd "$(dirname "$OLD")" && pwd)/$(basename "$OLD")"
NEW_ABS="$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")"

OLD_FV="$OUT/CXDF_abl_fv.bin"
NEW_FV="$OUT/EZB6_abl_fv.bin"

# ------------------------------------------------------------
# 1. Parse ELF + Firmware Volume automatically
# ------------------------------------------------------------

echo "=== [1] ELF / FV STRUCTURE ==="

python3 - "$OLD_ABS" "$NEW_ABS" "$OLD_FV" "$NEW_FV" <<'PY'
import sys
import os
import struct
import uuid
import hashlib

old_path, new_path, old_out, new_out = sys.argv[1:]

def parse(path, output):

    print()
    print("FILE:", path)

    with open(path, "rb") as f:
        data = f.read()

    if data[:4] != b"\x7fELF":
        raise RuntimeError("Not ELF")

    if data[4] != 1:
        raise RuntimeError("Expected ELF32")

    endian = "<" if data[5] == 1 else ">"

    # ELF32 header
    e_entry     = struct.unpack_from(endian+"I", data, 0x18)[0]
    e_phoff     = struct.unpack_from(endian+"I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from(endian+"H", data, 0x2A)[0]
    e_phnum     = struct.unpack_from(endian+"H", data, 0x2C)[0]

    print(f"ELF entry       : 0x{e_entry:08X}")
    print(f"Program headers : {e_phnum}")
    print()

    for i in range(e_phnum):

        off = e_phoff + i * e_phentsize

        (
            p_type,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_flags,
            p_align
        ) = struct.unpack_from(endian+"IIIIIIII", data, off)

        print(
            f"PHDR {i}: "
            f"type=0x{p_type:X} "
            f"offset=0x{p_offset:X} "
            f"vaddr=0x{p_vaddr:X} "
            f"filesz=0x{p_filesz:X} "
            f"memsz=0x{p_memsz:X} "
            f"flags=0x{p_flags:X} "
            f"align=0x{p_align:X}"
        )

    # Find all _FVH signatures
    positions = []

    start = 0

    while True:

        pos = data.find(b"_FVH", start)

        if pos == -1:
            break

        positions.append(pos)
        start = pos + 1

    print()
    print("_FVH signatures :", len(positions))

    for sig in positions:

        # EFI_FIRMWARE_VOLUME_HEADER:
        # signature sits 0x28 bytes after FV start
        fv_start = sig - 0x28

        if fv_start < 0:
            continue

        fs_guid_raw = data[fv_start+0x10:fv_start+0x20]

        # EFI GUID uses mixed-endian representation
        d1, d2, d3 = struct.unpack_from("<IHH", fs_guid_raw)

        d4 = fs_guid_raw[8:]

        guid = (
            f"{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[0]:02X}{d4[1]:02X}-"
            + "".join(f"{x:02X}" for x in d4[2:])
        )

        fv_length = struct.unpack_from(
            "<Q", data, fv_start + 0x20
        )[0]

        attrs = struct.unpack_from(
            "<I", data, fv_start + 0x2C
        )[0]

        hdr_len = struct.unpack_from(
            "<H", data, fv_start + 0x30
        )[0]

        ext_off = struct.unpack_from(
            "<H", data, fv_start + 0x34
        )[0]

        revision = data[fv_start + 0x37]

        fv_end = fv_start + fv_length

        print()
        print(f"FV start        : 0x{fv_start:X}")
        print(f"FV signature    : 0x{sig:X}")
        print(f"Filesystem GUID : {guid}")
        print(f"FV length       : 0x{fv_length:X} ({fv_length} bytes)")
        print(f"FV end          : 0x{fv_end:X}")
        print(f"Header length   : 0x{hdr_len:X}")
        print(f"Attributes      : 0x{attrs:X}")
        print(f"Ext header      : 0x{ext_off:X}")
        print(f"Revision        : {revision}")

        if fv_end > len(data):
            print("[ERROR] FV exceeds file")
            continue

        blob = data[fv_start:fv_end]

        with open(output, "wb") as f:
            f.write(blob)

        sha = hashlib.sha256(blob).hexdigest()

        print(f"Extracted       : {output}")
        print(f"FV SHA256       : {sha}")

        # We only expect one primary FV here
        break


parse(old_path, old_out)
parse(new_path, new_out)

PY

if [ ! -f "$OLD_FV" ] || [ ! -f "$NEW_FV" ]; then
    echo
    echo "[ERROR] Firmware Volume extraction failed."
    exit 1
fi

echo

# ------------------------------------------------------------
# 2. Locate or build UEFIExtract
# ------------------------------------------------------------

echo "=== [2] UEFIEXTRACT SETUP ==="

UEFIEXTRACT=""

if command -v uefiextract >/dev/null 2>&1; then

    UEFIEXTRACT="$(command -v uefiextract)"
    echo "Existing UEFIExtract: $UEFIEXTRACT"

else

    SRC="$TOOLS/UEFITool"
    BUILD="$SRC/build-uefiextract"

    if [ ! -d "$SRC/.git" ]; then

        echo "UEFIExtract not installed."
        echo "Cloning official UEFITool repository..."

        if ! command -v git >/dev/null 2>&1; then
            echo "[ERROR] git not available"
            exit 1
        fi

        git clone \
            --depth 1 \
            https://github.com/LongSoft/UEFITool.git \
            "$SRC"

        if [ $? -ne 0 ]; then
            echo "[ERROR] Git clone failed"
            exit 1
        fi

    else

        echo "Existing UEFITool source found."

    fi

    if ! command -v cmake >/dev/null 2>&1; then

        echo "cmake not installed."

        if command -v brew >/dev/null 2>&1; then

            echo "Installing cmake using Homebrew..."
            brew install cmake

        else

            echo "[ERROR] cmake missing and Homebrew not available."
            exit 1

        fi

    fi

    echo "Building UEFIExtract..."

    rm -rf "$BUILD"

    cmake \
        -S "$SRC/UEFIExtract" \
        -B "$BUILD" \
        -DCMAKE_BUILD_TYPE=Release

    if [ $? -ne 0 ]; then
        echo "[ERROR] CMake configuration failed"
        exit 1
    fi

    cmake --build "$BUILD" --parallel

    if [ $? -ne 0 ]; then
        echo "[ERROR] UEFIExtract build failed"
        exit 1
    fi

    if [ -x "$BUILD/uefiextract" ]; then
        UEFIEXTRACT="$BUILD/uefiextract"
    elif [ -x "$BUILD/UEFIExtract" ]; then
        UEFIEXTRACT="$BUILD/UEFIExtract"
    else
        echo "[ERROR] Built executable not found."
        exit 1
    fi

fi

echo
echo "Using:"
echo "$UEFIEXTRACT"
echo

"$UEFIEXTRACT" --version 2>/dev/null || true

echo

# ------------------------------------------------------------
# 3. Clean previous extraction
# ------------------------------------------------------------

rm -rf \
    "$OLD_FV.dump" \
    "$NEW_FV.dump"

rm -f \
    "$OLD_FV.report.txt" \
    "$NEW_FV.report.txt" \
    "$OLD_FV.guids.csv" \
    "$NEW_FV.guids.csv"

# ------------------------------------------------------------
# 4. Extract complete UEFI trees
# ------------------------------------------------------------

echo "=== [3] EXTRACTING CXDF FIRMWARE TREE ==="

"$UEFIEXTRACT" "$OLD_FV" all

OLD_RESULT=$?

echo
echo "CXDF UEFIExtract exit code: $OLD_RESULT"
echo

echo "=== [4] EXTRACTING EZB6 FIRMWARE TREE ==="

"$UEFIEXTRACT" "$NEW_FV" all

NEW_RESULT=$?

echo
echo "EZB6 UEFIExtract exit code: $NEW_RESULT"
echo

# ------------------------------------------------------------
# 5. Report existence
# ------------------------------------------------------------

echo "=== [5] EXTRACTION RESULTS ==="

for path in \
    "$OLD_FV.dump" \
    "$NEW_FV.dump" \
    "$OLD_FV.report.txt" \
    "$NEW_FV.report.txt"
do

    if [ -e "$path" ]; then
        echo "[OK] $path"
    else
        echo "[MISSING] $path"
    fi

done

echo

# ------------------------------------------------------------
# 6. Compare UEFIExtract reports
# ------------------------------------------------------------

echo "=== [6] UEFI TREE REPORT DIFF ==="

REPORT_DIFF="$OUT/uefi_report.diff"

if [ -f "$OLD_FV.report.txt" ] && \
   [ -f "$NEW_FV.report.txt" ]; then

    diff -u \
        "$OLD_FV.report.txt" \
        "$NEW_FV.report.txt" \
        > "$REPORT_DIFF" || true

    echo "Total report diff lines:"
    wc -l "$REPORT_DIFF"

    echo
    echo "--- First 300 report differences ---"

    head -n 300 "$REPORT_DIFF"

else

    echo "UEFIExtract reports unavailable."

fi

echo

# ------------------------------------------------------------
# 7. Compare recursively extracted modules
# ------------------------------------------------------------

echo "=== [7] MODULE-LEVEL HASH COMPARISON ==="

python3 - \
    "$OLD_FV.dump" \
    "$NEW_FV.dump" \
    "$OUT/module_comparison.txt" <<'PY'

import os
import sys
import hashlib

old_root, new_root, output = sys.argv[1:]

def files(root):

    result = {}

    if not os.path.isdir(root):
        return result

    for base, dirs, names in os.walk(root):

        for name in names:

            path = os.path.join(base, name)
            rel  = os.path.relpath(path, root)

            try:

                with open(path, "rb") as f:
                    blob = f.read()

            except Exception:
                continue

            result[rel] = {
                "path": path,
                "size": len(blob),
                "sha": hashlib.sha256(blob).hexdigest()
            }

    return result


old = files(old_root)
new = files(new_root)

old_keys = set(old)
new_keys = set(new)

common = old_keys & new_keys
only_old = old_keys - new_keys
only_new = new_keys - old_keys

same = []
changed = []

for key in sorted(common):

    if old[key]["sha"] == new[key]["sha"]:
        same.append(key)
    else:
        changed.append(key)


lines = []

lines.append(f"OLD extracted files : {len(old)}")
lines.append(f"NEW extracted files : {len(new)}")
lines.append(f"Common paths        : {len(common)}")
lines.append(f"Identical files     : {len(same)}")
lines.append(f"Changed files       : {len(changed)}")
lines.append(f"Only OLD            : {len(only_old)}")
lines.append(f"Only NEW            : {len(only_new)}")
lines.append("")

lines.append("========== CHANGED FILES ==========")

for key in changed:

    lines.append("")
    lines.append(key)
    lines.append(
        f"  OLD: {old[key]['size']} bytes "
        f"{old[key]['sha']}"
    )
    lines.append(
        f"  NEW: {new[key]['size']} bytes "
        f"{new[key]['sha']}"
    )


lines.append("")
lines.append("========== ONLY OLD ==========")

for key in sorted(only_old):
    lines.append(key)


lines.append("")
lines.append("========== ONLY NEW ==========")

for key in sorted(only_new):
    lines.append(key)


text = "\n".join(lines)

print(text)

with open(output, "w") as f:
    f.write(text)

PY

echo

# ------------------------------------------------------------
# 8. Identify executable-looking extracted modules
# ------------------------------------------------------------

echo "=== [8] EXECUTABLE MODULES ==="

EXEC_REPORT="$OUT/executable_modules.txt"

: > "$EXEC_REPORT"

for ROOT in "$OLD_FV.dump" "$NEW_FV.dump"; do

    echo >> "$EXEC_REPORT"
    echo "===== $ROOT =====" >> "$EXEC_REPORT"

    if [ ! -d "$ROOT" ]; then
        continue
    fi

    while IFS= read -r -d '' f; do

        INFO="$(file "$f")"

        if echo "$INFO" | grep -qiE \
            'PE32|PE32\+|EFI|ARM|executable|TE image'; then

            echo "$INFO" >> "$EXEC_REPORT"

        fi

    done < <(find "$ROOT" -type f -print0)

done

cat "$EXEC_REPORT"

echo

# ------------------------------------------------------------
# 9. Search meaningful strings in extracted modules
# ------------------------------------------------------------

echo "=== [9] BOOTLOADER / UNLOCK KEYWORD SEARCH ==="

KEYWORD_REPORT="$OUT/keyword_hits.txt"

: > "$KEYWORD_REPORT"

for ROOT in "$OLD_FV.dump" "$NEW_FV.dump"; do

    echo >> "$KEYWORD_REPORT"
    echo "==================================================" \
        >> "$KEYWORD_REPORT"
    echo "$ROOT" >> "$KEYWORD_REPORT"
    echo "==================================================" \
        >> "$KEYWORD_REPORT"

    if [ ! -d "$ROOT" ]; then
        continue
    fi

    while IFS= read -r -d '' f; do

        HIT="$(
            strings -a -n 6 "$f" 2>/dev/null |
            grep -iE \
            'unlock|bootloader|oem unlock|device.?state|flash.?lock|fastboot|vaultkeeper|verified.?boot|vbmeta|secure.?boot|warranty|knox|download.?mode' |
            head -n 40
        )"

        if [ -n "$HIT" ]; then

            echo >> "$KEYWORD_REPORT"
            echo "--- $f ---" >> "$KEYWORD_REPORT"
            echo "$HIT" >> "$KEYWORD_REPORT"

        fi

    done < <(find "$ROOT" -type f -print0)

done

cat "$KEYWORD_REPORT"

echo

# ------------------------------------------------------------
# 10. Summary
# ------------------------------------------------------------

echo "============================================================"
echo " ANALYSIS COMPLETE"
echo "============================================================"

echo
echo "Important output files:"
echo
echo "  $OUT/module_comparison.txt"
echo "  $OUT/uefi_report.diff"
echo "  $OUT/executable_modules.txt"
echo "  $OUT/keyword_hits.txt"
echo
echo "Extracted firmware volumes:"
echo
echo "  $OLD_FV"
echo "  $NEW_FV"
echo
echo "UEFI trees:"
echo
echo "  $OLD_FV.dump"
echo "  $NEW_FV.dump"
echo
echo "============================================================"
