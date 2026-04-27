#!/usr/bin/env python3
"""
Vietcong CBF Unpacker
=====================
Extracts files from Vietcong .CBF archives with full multi-chunk LZW support.

Based on cbfext.c + unlzw.c by Luigi Auriemma (GPLv2).

Usage:
    python cbf_unpacker.py <file.cbf> <output_dir>
    python cbf_unpacker.py <file.cbf> <output_dir> --filter .dds
    python cbf_unpacker.py <file.cbf> --list
"""

import struct
import os
import sys
import argparse
import time
from pathlib import Path

# ============================================================================
# Constants
# ============================================================================

VERSION = '1.0.0'

CBF_SIGNATURE = b'BIGF'
LZW_MAGIC = b'[..]'
TABLE_KEY = bytes([0x32, 0xf3, 0x1e, 0x06, 0x45, 0x70, 0x32, 0xaa,
                   0x55, 0x3f, 0xf1, 0xde, 0xa3, 0x44, 0x21, 0xb4])

# ============================================================================
# Decryption (from cbfext.c)
# ============================================================================

def cbf_head_dec(data: bytes, row_len: int) -> bytes:
    """Decrypt file table row using 16-byte rotating key."""
    result = bytearray(data)
    e = row_len & 0xFF
    for i in range(len(result)):
        t = result[i]
        result[i] = (t ^ TABLE_KEY[e & 15]) & 0xFF
        e = t
    return bytes(result)

def cbf_file_dec(data: bytes) -> bytes:
    """Decrypt uncompressed file data."""
    length = len(data)
    t1 = length & 0xFF
    t2 = (90 - t1) & 0xFF
    result = bytearray(data)
    for i in range(length):
        result[i] = ((result[i] - t2) ^ t1) & 0xFF
    return bytes(result)

# ============================================================================
# LZW Decompression — faithful port of unlzw.c by Luigi Auriemma
# ============================================================================

UNLZW_BITS = 9
UNLZW_END = 256

def unlzw(in_data: bytes, max_size: int) -> bytes:
    """Decompress a single LZW data block."""
    out = bytearray(max_size)
    dict_data = [None] * (1 << (UNLZW_BITS + 3))

    bits = UNLZW_BITS
    ibits = 0
    dictsize = UNLZW_END + 1
    dictoff = 0
    dictlen = 0
    inlen = 0
    outlen = 0
    insize = len(in_data)

    def init():
        nonlocal bits, ibits, dictsize, dictoff, dictlen, dict_data
        bits = UNLZW_BITS
        ibits = 0
        dictsize = UNLZW_END + 1
        dictoff = 0
        dictlen = 0
        needed = 1 << (UNLZW_BITS + 3)
        while len(dict_data) < needed:
            dict_data.append(None)
        for i in range(len(dict_data)):
            dict_data[i] = None

    def expand(code):
        nonlocal outlen
        if code >= dictsize:
            return 0
        if code >= UNLZW_END:
            entry = dict_data[code]
            if entry is None:
                return 0
            off, length = entry
            if (outlen + length) > max_size:
                return -1
            for i in range(length):
                out[outlen + i] = out[off + i]
            return length
        if (outlen + 1) > max_size:
            return -1
        out[outlen] = code
        return 1

    def dictionary():
        nonlocal dictlen, dictsize, bits, dict_data
        dictlen += 1
        if dictlen > 1:
            dl = dictlen
            if (dictoff + dl) > max_size:
                dl = max_size - dictoff
            dict_data[dictsize] = (dictoff, dl)
            dictsize += 1
            if (dictsize + 1) >> bits:
                bits += 1
                needed = 1 << bits
                while len(dict_data) < needed:
                    dict_data.append(None)

    init()

    while inlen < insize:
        code = in_data[inlen] if inlen < insize else 0
        if (insize - inlen) > 1:
            code |= in_data[inlen + 1] << 8
        if (insize - inlen) > 2:
            code |= in_data[inlen + 2] << 16
        code = (code >> ibits) & ((1 << bits) - 1)

        inlen += (bits + ibits) >> 3
        ibits = (bits + ibits) & 7

        if code == UNLZW_END:
            if ibits:
                inlen += 1
            init()
            continue

        if code == dictsize:
            dictionary()
            n = expand(code)
        else:
            n = expand(code)
            dictionary()

        if n is None or n < 0:
            break

        dictoff = outlen
        dictlen = n
        outlen += n

    return bytes(out[:outlen])

# ============================================================================
# CBF Parser
# ============================================================================

def parse_cbf(cbf_path, quiet=False):
    """Parse CBF archive file table. Returns list of entry dicts."""
    entries = []
    with open(cbf_path, 'rb') as f:
        sign = f.read(4)
        if sign != CBF_SIGNATURE:
            raise ValueError(f"Not a CBF archive: {sign!r}")

        f.seek(4)
        cbf_ver = struct.unpack('<B', f.read(1))[0]
        f.read(3 + 8)  # "ZBL" + fileSize + unknown
        file_num = struct.unpack('<I', f.read(4))[0]
        file_offset = struct.unpack('<I', f.read(4))[0]
        f.read(4)  # upper 32 bits of offset

        if not quiet:
            enc = "encrypted" if cbf_ver else "unencrypted"
            print(f"  Archive: {os.path.basename(cbf_path)}")
            print(f"  Version: ZBL{cbf_ver} ({enc})")
            print(f"  Files: {file_num}")

        for i in range(file_num):
            f.seek(file_offset)
            if cbf_ver:
                row_len = struct.unpack('<H', f.read(2))[0]
                file_offset += 2
            else:
                row_len = 40

            row_data = f.read(row_len)
            file_offset += row_len

            if cbf_ver:
                row_data = cbf_head_dec(row_data, row_len)

            data_offset = struct.unpack_from('<I', row_data, 0)[0]
            data_length = struct.unpack_from('<I', row_data, 20)[0]

            if cbf_ver:
                fname_raw = row_data[40:]
            else:
                fname_raw = row_data

            fname_end = fname_raw.find(b'\x00')
            fname = fname_raw[:fname_end].decode('ascii', errors='replace') if fname_end >= 0 else fname_raw.decode('ascii', errors='replace')

            if not cbf_ver:
                fname_bytes = bytearray()
                while True:
                    c = f.read(1)
                    if not c or c == b'\x00':
                        break
                    fname_bytes.extend(c)
                fname = fname_bytes.decode('ascii', errors='replace')
                file_offset += len(fname_bytes) + 1

            entries.append({
                'filename': fname.replace('\\', '/'),
                'offset': data_offset,
                'size': data_length,
            })

    if not quiet:
        print(f"  Parsed: {len(entries)} entries")
    return entries

# ============================================================================
# File extraction
# ============================================================================

def extract_file(f, offset, expected_size):
    """
    Extract a single file from CBF with multi-chunk LZW support.
    Returns (data_bytes, num_chunks).
    """
    f.seek(offset)
    sign = f.read(4)

    if sign == LZW_MAGIC:
        # LZW compressed — read ALL chunks
        f.seek(offset)
        output = bytearray()
        chunks = 0

        while True:
            chunk_header = f.read(12)
            if len(chunk_header) < 12:
                break
            if chunk_header[:4] != LZW_MAGIC:
                break

            zlen = struct.unpack_from('<I', chunk_header, 4)[0]
            ulen = struct.unpack_from('<I', chunk_header, 8)[0]

            compressed = f.read(zlen)
            decompressed = unlzw(compressed, ulen)
            output.extend(decompressed)
            chunks += 1

            if expected_size > 0 and len(output) >= expected_size:
                break

        return bytes(output), chunks
    else:
        # Uncompressed (possibly encrypted)
        f.seek(offset)
        data = f.read(expected_size)
        data = cbf_file_dec(data)
        return data, 0

# ============================================================================
# Main
# ============================================================================

def format_size(size):
    if size >= 1024 * 1024:
        return f"{size / (1024*1024):.1f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"

def main():
    parser = argparse.ArgumentParser(
        description='Vietcong CBF Unpacker — extracts files from .CBF archives',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s game.cbf output/              Extract all files
  %(prog)s game.cbf output/ --filter .dds   Extract only DDS textures
  %(prog)s game.cbf output/ --filter .bes   Extract only BES models
  %(prog)s game.cbf --list                  List files without extracting
        """)
    parser.add_argument('cbf', help='Input .CBF archive')
    parser.add_argument('output', nargs='?', default='.unpacked', help='Output directory (default: .unpacked)')
    parser.add_argument('--list', '-l', action='store_true', help='List files without extracting')
    parser.add_argument('--filter', '-f', default=None, help='Extract only files matching extension (e.g. .dds)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show each extracted file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    args = parser.parse_args()

    if not args.list and not args.output:
        parser.error("Output directory required (or use --list)")

    if not os.path.exists(args.cbf):
        print(f"Error: File not found: {args.cbf}")
        sys.exit(1)

    # Parse archive
    if not args.quiet:
        print(f"\nVietcong CBF Unpacker v{VERSION}")
        print(f"{'=' * 40}")
    entries = parse_cbf(args.cbf, quiet=args.quiet)

    # Filter
    if args.filter:
        ext = args.filter.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        entries = [e for e in entries if e['filename'].lower().endswith(ext)]
        if not args.quiet:
            print(f"  Filtered: {len(entries)} {ext} files")

    # List mode
    if args.list:
        print(f"\n  {'Size':>10}  Filename")
        print(f"  {'-'*10}  {'-'*60}")
        for e in entries:
            print(f"  {e['size']:>10}  {e['filename']}")
        print(f"\n  Total: {len(entries)} files")
        return

    # Extract
    output_dir = Path(args.output)
    if not args.quiet:
        print(f"\n  Extracting to: {output_dir}")
        print()

    extracted = 0
    lzw_count = 0
    errors = 0
    total_bytes = 0
    start_time = time.time()

    with open(args.cbf, 'rb') as cbf_f:
        for i, entry in enumerate(entries):
            out_path = output_dir / entry['filename'].replace('/', os.sep)

            try:
                # Zero-size entries are valid empty files (e.g. developer placeholders)
                if entry['size'] == 0:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_path, 'wb') as out_f:
                        pass
                    extracted += 1
                    continue

                data, chunks = extract_file(cbf_f, entry['offset'], entry['size'])

                if len(data) > 0:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_path, 'wb') as out_f:
                        out_f.write(data)
                    extracted += 1
                    total_bytes += len(data)
                    if chunks > 0:
                        lzw_count += 1

                    if args.verbose:
                        tag = f" ({chunks} chunks)" if chunks > 1 else ""
                        print(f"  {entry['filename']}{tag}")
                    elif not args.quiet and (extracted % 500 == 0):
                        print(f"  ... {extracted} files extracted")
                else:
                    errors += 1
                    if not args.quiet:
                        print(f"  EMPTY: {entry['filename']}")
            except Exception as e:
                errors += 1
                if not args.quiet:
                    print(f"  ERROR: {entry['filename']} — {e}")

    elapsed = time.time() - start_time

    if not args.quiet:
        print(f"\n{'=' * 40}")
        print(f"  Extracted: {extracted} files ({format_size(total_bytes)})")
        print(f"  LZW compressed: {lzw_count}")
        print(f"  Errors: {errors}")
        print(f"  Time: {elapsed:.1f}s")
        print()


if __name__ == '__main__':
    main()
