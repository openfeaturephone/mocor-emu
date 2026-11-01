#!/usr/bin/env python3
"""Parse the Spreadtrum fixed-NV stream (nvcal partition) and the journal-record format
used in the RunningNV/ProtectNV copies. Written from the bytes of a real dump.

  python parse_nv.py firmware/nvcal.bin
  python parse_nv.py firmware/p_10000003.bin journal
"""
import struct, sys, json

def nv_checksum(data: bytes) -> int:
    total = 0
    for off in range(0, len(data) - 1, 2):
        total += data[off] | (data[off + 1] << 8)
    if len(data) % 2:
        total += data[-1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def parse_fixed_stream(data: bytes, verbose=True):
    """DownloadedNV style: u32 generation word, then sorted {u16 id,u16 len}+data
    padded to 4, until FFFF FFFF."""
    gen = struct.unpack_from("<I", data, 0)[0]
    cur = 4
    prev = 0
    recs = []
    term = None
    order_ok = True
    while cur + 4 <= len(data):
        rid, rlen = struct.unpack_from("<HH", data, cur)
        hdr_off = cur
        cur += 4
        if rid == 0xFFFF and rlen == 0xFFFF:
            term = hdr_off
            break
        if rid <= prev:
            order_ok = False
        prev = rid
        pad = (rlen + 3) & ~3
        if cur + pad > len(data):
            recs.append((rid, rlen, hdr_off, None, "TRUNCATED"))
            break
        recs.append((rid, rlen, hdr_off, data[cur:cur+rlen], "ok"))
        cur += pad
    if verbose:
        print(f"  generation word: {gen:#010x}; stream {'SORTED-OK' if order_ok else 'ORDER-BROKEN'}; "
              f"terminator at {term and hex(term)}; consumed to {hex(cur)} of {hex(len(data))}")
        for rid, rlen, off, payload, st in recs:
            print(f"  id={rid:5d} (0x{rid:04x}) len={rlen:5d} hdr@{off:#08x} {st}")
    return gen, recs, term, order_ok

def scan_journal_records(data: bytes):
    """Scan for 12-byte journal headers {u16 hdr_crc,u16 payload_crc,u16 id,u16 size,u32 state}
    followed by size payload bytes; validate both checksums."""
    out = {}  # id -> list of (off, size, hdr_ok, payload_ok, payload)
    n = len(data)
    for off in range(0, n - 12):
        hdr_crc, pay_crc, rid, rlen, state = struct.unpack_from("<HHHHI", data, off)
        if rid == 0 or rid == 0xFFFF or rlen == 0 or rlen > 0x2000:
            continue
        if off + 12 + rlen > n:
            continue
        hdr_ok = hdr_crc == nv_checksum(data[off+4:off+12])
        if not hdr_ok and (state & 1) != 1:
            # require either a valid header checksum or a plausible valid-state bit
            continue
        if not hdr_ok:
            continue
        payload = data[off+12:off+12+rlen]
        pay_ok = pay_crc == nv_checksum(payload)
        out.setdefault(rid, []).append((off, rlen, hdr_ok, pay_ok, payload))
    return out

if __name__ == "__main__":
    part = sys.argv[1] if len(sys.argv) > 1 else "firmware/nvcal.bin"
    data = open(part, "rb").read()
    print(f"== {part} ({len(data)} bytes)")
    if len(sys.argv) > 2 and sys.argv[2] == "journal":
        recs = scan_journal_records(data)
        for rid in sorted(recs):
            copies = recs[rid]
            pays = {c[4] for c in copies if c[3]}
            ok = sum(1 for c in copies if c[3])
            print(f"  id={rid:5d} (0x{rid:04x}) copies={len(copies)} cksum-valid={ok} "
                  f"distinct-valid-payloads={len(pays)} sizes={sorted({c[1] for c in copies})} "
                  f"offsets={[hex(c[0]) for c in copies[:6]]}{'...' if len(copies)>6 else ''}")
    else:
        parse_fixed_stream(data)
