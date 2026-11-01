"""Python port of the kernel LZ decompressor at VA 0x81496d48.

Calling convention: r0=src, r1=dst, r2=output size.
Token format (little-endian byte stream):
  c   = control byte
  cnt = (c & 3) or next byte if 0          -> literals copied = cnt - 1
  rlen= (c >> 4) or next byte if 0         -> match copies rlen + 2 bytes
  if rlen: d = next byte
           base = dst_pos - d - ((c & 0xc) << 6)   [when (c&0xc)!=0xc]
           base = dst_pos - d - (next << 8)        [when (c&0xc)==0xc]
Terminates when output reaches `size` bytes.
"""


def decomp(src, size, verbose=False):
    out = bytearray()
    si = 0
    c = src[si]; si += 1
    while len(out) < size:
        r4 = c & 3
        if r4 == 0:
            r4 = src[si]; si += 1
        r5 = c >> 4
        if r5 == 0:
            r5 = src[si]; si += 1
        n = r4 - 1                      # literal count
        if n:
            if n < 0:
                raise ValueError("negative literal count (r4=%d) at out=%#x"
                                 % (r4, len(out)))
            out += src[si:si + n]; si += n
        if r5:
            d = src[si]; si += 1
            if (c & 0xC) == 0xC:
                ext = src[si]; si += 1
                base = len(out) - d - (ext << 8)
            else:
                base = len(out) - d - ((c & 0xC) << 6)
            if base < 0:
                raise ValueError("match before start (base=%d) at out=%#x"
                                 % (base, len(out)))
            m = r5 + 2                  # match copies rlen+2 bytes
            for _ in range(m):
                out.append(out[base]); base += 1
        if len(out) < size:
            c = src[si]; si += 1
    return bytes(out[:size]), si


if __name__ == "__main__":
    import sys
    ker = open(sys.argv[1], "rb").read()
    live = open(sys.argv[2], "rb").read()
    off = int(sys.argv[3], 0)
    size = len(live)
    try:
        got, consumed = decomp(ker[off:], size)
        same = sum(1 for a, b in zip(got, live) if a == b)
        print("decomp from file %#x: consumed %#x bytes, match %d/%d (%.2f%%)"
              % (off, consumed, same, size, 100.0 * same / size))
        if same == size:
            print("EXACT MATCH")
        else:
            for i, (a, b) in enumerate(zip(got, live)):
                if a != b:
                    print("first diff at %#x: got %02x want %02x" % (i, a, b))
                    print("got : %s" % got[max(0, i - 16):i + 16].hex())
                    print("live: %s" % live[max(0, i - 16):i + 16].hex())
                    break
    except Exception as e:
        print("FAILED: %s" % e)
