#!/usr/bin/env python3
"""Convert ECDSA signatures between ASN.1 DER (OpenSSL) and JWS R||S form (RFC 7518 section 3.4).

Usage: ecdsa_jws.py {der-to-jose|jose-to-der} {ES256|ES384} < input > output
"""

import sys

COMPONENT_WIDTH = {"ES256": 32, "ES384": 48}


def component_width(alg):
    if alg not in COMPONENT_WIDTH:
        raise ValueError(f"unsupported ECDSA JWT alg: {alg}")
    return COMPONENT_WIDTH[alg]


def _read_tlv(data, tag):
    if len(data) < 2 or data[0] != tag or data[1] >= 0x80 or len(data) < 2 + data[1]:
        raise ValueError(f"malformed DER element (expected tag {tag:#04x})")
    end = 2 + data[1]
    return data[2:end], data[end:]


def _der_uint_to_fixed(value, width):
    if not value:
        raise ValueError("empty DER INTEGER")
    if value[0] & 0x80:
        raise ValueError("negative DER INTEGER")
    if value[0] == 0:
        if len(value) == 1:
            raise ValueError("zero ECDSA signature component")
        if not value[1] & 0x80:
            raise ValueError("non-minimal DER INTEGER")
        value = value[1:]
    if len(value) > width:
        raise ValueError(f"ECDSA signature component wider than {width} bytes")
    return value.rjust(width, b"\x00")


def _fixed_to_der_uint(component):
    magnitude = component.lstrip(b"\x00")
    if not magnitude:
        raise ValueError("zero ECDSA signature component")
    if magnitude[0] & 0x80:
        magnitude = b"\x00" + magnitude
    return bytes([0x02, len(magnitude)]) + magnitude


def der_to_jose(der, alg):
    width = component_width(alg)
    seq, trailing = _read_tlv(der, 0x30)
    if trailing:
        raise ValueError("trailing bytes after DER ECDSA signature")
    r, rest = _read_tlv(seq, 0x02)
    s, rest = _read_tlv(rest, 0x02)
    if rest:
        raise ValueError("unexpected extra elements in DER ECDSA signature")
    return _der_uint_to_fixed(r, width) + _der_uint_to_fixed(s, width)


def jose_to_der(jose, alg):
    width = component_width(alg)
    if len(jose) != 2 * width:
        raise ValueError(f"{alg} signature must be {2 * width} bytes, got {len(jose)}")
    body = _fixed_to_der_uint(jose[:width]) + _fixed_to_der_uint(jose[width:])
    return bytes([0x30, len(body)]) + body


def main(argv):
    if len(argv) != 3 or argv[1] not in ("der-to-jose", "jose-to-der"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    convert = der_to_jose if argv[1] == "der-to-jose" else jose_to_der
    try:
        sys.stdout.buffer.write(convert(sys.stdin.buffer.read(), argv[2]))
    except ValueError as e:
        print(f"ecdsa_jws: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
