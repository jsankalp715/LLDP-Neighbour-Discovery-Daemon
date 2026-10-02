#!/usr/bin/env python3
"""
inject_lldp.py - send hand-crafted (mostly malformed) LLDP frames onto an
interface, to check that a running lldpnd rejects each one for the right
reason. Used by testbed.sh. Needs CAP_NET_RAW.

    inject_lldp.py <ifname> <src-mac>

Prints one line per frame: "<expected daemon log substring>".
"""
import socket
import struct
import sys
import time

DST = bytes.fromhex("0180c200000e")
ETYPE = b"\x88\xcc"


def tlv(t, v, length=None):
    """TLV header (8.4): 7-bit type, 9-bit length; length may lie."""
    n = len(v) if length is None else length
    return struct.pack("!H", (t << 9) | n) + v


def chassis(mac):
    return tlv(1, b"\x04" + mac)


def port(name=b"inj0"):
    return tlv(2, b"\x05" + name)


def ttl(s):
    return tlv(3, struct.pack("!H", s))


END = tlv(0, b"")


def main():
    ifname, src = sys.argv[1], bytes.fromhex(sys.argv[2].replace(":", ""))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((ifname, 0))

    # (expected log text, LLDPDU)
    cases = [
        ("truncated TLV / length exceeds frame",
         chassis(src) + port() + tlv(3, b"\x00\x78", length=200)),
        ("third TLV is not TTL",
         chassis(src) + port() + tlv(5, b"no-ttl") + END),
        ("first TLV is not Chassis ID",
         port() + chassis(src) + ttl(120) + END),
        ("second TLV is not Port ID",
         chassis(src) + ttl(120) + port() + END),
        ("End Of LLDPDU TLV with nonzero length",
         chassis(src) + port() + ttl(120) + tlv(0, b"xx")),
        ("invalid Chassis ID TLV",
         tlv(1, b"\x04" + src[:5]) + port() + ttl(120) + END),
        ("invalid TTL TLV length",
         chassis(src) + port() + tlv(3, b"\x00\x00\x78") + END),
        ("single-instance optional TLV repeated",
         chassis(src) + port() + ttl(120) + tlv(5, b"a") + tlv(5, b"b") + END),
        ("optional TLV has invalid length",
         chassis(src) + port() + ttl(120) + tlv(6, b"D" * 300) + END),
        ("mandatory TLV repeated",
         chassis(src) + port() + ttl(120) + chassis(src) + END),
        # a VALID frame with unknown + org-specific TLVs: must be accepted
        ("NEIGHBOUR ADD chassis=" + src.hex(":") + " port=inj0(st5) name=injected",
         chassis(src) + port() + ttl(120) + tlv(42, b"reserved-type")
         + tlv(127, b"\x00\x80\xc2\x01\x00\x01") + tlv(5, b"injected") + END),
        # ... and its shutdown LLDPDU must delete it again
        ("NEIGHBOUR DELETE chassis=" + src.hex(":") + " port=inj0(st5)",
         chassis(src) + port() + ttl(0) + END),
    ]
    for expect, pdu in cases:
        frame = DST + src + ETYPE + pdu
        frame += b"\x00" * max(0, 60 - len(frame))
        s.send(frame)
        print(expect)
        time.sleep(0.05)


if __name__ == "__main__":
    main()
