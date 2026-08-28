#!/usr/bin/env python3
"""mayhem/gen_pud_inputs.py -- regenerate wargus's hand-built .pud inputs (deterministic).

Not run by build.sh or test.sh: the generated files are committed. This script only documents,
byte for byte, how they were made, so a reviewer can re-derive them. Run from the repo root:

    python3 mayhem/gen_pud_inputs.py

A .pud map is a sequence of sections: 4-byte tag, 4-byte little-endian length, then `length`
body bytes. PudData::Parse (pud.cpp) needs a leading TYPE section whose body starts with
"WAR2 MAP\\0", then walks sections until it reaches the end of the buffer.

Every section below has the length doc/pud-specs.txt gives it: TYPE 16 ("WAR2 MAP\\0" + a 7-byte
id tag -- byte-for-byte the layout of farscape2006.pud and of every map under maps/), VER 2,
DESC 32, OWNR/SIDE/AIPL 16, SGLD/SLBR/SOIL 32, ERA 2, DIM 4, MTXM/SQM/REGM 2*X*Y, OILM X*Y,
UNIT 8*n. Player-slot values follow the spec too (unused slots nobody/$00, slot 15 neutral).

Outputs:

  mayhem/parse/testsuite/section-*   Seeds for the `parse` target. Each is EXACTLY 100 bytes: TYPE,
                                     ONE other section kind (after a DIM for the per-tile maps
                                     MTXM/SQM/OILM/REGM, so their length matches X*Y), then a SIGN
                                     section whose length pads the file to 100 bytes. fuzz_Parse.cpp
                                     copies at most 100 input bytes into a 100-byte heap buffer and
                                     always calls Parse(buf, 100), so a seed shorter than 100 bytes
                                     would be parsed with an uninitialised tail. Each seed reaches a
                                     different Parse branch, and none of them crashes the unmodified
                                     parser. (Before this, the server testsuite had only 4
                                     non-crashing testcases, 71 libFuzzer features.)
  mayhem/parse/testsuite/map100.pud  A complete small map of EXACTLY 100 bytes (the only length the
                                     `parse` harness ever hands to Parse): TYPE/OWNR/ERA/DIM 3x1/
                                     MTXM/UNIT. A parse seed, and a mayhem/test.sh fixture.
  mayhem/parse/testsuite/named100.pud
                                     A second 100-byte map, with a DESC name: TYPE/DESC/ERA/DIM 1x3/
                                     MTXM. A parse seed, and a test.sh fixture.
  mayhem/pudconvert/testsuite/twokeeps.pud
                                     A 464-byte two-player map with every section PudData::Parse
                                     decodes (DESC/OWNR/ERA/DIM/SIDE/SGLD/SLBR/SOIL/AIPL/MTXM/UNIT)
                                     plus VER/SQM/OILM/REGM. A pudconvert seed, and a mayhem/test.sh
                                     fixture.

What is still necessarily off-spec, and why:
  * Size. The in-tree maps are 64..128 tiles square and also carry the UDTA/UGRD sections
    (thousands of bytes; doc/pud-specs.txt marks both optional, so these inputs leave them out).
    A 100-byte map has room for only a handful of sections: map100 has no VER/DESC, named100 has
    no VER/OWNR. mayhem/test.sh therefore tests upstream's acceptance of small, internally
    consistent maps -- which the unmodified parser does accept -- not a strict "all sections
    present" validator.
  * The section-udta/-ugrd/-alow seeds carry 4-byte bodies (the real UDTA/UGRD are 5696/5950 and
    782 bytes; ALOW is not described in doc/pud-specs.txt). Parse skips all three.
  * SIGN (not described in doc/pud-specs.txt either; Parse accepts and skips it) is used as the
    variable-length filler of the section seeds.
"""
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent


def sec(tag: bytes, body: bytes) -> bytes:
    assert len(tag) == 4
    return tag + struct.pack("<I", len(body)) + body


def le16(*vals: int) -> bytes:
    return b"".join(struct.pack("<H", v) for v in vals)


def unit(x: int, y: int, utype: int, player: int, data: int) -> bytes:
    return struct.pack("<HHBBH", x, y, utype, player, data)


# "WAR2 MAP\0" + 7-byte id tag. Every in-tree map uses 00 0a ff + a 4-byte id as the tag.
TYPE = sec(b"TYPE", b"WAR2 MAP\0" + b"\x00\x0a\xff" + struct.pack("<I", 1131))
assert len(TYPE) == 8 + 16
# Player slots: 5 = person, 4 = computer, 3 = nobody, 2 = neutral (slot 15 is the neutral player).
OWNR = sec(b"OWNR", bytes([5, 4] + [3] * 13 + [2]))
GOLD_MINE, HUMAN_START, ORC_START = 0x5C, 0x5E, 0x5F


def padded_seed(body: bytes) -> bytes:
    """TYPE + body + a SIGN section sized so the whole file is exactly 100 bytes."""
    head = TYPE + body
    fill = 100 - len(head) - 8
    assert fill >= 0, len(head)
    out = head + sec(b"SIGN", bytes(fill))
    assert len(out) == 100
    return out


SECTION_SEEDS = {
    "ver": sec(b"VER ", le16(0x11)),
    # An EMPTY (still null-terminated, 32-byte) description: Parse's "(unnamed)" branch. The named
    # branch is exercised by named100.pud.
    "desc": sec(b"DESC", bytes(32)),
    "ownr": OWNR,
    "era": sec(b"ERA ", le16(1)),
    "erax": sec(b"ERAX", le16(2)),
    "dim": sec(b"DIM ", le16(32, 32)),
    "udta": sec(b"UDTA", bytes(4)),
    "alow": sec(b"ALOW", bytes(4)),
    "ugrd": sec(b"UGRD", bytes(4)),
    # 8 player slots, 7 garbage bytes ($00), neutral slot 15 ($02 / 0).
    "side": sec(b"SIDE", bytes([0, 1] * 4 + [0] * 7 + [2])),
    "sgld": sec(b"SGLD", le16(*[2000] * 8, *[0] * 8)),
    "slbr": sec(b"SLBR", le16(*[1000] * 8, *[0] * 8)),
    "soil": sec(b"SOIL", le16(*[500] * 8, *[0] * 8)),
    "aipl": sec(b"AIPL", bytes([0, 1] * 4 + [0] * 8)),
    # The per-tile sections follow a DIM so that their length matches X*Y.
    # MTXM: 2x2 map -- plain, orc wall (0x09xx), human wall (0x00Bx), plain. Together with map100
    # (0x00Ax orc, 0x009x human) and named100 (0x00Cx orc, 0x08xx human) every wall-classification
    # branch of the MTXM decode is reached by a 100-byte seed.
    "mtxm": sec(b"DIM ", le16(2, 2)) + sec(b"MTXM", le16(0x0050, 0x0901, 0x00B4, 0x0011)),
    "sqm": sec(b"DIM ", le16(2, 1)) + sec(b"SQM ", le16(0x0001, 0x0040)),  # land, water
    "oilm": sec(b"DIM ", le16(2, 2)) + sec(b"OILM", bytes(4)),
    "regm": sec(b"DIM ", le16(2, 1)) + sec(b"REGM", le16(0x4000, 0x0000)),  # land, water
    # A human start location (sets StartX/StartY for player 0) and a neutral gold mine.
    "unit": sec(b"UNIT", unit(1, 1, HUMAN_START, 0, 0) + unit(0, 1, GOLD_MINE, 15, 4)),
}

# 3x1 map: plain, orc wall, human wall; one neutral gold mine. With TYPE at its spec length this is
# the fullest map that fits in exactly 100 bytes with OWNR (24+24+10+12+14+16).
MAP100 = (
    TYPE
    + OWNR
    + sec(b"ERA ", le16(1))  # winter
    + sec(b"DIM ", le16(3, 1))
    + sec(b"MTXM", le16(0x0050, 0x00A3, 0x0093))
    + sec(b"UNIT", unit(2, 0, GOLD_MINE, 15, 4))
)
assert len(MAP100) == 100, len(MAP100)

# The other 100-byte layout: a NAMED 1x3 map (24+40+10+12+14) -- exercises the DESC decode at the
# parse harness's length. It has no OWNR (there is no room for DESC + OWNR + DIM + MTXM in 100
# bytes), so its player count is an upstream default that mayhem/test.sh deliberately does not
# assert.
NAMED100 = (
    TYPE
    + sec(b"DESC", b"Tiny Isle".ljust(32, b"\0"))
    + sec(b"ERA ", le16(3))  # swamp
    + sec(b"DIM ", le16(1, 3))
    + sec(b"MTXM", le16(0x00C4, 0x0050, 0x0801))  # orc wall, plain, human wall (0x08xx)
)
assert len(NAMED100) == 100, len(NAMED100)

TWOKEEPS = (
    TYPE
    + sec(b"VER ", le16(0x11))
    + sec(b"DESC", b"Two Keeps".ljust(32, b"\0"))
    + OWNR
    + sec(b"ERA ", le16(2))  # wasteland
    + sec(b"DIM ", le16(4, 4))
    + sec(b"SIDE", bytes([0, 1] + [0] * 13 + [2]))  # player 0 human, player 1 orc, neutral
    + sec(b"SGLD", le16(2000, 1500, *[0] * 14))
    + sec(b"SLBR", le16(1000, 800, *[0] * 14))
    + sec(b"SOIL", le16(500, 300, *[0] * 14))
    + sec(b"AIPL", bytes([0, 1] + [0] * 14))
    + sec(b"MTXM", le16(0x0050, 0x0051, 0x0052, 0x0053,
                        0x00A3, 0x00B4, 0x0093, 0x0011,
                        0x0801, 0x0902, 0x00C5, 0x0060,
                        0x0070, 0x0080, 0x0010, 0x0020))
    + sec(b"SQM ", bytes(32))
    + sec(b"OILM", bytes(16))
    + sec(b"REGM", bytes(32))
    + sec(b"UNIT", unit(1, 0, HUMAN_START, 0, 0)
                   + unit(3, 3, ORC_START, 1, 0)
                   + unit(1, 2, GOLD_MINE, 15, 6))
)
assert len(TWOKEEPS) == 464, len(TWOKEEPS)


def write(rel: str, data: bytes) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    for name, body in SECTION_SEEDS.items():
        write(f"mayhem/parse/testsuite/section-{name}", padded_seed(body))
    write("mayhem/parse/testsuite/map100.pud", MAP100)
    write("mayhem/parse/testsuite/named100.pud", NAMED100)
    write("mayhem/pudconvert/testsuite/twokeeps.pud", TWOKEEPS)


if __name__ == "__main__":
    main()
