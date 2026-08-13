#!/usr/bin/env python3
"""Generate the cross-implementation test vectors in
internal/auth/krbseal/vectors_test.go.

Why this exists
---------------
krbseal's own tests (seal_test.go) all build their input with the production
`wrap` and then assert `unwrap` reads it back. That is blind by construction: a
self-consistent *wrong* implementation of RFC 4757 §7.3 -- a swapped HMAC
nesting order, a dropped `xorF0`, `le32(0)` become `le32(1)` -- round-trips
against itself perfectly and passes every one of them. The algorithm is only
pinned by the live matrix against a real Windows DC, which is an ephemeral box.

So this script produces the same wrap tokens from an *independent*
implementation -- impacket's `impacket.krb5.gssapi`, written from the RFCs by
different people -- at a fixed key, sequence number, plaintext and confounder.
Freezing those bytes in vectors_test.go gives krbseal a second test style whose
power differs from the round-trip style, the same role `vectors_test.go` plays
in internal/auth/ntlmseal.

Run it to re-derive the constants; it prints a Go const block. It is not run by
CI or by `make check` -- the frozen bytes are the artifact, and needing impacket
to run the test suite would be a worse trade than checking the numbers in.

    python3 scripts/krbseal-vectors.py

Two places impacket and krbseal legitimately differ, both accounted for below:

1. **RFC 1964 padding.** impacket pads the plaintext to a multiple of 8 and
   krbseal deliberately does not -- WinRM uses SSPI in-place SECBUFFER_DATA
   encryption, for which the RC4 stream cipher adds no padding (see wrapRC4's
   comment). The vectors therefore use a plaintext whose length is already a
   multiple of 8, which makes impacket's pad zero-length and the two agree
   byte-for-byte. PLAINTEXT's length is asserted below so a future edit cannot
   silently reintroduce the difference.

2. **GSS framing length.** impacket hardcodes `60 2b` -- 0x2b = 11 (OID) + 32
   (token), counting the signature only. krbseal counts the separate data
   buffer too, per WinRM's IOV layout. Only the framing byte differs, and
   `unwrapRC4` locates the token by searching for the OID rather than trusting
   the length, so the vector is unaffected. The Go test asserts on the token,
   not the framing.

impacket's AES `GSS_Wrap` is *not* usable as-is for the AES vector: it hardcodes
`Flags = 6` (Sealed|AcceptorSubkey) and always encrypts with
KG_USAGE_INITIATOR_SEAL, so it cannot express the acceptor-sealed token krbseal
must read. The AES vector therefore builds the RFC 4121 §4.2.4 header here and
uses impacket only for the cryptosystem (`_AES256CTS`, i.e. the key derivation,
CTS encryption and SHA1-96 HMAC). That makes the AES vector's independence
partial -- it pins the key usage, rotation direction, RRC and header layout
against a second implementation of the *crypto*, not of the token framing. The
RC4 vector, where krbseal hand-rolls the crypto itself, is the load-bearing one.
"""

import string
import struct

from Cryptodome.Hash import HMAC, MD5

from impacket.krb5 import crypto, gssapi
from impacket.krb5.crypto import Key

# ---- fixed inputs -----------------------------------------------------------
#
# Arbitrary but frozen. RC4_KEY is the AES-128 sample key from FIPS-197, used
# here purely as 16 recognisable bytes -- nothing about it is Kerberos-specific.

RC4_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
AES_KEY = bytes.fromhex(
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
)
SEQ = 7
PLAINTEXT = b"<s:Envelope>whoami!</s:Envelope>"  # 32 bytes; see note 1 above
CONFOUNDER = b"Confound"  # RC4: 8 bytes, chosen from ascii_letters
AES_CONFOUNDER = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 16 bytes

assert len(PLAINTEXT) % 8 == 0, "plaintext must be a multiple of 8 -- see note 1"
assert len(CONFOUNDER) == 8
assert all(chr(c) in string.ascii_letters for c in CONFOUNDER)

KG_USAGE_ACCEPTOR_SEAL = 22


class _FixedRand:
    """Feeds impacket's confounder generator a fixed string.

    GSSAPI_RC4.GSS_Wrap builds its confounder with
    `rand.choice(string.ascii_letters)` eight times, so replacing the module's
    `rand` with this makes the token deterministic without touching impacket.
    """

    def __init__(self, s):
        self.s = s
        self.i = 0

    def choice(self, _seq):
        c = self.s[self.i % len(self.s)]
        self.i += 1
        return c


def rc4_vector():
    """An acceptor-sealed RFC 4757 wrap token, straight from impacket.

    `direction='accept'` sets the RFC 1964 §1.2.1 trailing direction tag to
    0xFFFFFFFF, which is what unwrapRC4 demands -- and RC4-HMAC keys both
    directions identically, so unlike AES this needs no other adjustment.
    """
    gssapi.rand = _FixedRand(CONFOUNDER.decode())
    ciphertext, sig = gssapi.GSSAPI_RC4().GSS_Wrap(
        Key(23, RC4_KEY), PLAINTEXT, SEQ, direction="accept"
    )
    assert len(ciphertext) == len(PLAINTEXT), "impacket padded: see note 1"
    return sig, ciphertext


def rc4_derived_keys():
    """Ksign and Kcrypt, recomputed here from RFC 4757 §7.3.

    These pin the *send* direction, which cannot be frozen as a token: wrapRC4
    draws its confounder from crypto/rand, so its output is not reproducible.
    With Kcrypt as independent ground truth the Go test can decrypt whatever
    wrapRC4 produced and check the plaintext came back, which catches a mutated
    derivation without needing a test seam in the production code.
    """
    ksign = HMAC.new(RC4_KEY, b"signaturekey\0", MD5).digest()
    klocal = bytes(b ^ 0xF0 for b in RC4_KEY)
    kcrypt = HMAC.new(klocal, struct.pack("<L", 0), MD5).digest()
    kcrypt = HMAC.new(kcrypt, struct.pack(">L", SEQ), MD5).digest()
    return ksign, kcrypt


def aes_vector():
    """An acceptor-sealed RFC 4121 §4.2.4 CONFIDENTIALITY wrap token.

    Header built here (impacket cannot express it -- see the module docstring);
    cryptosystem from impacket. EC is 0 and RRC is confounder+HMAC == 28, which
    is what a Windows acceptor sends and what krbseal's sealer computes.
    """
    hdr = bytearray(16)
    hdr[0], hdr[1] = 0x05, 0x04
    hdr[2] = 0x03  # Sealed | SentByAcceptor
    hdr[3] = 0xFF
    struct.pack_into(">H", hdr, 4, 0)  # EC
    struct.pack_into(">H", hdr, 6, 0)  # RRC is zero while encrypting
    struct.pack_into(">Q", hdr, 8, SEQ)

    ciphertext = crypto._AES256CTS.encrypt(
        Key(18, AES_KEY),
        KG_USAGE_ACCEPTOR_SEAL,
        bytes(PLAINTEXT) + bytes(hdr),
        AES_CONFOUNDER,
    )

    rrc = 28  # confounder (16) + SHA1-96 HMAC (12)
    struct.pack_into(">H", hdr, 6, rrc)
    rotated = ciphertext[-rrc:] + ciphertext[:-rrc]  # rotate right by RRC
    token = bytes(hdr) + rotated

    # WinRM's split: the last len(plaintext) bytes are the "data" buffer.
    off = len(token) - len(PLAINTEXT)
    return token[:off], token[off:]


def go_const(name, value, comment=None):
    out = ""
    if comment:
        out += "\t// %s\n" % comment
    return out + '\t%s = "%s"\n' % (name, value.hex())


def main():
    rc4_sig, rc4_data = rc4_vector()
    ksign, kcrypt = rc4_derived_keys()
    aes_sig, aes_data = aes_vector()

    print("// Generated by scripts/krbseal-vectors.py -- see that file for the")
    print("// provenance of every value here and the two places impacket and")
    print("// krbseal deliberately differ.")
    print("const (")
    print(go_const("vecRC4Key", RC4_KEY))
    print(go_const("vecAESKey", AES_KEY))
    print(go_const("vecPlaintext", PLAINTEXT, "%d bytes: %r" % (len(PLAINTEXT), PLAINTEXT)))
    print("\tvecSeq = %d\n" % SEQ)
    print(go_const("vecRC4Sig", rc4_sig, "impacket GSS_Wrap(direction='accept')"))
    print(go_const("vecRC4Data", rc4_data))
    print(go_const("vecRC4Ksign", ksign, "HMAC-MD5(key, \"signaturekey\\0\")"))
    print(go_const("vecRC4Kcrypt", kcrypt, "HMAC-MD5(HMAC-MD5(key^F0, le32(0)), be32(seq))"))
    print(go_const("vecAESSig", aes_sig, "acceptor-sealed, impacket _AES256CTS"))
    print(go_const("vecAESData", aes_data))
    print(")")


if __name__ == "__main__":
    main()
