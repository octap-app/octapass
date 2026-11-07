"""Writes the keepass-*.kdbx fixtures: keepass.xml (a KeePass 2 XML export) sealed as KeePass
databases, independently of the Rust importer. Then opens each one with pykeepass as a check.

    python3 -m venv /tmp/kp && /tmp/kp/bin/pip install pykeepass
    /tmp/kp/bin/python crates/octapass-core/tests/import-fixtures/make-keepass.py

pykeepass brings everything used here: pycryptodomex (AES, ChaCha20, Salsa20), its own Twofish,
argon2-cffi and lxml. Seeds and IVs are derived from fixed labels so the output is reproducible;
real databases use random ones. KDF settings are tiny so the tests stay fast.
"""

import base64
import datetime
import gzip
import hashlib
import hmac
import re
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Cryptodome.Cipher import AES, ChaCha20, Salsa20
from Cryptodome.Util.Padding import pad
from lxml import etree
from pykeepass import PyKeePass
from pykeepass.kdbx_parsing.twofish import Twofish

DIR = Path(__file__).resolve().parent
PASSWORD = "correct horse battery staple"
ARABIC_PASSWORD = "كلمة المرور 🔑"

AES256 = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
TWOFISH = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")
CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
AES_KDF = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
SALSA20_IV = bytes.fromhex("e830094b97205d2a")
EPOCH_0001 = 62135596800  # seconds from 0001-01-01 to 1970-01-01


def fixed(label, n):
    return hashlib.sha512(label.encode()).digest()[:n]


def sha256(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def key_file_key(data):
    """XML v2 key files hold the key in hex; any other file is hashed (KeePass's rules)."""
    match = re.search(rb"<Data Hash=\"[0-9A-F]+\">([0-9A-F\s]+)</Data>", data)
    if match:
        return bytes.fromhex(match.group(1).decode())
    return sha256(data)


def composite(password, key_file):
    parts = []
    if password:
        parts.append(sha256(password.encode()))
    if key_file:
        parts.append(key_file_key(key_file))
    return sha256(*parts)


def aes_kdf(key, seed, rounds):
    cipher = AES.new(seed, AES.MODE_ECB)
    for _ in range(rounds):
        key = cipher.encrypt(key)
    return sha256(key)


def inner_stream(stream_id, key):
    if stream_id == 2:
        return Salsa20.new(key=sha256(key), nonce=SALSA20_IV)
    digest = hashlib.sha512(key).digest()
    return ChaCha20.new(key=digest[:32], nonce=digest[32:44])


def encrypt(cipher_id, key, iv, data):
    if cipher_id == AES256:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    if cipher_id == TWOFISH:
        return Twofish.new(key, mode=Twofish.MODE_CBC, IV=iv).encrypt(pad(data, 16))
    return ChaCha20.new(key=key, nonce=iv).encrypt(data)


def protect(root, stream):
    """The export's ProtectedInMemory values become Protected, masked in document order."""
    for element in root.iter():
        if element.get("ProtectedInMemory") == "True":
            del element.attrib["ProtectedInMemory"]
            element.set("Protected", "True")
            masked = stream.encrypt((element.text or "").encode())
            element.text = base64.b64encode(masked).decode()


def kdbx4_times(root):
    """KDBX 4 writes times as base64 of the seconds since 0001-01-01."""
    pattern = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    for element in root.iter():
        if element.text and pattern.match(element.text):
            parsed = datetime.datetime.strptime(element.text, "%Y-%m-%dT%H:%M:%SZ")
            seconds = int(parsed.replace(tzinfo=datetime.timezone.utc).timestamp())
            element.text = base64.b64encode(struct.pack("<q", seconds + EPOCH_0001)).decode()


def write_kdbx3(name, password, key_file, cipher_id, rounds):
    master_seed, transform_seed = fixed(name + "master", 32), fixed(name + "transform", 32)
    iv, stream_key, start = fixed(name + "iv", 16), fixed(name + "stream", 32), fixed(name + "start", 32)

    def field(id, data):
        return struct.pack("<BH", id, len(data)) + data

    header = (
        bytes.fromhex("03d9a29a67fb4bb5")
        + struct.pack("<HH", 1, 3)
        + field(2, cipher_id)
        + field(3, struct.pack("<I", 1))
        + field(4, master_seed)
        + field(5, transform_seed)
        + field(6, struct.pack("<Q", rounds))
        + field(7, iv)
        + field(8, stream_key)
        + field(9, start)
        + field(10, struct.pack("<I", 2))
        + field(0, b"\r\n\r\n")
    )
    root = etree.parse(str(DIR / "keepass.xml")).getroot()
    meta = root.find("Meta")
    header_hash = etree.Element("HeaderHash")
    header_hash.text = base64.b64encode(sha256(header)).decode()
    meta.insert(1, header_hash)
    protect(root, inner_stream(2, stream_key))
    xml = etree.tostring(root, xml_declaration=True, encoding="utf-8", standalone=True)

    payload = gzip.compress(xml, mtime=0)
    blocks = struct.pack("<I", 0) + sha256(payload) + struct.pack("<I", len(payload)) + payload
    blocks += struct.pack("<I", 1) + bytes(32) + struct.pack("<I", 0)
    transformed = aes_kdf(composite(password, key_file), transform_seed, rounds)
    master = sha256(master_seed, transformed)
    (DIR / name).write_bytes(header + encrypt(cipher_id, master, iv, start + blocks))


def variant_dictionary(entries):
    out = struct.pack("<H", 0x0100)
    for key, kind, value in entries:
        out += struct.pack("<BI", kind, len(key)) + key.encode() + struct.pack("<I", len(value)) + value
    return out + b"\x00"


def write_kdbx4(name, password, key_file, cipher_id, kdf, compress, minor=0):
    master_seed = fixed(name + "master", 32)
    iv = fixed(name + "iv", 12 if cipher_id == CHACHA20 else 16)
    stream_key = fixed(name + "stream", 64)
    salt = fixed(name + "salt", 32)
    key = composite(password, key_file)
    if kdf[0] == "aes":
        params = [("$UUID", 0x42, AES_KDF), ("R", 0x05, struct.pack("<Q", kdf[1])), ("S", 0x42, salt)]
        transformed = aes_kdf(key, salt, kdf[1])
    else:
        kind, memory_kib, iterations, lanes = kdf
        params = [
            ("$UUID", 0x42, ARGON2D if kind == "argon2d" else ARGON2ID),
            ("S", 0x42, salt),
            ("P", 0x04, struct.pack("<I", lanes)),
            ("M", 0x05, struct.pack("<Q", memory_kib * 1024)),
            ("I", 0x05, struct.pack("<Q", iterations)),
            ("V", 0x04, struct.pack("<I", 0x13)),
        ]
        transformed = hash_secret_raw(
            key, salt, iterations, memory_kib, lanes, 32, Type.D if kind == "argon2d" else Type.ID, 0x13
        )

    def field(id, data):
        return struct.pack("<BI", id, len(data)) + data

    header = (
        bytes.fromhex("03d9a29a67fb4bb5")
        + struct.pack("<HH", minor, 4)
        + field(2, cipher_id)
        + field(3, struct.pack("<I", 1 if compress else 0))
        + field(4, master_seed)
        + field(7, iv)
        + field(11, variant_dictionary(params))
        + field(0, b"\r\n\r\n")
    )

    root = etree.parse(str(DIR / "keepass.xml")).getroot()
    # Attachments move from Meta/Binaries to the inner header.
    meta = root.find("Meta")
    binaries = meta.find("Binaries")
    meta.remove(binaries)
    kdbx4_times(root)
    protect(root, inner_stream(3, stream_key))
    xml = etree.tostring(root, xml_declaration=True, encoding="utf-8", standalone=True)
    inner = field(1, struct.pack("<I", 3)) + field(2, stream_key)
    for binary in binaries:
        inner += field(3, b"\x00" + base64.b64decode(binary.text))
    inner += field(0, b"")
    payload = inner + xml
    if compress:
        payload = gzip.compress(payload, mtime=0)

    hmac_key = hashlib.sha512(master_seed + transformed + b"\x01").digest()

    def block_key(index):
        return hashlib.sha512(struct.pack("<Q", index) + hmac_key).digest()

    ciphertext = encrypt(cipher_id, sha256(master_seed, transformed), iv, payload)
    out = header + sha256(header) + hmac.new(block_key(2**64 - 1), header, "sha256").digest()
    chunks = [ciphertext[i : i + 4096] for i in range(0, len(ciphertext), 4096)] + [b""]
    for index, chunk in enumerate(chunks):
        size = struct.pack("<I", len(chunk))
        mac = hmac.new(block_key(index), struct.pack("<Q", index) + size + chunk, "sha256").digest()
        out += mac + size + chunk
    (DIR / name).write_bytes(out)


def key_file_v2(name):
    key = fixed(name, 32).hex().upper()
    groups = " ".join(key[i : i + 8] for i in range(0, 64, 8))
    checksum = sha256(bytes.fromhex(key))[:4].hex().upper()
    text = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
\t<Meta>
\t\t<Version>2.0</Version>
\t</Meta>
\t<Key>
\t\t<Data Hash="{checksum}">
\t\t\t{groups[:35]}
\t\t\t{groups[36:]}
\t\t</Data>
\t</Key>
</KeyFile>
"""
    (DIR / name).write_text(text)
    return text.encode()


def check(name, password, key_file):
    db = PyKeePass(str(DIR / name), password=password, keyfile=str(DIR / key_file) if key_file else None)
    github = db.find_entries(title="GitHub", first=True)
    assert github.password == 'gh-Pa55 "quoted" & <angled>', github.password
    assert github.get_custom_property("Recovery codes") == "1111-2222\n3333-4444"
    assert [h.password for h in github.history] == ["first-password", "second-password", "second-password"]
    bank = db.find_entries(title="بنك الأمل", first=True)
    assert bank.password == "كلمة-سر-٢٠٢٥"
    assert len(db.entries) == 8, len(db.entries)
    print("ok", name)


key_v2 = key_file_v2("keepass-keyfile.keyx")
key_any = b"Any file can be a KeePass key file; this one is hashed with SHA-256.\n"
(DIR / "keepass-keyfile.txt").write_bytes(key_any)

write_kdbx3("keepass-kdbx3.kdbx", PASSWORD, None, AES256, rounds=1000)
write_kdbx4("keepass-kdbx4-argon2d.kdbx", PASSWORD, None, AES256, ("argon2d", 1024, 2, 2), compress=True)
write_kdbx4(
    "keepass-kdbx4-argon2id-keyfile.kdbx",
    ARABIC_PASSWORD,
    key_v2,
    CHACHA20,
    ("argon2id", 1024, 2, 1),
    compress=False,
    minor=1,
)
write_kdbx4("keepass-kdbx4-aes-twofish.kdbx", None, key_any, TWOFISH, ("aes", 1000), compress=True)

check("keepass-kdbx3.kdbx", PASSWORD, None)
check("keepass-kdbx4-argon2d.kdbx", PASSWORD, None)
check("keepass-kdbx4-argon2id-keyfile.kdbx", ARABIC_PASSWORD, "keepass-keyfile.keyx")
check("keepass-kdbx4-aes-twofish.kdbx", None, "keepass-keyfile.txt")
