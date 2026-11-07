"""Writes the Ente Auth fixtures with libsodium (through PyNaCl), independently of the Rust code
that reads them.

ente-auth.txt is the plaintext export: one `otpauth://` link per line, as Ente Auth's
`_getAuthDataForExport` writes each code's `rawData` (with the `codeDisplay` parameter that
`Code.toOTPAuthUrlFormat` adds, and `,` written as `%2C`). The encrypted files hold that text:

    ente-auth-encrypted.json            as Ente Auth's export: one secretstream message, tag FINAL
    ente-auth-encrypted-message.json    the same message with tag MESSAGE (older Ente versions)
    ente-auth-encrypted-push.json       tag PUSH: not something Ente writes, refused
    ente-auth-encrypted-two-chunks.json the text in two messages (MESSAGE, FINAL): refused
    ente-auth-encrypted-reordered.json  those two messages swapped: refused

The password is `correct horse battery staple`. Ente derives the key with libsodium's
"sensitive" limits (1 GiB); these files use 8 MiB and 2 passes so the tests stay fast (the
importer reads the limits from the file). Salts, headers and so the files change on every run.

    python3 -m venv /tmp/ente && /tmp/ente/bin/pip install pynacl
    /tmp/ente/bin/python crates/octapass-core/tests/import-fixtures/make-ente.py
"""

import base64
import json
import pathlib
import urllib.parse

import nacl.bindings as sodium
import nacl.utils

HERE = pathlib.Path(__file__).resolve().parent
PASSWORD = b"correct horse battery staple"
MEMLIMIT = 8 * 1024 * 1024
OPSLIMIT = 2


def link(kind, issuer, account, secret, display=None, **params):
    """A code's rawData as Ente Auth stores and exports it."""
    path = urllib.parse.quote(f"{issuer}:{account}", safe=":@")
    query = {"algorithm": "SHA1", "digits": "6", "issuer": issuer, "period": "30", "secret": secret}
    query.update(params)
    if display is not None:
        full = {"pinned": False, "trashed": False, "lastUsedAt": 0, "tapCount": 0, "tags": [],
                "note": "", "position": 0, "iconSrc": "", "iconID": ""}
        full.update(display)
        query["codeDisplay"] = json.dumps(full, ensure_ascii=False, separators=(",", ":"))
    text = f"otpauth://{kind}/{path}?" + urllib.parse.urlencode(query)
    return text.replace(",", "%2C")


LINKS = [
    # An older code, from before codeDisplay: it matches the tests' existing GitHub login.
    link("totp", "GitHub", "octo", "JBSWY3DPEHPK3PXP"),
    link("totp", "بنك الأمل", "سارة", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
         {"pinned": True, "tags": ["مالية", "Work"], "note": "Recovery codes in the safe.\nSecond line.",
          "lastUsedAt": 1767225600000000, "tapCount": 12}, algorithm="SHA256", digits="8", period="60"),
    link("totp", "Café ☕", "me+test@example.com", "MFRGGZDFMZTWQ2LK", {"tags": ["Food"]}),
    link("steam", "Steam", "gamer", "KRSXG5CTMVRXEZLU", {}, digits="5"),
    link("hotp", "Old Bank", "me", "ONSWG4TFORWGC2LO", {}, counter="5"),
    link("totp", "Deleted Shop", "gone", "NBSWY3DPO5XXE3DE", {"trashed": True}),
]


def encrypt(chunks):
    """`chunks` as (text, tag) messages of one secretstream, in an Ente Auth export file."""
    salt = nacl.utils.random(sodium.crypto_pwhash_SALTBYTES)
    key = sodium.crypto_pwhash_alg(32, PASSWORD, salt, OPSLIMIT, MEMLIMIT, sodium.crypto_pwhash_ALG_ARGON2ID13)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    sealed = [sodium.crypto_secretstream_xchacha20poly1305_push(state, text, tag=tag) for text, tag in chunks]
    return sealed, header, salt


def write(name, sealed, header, salt):
    export = {
        "version": 1,
        "kdfParams": {"memLimit": MEMLIMIT, "opsLimit": OPSLIMIT, "salt": base64.b64encode(salt).decode()},
        "encryptedData": base64.b64encode(b"".join(sealed)).decode(),
        "encryptionNonce": base64.b64encode(header).decode(),
    }
    (HERE / name).write_text(json.dumps(export) + "\n")


plain = "".join(f"{line}\n" for line in LINKS)
(HERE / "ente-auth.txt").write_text(plain)
data = plain.encode()
FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
PUSH = sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH
write("ente-auth-encrypted.json", *encrypt([(data, FINAL)]))
write("ente-auth-encrypted-message.json", *encrypt([(data, MESSAGE)]))
write("ente-auth-encrypted-push.json", *encrypt([(data, PUSH)]))
half = len(data) // 2
sealed, header, salt = encrypt([(data[:half], MESSAGE), (data[half:], FINAL)])
write("ente-auth-encrypted-two-chunks.json", sealed, header, salt)
write("ente-auth-encrypted-reordered.json", sealed[::-1], header, salt)
