"""Builds the Proton Pass ZIP fixtures from protonpass-data.json.

protonpass.zip is laid out like Proton Pass's own export (an uncompressed ZIP with
`Proton Pass/data.json`). protonpass-encrypted.zip has `Proton Pass/data.pgp` instead, the way the
PGP-encrypted export does: protonpass-data.pgp, which make-protonpass-pgp.mjs writes with
OpenPGP.js (run that first when protonpass-data.json changes).

    python3 crates/octapass-core/tests/import-fixtures/make-protonpass.py
"""

import pathlib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
# A fixed time, so the files only change when their content does.
DATE = (2025, 10, 23, 0, 0, 0)


def entry(name):
    info = zipfile.ZipInfo(name, date_time=DATE)
    info.compress_type = zipfile.ZIP_STORED
    return info


def write(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(entry("Proton Pass/"), b"")
        for name, data in files:
            archive.writestr(entry(name), data)


write(
    HERE / "protonpass.zip",
    [("Proton Pass/data.json", (HERE / "protonpass-data.json").read_bytes())],
)
write(
    HERE / "protonpass-encrypted.zip",
    [("Proton Pass/data.pgp", (HERE / "protonpass-data.pgp").read_bytes())],
)
