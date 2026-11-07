"""Builds dashlane.zip from the dashlane-*.csv fixtures, with the file names Dashlane's CSV
export uses, plus one file the importer doesn't know (it must be skipped with a warning).

    python3 crates/octapass-core/tests/import-fixtures/make-dashlane.py
"""

import pathlib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
# A fixed time, so the file only changes when its content does.
DATE = (2025, 10, 23, 0, 0, 0)

FILES = [
    ("credentials.csv", "dashlane-credentials.csv"),
    ("securenotes.csv", "dashlane-securenotes.csv"),
    ("payments.csv", "dashlane-payments.csv"),
    ("ids.csv", "dashlane-ids.csv"),
    ("personalInfo.csv", "dashlane-personalInfo.csv"),
]

with zipfile.ZipFile(HERE / "dashlane.zip", "w") as archive:
    for name, source in FILES:
        info = zipfile.ZipInfo(name, date_time=DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, (HERE / source).read_bytes())
    info = zipfile.ZipInfo("future-feature.csv", date_time=DATE)
    archive.writestr(info, b"id,value\n1,something new\n")
