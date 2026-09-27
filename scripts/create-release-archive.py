#!/usr/bin/env python3
"""Create a gzip tar archive with normalized ownership, timestamps, and order."""

import gzip
import os
from pathlib import Path
import stat
import sys
import tarfile


def add_entry(archive: tarfile.TarFile, path: Path, root: Path) -> None:
    relative = path.relative_to(root).as_posix()
    metadata = path.lstat()
    is_directory = stat.S_ISDIR(metadata.st_mode)
    info = tarfile.TarInfo(f"./{relative}" + ("/" if is_directory else ""))
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = stat.S_IMODE(metadata.st_mode)

    if stat.S_ISDIR(metadata.st_mode):
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        archive.addfile(info)
    elif stat.S_ISREG(metadata.st_mode):
        info.type = tarfile.REGTYPE
        info.size = metadata.st_size
        with path.open("rb") as source:
            archive.addfile(info, source)
    elif stat.S_ISLNK(metadata.st_mode):
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        archive.addfile(info)
    else:
        raise ValueError(f"unsupported release archive entry: {path}")


def create_archive(source: Path, destination: Path) -> None:
    root = source.resolve(strict=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    entries = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    with destination.open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in entries:
                    add_entry(archive, path, root)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <staging-directory> <output.tar.gz>", file=sys.stderr)
        return 2
    create_archive(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
