#!/usr/bin/env python3
"""Build portable and source ZIPs without third-party runtime/build dependencies."""

import argparse
import ast
import hashlib
import zipfile
from pathlib import Path

ROOT_FILES = {
    "riskcheck.py",
    "pyproject.toml",
    "README.md",
    "README.en.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "Dockerfile",
    "MANIFEST.in",
    "requirements-dev.txt",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".dockerignore",
}
SOURCE_DIRS = {"riskcheck_data", "docs", "schemas", "examples", "tests", "tools", ".github"}
SOURCE_SUFFIXES = {".py", ".json", ".md", ".toml", ".yml", ".yaml", ".txt"}


def release_version(project):
    tree = ast.parse((project / "riskcheck.py").read_text(encoding="utf-8"))
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "__version__" for t in statement.targets):
                value = ast.literal_eval(statement.value)
                if isinstance(value, str) and len(value.split(".")) == 3:
                    return value
    raise ValueError("riskcheck.py must define a literal __version__")


def write_archive(path, entries, executable=False):
    with path.open("wb") as stream:
        if executable:
            stream.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(entries.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)


def source_files(project):
    paths = [project / name for name in ROOT_FILES if (project / name).is_file()]
    for dirname in sorted(SOURCE_DIRS):
        folder = project / dirname
        if folder.is_dir() and not folder.is_symlink():
            paths.extend(
                p
                for p in folder.rglob("*")
                if p.is_file()
                and not p.is_symlink()
                and "__pycache__" not in p.parts
                and p.suffix in SOURCE_SUFFIXES
            )
    return sorted(paths)


def build_release(project, output):
    project, output = Path(project).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    version = release_version(project)
    portable = output / ("riskcheck-" + version + ".pyz")
    source = output / ("riskcheck-" + version + "-source.zip")
    entries = {
        "riskcheck.py": (project / "riskcheck.py").read_bytes(),
        "riskcheck_data/__init__.py": (project / "riskcheck_data/__init__.py").read_bytes(),
        "riskcheck_data/rules.json": (project / "riskcheck_data/rules.json").read_bytes(),
        "__main__.py": b"from riskcheck import main\nraise SystemExit(main())\n",
    }
    write_archive(portable, entries, executable=True)
    prefix = "riskcheck-" + version + "/"
    write_archive(
        source,
        {prefix + p.relative_to(project).as_posix(): p.read_bytes() for p in source_files(project)},
    )
    artifacts = [portable, source]
    for pattern in (
        "riskcheck_offline-" + version + "-*.whl",
        "riskcheck_offline-" + version + ".tar.gz",
    ):
        artifacts.extend(sorted(output.glob(pattern)))
    manifest = output / "SHA256SUMS"
    manifest.write_text(
        "".join(
            hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
            for p in sorted(artifacts)
        ),
        encoding="utf-8",
    )
    return artifacts + [manifest]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    for artifact in build_release(args.project, args.output):
        print(artifact.name)


if __name__ == "__main__":
    main()
