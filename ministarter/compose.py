#!/usr/bin/env python3
import glob
import os
import shlex
import shutil
import subprocess as sp
import sys
import tempfile
import zipapp
from argparse import ArgumentParser, FileType, Namespace
from configparser import ConfigParser
from pathlib import Path
from typing import Dict, List, Optional

DOWNLOAD_URL_TEMPLATE = "https://research.cs.wisc.edu/htcondor/tarball/{series}/current/condor-{arch}_{os}-stripped.tar.gz"

CHOICES = {
    "arch": ("x86_64",),
    "os": ("AlmaLinux8", "AlmaLinux9"),
}

DEFAULTS = {
    "series": "23.x",
    "os": "AlmaLinux8",
    "arch": "x86_64",
    "python": "/usr/bin/python3",
    "pilotfile": "pilot.pyz",
}

for _k, _v in DEFAULTS.items():
    if _k in CHOICES:
        assert _v in CHOICES[_k]


def get_tempdir() -> str:
    """
    Returns the directory we should make temp files/directories in.
    This obeys TMPDIR, TEMP, or TMP environment variables, but makes the
    default /var/tmp instead of /tmp, because /var/tmp is larger.
    """
    td = os.environ.get("TMPDIR", os.environ.get("TEMP", os.environ.get("TMP", None)))
    if td:
        return td
    td = tempfile.gettempdir()
    if td == "/tmp":
        td = "/var/tmp"
    return td


def get_args(argv: List[str]) -> Namespace:
    """
    Use argparse to parse command-line arguments.
    """
    parser = ArgumentParser()
    parser.add_argument(
        "--config",
        default=None,
        type=FileType("rt", encoding="latin-1"),
        help="Config file to read",
    )
    parser.add_argument(
        "--series",
        help=f"HTCondor series [{DEFAULTS['series']}]",
    )
    parser.add_argument(
        "--os",
        choices=CHOICES["os"],
        help=f"Worker Linux distribution [{DEFAULTS['os']}]",
    )
    parser.add_argument(
        "--arch",
        choices=CHOICES["arch"],
        help=f"Worker machine architecture [{DEFAULTS['arch']}]",
    )
    parser.add_argument(
        "--python",
        help=f"Python 3 executable on worker [{DEFAULTS['python']}]",
    )
    parser.add_argument(
        "--pilotfile",
        help=f"Name of pilot zip file to write [{DEFAULTS['pilotfile']}]",
    )

    args = parser.parse_args(argv[1:])
    return args


def get_options(argv: List[str]) -> Dict:
    """
    Combine config file and command-line arguments into a dictionary.
    """
    args = get_args(argv)
    config = ConfigParser()
    if args.config:
        config.read_file(args.config)
    options = DEFAULTS.copy()
    if config.has_section("compose"):
        options.update(dict(config["compose"]))
    for key, value in vars(args).items():
        if key in DEFAULTS and value is not None:
            options[key] = value
    return options


def repackage_condor(condor_tarball: str, download_url: str, arch: str) -> None:
    """
    Downloads condor, untars it, excluding files not needed for the
    ministarter, then retars it.

    Args:
        condor_tarball: path to the tarball to be created
        download_url: URL of the condor tarball to download
        arch: the architecture (used for excluding some directories)
    """
    os.mkdir("condor")
    # -m ignores timestamps (the condor tarball has some 1/1/1970 timestamps
    # which generate warnings from tar and an error creating the zip (because
    # zip doesn't support timestamps earlier than 1980)
    sp.run(
        f"curl -LSs {shlex.quote(download_url)}"
        " | tar -C condor/ -xmzf- --strip-components=1"
        " --exclude='*/usr/include'"
        " --exclude='*/usr/libexec'"
        " --exclude='*/usr/share'"
        f" --exclude='*/usr/{arch}'",
        shell=True,
        check=True,
    )
    sp.run(["tar", "--remove-files", "-czf", condor_tarball, "condor"], check=True)


def package_pilot(pilot_zip: str, python: str) -> None:
    """
    Compress the current directory into a zip file and set the shebang line.

    Args:
        pilot_zip: the path to the pilot zip file to create
        python: the interpreter to use in the shebang line
    """
    tmp_pilot_zip = "tmp.zip"
    sp.run(["zip", "-qry", tmp_pilot_zip] + glob.glob("./*"), check=True)
    zipapp.create_archive(tmp_pilot_zip, pilot_zip, python)
    os.chmod(pilot_zip, 0o755)


def do_compose(pilot_zip: str, download_url: str, arch: str, python: str) -> None:
    """
    Compose a pilot zip file.  Make a temp directory; copy the hermitcrab
    scripts, download and extract the condor tarball, and create the self-
    extracting zip file.

    Args:
        pilot_zip: the path to the pilot zip file to create
        download_url: the download URL of the condor tarball
        arch: the CPU architecture of the condor tarball (used to exclude
              some directories
        python: the interpreter to use in the shebang line
    """
    with tempfile.TemporaryDirectory(
        prefix="glideman-compose-", dir=get_tempdir()
    ) as pilot_tmp_dir_:
        pilot_tmp_dir = Path(pilot_tmp_dir_)
        shutil.copy("ministarter.py", pilot_tmp_dir / "__main__.py")
        shutil.copy("procstat.py", pilot_tmp_dir / "procstat.py")
        olddir = os.getcwd()
        os.chdir(pilot_tmp_dir)
        try:
            try:
                from ministarter import VERSION as MINISTARTER_VERSION
            except ImportError:
                MINISTARTER_VERSION = "unknown"
            condor_tarball = "condor.tar.gz"
            repackage_condor(condor_tarball, download_url, arch)
            package_pilot(pilot_zip, python)
            pilot_zip_size = os.path.getsize(pilot_zip)
            print(
                f"pilot zip file {pilot_zip} with ministarter version {MINISTARTER_VERSION}"
                f" created with size {pilot_zip_size:#,} bytes"
            )
        finally:
            os.chdir(olddir)


def main(argv: Optional[str] = None) -> int:
    """Entry point to this script."""
    options = get_options(argv or sys.argv)
    pilot_zip = os.path.abspath(options["pilotfile"])
    python = options["python"]
    arch = options["arch"]

    download_url = DOWNLOAD_URL_TEMPLATE.format(**options)

    do_compose(pilot_zip, download_url, arch, python)

    return 0


if __name__ == "__main__":
    sys.exit(main())
