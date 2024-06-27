#!/usr/bin/env python3
# This program requires Python 3.6+

# import glob
import argparse
import atexit
import functools
import logging
import os
import re
import resource
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Union

from procstat import ProcFamily

VERSION = "0.31-dockerpilot"
# ^^ something to print at the beginning to see what version of
#    this program is running; try to base it on "git describe"

ERR_USAGE = 2
ERR_NO_EXECUTABLE = 3
ERR_CANT_ADVERTISE = 4
ERR_NOT_ZIP = 5
ERR_UNKNOWN = 99

# This needs to match the `filename` in the JOB_ROUTER_CREATE_IDTOKEN entry
# for these pilots.
DEFAULT_IDTOKEN_FILENAME = "ministarter-advertise.idtoken"

# number of seconds to wait between polling the subprocess
POLL_PERIOD = 1.0
# number of seconds to wait between advertising again
ADVERTISE_PERIOD = 20.0
# number of seconds to wait before killing condor_advertise
ADVERTISE_TIMEOUT = 20.0

_debug = False
_log = logging.getLogger(__name__)


def _cleanup_dir(dir_path: Path) -> None:
    try:
        shutil.rmtree(dir_path)
    except Exception as err:
        _log.warning("Error cleaning up %s: %s", dir_path, err, exc_info=True)


def _log_ml(lvl: int, msg: str, *args, **kwargs):
    """
    Log a potentially multi-line message by splitting the lines and doing
    individual calls to _log.log().  exc_info and stack_info will only be
    printed for the last line.
    """
    if lvl >= _log.getEffectiveLevel():
        orig_kwargs = kwargs.copy()
        msg_lines = (msg % args).splitlines()
        last_line = msg_lines[-1]
        kwargs.pop("exc_info", None)
        kwargs.pop("stack_info", None)
        for line in msg_lines[:-1]:
            _log.log(lvl, "%s", line, **kwargs)
        return _log.log(lvl, "%s", last_line, **orig_kwargs)


def handler_propagate_to_proc(proc: subprocess.Popen, signum, frame):
    """
    A signal handler that propagates the received signal to the proc.
    """
    # TODO Also attempt to send an ad indicating the received signal
    _ = frame
    proc.send_signal(signum)


class AdvertiseSetupError(Exception):
    """Exception raised when setting up advertising fails."""


class CompletedCommand(NamedTuple):
    """
    Stats on a completed command.

    Contains the following:
    -   end_time: The time we noticed the program having exited.
    -   elapsed_time: The total time elapsed since the job started (to the
    precision of POLL_PERIOD).
    -   max_family_count: The max family (process) count (itself + number of descendants) of
    the process
    -   max_family_rss: The max family resident set size (in bytes)
    -   rc: the process's return code
    """

    end_time: float
    elapsed_time: float
    max_family_count: int
    max_family_rss: int
    rc: int

    def as_dict(self) -> Dict[str, str]:
        """Converts a CompletedCommand into a dict suitable for advertising."""
        return {
            "CmdEndTime": str(int(self.end_time)),
            "CmdElapsedTime": str(int(self.elapsed_time)),
            "CmdMaxFamilyCount": str(self.max_family_count),
            "CmdMaxFamilyRSS": str(self.max_family_rss),
            "CmdExitCode": str(self.rc),
        }


class Advertiser:
    """A class for advertising ads to the CE's collector"""

    def __init__(self, collector_host: str, ad_file: Union[None, Path, str] = None):
        self.condor_dir = Path()
        self.collector_host = collector_host
        self.condor_env: Dict[str, str] = {}
        self.failure_count = 0
        self.success_count = 0
        if ad_file:
            self.ad_file = Path(ad_file)
        else:
            self.ad_file = None
        self.initialized = False
        # TODO name should be passed in
        self.name = f"MS-{socket.getfqdn()}-{secrets.token_hex(4)}"
        start_time_str = str(int(time.time()))

        self.ad_template = {
            "MyType": '"DaemonMaster"',
            "Name": f'"{self.name}"',
            "DaemonStartTime": start_time_str,
            "DaemonLastReconfigTime": start_time_str,
            "MSMiniStarterVersion": f'"{VERSION}"',
        }

    #
    # Public methods
    #

    def setup_condor(self, scratch_dir: Path, idtoken_file: str):
        """
        Extract the condor tarball into a directory; place the token, and set up
        the environment for using the binaries from the tarball.

        Sets the following members:
            initialized: if we were successful
            idtoken_file as a Path to the given idtoken file
            condor_dir as a Path to the extracted condor files
            token_dir as a Path to the directory the token is placed in

        Args:
            scratch_dir: The scratch directory (job sandbox)
            idtoken_file: The path to the idtoken file for contacting the CE's collector

        Raises:
            AdvertiseSetupError: If a required file is missing or setup fails.
        """
        self.initialized = False
        if isinstance(self.ad_file, Path):
            try:
                self.ad_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError as err:
                raise AdvertiseSetupError(
                    f"Unable to set up ad file at {self.ad_file!s}: {err}"
                )
            self.initialized = True
            return

        # Required information checks
        if idtoken_file:
            idtoken_file_p = Path(idtoken_file)
        else:
            raise AdvertiseSetupError("idtoken file not provided")

        # File existence checks
        if not idtoken_file_p.is_file():
            raise AdvertiseSetupError(
                "idtoken file not found at %s or is not a file" % idtoken_file
            )

        # Create a dir to hold the tarball contents
        self.condor_dir = Path(
            tempfile.mkdtemp(suffix="_condor", prefix="ministarter_", dir=scratch_dir)
        )
        atexit.register(_cleanup_dir, self.condor_dir)
        token_dir = self.condor_dir / "token"

        self._untar_condor(self.condor_dir)
        self._setup_token(token_dir, idtoken_file_p)
        self.condor_env = self._get_environment(self.condor_dir, token_dir)
        _log_ml(logging.DEBUG, "condor environment: %r", self.condor_env)
        self._verify_condor(self.condor_dir, self.condor_env)

        self.initialized = True

    def advertise(self, contents: Dict[str, str], debug=False) -> bool:
        """Advertise the given dict as a master ad to the collector, if initialized.

        Args:
            contents: a dict of classad attributes to advertise; values must
                      already be formatted (e.g., strings must be quoted)
            debug: whether to run condor_advertise with -debug

        Returns:
            True if successful, False otherwise.  Also return False if uninitialized.
        """
        if not self.initialized:
            return False

        ad = self.ad_template.copy()
        ad.update(contents)
        ad["MSReportTime"] = str(int(time.time()))
        ad["MSAdvertiseFailureCount"] = str(self.failure_count)
        ad["MSAdvertiseSuccessCount"] = str(self.success_count + 1)
        # ^^ advertise success; if it's not successful, the collector won't get the update anyway

        try:
            # We have an ad file -- instead of calling condor_advertise, write to
            # the file and return.
            if isinstance(self.ad_file, Path):
                with self.ad_file.open(mode="a+t", encoding="utf-8") as adfh:
                    for key, value in ad.items():
                        print(f"{key} = {value}", file=adfh)
                    print("", file=adfh)
                    adfh.flush()
                return True

            # We do not have an ad file.  Use condor_advertise.
            return self._condor_advertise(ad, debug)
        except Exception as err:
            msg = "Exception raised while advertising: %s"
            if _debug:
                _log.exception(msg, err)
            else:
                _log.error(msg, err)
            self.failure_count += 1
            return False

    #
    # Private methods
    #

    def _condor_advertise(self, ad: Dict, debug: bool) -> bool:
        """
        Use condor_advertise to send an ad.  This involves writing the ad to
        a temporary file first.

        Returns True on success, False on failure. May increment
        self.success_count or self.failure_count.  Does not catch exceptions.
        """
        with tempfile.NamedTemporaryFile(
            mode="w+t", encoding="utf-8", suffix=".ad"
        ) as adfh:
            for key, value in ad.items():
                print(f"{key} = {value}", file=adfh)
            adfh.flush()
            args = [str(self.condor_dir / "sbin/condor_advertise")]
            args += ["-pool", self.collector_host]
            if debug:
                args += ["-debug"]
            args += ["UPDATE_MASTER_AD", adfh.name]
            try:
                ret = subprocess.run(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=self.condor_env,
                    encoding="latin-1",
                    timeout=ADVERTISE_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                _log.warning("condor_advertise timed out")
                self.failure_count += 1
                return False

            if ret.returncode == 0:
                _log.debug("condor_advertise successful")
                _log_ml(logging.DEBUG, "Output: %s", ret.stdout)
                self.success_count += 1
                return True
            else:
                _log.warning(
                    "condor_advertise unsuccessful, exit code %d", ret.returncode
                )
                _log_ml(logging.WARNING, "Output: %s", ret.stdout)
                with open(adfh.name, encoding="utf-8") as adfh_read:
                    _log_ml(logging.DEBUG, "ad:\n%s", adfh_read.read())
                self.failure_count += 1
                return False

    def _untar_condor(self, condor_dir: Path) -> None:
        _log.debug(
            "setting up condor tarball inside %s into %s",
            sys.path[0],
            condor_dir,
        )
        with zipfile.ZipFile(sys.path[0], "r") as zip_:
            zip_.extract("condor.tar.gz", path=condor_dir)
        condor_tarball_str = condor_dir / "condor.tar.gz"

        try:
            # -m ignores times (silences 'implausible mtime' warning)
            subprocess.run(
                [
                    "tar",
                    "-C",
                    str(condor_dir),
                    "--strip-components=1",
                    "-xmf",
                    condor_tarball_str,
                ],
                check=True,
            )
        except subprocess.CalledProcessError as err:
            # we didn't pipe stdout/stderr so it will already show up in the log
            raise AdvertiseSetupError(
                "condor tarball extraction failed with code %s" % err.returncode
            )

    def _setup_token(self, token_dir: Path, idtoken_file: Path) -> None:
        try:
            dest_token_file = token_dir / "collector_token"
            os.makedirs(token_dir, exist_ok=True)
            os.chmod(token_dir, 0o700)
            shutil.copy2(idtoken_file, dest_token_file)
            os.chmod(dest_token_file, 0o600)
        except OSError as err:
            raise AdvertiseSetupError("setting up token failed with exception %s" % err)

    def _get_environment(self, condor_dir: Path, token_dir: Path) -> Dict[str, str]:
        # We have the tarball extracted; set the appropriate paths for subprocesses.
        condor_env = os.environ.copy()
        condor_env["LD_LIBRARY_PATH"] = (
            str(condor_dir / "usr/lib64") + ":" + condor_env.get("LD_LIBRARY_PATH", "")
        ).rstrip(":")
        condor_env["PYTHONPATH"] = (
            str(self.condor_dir / "usr/lib/python3")
            + ":"
            + condor_env.get("PYTHONPATH", "")
        ).rstrip(":")
        condor_env["CONDOR_CONFIG"] = "/dev/null"
        condor_env["_CONDOR_SEC_TOKEN_DIRECTORY"] = str(token_dir)
        condor_env["_CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS"] = "IDTOKENS"
        condor_env["_CONDOR_SEC_CLIENT_AUTHENTICATION"] = "REQUIRED"
        if _debug:
            condor_env["_CONDOR_TOOL_DEBUG"] = (
                "D_FULLDEBUG,D_CAT,D_SECURITY:2,D_NETWORK:2"
            )
        return condor_env

    def _verify_condor(self, condor_dir: Path, condor_env: Dict[str, str]) -> None:
        """Verify basic functionality of the condor we extracted from the tarball
        by running condor_version.
        """
        result = subprocess.run(
            str(condor_dir / "usr/bin/condor_version"),
            stdout=subprocess.PIPE,
            env=condor_env,
        )
        if result.returncode == 0:
            _log_ml(
                logging.INFO, "condor_version succeeded. Output:\n%s", result.stdout
            )
        else:
            _log_ml(
                logging.WARNING,
                "condor_version failed with return code %d. Output:\n%s",
                result.returncode,
                result.stdout,
            )
            # condor_version didn't work, condor_advertise won't
            raise AdvertiseSetupError("condor_version failed")


#
# End class Advertiser
#


def build_cmd_ad(
    elapsed_time: float,
    family: ProcFamily,
    max_family_rss: int,
    max_family_count: int,
    watch_command: List[str],
) -> Dict[str, str]:
    """
    Build the Cmd sections of the classad that will be advertised to the CE
    Args:
        elapsed_time: how long since the program was started
        family: the ProcFamily of the process at last poll time
        max_family_rss: the high water mark for total family process RSS
        max_family_count: the high water mark for total family process count
        watch_command: a list of label=regexps to write info about separately

    Returns:
        an dict with the "Cmd" attributes filled in; values are already strings
        in classad syntax
    """
    ad = {
        "CmdIsAlive": "True",
        "CmdElapsedTime": str(int(elapsed_time)),
        "CmdFamilyCount": str(family.family_count),
        "CmdMaxFamilyCount": str(max_family_count),
        "CmdFamilyRSS": str(family.family_rss_bytes),
        "CmdMaxFamilyRSS": str(max_family_rss),
    }
    watched_command_info = []
    for wc in watch_command:
        if "=" not in wc:
            continue
        wc_label, wc_regex = wc.split("=", 1)
        subfamily_procinfos = [
            pi
            for pi in family.family_procinfos
            if re.search(wc_regex, " ".join(pi.cmdline))
        ]
        watched_command_info.append(
            f'[ Label="{wc_label}";'
            f'  Pattern="{wc_regex}";'
            f"  Size={len(subfamily_procinfos)};"
            f"  Rss={sum(pi.stat.rss_bytes for pi in subfamily_procinfos)};"
            "]"
        )
    if watched_command_info:
        ad["CmdWatchedCmdInfo"] = "{" + ",".join(watched_command_info) + " }"
    return ad


def watch_job(
    advertiser: Advertiser, proc: subprocess.Popen, watch_command: List[str]
) -> CompletedCommand:
    """
    Watch the job and send periodic updates using the given advertiser.
    Once this function returns, the process will have exited.

    Args:
        advertiser: used to send classads to the CE's collector
        proc: the process to watch
        watch_command: a list of label=regexp commands to send info about separately

    """

    # I use time.monotonic() in several places; this value always increases, even if
    # the system clock goes backwards.  It's better than time.now() for time deltas,
    # but not for timestamps.
    # The suffix `_clock` denotes use of the monotonic clock.
    # The suffix `_ts` denotes use of an absolute timestamp.

    start_clock = time.monotonic()
    elapsed_time = 0.0
    next_advertise_clock = time.monotonic()

    max_family_count = 0
    max_family_rss = 0

    while proc.poll() is None:
        poll_clock = time.monotonic()
        elapsed_time = poll_clock - start_clock

        family = ProcFamily(proc.pid)
        gather_time = time.monotonic() - poll_clock
        if gather_time >= 0.1:
            _log.debug("ProcFamily gather time %f sec.", gather_time)
        if family.family_count > max_family_count:
            max_family_count = family.family_count
        if family.family_rss_bytes > max_family_rss:
            max_family_rss = family.family_rss_bytes

        advertise_clock = time.monotonic()
        if advertise_clock > next_advertise_clock:
            _log.debug("Watched command still running")
            ad = build_cmd_ad(
                elapsed_time, family, max_family_rss, max_family_count, watch_command
            )
            advertiser.advertise(ad)
            post_advertise_clock = time.monotonic()
            advertise_time = post_advertise_clock - advertise_clock
            if advertise_time >= 1.0:
                _log.debug("Advertise time %f sec.", advertise_time)
            next_advertise_clock = post_advertise_clock + ADVERTISE_PERIOD

        time.sleep(POLL_PERIOD)
    # end while proc.poll() is None

    end_time = time.time()

    results = CompletedCommand(
        end_time=end_time,
        elapsed_time=elapsed_time,
        max_family_count=max_family_count,
        max_family_rss=max_family_rss,
        rc=proc.returncode,
    )
    return results


def parse_args(argv):
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument(
        "--collector-host",
        default=os.environ.get("CONDORCE_COLLECTOR_HOST", ""),
        help="Endpoint of the collector to advertise to",
    )
    parser.add_argument(
        "--idtoken-file",
        default=DEFAULT_IDTOKEN_FILENAME,
        help="File name of idtoken to authenticate to the collector with",
    )
    parser.add_argument(
        "--must-advertise",
        action="store_true",
        help="Exit if we are unable to set up advertising",
    )
    parser.add_argument(
        "--watch-command",  # TODO come up with a better name
        action="append",
        default=[],
        help="A label=regexp of command lines to watch separately; "
        "this may be specified multiple times",
    )
    parser.add_argument(
        "--job-id",
        default="",
        help="Pilot job ID to put in the ministarter ad to identify the pilot",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug messages")
    parser.add_argument(
        "--ads-to-file",
        metavar="FILE",
        default=None,
        help="Write ads to the given file instead of advertising. "
        "In this case, neither an idtoken-file, nor a collector-host are necessary.",
    )
    parser.add_argument("executable", help="Executable to start and monitor")
    parser.add_argument(
        "exec_args", nargs=argparse.REMAINDER, help="Arguments to executable"
    )
    args = parser.parse_args(argv[1:])
    if not args.executable:
        parser.error("executable not provided")
    return args


def setup_logging():
    """Sets up logging; simple: if debug mode is on, run at DEBUG; else, run at INFO"""
    logging.basicConfig(
        level=logging.DEBUG if _debug else logging.INFO,
        format="ministarter => %(levelname)-7s %(asctime)s|\t%(message)s",
    )


def main(argv=None) -> int:
    """Main function"""
    global _debug

    args = parse_args(argv or sys.argv)
    _debug = args.debug
    setup_logging()

    executable: str = args.executable
    exec_args: List[str] = args.exec_args
    collector_host: str = args.collector_host
    idtoken_file: str = args.idtoken_file
    must_advertise: bool = args.must_advertise
    watch_command: List[str] = args.watch_command
    job_id: str = args.job_id
    ad_file: Optional[str] = args.ads_to_file

    if not os.path.exists(executable):
        _log.error("Executable %s not found", executable)
        return ERR_NO_EXECUTABLE

    _log.info("Starting")

    try:
        with zipfile.ZipFile(sys.path[0], "r") as _:
            pass
    except (OSError, zipfile.BadZipFile) as err:
        _log_ml(
            logging.ERROR,
            "%s is not a .pyz or .zip file or can't be opened: %s",
            sys.path[0],
            err,
        )
        return ERR_NOT_ZIP

    if "_CONDOR_SCRATCH_DIR" in os.environ:
        _log.debug("We are in a condor job")
        scratch_dir = Path(os.environ["_CONDOR_SCRATCH_DIR"])
    else:
        _log.debug("We are not in a condor job")
        scratch_dir = Path.cwd()
    if _debug:
        _log_ml(
            logging.DEBUG,
            "Directory listing:\n%s",
            subprocess.run(
                shlex.split(
                    f"find '{scratch_dir}' -xdev "
                    "-name lost+found -prune -o "
                    "-name .git -prune -o "
                    "-name .*cache -prune -o "
                    "-ls",
                ),
                stdout=subprocess.PIPE,
                encoding="latin-1",
            ).stdout,
        )
    advertiser = Advertiser(collector_host, ad_file)
    try:
        advertiser.setup_condor(scratch_dir, idtoken_file)
    except AdvertiseSetupError as err:
        if must_advertise:
            raise
        else:
            _log.warning(
                "Setting up advertising failed with %s; advertising will not be available",
                err,
            )

    if job_id:
        advertiser.ad_template["MSJobId"] = f'"{job_id}"'

    abs_executable = os.path.abspath(executable)
    popen_args = [abs_executable] + exec_args
    advertiser.ad_template["CmdExecutable"] = f'"{abs_executable}"'
    # Send an initial advertisement with debugging on (if desired); this gives us
    # more info on why advertising might fail.
    advertiser.advertise({}, debug=_debug)

    _log.info("Starting command %r", executable)
    _log.debug("Full command: %r", popen_args)
    proc = subprocess.Popen(popen_args)
    advertiser.ad_template["CmdStartTime"] = f"{int(time.time())}"

    handler = functools.partial(handler_propagate_to_proc, proc=proc)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    completed = watch_job(advertiser, proc, watch_command)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    rc = completed.rc
    if rc == 0:
        _log.info("Command exited successfully")
    else:
        _log.warning("Command exited with nonzero return code %d", rc)

    rusage_me = resource.getrusage(resource.RUSAGE_SELF)
    rusage_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    rusage_ad = (
        "[ "
        f"UserCpu = {rusage_me.ru_utime + rusage_children.ru_utime}; "
        f"SysCpu = {rusage_me.ru_stime + rusage_children.ru_stime}; "
        "]"
    )
    ad = {
        "CmdIsAlive": "False",
        "MSResourceUsage": rusage_ad,
    }
    ad.update(completed.as_dict())
    advertiser.advertise(ad)

    _log.info("Done")
    return rc if rc >= 0 else 128 - rc  # rc is negative if there was a signal


if __name__ == "__main__":
    text = f"ministarter => Running version {VERSION}"
    print(text, file=sys.stdout)
    print(text, file=sys.stderr)
    _ret = ERR_UNKNOWN
    try:
        _ret = main()
    except AdvertiseSetupError as _err:
        _msg = "Setting up advertising failed with %s"
        if _debug:
            _log.exception(_msg, _err)
            _log.error("Sleeping for 60s before exiting")
            time.sleep(60)
        else:
            _log.error(_msg, _err)
        sys.exit(ERR_CANT_ADVERTISE)
    except Exception as _err:
        _log.critical("Unhandled exception %s; sleeping for 60s before exiting" % _err)
        time.sleep(60)
        raise
    sys.exit(_ret)


# vim:set ft=python
