#!/usr/bin/env python3
"""
Read and record MiniStarter ads from the CE's collector.
"""

# import glob
import json
import logging
import os

# import pathlib
import re

# import shutil
import sqlite3
import subprocess
import sys
import time
from argparse import ArgumentParser
from typing import Dict, List

# from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# local imports here


DEFAULT_DB = "msrecorder.db"
DEFAULT_DELAY_START = 15
DEFAULT_INTERVAL = 20
DEFAULT_ERROR_BACKOFF = 60

_log = logging.getLogger(__name__)


def create_table(con: sqlite3.Connection):
    """Create the table if it doesn't exist"""
    with con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS ads (
                jobid TEXT,
                timestamp TEXT,
                updatenum INTEGER,
                name TEXT,
                cmdexecutable TEXT,
                cmdisalive INTEGER,
                classad TEXT,
                PRIMARY KEY (jobid, timestamp)
            )
            """
        )


def get_condor_status() -> List[Dict]:
    try:
        result = subprocess.run(
            [
                "condor_ce_status",
                "-master",
                "-const",
                '!isUndefined(MSJobId) && MSJobId != "" && MSJobId != "unknown" && !isUndefined(MSReportTime)',
                "-json",
            ],
            encoding="latin-1",
            stdout=subprocess.PIPE,
            timeout=30,
            check=True,
        )
        result_str = result.stdout.strip()
        if not result_str:  # empty result
            return []
        result_json = json.loads(result_str)
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as err:
        _log.warning("error getting condor_ce_status: %s", err)
        return []
    if not isinstance(result_json, list):
        _log.warning(
            "unexpected result from condor_ce_status: %s...", result_str[0:100]
        )
        return []
    return result_json


def get_args(argv):
    """Parse and validate arguments"""
    parser = ArgumentParser()
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help="SQLite database file for recording events [%(default)s]",
    )
    parser.add_argument(
        "--interval",
        default=DEFAULT_INTERVAL,
        type=int,
        help="Interval between checks in seconds (daemon mode only) [%(default)s]",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run in a loop, checking every --interval seconds [%(default)s]",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging [%(default)s]",
    )
    parser.add_argument(
        "--delay-start",
        default=DEFAULT_DELAY_START,
        type=int,
        help="Wait for this many seconds before starting to query the collector; "
        "used for waiting for the collector to start up. (Daemon mode only.) "
        "[%(default)s]",
    )
    args = parser.parse_args(argv[1:])
    return args


def record_status(con: sqlite3.Connection) -> int:
    ads = get_condor_status()
    count = 0
    for ad in ads:
        if not re.match(r"\d+[.]\d+$", ad["MSJobId"]):
            continue
        with con:
            con.execute(
                """
                INSERT OR REPLACE INTO ads (
                    jobid,
                    timestamp,
                    updatenum,
                    name,
                    cmdexecutable,
                    cmdisalive,
                    classad
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ad["MSJobId"],
                    ad["MSReportTime"],
                    ad.get("UpdatesTotal", -1),
                    ad.get("Name", ""),
                    ad.get("CmdExecutable", ""),
                    ad.get("CmdIsAlive", -1),
                    json.dumps(ad, separators=(",", ":"), sort_keys=True),
                ),
            )
        count += 1
    return count


def main(argv=None):
    args = get_args(argv or sys.argv)
    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    error_backoff = DEFAULT_ERROR_BACKOFF

    con = sqlite3.connect(args.db)
    create_table(con)
    while True:
        try:
            count = record_status(con)
            _log.debug("recorded %d ads", count)
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            AttributeError,
            sqlite3.Error,
        ) as err:
            if args.daemon:
                _log.warning(
                    "%s(%s); backing off for %d s",
                    type(err),
                    err,
                    error_backoff,
                    exc_info=args.debug,
                )
                time.sleep(error_backoff)
            else:
                raise
        if not args.daemon:
            break
        time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
