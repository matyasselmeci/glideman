"""
Helper for getting the contents of /proc/PID/stat
"""

import glob
import logging
import os
import re
from typing import List, NamedTuple, Optional, Union

# from ctypes import cdll


# libc = cdll.LoadLibrary("libc.so.6")


# XXX get these more safely
try:
    SC_CLK_TCK: int = int(os.popen("getconf CLK_TCK").read().strip())
except (OSError, ValueError):
    SC_CLK_TCK = 100
try:
    PAGESIZE: int = int(os.popen("getconf PAGESIZE").read().strip())
except (OSError, ValueError):
    PAGESIZE = 4096
# these don't work: libc._SC_CLK_TCK isn't defined (it's a macro)
# SC_CLK_TCK: int = libc.sysconf(libc._SC_CLK_TCK).value  # clock ticks per second
# PAGESIZE: int = libc.sysconf(libc._SC_PAGESIZE).value  # size of a page in bytes


class ProcStat(NamedTuple):
    pid: int
    comm: str
    state: str
    ppid: int
    pgrp: int
    session: int
    tty_nr: int
    tpgid: int
    flags: int
    minflt: int
    cminflt: int
    majflt: int
    cmajflt: int
    utime_ticks: int
    stime_ticks: int
    cutime_ticks: int
    cstime_ticks: int
    priority: int
    nice: int
    num_threads: int
    itrealvalue: int
    starttime_ticks: int
    vsize_bytes: int
    rss_pages: int
    rsslim: int
    startcode: int
    endcode: int
    startstack: int
    kstkesp: int
    kstkeip: int
    signal: int
    blocked: int
    sigignore: int
    sigcatch: int
    mchan: int
    nswap: int
    cnswap: int
    exit_signal: int
    processor: int
    rt_priority: int
    policy: int
    delayacct_blkio_ticks: int
    guest_time_ticks: int
    cguest_time_ticks: int

    @property
    def utime_seconds(self) -> float:
        return float(self.utime_ticks) / SC_CLK_TCK

    @property
    def stime_seconds(self) -> float:
        return float(self.stime_ticks) / SC_CLK_TCK

    @property
    def cutime_seconds(self) -> float:
        return float(self.cutime_ticks) / SC_CLK_TCK

    @property
    def cstime_seconds(self) -> float:
        return float(self.cstime_ticks) / SC_CLK_TCK

    @property
    def starttime_seconds(self) -> float:
        return float(self.starttime_ticks) / SC_CLK_TCK

    @property
    def rss_bytes(self) -> int:
        return self.rss_pages * PAGESIZE

    @property
    def delayacct_blkio_seconds(self) -> float:
        return float(self.delayacct_blkio_ticks) / SC_CLK_TCK

    @property
    def guest_time_seconds(self) -> float:
        return float(self.guest_time_ticks) / SC_CLK_TCK

    @property
    def cguest_time_seconds(self) -> float:
        return float(self.cguest_time_ticks) / SC_CLK_TCK


def get_cmdline(in_pid: Union[int, str]) -> List[str]:
    if not re.fullmatch(r"\d+|self", str(in_pid)):
        raise ValueError("invalid pid: must be a number or 'self'")

    with open(f"/proc/{in_pid}/cmdline", encoding="latin-1") as proc_cmdline_fh:
        cmdline_raw = proc_cmdline_fh.read()
        return cmdline_raw.split("\0")


def get_proc_stat(in_pid: Union[int, str]) -> ProcStat:
    if not re.fullmatch(r"\d+|self", str(in_pid)):
        raise ValueError("invalid pid: must be a number or 'self'")

    with open(
        f"/proc/{in_pid}/stat", encoding="ascii", errors="ignore"
    ) as proc_stat_fh:
        stat_str = proc_stat_fh.read()

    # /proc/PID/stat contains:
    # -  pid (int)
    # -  comm [command] (str, in parens, may contain spaces and parens inside)
    # -  state (char)
    # -  41 more ints on EL7; additional ones on newer OS's
    #
    # comm is the only str so we can assume the rightmost paren in the file
    # is the last character of comm, and it is followed by a space.
    left, _, right = stat_str.rpartition(") ")
    pid, comm = left.split(" ", 1)
    pid = int(pid)
    comm = comm + ")"
    rest = right.split(" ")
    state = rest[0]
    numbers = [int(field) for field in rest[1:]]

    procstat_args = [pid, comm, state] + numbers[0:41]

    assert len(procstat_args) == 44

    return ProcStat(*procstat_args)


class ProcInfo:
    """
    Class containing information about a process.

    Includes stat (ProcStat) and cmdline (command line as string list)
    """

    def __init__(self, stat: ProcStat, cmdline: List[str]):
        self.stat = stat
        self.cmdline = cmdline

    @classmethod
    def from_pid(cls, in_pid: Union[int, str]):
        self = cls(
            get_proc_stat(in_pid),
            get_cmdline(in_pid),
        )
        return self


class ProcFamily:
    """
    Class containing all the ProcStat information about an entire process family,
    starting at the pid given in the constructor.
    """

    def __init__(self, pid: int):
        self.log = logging.getLogger(__name__)
        self.family_procinfos: List[ProcInfo] = []
        self.family_pids: List[int] = []
        self._add_info_for_family(pid)

    @property
    def family_rss_bytes(self):
        return sum(pi.stat.rss_bytes for pi in self.family_procinfos)

    @property
    def family_count(self):
        return len(self.family_procinfos)

    def _add_info_for_family(
        self, rootpid: int, rootpid_procinfo: Optional[ProcInfo] = None
    ):
        """
        Recursively get and add ProcStat about a process, and all its
        children, grandchildren, etc. to self.family_procstats.  The pid will
        be added to self.family_pids.

        Does nothing if the pid is already in self.family_pids, or if the
        process doesn't exist.

        Args:
            rootpid: The pid whose family info to get
            rootpid_procinfo: The ProcInfo to add (descendenta only).
                If None, the ProcInfo will be obtained based on
                /proc/{rootpid}.

        Returns: None
        """
        if not os.path.exists(f"/proc/{rootpid}"):
            return

        if rootpid in self.family_pids:
            return

        try:
            if rootpid_procinfo is None:
                rootpid_procinfo = ProcInfo.from_pid(rootpid)
        except (OSError, ValueError) as err:
            self.log.warning("error getting stat for pid %d: %s", rootpid, err)
            return
        rootpid_procstat = rootpid_procinfo.stat
        if rootpid_procstat.pid != rootpid:  # uh what
            self.log.warning(
                f"given pid {rootpid} does not match pid from /proc/{rootpid}/stat {rootpid_procstat.pid}"
            )
            return
        self.family_procinfos.append(rootpid_procinfo)
        self.family_pids.append(rootpid_procstat.pid)

        for proc_dirent in glob.glob("/proc/[0-9]*"):
            if proc_dirent == "/proc/1":  # don't care about init
                continue

            try:
                child_procstat = get_proc_stat(proc_dirent[6:])
            except (OSError, ValueError):  # as err:
                ## I omit this debug message because it's way too frequent
                # _log.debug("error getting stat for child pid %d: %s", child_pid, err)
                continue

            if child_procstat.ppid == rootpid:
                child_cmdline = get_cmdline(child_procstat.pid)
                child_procinfo = ProcInfo(stat=child_procstat, cmdline=child_cmdline)
                # We needed to get the procstat anyway to find our parent so pass it
                # down so we don't read it again.
                self._add_info_for_family(child_procstat.pid, child_procinfo)
