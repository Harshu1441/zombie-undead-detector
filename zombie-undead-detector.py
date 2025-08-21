from __future__ import annotations
import os
import re
import time
import json
import argparse
import logging
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import logging.handlers

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

KERNEL_COMM_RE = re.compile(
    r"^(?:\[[^\]]+\]|kthreadd|kworker|rcu_|migration|ksoftirqd|watchdog|kswapd|jbd2/|scsi_eh_|irq/|oom_reaper|kdevtmpfs|kcompactd|khungtaskd)",
    re.IGNORECASE,
)

# ---------------- Data containers ---------------- #

@dataclass
class Sample:
    pid: int
    ppid: int
    comm: str
    name: str  # from /proc/<pid>/status Name (fallback)
    cmdline: str
    exe: str
    rss: int  # bytes
    cpu_ticks: int  # utime+stime
    fd_count: Optional[int]
    wchan: str
    state: str  # single letter state from stat (R,S,D,Z,...)
    threads: Optional[int]
    cgroup: str  # from /proc/<pid>/cgroup
    throttled_count: int  # from /proc/<pid>/sched nr_throttled
    ts: float

@dataclass
class Detection:
    pid: int
    ppid: int
    comm: str
    cmdline: str
    exe: str
    fd_targets: List[str]
    rss: int
    cpu_delta_ticks: int
    seen_intervals: int
    kinds: List[str]
    wchan: str
    last_state: str
    first_seen_ts: float
    last_seen_ts: float
    tree: str
    cgroup: str

# ---------------- /proc readers ----------------- #

def list_pids() -> List[int]:
    try:
        return [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except Exception as e:
        logging.error(f"Failed to list pids: {e}")
        return []

def parse_proc_stat(pid: int) -> Optional[Tuple[str, str, int, int, int, int]]:
    """Return (comm, state, ppid, utime, stime, starttime) or None"""
    path = f"/proc/{pid}/stat"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        first_paren = data.find('(')
        last_paren = data.rfind(')')
        comm = data[first_paren+1:last_paren]
        rest = data[last_paren+2:].split()
        state = rest[0]
        ppid = int(rest[1])
        utime = int(rest[11])
        stime = int(rest[12])
        start = int(rest[19])
        return (comm, state, ppid, utime, stime, start)
    except Exception as e:
        logging.debug(f"Failed to parse stat for {pid}: {e}")
        return None

def read_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        return raw.replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
    except Exception as e:
        logging.debug(f"Failed to read cmdline for {pid}: {e}")
        return ""

def read_status_fields(pid: int) -> Dict[str, str]:
    out = {}
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ':' in ln:
                    k, v = ln.split(':', 1)
                    out[k.strip()] = v.strip()
    except Exception as e:
        logging.debug(f"Failed to read status for {pid}: {e}")
    return out

def read_statm_rss_bytes(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/statm", "r", encoding="utf-8", errors="ignore") as f:
            parts = f.read().split()
            if len(parts) >= 2:
                return int(parts[1]) * PAGE_SIZE
    except Exception:
        pass
    # fallback try VmRSS
    st = read_status_fields(pid)
    if 'VmRSS' in st:
        try:
            return int(st['VmRSS'].split()[0]) * 1024
        except Exception:
            pass
    return 0

def count_fds(pid: int) -> Optional[int]:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except Exception as e:
        logging.debug(f"Failed to count fds for {pid}: {e}")
        return None

def read_wchan(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/wchan", "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception as e:
        logging.debug(f"Failed to read wchan for {pid}: {e}")
        return ""

def read_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception as e:
        logging.debug(f"Failed to read exe for {pid}: {e}")
        return ""

def read_fd_targets(pid: int, limit: int = 20) -> List[str]:
    out = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        for i, fd in enumerate(os.listdir(fd_dir)):
            if i >= limit:
                break
            try:
                tgt = os.readlink(os.path.join(fd_dir, fd))
            except Exception:
                tgt = ""
            out.append(tgt)
    except Exception as e:
        logging.debug(f"Failed to read fds for {pid}: {e}")
    return out

def read_cgroup(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception as e:
        logging.debug(f"Failed to read cgroup for {pid}: {e}")
        return ""

def read_throttled_count(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/sched", "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if 'nr_throttled' in ln:
                    return int(ln.split()[-1])
    except Exception as e:
        logging.debug(f"Failed to read sched for {pid}: {e}")
    return 0

# ---------- Kernel ignore predicate ---------- #

def is_kernel_proc(comm: str, ppid: int) -> bool:
    if comm is None:
        return True
    if comm.startswith('[') and comm.endswith(']'):
        return True
    if ppid == 2:
        return True
    if KERNEL_COMM_RE.match(comm):
        return True
    if comm.lower() == 'kthreadd':
        return True
    return False

# ---------------- Snapshot collector ---------------- #

def collect_snapshot(max_pids: Optional[int] = None) -> Tuple[Dict[int, Sample], float]:
    start_time = time.time()
    now = time.time()
    samples: Dict[int, Sample] = {}
    pids = list_pids()
    if max_pids and len(pids) > max_pids:
        logging.warning(f"Too many processes ({len(pids)}), sampling only {max_pids}")
        pids = pids[:max_pids]  # Simple sampling; could be random
    for pid in pids:
        stat = parse_proc_stat(pid)
        if not stat:
            continue
        comm, state, ppid, utime, stime, start = stat
        cmdline = read_cmdline(pid)
        exe = read_exe(pid)
        rss = read_statm_rss_bytes(pid)
        fdn = count_fds(pid)
        wchan = read_wchan(pid)
        status_fields = read_status_fields(pid)
        threads = None
        if 'Threads' in status_fields:
            try:
                threads = int(status_fields['Threads'])
            except Exception:
                threads = None
        cgroup = read_cgroup(pid)
        throttled_count = read_throttled_count(pid)
        samples[pid] = Sample(
            pid=pid,
            ppid=ppid,
            comm=comm,
            name=status_fields.get('Name', comm),
            cmdline=cmdline,
            exe=exe,
            rss=rss,
            cpu_ticks=utime + stime,
            fd_count=fdn,
            wchan=wchan,
            state=state,
            threads=threads,
            cgroup=cgroup,
            throttled_count=throttled_count,
            ts=now
        )
    duration = time.time() - start_time
    logging.info(f"Snapshot collection took {duration:.2f} seconds for {len(samples)} processes")
    return samples, now

# ---------------- Detection logic ---------------- #

def detect(
    snapshots: List[Tuple[Dict[int, Sample], float]],
    min_zero_intervals: int = 3,
    rss_threshold: int = 1024,
    require_persistence: int = 2,
    in_container: bool = False,
) -> List[Detection]:
    if len(snapshots) < 1:
        return []
    # Build timeline per pid
    pid_history: Dict[int, List[Sample]] = {}
    for snap, ts in snapshots:
        for pid, s in snap.items():
            pid_history.setdefault(pid, []).append(s)
    last_snap_samples = snapshots[-1][0]
    last_pids = set(last_snap_samples.keys())
    detections: List[Detection] = []
    for pid, samples in pid_history.items():
        # Skip kernel processes entirely
        first = samples[0]
        if is_kernel_proc(first.comm, first.ppid):
            continue
        # Must persist across snapshots
        if len(samples) < require_persistence:
            continue
        # Compute deltas and checks
        cpu_zero_intervals = 0
        total_intervals = 0
        rss_all_zero = True
        state_all_D = True
        wchans = set()
        cmdline_empty_all = True
        fd_zero_all = True
        classic_z_present = False
        defunct_hint = False
        throttled = False
        io_uring_hint = False
        for i in range(1, len(samples)):
            prev = samples[i-1]
            cur = samples[i]
            total_intervals += 1
            delta_cpu = cur.cpu_ticks - prev.cpu_ticks
            if delta_cpu <= 0:
                cpu_zero_intervals += 1
            if cur.rss > rss_threshold or prev.rss > rss_threshold:
                rss_all_zero = False
            if cur.state != 'D':
                state_all_D = False
            wchans.add(cur.wchan)
            if cur.cmdline:
                cmdline_empty_all = False
            if cur.fd_count and cur.fd_count > 0:
                fd_zero_all = False
            if cur.state == 'Z':
                classic_z_present = True
            if 'defunct' in cur.name.lower() or 'defunct' in cur.comm.lower():
                defunct_hint = True
            if cur.throttled_count > prev.throttled_count:
                throttled = True
        first_ts = samples[0].ts
        last_ts = samples[-1].ts
        last_sample = samples[-1]
        fd_targets = read_fd_targets(pid, limit=20)
        # Check for modern I/O like io_uring
        io_uring_hint = any('anon_inode:[io_uring]' in t for t in fd_targets)
        # Heuristic checks
        kinds: List[str] = []
        if classic_z_present:
            kinds.append('classic-z')
        if cmdline_empty_all and (defunct_hint or fd_zero_all):
            kinds.append('defunct-like')
        if cpu_zero_intervals >= min_zero_intervals and rss_all_zero and cmdline_empty_all:
            kinds.append('resource-ghost')
        if state_all_D and len(wchans) == 1 and cpu_zero_intervals >= min_zero_intervals:
            kinds.append('stuck-D')
        parent_missing = (last_sample.ppid not in last_pids and last_sample.ppid != 0)
        reparented_to_init = (last_sample.ppid == 1)
        if parent_missing or reparented_to_init:
            # Avoid false positives for container pause processes
            if not (in_container and ('pause' in last_sample.comm.lower() or 'docker' in last_sample.cgroup or 'kubepods' in last_sample.cgroup)):
                kinds.append('orphan')
        fd_pipe_hint = any(('pipe:' in t or 'fifo' in t or 'socket:' in t or 'anon_inode:' in t) for t in fd_targets)
        if fd_pipe_hint and cmdline_empty_all:
            kinds.append('fd-hung')
        if throttled and cpu_zero_intervals >= min_zero_intervals:
            kinds.append('cgroup-throttled')
        if io_uring_hint and cpu_zero_intervals >= min_zero_intervals:
            kinds.append('io-uring-stuck')
        if not kinds:
            continue
        cpu_delta = samples[-1].cpu_ticks - samples[0].cpu_ticks
        tree = build_tree(pid, last_snap_samples)
        det = Detection(
            pid=pid,
            ppid=last_sample.ppid,
            comm=last_sample.comm,
            cmdline=last_sample.cmdline,
            exe=last_sample.exe,
            fd_targets=fd_targets,
            rss=last_sample.rss,
            cpu_delta_ticks=cpu_delta,
            seen_intervals=len(samples),
            kinds=kinds,
            wchan=last_sample.wchan,
            last_state=last_sample.state,
            first_seen_ts=first_ts,
            last_seen_ts=last_ts,
            tree=tree,
            cgroup=last_sample.cgroup,
        )
        detections.append(det)
    detections.sort(key=lambda d: (','.join(d.kinds), d.pid))
    return detections

# ---------- process tree builder ---------- #

def build_tree(pid: int, last_samples: Dict[int, Sample]) -> str:
    parts = []
    cur = pid
    visited = set()
    while True:
        if cur in visited:
            parts.append(f"{cur}:<loop>")
            break
        visited.add(cur)
        s = last_samples.get(cur)
        if s:
            parts.append(f"{cur}:{s.comm}")
            if s.ppid == 0 or s.ppid == cur:
                break
            cur = s.ppid
        else:
            try:
                stat = parse_proc_stat(cur)
                if not stat:
                    parts.append(f"{cur}:<gone>")
                    break
                comm, state, ppid, _, _, _ = stat
                parts.append(f"{cur}:{comm}")
                if ppid == 0 or ppid == cur:
                    break
                cur = ppid
            except Exception:
                parts.append(f"{cur}:<unknown>")
                break
    return " -> ".join(reversed(parts))

# ---------------- table printer ---------------- #

def print_table(detections: List[Detection]):
    if not detections:
        return
    headers = ["PID", "PPID", "KINDS", "STATE", "RSS", "CPUΔ", "FDs", "WCHAN", "EXE", "CMDLINE", "CGROUP", "TREE"]
    rows = []
    for d in detections:
        rows.append([
            str(d.pid),
            str(d.ppid),
            ",".join(d.kinds),
            d.last_state,
            human_size(d.rss),
            str(d.cpu_delta_ticks),
            str(len(d.fd_targets) if d.fd_targets else 0),
            d.wchan or "",
            (d.exe or "")[:80],
            (d.cmdline or "")[:80],
            (d.cgroup or "")[:80],
            (d.tree or "")[:80]
        ])
    # col widths
    widths = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]
    sep = "  "
    # header
    hdr = sep.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print("\n" + hdr)
    print("-" * (sum(widths) + len(sep) * (len(headers) - 1)))
    for r in rows:
        print(sep.join(r[i].ljust(widths[i]) for i in range(len(headers))))
    print("\nNote: Heuristics are not foolproof; review detections manually, especially in container environments. May include idle processes.")

def human_size(n: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    f = float(n)
    for u in units:
        if f < 1024.0:
            return f"{f:.1f}{u}"
        f /= 1024.0
    return f"{f:.1f}PB"

# ---------------- Container check ---------------- #

def is_in_container() -> bool:
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if 'docker' in content or 'kubepods' in content:
                return True
    except Exception:
        pass
    return False

# ---------------- CLI & main ----------------- #

def main():
    in_container = is_in_container()
    if os.getuid() != 0:
        logging.warning("Running without root privileges. Some /proc data may be inaccessible.")
    if in_container:
        logging.info("Detected running inside a container. Results may be namespace-specific. Adjusting orphan heuristic to reduce false positives.")

    ap = argparse.ArgumentParser(description="Smart user-level undead detector (multi-check, ignore kernel threads).")
    ap.add_argument("--iterations", type=int, default=3, help="Snapshots to collect (>=1).")
    ap.add_argument("--interval", type=int, default=3, help="Seconds between snapshots.")
    ap.add_argument("--min-zero-intervals", type=int, default=3, help="Min zero-CPU intervals for resource checks.")
    ap.add_argument("--rss-threshold", type=int, default=1024, help="RSS threshold (bytes) considered zero.")
    ap.add_argument("--persist", type=int, default=2, help="Minimum snapshots process must appear in to be reported.")
    ap.add_argument("--json", type=str, default=None, help="Optional JSON output file.")
    ap.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR).")
    ap.add_argument("--log-file", type=str, default=None, help="Log file for output (enables rotation).")
    ap.add_argument("--daemon", action="store_true", help="Run in daemon mode (continuous monitoring).")
    ap.add_argument("--daemon-interval", type=int, default=300, help="Seconds between daemon cycles (default: 300).")
    ap.add_argument("--max-pids", type=int, default=None, help="Max processes to scan per snapshot (for performance; default: all).")
    ap.add_argument("--kill", action="store_true", help="Attempt to kill detected processes with SIGTERM after confirmation (DANGEROUS, use with caution in test/dev only).")
    ap.add_argument("--no-confirm", action="store_true", help="Skip confirmation for --kill (even more dangerous).")
    ap.add_argument("--version", action="version", version="%(prog)s 2.2")
    args = ap.parse_args()

    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s - %(levelname)s - %(message)s")
    if args.log_file:
        handler = logging.handlers.RotatingFileHandler(args.log_file, maxBytes=10**6, backupCount=5)
        logging.getLogger().addHandler(handler)
    if args.daemon and args.log_level.upper() == "INFO":
        logging.getLogger().setLevel(logging.WARNING)
        logging.warning("Daemon mode: Set log level to WARNING to reduce output; use --log-level DEBUG for more details.")

    if args.iterations < 1:
        ap.error("iterations must be >= 1")

    if args.kill:
        print("\nWARNING: --kill is enabled. This will attempt to SIGTERM detected processes after manual confirmation (unless --no-confirm). Use ONLY in test/dev environments!\n")

    while True:
        snapshots: List[Tuple[Dict[int, Sample], float]] = []
        for i in range(args.iterations):
            snap, ts = collect_snapshot(max_pids=args.max_pids)
            snapshots.append((snap, ts))
            logging.info(f"Collected snapshot {i+1}/{args.iterations}")
            if i != args.iterations - 1:
                time.sleep(args.interval)

        detections = detect(
            snapshots,
            min_zero_intervals=args.min_zero_intervals,
            rss_threshold=args.rss_threshold,
            require_persistence=args.persist,
            in_container=in_container,
        )
        if detections or not args.daemon:
            print_table(detections)
        else:
            logging.info("No detections in this cycle.")

        if args.json:
            timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            json_file = args.json
            if args.daemon:
                json_file = f"{args.json.rsplit('.', 1)[0]}_{timestamp}.json" if '.' in args.json else f"{args.json}_{timestamp}.json"
            out = {
                "generated_at": time.time(),
                "iterations": args.iterations,
                "interval": args.interval,
                "detections": [asdict(d) for d in detections],
            }
            try:
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(out, f, indent=2)
                logging.info(f"JSON written to {json_file}")
            except Exception as e:
                logging.error(f"Failed to write JSON: {e}")

        if args.kill:
            for d in detections:
                if not args.no_confirm:
                    confirm = input(f"Confirm kill PID {d.pid} ({','.join(d.kinds)}) with SIGTERM? (y/n): ").lower()
                    if confirm != 'y':
                        logging.info(f"Skipped killing PID {d.pid}")
                        continue
                try:
                    os.kill(d.pid, 15)  # SIGTERM
                    logging.warning(f"SIGTERM sent to PID {d.pid} ({','.join(d.kinds)})")
                except Exception as e:
                    logging.error(f"Failed to send SIGTERM to {d.pid}: {e}")

        if not args.daemon:
            break
        time.sleep(args.daemon_interval)  # Configurable throttling

if __name__ == "__main__":
    main()
