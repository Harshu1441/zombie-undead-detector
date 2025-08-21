# Zombie Undead Detector

A robust, production-ready Python tool for detecting zombie and undead processes on Linux systems. This script identifies problematic processes using multiple heuristics, ignoring kernel threads, and provides detailed output in a compact ASCII table or JSON format. It supports daemon mode for continuous monitoring and container-aware detection.

## Description

`zombie_undead_detector.py` is a tool designed to detect zombie and other problematic (undead) processes on Linux systems. It uses a variety of heuristics beyond the kernel's `Z` flag to identify issues like defunct processes, resource ghosts, stuck processes, and more. The tool is optimized for performance, handles permissions gracefully, and includes logging and container-awareness to reduce false positives in environments like Docker or Kubernetes.

### Key Features
- **Multi-Heuristic Detection**: Identifies classic zombies, defunct-like processes, resource ghosts, stuck D-state processes, orphans, cgroup-throttled processes, and io_uring-stuck processes.
- **Kernel Thread Filtering**: Ignores kernel threads (e.g., `kworker`, `kthreadd`, `[bracketed]` names) to focus on user processes.
- **Persistence Checks**: Collects multiple snapshots to confirm process state persistence, reducing false positives.
- **Output Formats**: Displays a compact ASCII table and optionally writes detailed JSON reports.
- **Daemon Mode**: Supports continuous monitoring with configurable intervals.
- **Container Awareness**: Adjusts heuristics to handle container-specific processes (e.g., Docker `pause` processes).
- **Safe Operation**: No automatic remediation; optional `--kill` flag for testing with SIGTERM (use with caution).
- **Performance Optimized**: Handles large process counts with optional PID limits and efficient /proc parsing.
- **Logging**: Comprehensive logging with file rotation support for debugging and monitoring.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zombie-undead-detector.git
   cd zombie-undead-detector
   ```

2. Ensure Python 3.6+ is installed:
   ```bash
   python3 --version
   ```

3. No external dependencies are required, as the script uses only standard Python libraries.

4. (Optional) Run with root privileges for full /proc access:
   ```bash
   sudo python3 zombie_undead_detector.py
   ```

## Usage

Run the script with default settings (3 snapshots, 3-second intervals):
```bash
python3 zombie_undead_detector.py
```

### Command-Line Options
- `--iterations <n>`: Number of snapshots to collect (default: 3).
- `--interval <seconds>`: Seconds between snapshots (default: 3).
- `--min-zero-intervals <n>`: Minimum intervals with zero CPU usage for detection (default: 3).
- `--rss-threshold <bytes>`: RSS threshold considered "zero" (default: 1024).
- `--persist <n>`: Minimum snapshots a process must appear in (default: 2).
- `--json <file>`: Output detections to a JSON file.
- `--log-level <level>`: Logging level (DEBUG, INFO, WARNING, ERROR; default: INFO).
- `--log-file <file>`: Enable logging to a file with rotation.
- `--daemon`: Run in continuous monitoring mode.
- `--daemon-interval <seconds>`: Seconds between daemon cycles (default: 300).
- `--max-pids <n>`: Limit the number of processes scanned per snapshot.
- `--kill`: Attempt to SIGTERM detected processes (dangerous, requires confirmation).
- `--no-confirm`: Skip confirmation for `--kill` (use with extreme caution).
- `--version`: Show script version (2.2).

### Example
Run with 5 snapshots, 2-second intervals, and JSON output:
```bash
python3 zombie_undead_detector.py --iterations 5 --interval 2 --json detections.json
```

Run in daemon mode with logging to a file:
```bash
python3 zombie_undead_detector.py --daemon --log-file zombie.log --log-level DEBUG
```

### Example Output
```plaintext
PID    PPID  KINDS            STATE  RSS   CPUΔ  FDs  WCHAN        EXE                CMDLINE             CGROUP              TREE
-----  ----   spada ---------------  -----  ---- Facile ----  ---  -----------  -----------------  ------------------  ------------------  ------------------
1234   1     resource-ghost   Z      0.0B  0     0    do_exit      /usr/bin/python3                       0::/user.slice      1:init -> 1234:python3
5678   1     orphan,stuck-D   D      0.0B  0     2    sys_poll                        sleep 3600         0::/kubepods/abc    1:init -> 5678:sleep

Note: Heuristics are not foolproof; review detections manually, especially in container environments. May include idle processes.
```

## Notes
- **Root Privileges**: Running as root provides full access to /proc data. Without root, some fields (e.g., cgroups, fds) may be inaccessible.
- **Container Environments**: The tool detects if it’s running in a container and adjusts heuristics to avoid false positives (e.g., for `pause` processes).
- **Safety**: The `--kill` option is for testing only and requires manual confirmation unless `--no-confirm` is used. Use with extreme caution to avoid disrupting critical processes.
- **Performance**: Use `--max-pids` to limit scanning on systems with thousands of processes.


## Contributing
Contributions are welcome! Please submit issues or pull requests to the GitHub repository.
