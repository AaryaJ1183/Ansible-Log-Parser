#!/usr/bin/env python3
"""
Ansible Log Compressor — streaming parser for LLM root cause analysis.

Usage:
    python parser.py <logfile>           # compressed output
    python parser.py <logfile> --verbose # includes host lists for ok/changed/skipped
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_PLAY = re.compile(r'^PLAY \[(.+?)\]')
RE_TASK = re.compile(r'^TASK \[(.+?)\]')

# Matches: ok/changed/skipped/failed/fatal: [host] or [host -> delegate]
# Optionally followed by => (item=...) or => { or => {...}
RE_RESULT = re.compile(
    r'^(ok|changed|skipped|failed|fatal)'
    r':\s+\[([^\]]+)\]'            # host (possibly "host -> delegate")
    r'(?:\s+=>\s+\(item=([^)]*)\))?'  # optional item
    r'(?:\s+=>\s+(\{.*))?'         # optional inline JSON payload start
    r'\s*$'
)

RE_IGNORING = re.compile(r'^\.\.\.(ignoring|FAILED - IGNORING)\s*$', re.IGNORECASE)

# ANSI escape code stripper
RE_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

# Connectivity-failure keywords
CONNECTIVITY_KEYWORDS = ('connection refused', 'timed out', 'timeout', 'unreachable')


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def strip_ansi(text: str) -> str:
    """Remove ANSI terminal escape codes from a string."""
    return RE_ANSI.sub('', text)


def normalize_error(raw: str) -> str:
    """Produce a stable grouping key from a raw error string."""
    return strip_ansi(raw).lower().strip()


def is_connectivity_failure(error: str) -> bool:
    """Return True when the normalized error looks like a connectivity issue."""
    low = error.lower()
    return any(kw in low for kw in CONNECTIVITY_KEYWORDS)


def extract_msg_from_json(payload: str) -> Optional[str]:
    """
    Try to extract the top-level 'msg' field from a JSON string.
    Returns None when the payload is not valid JSON or has no 'msg'.
    """
    try:
        data = json.loads(payload)
        if isinstance(data, dict) and 'msg' in data:
            return str(data['msg'])
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def parse_host_delegation(host_raw: str) -> tuple[str, Optional[str]]:
    """
    Split 'host -> delegate' notation.
    Returns (host, delegate_or_None).
    """
    if '->' in host_raw:
        parts = [p.strip() for p in host_raw.split('->', 1)]
        return parts[0], parts[1]
    return host_raw.strip(), None


# ---------------------------------------------------------------------------
# Brace-balanced multiline JSON collector
# ---------------------------------------------------------------------------

class BraceCollector:
    """
    Collects lines until the opening brace is balanced.
    Feed lines one at a time; call complete() to check if done.
    """

    def __init__(self, first_fragment: str):
        self._buf = first_fragment
        self._depth = first_fragment.count('{') - first_fragment.count('}')

    def feed(self, line: str) -> None:
        self._buf += '\n' + line
        self._depth += line.count('{') - line.count('}')

    def complete(self) -> bool:
        return self._depth <= 0

    def payload(self) -> str:
        return self._buf


# ---------------------------------------------------------------------------
# Per-task result aggregation
# ---------------------------------------------------------------------------

@dataclass
class FailureGroup:
    """
    Groups one or more hosts that share the same normalized error.
    Covers both 'failed' and 'fatal' result types.
    """
    error_key: str          # normalized, used as dict key
    raw_error: str          # first seen raw error (for display)
    hosts: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    ignored: bool = False
    result_type: str = 'failed'   # 'failed' or 'fatal'


@dataclass
class TaskAccumulator:
    """Holds everything collected while parsing a single task block."""
    name: str

    # Counts / host lists for non-failure outcomes
    ok_hosts: list[str] = field(default_factory=list)
    changed_hosts: list[str] = field(default_factory=list)
    skipped_hosts: list[str] = field(default_factory=list)

    # Keyed by normalized error string for deduplication
    failed_groups: dict[str, FailureGroup] = field(default_factory=dict)
    fatal_groups: dict[str, FailureGroup] = field(default_factory=dict)

    # The most recent failed/fatal group — used to attach 'ignored'
    last_failure_group: Optional[FailureGroup] = None

    def add_ok(self, host: str) -> None:
        self.ok_hosts.append(host)

    def add_changed(self, host: str) -> None:
        self.changed_hosts.append(host)

    def add_skipped(self, host: str) -> None:
        self.skipped_hosts.append(host)

    def add_failure(
        self,
        result_type: str,
        host: str,
        raw_error: str,
        command: Optional[str] = None,
    ) -> None:
        key = normalize_error(raw_error)
        store = self.failed_groups if result_type == 'failed' else self.fatal_groups
        if key not in store:
            store[key] = FailureGroup(
                error_key=key,
                raw_error=raw_error,
                result_type=result_type,
            )
        grp = store[key]
        if host not in grp.hosts:
            grp.hosts.append(host)
        if command and command not in grp.commands:
            grp.commands.append(command)
        self.last_failure_group = grp

    def mark_last_ignored(self) -> None:
        """Attach ignored=True to whichever failure/fatal was seen most recently."""
        if self.last_failure_group is not None:
            self.last_failure_group.ignored = True

    def to_dict(self, verbose: bool) -> dict:
        """Serialize the task to the output schema."""
        def outcome(hosts: list[str]) -> int | dict:
            if verbose:
                return {'count': len(hosts), 'hosts': hosts}
            return len(hosts)

        def serialize_groups(groups: dict[str, FailureGroup]) -> list[dict]:
            result = []
            for grp in groups.values():
                entry: dict = {
                    'hosts': grp.hosts,
                    'error': grp.raw_error,
                    'ignored': grp.ignored,
                }
                if grp.commands:
                    entry['commands'] = grp.commands
                result.append(entry)
            return result

        return {
            'task': self.name,
            'ok': outcome(self.ok_hosts),
            'changed': outcome(self.changed_hosts),
            'skipped': outcome(self.skipped_hosts),
            'failed': serialize_groups(self.failed_groups),
            'fatal': serialize_groups(self.fatal_groups),
        }


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class AnsibleLogParser:
    """
    Streaming Ansible log parser.  Reads the log file line-by-line and builds
    a compressed, LLM-friendly JSON structure.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

        # Current play / task context
        self._current_play: Optional[str] = None
        self._current_task: Optional[TaskAccumulator] = None

        # Output structure
        self._plays: list[dict] = []
        self._play_tasks: list[TaskAccumulator] = []  # tasks for current play

        # Multiline JSON collection state
        self._collector: Optional[BraceCollector] = None
        # Pending event context while collecting a multiline payload
        self._pending_result_type: Optional[str] = None
        self._pending_host: Optional[str] = None
        self._pending_command: Optional[str] = None
        self._pending_incomplete: bool = False

        # Global counters for the summary
        self._totals: dict[str, int] = {
            'ok': 0, 'changed': 0, 'skipped': 0, 'failed': 0,
            'fatal': 0, 'ignored': 0,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def parse(self, path: str) -> dict:
        """Parse the log file at *path* and return the compressed JSON dict."""
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for raw_line in fh:
                self._process_line(raw_line.rstrip('\n'))

        # Handle a multiline payload that reached EOF without closing
        if self._collector is not None:
            self._flush_collector(incomplete=True)

        # Close the last play
        self._close_play()

        return self._build_output()

    # ------------------------------------------------------------------
    # Line dispatcher
    # ------------------------------------------------------------------

    def _process_line(self, line: str) -> None:
        # If we are inside a multiline brace-balanced payload, feed the collector
        if self._collector is not None:
            self._collector.feed(line)
            if self._collector.complete():
                self._flush_collector(incomplete=False)
            return

        # --- PLAY boundary ---
        m = RE_PLAY.match(line)
        if m:
            self._on_play(m.group(1).strip())
            return

        # --- TASK boundary ---
        m = RE_TASK.match(line)
        if m:
            self._on_task(m.group(1).strip())
            return

        # --- ...ignoring line ---
        if RE_IGNORING.match(line):
            self._on_ignoring()
            return

        # --- Result line ---
        m = RE_RESULT.match(line)
        if m:
            self._on_result(
                status=m.group(1),
                host_raw=m.group(2),
                item=m.group(3),
                inline_json=m.group(4),
            )
            return

    # ------------------------------------------------------------------
    # Boundary handlers
    # ------------------------------------------------------------------

    def _on_play(self, name: str) -> None:
        self._close_play()
        self._current_play = name
        self._play_tasks = []
        self._current_task = None

    def _on_task(self, name: str) -> None:
        # Close the previous task (no-op if none)
        self._close_task()
        self._current_task = TaskAccumulator(name=name)

    def _on_ignoring(self) -> None:
        if self._current_task is not None:
            self._current_task.mark_last_ignored()
            self._totals['ignored'] += 1

    # ------------------------------------------------------------------
    # Result line handler
    # ------------------------------------------------------------------

    def _on_result(
        self,
        status: str,
        host_raw: str,
        item: Optional[str],
        inline_json: Optional[str],
    ) -> None:
        if self._current_task is None:
            # Results before any TASK line — create an anonymous task
            self._current_task = TaskAccumulator(name='(pre-task)')

        host, _delegate = parse_host_delegation(host_raw)

        if status in ('ok', 'changed', 'skipped'):
            # Successes: just count (and store host for --verbose)
            getattr(self._current_task, f'add_{status}')(host)
            self._totals[status] += 1
            return

        # status is 'failed' or 'fatal' — we need an error message
        if inline_json:
            stripped = inline_json.strip()
            if stripped == '{' or (stripped.startswith('{') and not stripped.endswith('}')):
                # Multiline payload begins here; defer until balanced
                self._collector = BraceCollector(stripped)
                self._pending_result_type = status
                self._pending_host = host
                self._pending_command = item
                return
            # Single-line JSON payload
            error = extract_msg_from_json(stripped) or strip_ansi(stripped)
        else:
            error = f'{status}: [{host_raw}]'

        self._record_failure(status, host, error, item)

    # ------------------------------------------------------------------
    # Multiline collector flush
    # ------------------------------------------------------------------

    def _flush_collector(self, incomplete: bool) -> None:
        """Resolve a completed (or EOF-truncated) multiline JSON payload."""
        payload = self._collector.payload()
        self._collector = None

        error = extract_msg_from_json(payload)
        if error is None:
            error = strip_ansi(payload[:200])  # cap to avoid huge error strings

        self._record_failure(
            self._pending_result_type,
            self._pending_host,
            error,
            self._pending_command,
            incomplete=incomplete,
        )
        # Clear pending state
        self._pending_result_type = None
        self._pending_host = None
        self._pending_command = None

    def _record_failure(
        self,
        status: str,
        host: str,
        error: str,
        command: Optional[str],
        incomplete: bool = False,
    ) -> None:
        """Add a failure/fatal event to the current task accumulator."""
        if self._current_task is None:
            self._current_task = TaskAccumulator(name='(pre-task)')

        self._current_task.add_failure(status, host, error, command)
        self._totals[status] += 1

        # Mark the freshly added group as incomplete if needed
        if incomplete and self._current_task.last_failure_group is not None:
            self._current_task.last_failure_group.raw_error += ' [incomplete payload]'

    # ------------------------------------------------------------------
    # Close helpers
    # ------------------------------------------------------------------

    def _close_task(self) -> None:
        if self._current_task is not None:
            self._play_tasks.append(self._current_task)
            self._current_task = None

    def _close_play(self) -> None:
        self._close_task()
        if self._current_play is not None:
            self._plays.append({
                'play': self._current_play,
                'tasks': [t.to_dict(self.verbose) for t in self._play_tasks],
            })
        self._current_play = None
        self._play_tasks = []

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------

    def _build_summary(self) -> dict:
        """Aggregate all failure groups across every play/task for the summary."""
        # Keyed by normalized error for cross-task deduplication
        failures_map: dict[str, dict] = {}
        connectivity_map: dict[str, dict] = {}

        for play in self._plays:
            for task in play.get('tasks', []):
                for entry in task.get('failed', []) + task.get('fatal', []):
                    key = normalize_error(entry['error'])
                    target = connectivity_map if is_connectivity_failure(key) else failures_map
                    if key not in target:
                        target[key] = {
                            'error': entry['error'],
                            'hosts': [],
                            'commands': [],
                            'ignored': entry['ignored'],
                            'occurrences': 0,
                        }
                    grp = target[key]
                    for h in entry['hosts']:
                        if h not in grp['hosts']:
                            grp['hosts'].append(h)
                    for c in entry.get('commands', []):
                        if c not in grp['commands']:
                            grp['commands'].append(c)
                    grp['occurrences'] += len(entry['hosts'])
                    # If any occurrence is NOT ignored, mark the group not ignored
                    if not entry['ignored']:
                        grp['ignored'] = False

        def clean(groups: dict) -> list[dict]:
            out = []
            for grp in groups.values():
                entry = {
                    'error': grp['error'],
                    'hosts': grp['hosts'],
                    'ignored': grp['ignored'],
                    'occurrences': grp['occurrences'],
                }
                if grp['commands']:
                    entry['commands'] = grp['commands']
                out.append(entry)
            return out

        return {
            'total': dict(self._totals),
            'failures': clean(failures_map),
            'connectivity_failures': clean(connectivity_map),
        }

    def _build_output(self) -> dict:
        return {
            'plays': self._plays,
            'summary': self._build_summary(),
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description='Streaming Ansible log compressor for LLM root-cause analysis.'
    )
    ap.add_argument('logfile', help='Path to the Ansible log file')
    ap.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Include host lists for ok/changed/skipped outcomes',
    )
    args = ap.parse_args()

    parser = AnsibleLogParser(verbose=args.verbose)
    try:
        result = parser.parse(args.logfile)
    except FileNotFoundError:
        sys.exit(f'Error: file not found — {args.logfile}')
    except OSError as exc:
        sys.exit(f'Error reading file: {exc}')

    # Compact JSON — tight separators reduce token count for LLM consumption
    print(json.dumps(result, separators=(',', ':'), indent=2))


if __name__ == '__main__':
    main()