"""ADR-0004 structured log parser.

The on-wire format is::

    <ts>\\t<module>\\t<event>\\t<key>=<value>[\\t<key>=<value>...]\\r\\n

* `ts` is the timestamp emitted by `log_event` (typically 8 hex chars =
  milliseconds since boot encoded as a 32-bit hex; the asm uses `log_hex`
  with width 8, which is the cheapest format to emit). The parser stores
  the raw token and a parsed integer interpretation.
* `module` and `event` are short ASCII identifiers (no whitespace).
* `key=value` pairs carry hex or decimal values; whitespace inside a value
  is forbidden by the ADR.

Lines that do not conform to the format (boot ROM noise, partial lines)
parse to `None`; the caller decides what to do with them.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable

# Strict line shape: ts<TAB>module<TAB>event[<TAB>key=value]*
LINE_RE = re.compile(
    r"^(?P<ts>[0-9a-fA-F]+)\t"
    r"(?P<module>[A-Za-z_][A-Za-z0-9_]*)\t"
    r"(?P<event>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<rest>(?:\t[^\t=\s]+=[^\t\s]+)*)\s*$"
)
KV_RE = re.compile(r"\t([^\t=]+)=([^\t]+)")


@dataclasses.dataclass(frozen=True)
class LogEvent:
    ts_raw: str
    ts_ms: int  # parsed as hex; consistent with `log_hex`-emitted timestamps
    module: str
    event: str
    fields: dict[str, str]
    raw: str

    def __getitem__(self, key: str) -> str:
        return self.fields[key]

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.fields.get(key, default)


def parse_line(line: str) -> LogEvent | None:
    """Parse one log line. Returns None for non-conforming input."""
    # Tolerate trailing CR/LF and surrounding whitespace.
    stripped = line.rstrip("\r\n").rstrip()
    if not stripped:
        return None
    m = LINE_RE.match(stripped)
    if not m:
        return None
    ts_raw = m.group("ts")
    try:
        ts_ms = int(ts_raw, 16)
    except ValueError:
        return None
    fields = dict(KV_RE.findall(m.group("rest")))
    return LogEvent(
        ts_raw=ts_raw,
        ts_ms=ts_ms,
        module=m.group("module"),
        event=m.group("event"),
        fields=fields,
        raw=stripped,
    )


def parse_lines(lines: Iterable[str]) -> list[LogEvent]:
    """Parse an iterable of lines, dropping non-conforming ones."""
    out: list[LogEvent] = []
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            out.append(ev)
    return out


def find_event(
    events: Iterable[LogEvent],
    *,
    module: str | None = None,
    event: str | None = None,
    **fields: str,
) -> LogEvent | None:
    """Return the first event matching all given selectors, or None.

    Each kwarg in `fields` must equal the event's same-named field. Use
    `find_event(events, module='kiss', event='rx_frame', dest='a1b2c3d4')`.
    """
    for ev in events:
        if module is not None and ev.module != module:
            continue
        if event is not None and ev.event != event:
            continue
        if any(ev.fields.get(k) != v for k, v in fields.items()):
            continue
        return ev
    return None


def find_all(
    events: Iterable[LogEvent],
    *,
    module: str | None = None,
    event: str | None = None,
    **fields: str,
) -> list[LogEvent]:
    """Return every event matching the selectors."""
    out: list[LogEvent] = []
    for ev in events:
        if module is not None and ev.module != module:
            continue
        if event is not None and ev.event != event:
            continue
        if any(ev.fields.get(k) != v for k, v in fields.items()):
            continue
        out.append(ev)
    return out


def assert_event(
    events: Iterable[LogEvent],
    *,
    module: str | None = None,
    event: str | None = None,
    **fields: str,
) -> LogEvent:
    """Like `find_event` but raises AssertionError if no match."""
    found = find_event(events, module=module, event=event, **fields)
    if found is None:
        selector = ", ".join(
            [f"module={module!r}" if module else "",
             f"event={event!r}" if event else ""]
            + [f"{k}={v!r}" for k, v in fields.items()]
        ).strip(", ")
        raise AssertionError(f"no log event matching {selector}")
    return found
