"""
AegisDPI — Shared Offline Window Simulation
Simulates event replay, WindowAdmitter ingestion, 1 s ticks, 5 s sliding window,
and minimum event thresholding.
"""

import collections
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Set, Tuple
from window_logic import WindowAdmitter


def simulate_windows(
    events: Iterable[Any],
    local_ips: Set[str],
    tick_interval: float = 1.0,
    window_s: float = 5.0,
    min_events: int = 3,
    on_admitted_event: Optional[Callable[[float, str, Dict[str, Any]], None]] = None,
) -> Generator[Tuple[float, str, List[Dict[str, Any]]], None, None]:
    """
    Simulates real-time sliding windows over an event stream:
    - Ingests events ordered by timestamp using WindowAdmitter.
    - Steps from the first to the last event timestamp at `tick_interval`.
    - Prunes events older than `current_tick - window_s`.
    - Yields (current_tick, src_ip, list_of_event_dicts) for each source IP
      with at least `min_events` events in its active window.
    - Optional callback `on_admitted_event(ts, src_ip, event)` is called for each
      event admitted by WindowAdmitter.
    """
    if not isinstance(events, list):
        events_list = list(events)
    else:
        events_list = events

    if not events_list:
        return

    first_item = events_list[0]
    if isinstance(first_item, (tuple, list)):
        normalized_events = events_list
    elif isinstance(first_item, dict):
        normalized_events = [(float(e["ts"]), e) for e in events_list]
    else:
        raise ValueError("Unsupported event item type; expected tuple (ts, dict) or dict")

    # Ensure sorted by timestamp
    normalized_events.sort(key=lambda x: x[0])

    admitter = WindowAdmitter(local_ips)
    first_ts = normalized_events[0][0]
    last_ts = normalized_events[-1][0]
    total_events = len(normalized_events)

    ip_windows: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
    event_idx = 0

    current_tick = first_ts
    while current_tick <= last_ts:
        # Ingest events up to current_tick
        while event_idx < total_events and normalized_events[event_idx][0] <= current_tick:
            ts, event = normalized_events[event_idx]
            src_ip = admitter.admit(event, ts)
            if src_ip:
                if on_admitted_event is not None:
                    on_admitted_event(ts, src_ip, event)
                ip_windows[src_ip].append((ts, event))
            event_idx += 1

        # Expire stale flows in connection tracking
        admitter.expire_flows(current_tick)

        # Sliding window pruning and evaluation
        cutoff = current_tick - window_s
        active_ips = sorted(list(ip_windows.keys()))
        for src_ip in active_ips:
            window = ip_windows[src_ip]
            while window and window[0][0] < cutoff:
                window.popleft()

            if not window:
                del ip_windows[src_ip]
                continue

            if len(window) < min_events:
                continue

            event_dicts = [item[1] for item in window]
            yield (current_tick, src_ip, event_dicts)

        current_tick += tick_interval
