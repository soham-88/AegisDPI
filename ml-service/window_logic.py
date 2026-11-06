"""
AegisDPI — Sliding Window Admission Logic
Encapsulates connection tracking flow table, packet filtering, and window admission decisions.
"""

import ipaddress
from collections import OrderedDict
from functools import lru_cache
from typing import Optional, Set, Iterable


@lru_cache(maxsize=8192)
def is_non_unicast(ip_str: str) -> bool:
    if not ip_str or ip_str == "255.255.255.255":
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_multicast
            or ip.is_link_local
            or ip.is_unspecified
            or ip_str == "255.255.255.255"
        )
    except ValueError:
        return True


class WindowAdmitter:
    """
    Decides for every dpi:logs event whether it feeds a source IP's sliding window.
    Maintains a connection tracking flow table to identify flow initiators.
    """

    def __init__(
        self,
        local_ips: Optional[Set[str]] = None,
        flow_table_ttl_s: float = 120.0,
        max_flow_entries: int = 50000,
    ):
        self.local_ips: Set[str] = set(local_ips) if local_ips is not None else set()
        self.flow_table_ttl_s: float = float(flow_table_ttl_s)
        self.max_flow_entries: int = int(max_flow_entries)
        # Connection tracking flow table:
        # key: (remote_ip, remote_port, local_port, protocol) or (remote_ip, protocol)
        # value: [initiator, last_seen, is_explicit] where initiator in {"local", "remote"}
        self.flow_table: OrderedDict = OrderedDict()

    def set_local_ips(self, ips: Iterable[str]) -> None:
        self.local_ips = set(ips)

    def expire_flows(self, now: float) -> None:
        """Expire flow table entries older than flow_table_ttl_s."""
        cutoff_flow = now - self.flow_table_ttl_s
        while self.flow_table:
            oldest_key, entry = next(iter(self.flow_table.items()))
            if entry[1] < cutoff_flow:
                self.flow_table.popitem(last=False)
            else:
                break

    def admit(self, data: dict, now: float) -> Optional[str]:
        """
        Evaluates event data and returns the source IP to admit into a sliding window,
        or None if the packet should be dropped/ignored.
        """
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dst_ip", "")
        if not src_ip:
            return None

        # 3. Skip non-unicast traffic (multicast, broadcast, link-local, unspecified)
        if is_non_unicast(src_ip) or is_non_unicast(dst_ip):
            return None

        src_is_local = src_ip in self.local_ips
        dst_is_local = dst_ip in self.local_ips

        # Local-to-local traffic never feeds any window
        if src_is_local and dst_is_local:
            return None

        src_port = int(data.get("src_port") or 0)
        dst_port = int(data.get("dst_port") or 0)
        protocol = str(data.get("protocol") or "")

        # 1. Connection tracking with fixed initiator & explicit evidence
        if src_is_local or dst_is_local:
            if src_is_local:
                remote_ip = dst_ip
                remote_port = dst_port
                local_port = src_port
            else:
                remote_ip = src_ip
                remote_port = src_port
                local_port = dst_port

            if remote_port == 0 and local_port == 0:
                flow_key = (remote_ip, protocol)
            else:
                flow_key = (remote_ip, remote_port, local_port, protocol)

            # Parse optional tcp_flags and icmp_type if present
            raw_tcp_flags = data.get("tcp_flags")
            tcp_flags_val = None
            if raw_tcp_flags is not None and str(raw_tcp_flags).strip() != "":
                try:
                    tcp_flags_val = int(raw_tcp_flags)
                except ValueError:
                    pass

            raw_icmp_type = data.get("icmp_type")
            icmp_type_val = None
            if raw_icmp_type is not None and str(raw_icmp_type).strip() != "":
                try:
                    icmp_type_val = int(raw_icmp_type)
                except ValueError:
                    pass

            is_icmp = protocol.upper() in ("1", "ICMP") or (icmp_type_val is not None and icmp_type_val >= 0)
            is_tcp = protocol.upper() in ("6", "TCP") or (tcp_flags_val is not None and tcp_flags_val > 0)

            candidate_initiator = None
            is_explicit = False

            if is_icmp and icmp_type_val is not None and icmp_type_val >= 0:
                # ICMP: echo/timestamp/info REQUEST types (8, 13, 15) -> initiator = sender
                if icmp_type_val in (8, 13, 15):
                    candidate_initiator = "local" if src_is_local else "remote"
                    is_explicit = True
                # Their REPLY types (0, 14, 16) -> initiator = receiver
                elif icmp_type_val in (0, 14, 16):
                    candidate_initiator = "local" if dst_is_local else "remote"
                    is_explicit = True
                else:
                    # Error types (3, 11, others) never create a remote-initiated flow
                    candidate_initiator = "local"
                    is_explicit = False
            elif is_tcp and tcp_flags_val is not None:
                is_syn = (tcp_flags_val & 0x02) != 0
                is_ack = (tcp_flags_val & 0x10) != 0
                if is_syn and not is_ack:
                    # SYN without ACK -> initiator = sender
                    candidate_initiator = "local" if src_is_local else "remote"
                    is_explicit = True
                elif is_syn and is_ack:
                    # SYN+ACK -> initiator = receiver
                    candidate_initiator = "local" if dst_is_local else "remote"
                    is_explicit = True
                else:
                    # Other packets: existing first-seen rule
                    candidate_initiator = "local" if src_is_local else "remote"
                    is_explicit = False
            else:
                # UDP, other protocols, or older log entries without new fields: existing first-seen rule
                candidate_initiator = "local" if src_is_local else "remote"
                is_explicit = False

            entry = self.flow_table.get(flow_key)
            if entry is None:
                self.flow_table[flow_key] = [candidate_initiator, now, is_explicit]
                initiator = candidate_initiator
                if len(self.flow_table) > self.max_flow_entries:
                    self.flow_table.popitem(last=False)
            else:
                current_is_explicit = entry[2] if len(entry) > 2 else False
                if is_explicit:
                    # Explicit evidence (request type or SYN) OVERRIDES an earlier first-seen guess
                    entry[0] = candidate_initiator
                    if len(entry) > 2:
                        entry[2] = True
                    else:
                        entry.append(True)
                    initiator = candidate_initiator
                else:
                    # First-seen never overrides explicit evidence
                    initiator = entry[0]
                entry[1] = now
                self.flow_table.move_to_end(flow_key)

            # Local-sourced packets never feed any window
            if src_is_local:
                return None

            # Inbound packet (dst LOCAL) feeds window only if flow initiator == "remote"
            if initiator != "remote":
                return None

        return src_ip

