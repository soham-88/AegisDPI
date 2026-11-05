#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 {up|down|status|attack [N]}"
    exit 1
}

cmd_up() {
    # 0. Check dependencies
    if ! command -v ethtool &>/dev/null; then
        echo "Error: ethtool is not installed. Please install it using: sudo apt install -y ethtool" >&2
        exit 1
    fi

    # 1. Remove old leftovers if present
    if sudo ip netns list 2>/dev/null | grep -qw "ns_admin"; then
        sudo ip netns del ns_admin
    fi
    if ip link show veth_ctrl_host &>/dev/null; then
        sudo ip link del veth_ctrl_host
    fi
    if ip link show veth_admin &>/dev/null; then
        sudo ip link del veth_admin
    fi

    # 2. Create namespace ns_attacker if missing
    if ! sudo ip netns list 2>/dev/null | grep -qw "ns_attacker"; then
        sudo ip netns add ns_attacker
    fi

    # 3. Ensure loopback is up inside ns_attacker
    sudo ip netns exec ns_attacker ip link set lo up

    # 4. Create veth pair if veth_lab missing
    if ! ip link show veth_lab &>/dev/null; then
        sudo ip link add veth_lab type veth peer name veth_attacker
        sudo ip link set veth_attacker netns ns_attacker
    fi

    # 5. If veth_attacker was left in host namespace, move it
    if ip link show veth_attacker &>/dev/null; then
        sudo ip link set veth_attacker netns ns_attacker
    fi

    # 6. Configure host end (veth_lab: 10.10.0.1/24)
    if ! ip -4 addr show dev veth_lab 2>/dev/null | grep -qw "10.10.0.1/24"; then
        sudo ip addr add 10.10.0.1/24 dev veth_lab
    fi
    sudo ip link set veth_lab up

    # 7. Configure namespace end (veth_attacker: 10.10.0.2/24 and secondaries)
    if ! sudo ip netns exec ns_attacker ip -4 addr show dev veth_attacker 2>/dev/null | grep -qw "10.10.0.2/24"; then
        sudo ip netns exec ns_attacker ip addr add 10.10.0.2/24 dev veth_attacker
    fi
    for ip in 10.10.0.3/24 10.10.0.4/24 10.10.0.5/24 10.10.0.6/24; do
        if ! sudo ip netns exec ns_attacker ip -4 addr show dev veth_attacker 2>/dev/null | grep -qw "${ip}"; then
            sudo ip netns exec ns_attacker ip addr add "${ip}" dev veth_attacker
        fi
    done
    sudo ip netns exec ns_attacker ip link set veth_attacker up

    # 8. Disable packet offloads on both ends (IDS best practice)
    # When offloads (TSO/GSO/GRO) are enabled, the Linux network stack coalesces packets into
    # "super-packets" up to 64 KB instead of real on-wire packets (<= 1514 bytes).
    # For example, a 20 MB file download appears as a few hundred frames instead of ~14,000,
    # distorting packet-rate, flow duration, and packet-size distributions used by the ML anomaly detector.
    # In accordance with Suricata/Snort IDS best practices, disable offloads on capture interfaces.
    echo "Configuring offload settings on veth interfaces..."
    for feat in tso gso gro lro; do
        if ! sudo ethtool -K veth_lab "${feat}" off 2>/dev/null; then
            echo "Warning: failed to disable ${feat} offload on veth_lab (may be unsupported or fixed)." >&2
        fi
        if ! sudo ip netns exec ns_attacker ethtool -K veth_attacker "${feat}" off 2>/dev/null; then
            echo "Warning: failed to disable ${feat} offload on veth_attacker (may be unsupported or fixed)." >&2
        fi
    done

    # 9. Output addresses and offload status
    ip -br addr show veth_lab
    sudo ip netns exec ns_attacker ip -br addr

    echo "=== Offload Features (veth_lab) ==="
    sudo ethtool -k veth_lab | grep -E "tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload"
    echo "=== Offload Features (veth_attacker) ==="
    sudo ip netns exec ns_attacker ethtool -k veth_attacker | grep -E "tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload"
}

cmd_down() {
    if sudo ip netns list 2>/dev/null | grep -qw "ns_attacker"; then
        sudo ip netns del ns_attacker
    fi
    if ip link show veth_lab &>/dev/null; then
        sudo ip link del veth_lab
    fi
    if sudo ip netns list 2>/dev/null | grep -qw "ns_admin"; then
        sudo ip netns del ns_admin
    fi
    if ip link show veth_ctrl_host &>/dev/null; then
        sudo ip link del veth_ctrl_host
    fi
    if ip link show veth_admin &>/dev/null; then
        sudo ip link del veth_admin
    fi
    echo "Lab topology torn down."
}

cmd_status() {
    echo "=== Lab Status ==="
    if sudo ip netns list 2>/dev/null | grep -qw "ns_attacker"; then
        echo "Namespace ns_attacker: ACTIVE"
        sudo ip netns exec ns_attacker ip -br addr
    else
        echo "Namespace ns_attacker: NOT FOUND"
    fi

    if ip link show veth_lab &>/dev/null; then
        echo "Host interface veth_lab: ACTIVE"
        ip -br addr show veth_lab
    else
        echo "Host interface veth_lab: NOT FOUND"
    fi
}

cmd_attack() {
    local count="${1:-3000}"
    sudo ip netns exec ns_attacker ping -f -c "${count}" 10.10.0.1
}

case "${1:-}" in
    up)
        cmd_up
        ;;
    down)
        cmd_down
        ;;
    status)
        cmd_status
        ;;
    attack)
        shift || true
        cmd_attack "${1:-3000}"
        ;;
    *)
        usage
        ;;
esac
