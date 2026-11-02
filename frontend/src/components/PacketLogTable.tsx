import React, { useState, useMemo, useEffect } from "react";
import { TableVirtuoso } from "react-virtuoso";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import { DpiLogEntry } from "@/types/aegis";
import { api } from "@/lib/api";
import {
  Search,
  Filter,
  ShieldAlert,
  Info,
  Network,
  Play,
  Square,
  ChevronDown,
  ChevronUp,
  Terminal,
  AlertCircle,
  Radio,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";

function matchesSearchToken(log: DpiLogEntry, token: string): boolean {
  const colonIdx = token.indexOf(":");
  if (colonIdx !== -1) {
    const key = token.slice(0, colonIdx).toLowerCase();
    const val = token.slice(colonIdx + 1).toLowerCase();
    if (!val) return true; // empty value after colon, ignore

    if (key === "ip") {
      return (
        log.src_ip.toLowerCase().includes(val) ||
        log.dst_ip.toLowerCase().includes(val)
      );
    }
    if (key === "src") {
      return log.src_ip.toLowerCase().includes(val);
    }
    if (key === "dst") {
      return log.dst_ip.toLowerCase().includes(val);
    }
    if (key === "port") {
      const portNum = parseInt(val, 10);
      if (isNaN(portNum) || portNum < 0) return true; // invalid port ignored
      return log.src_port === portNum || log.dst_port === portNum;
    }
    if (key === "sni") {
      return log.sni.toLowerCase().includes(val);
    }
    if (key === "proto") {
      return log.protocol.toLowerCase() === val;
    }
    if (key === "action") {
      return log.action.toLowerCase() === val;
    }
  }

  // Free text token: matches 5 existing fields + src_port + dst_port
  const q = token.toLowerCase();
  return (
    log.src_ip.toLowerCase().includes(q) ||
    log.dst_ip.toLowerCase().includes(q) ||
    log.sni.toLowerCase().includes(q) ||
    log.reason.toLowerCase().includes(q) ||
    log.protocol.toLowerCase().includes(q) ||
    String(log.src_port).includes(q) ||
    String(log.dst_port).includes(q)
  );
}

function formatKernelEnforcement(
  action: "FORWARD" | "DROP" | "UNHANDLED",
  reason: string,
  protocol?: string,
  l3?: string
): string {
  if (protocol?.toUpperCase() === "ARP" || l3 === "arp") {
    return "Not filtered: the nftables inet table does not apply to ARP";
  }
  if (action === "FORWARD") {
    return "Passed inspection - no rule matched";
  }
  if (action === "UNHANDLED") {
    return `Not deep-inspected (${reason || "unhandled"})`;
  }
  // DROP
  let plainReason = reason || "unknown";
  const rLower = plainReason.toLowerCase();
  if (rLower === "blocklist:ip" || rLower.includes("blocklist")) {
    plainReason = "source IP is in the nftables blocklist set";
  } else if (rLower === "malformed_ethernet") {
    plainReason = "malformed frame";
  } else if (rLower === "malformed_ip") {
    plainReason = "malformed IP header";
  } else if (rLower === "malformed_tcp") {
    plainReason = "malformed TCP header";
  } else if (rLower === "non_ipv4") {
    plainReason = "non-IPv4 packet";
  }
  return `Dropped: ${plainReason}`;
}

function hasPort(protocol: string): boolean {
  const p = (protocol || "").toUpperCase();
  return p !== "ICMP" && p !== "OTHER" && p !== "ARP" && p !== "IPV6";
}

function formatUptime(startedAt?: number): string {
  if (!startedAt) return "00:00:00";
  const startMs = startedAt < 1e11 ? startedAt * 1000 : startedAt;
  const sec = Math.max(0, Math.floor((Date.now() - startMs) / 1000));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

function isLocalOrLoopback(ip: string, ifaceList: { name: string; ip: string }[]): boolean {
  if (!ip) return false;
  const clean = ip.trim();
  if (clean.startsWith("127.") || clean === "::1" || clean === "0.0.0.0") return true;
  return ifaceList.some((i) => i.ip && i.ip === clean);
}

function formatTcpFlags(flags?: number): string {
  if (flags === undefined || flags === null || flags < 0) return "None";
  const names: string[] = [];
  if (flags & 0x02) names.push("SYN");
  if (flags & 0x10) names.push("ACK");
  if (flags & 0x01) names.push("FIN");
  if (flags & 0x04) names.push("RST");
  if (flags & 0x08) names.push("PSH");
  if (flags & 0x20) names.push("URG");
  if (names.length === 0) return `0x${flags.toString(16)}`;
  return names.join(", ");
}

function formatIcmpType(type?: number): string {
  if (type === undefined || type === null || type < 0) return "N/A";
  switch (type) {
    case 0:
      return "echo reply";
    case 3:
      return "destination unreachable";
    case 8:
      return "echo request";
    case 11:
      return "time exceeded";
    case 13:
      return "timestamp request";
    case 14:
      return "timestamp reply";
    case 15:
      return "info request";
    case 16:
      return "info reply";
    default:
      return `type ${type}`;
  }
}

export const PacketLogTable: React.FC = () => {
  const { logs, selectedLog, setSelectedLog, addBlocklistRule } =
    useAegisStore();
  const isEngineLive = useIsEngineLive();

  const [searchQuery, setSearchQuery] = useState("");
  const [actionFilter, setActionFilter] = useState<string>("ALL");
  const [protoFilter, setProtoFilter] = useState<string>("ALL");

  // Capture bar state
  const [isCaptureOpen, setIsCaptureOpen] = useState(true);
  const [interfaces, setInterfaces] = useState<{ name: string; ip: string }[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>("");
  const [captureStatus, setCaptureStatus] = useState<any>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [showLogs, setShowLogs] = useState(false);
  const [isActionPending, setIsActionPending] = useState(false);

  // Esc key closes inspector drawer on < 3xl
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSelectedLog(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [setSelectedLog]);

  // Load available network interfaces and poll capture status every 3s
  useEffect(() => {
    let isMounted = true;
    const fetchStatusAndInterfaces = async () => {
      try {
        const [st, ifaceList] = await Promise.all([
          api.getCaptureStatus(),
          api.getCaptureInterfaces(),
        ]);
        if (!isMounted) return;
        if (Array.isArray(ifaceList)) {
          setInterfaces(ifaceList);
          setSelectedIface((prev) => {
            if (!prev && ifaceList.length > 0) return ifaceList[0].name;
            return prev;
          });
        }
        if (st) {
          setCaptureStatus(st);
          if (
            (st.state === "running" || st.state === "starting") &&
            st.iface
          ) {
            setSelectedIface(st.iface);
          }
        }
      } catch (err) {
        console.warn("[CAPTURE] Polling error:", err);
      }
    };

    fetchStatusAndInterfaces();
    const interval = setInterval(fetchStatusAndInterfaces, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleStartCapture = async () => {
    if (!selectedIface) return;
    setActionError(null);
    setIsActionPending(true);
    try {
      const res = await api.startCapture(selectedIface);
      if (res?.error) {
        setActionError(res.error);
      } else {
        setCaptureStatus(res);
      }
    } catch (err: any) {
      setActionError(err.message || "Failed to start capture");
    } finally {
      setIsActionPending(false);
    }
  };

  const handleStopCapture = async () => {
    if (
      !window.confirm(
        "Are you sure you want to stop packet capture? This will halt live DPI inspection."
      )
    ) {
      return;
    }
    setActionError(null);
    setIsActionPending(true);
    try {
      const res = await api.stopCapture();
      if (res?.error) {
        setActionError(res.error);
      } else {
        setCaptureStatus(res);
      }
    } catch (err: any) {
      setActionError(err.message || "Failed to stop capture");
    } finally {
      setIsActionPending(false);
    }
  };

  const controlEnabled = Boolean(captureStatus?.control_enabled);
  const isRunning = captureStatus?.state === "running";
  const isStarting = captureStatus?.state === "starting";
  const isStopping = captureStatus?.state === "stopping";
  const isExternal = captureStatus?.state === "external";
  const isStopped = !captureStatus || captureStatus?.state === "stopped";

  const isStartDisabled =
    !controlEnabled ||
    isRunning ||
    isExternal ||
    isStarting ||
    isStopping ||
    isActionPending ||
    !selectedIface;
  const isStopDisabled =
    !controlEnabled || isStopped || isStopping || isActionPending;

  // Dynamically compute distinct sorted protocols present in current logs
  const availableProtos = useMemo(() => {
    return Array.from(new Set(logs.map((l) => l.protocol).filter(Boolean))).sort();
  }, [logs]);

  // Fall back to "ALL" if the selected protocol is no longer present in current logs
  useEffect(() => {
    if (protoFilter !== "ALL" && !availableProtos.includes(protoFilter)) {
      setProtoFilter("ALL");
    }
  }, [availableProtos, protoFilter]);

  const filteredLogs = useMemo(() => {
    const tokens = searchQuery.trim().split(/\s+/).filter(Boolean);

    return logs.filter((log) => {
      if (actionFilter !== "ALL" && log.action !== actionFilter) return false;
      if (protoFilter !== "ALL" && log.protocol !== protoFilter) return false;

      if (tokens.length > 0) {
        for (const token of tokens) {
          if (!matchesSearchToken(log, token)) return false;
        }
      }
      return true;
    });
  }, [logs, actionFilter, protoFilter, searchQuery]);

  const selectedLogFilterStatus = useMemo(() => {
    if (!selectedLog) return null;
    const inBuffer = logs.some((l) => l.id === selectedLog.id);
    if (!inBuffer) {
      return "evicted";
    }
    const inFiltered = filteredLogs.some((l) => l.id === selectedLog.id);
    if (!inFiltered) {
      return "hidden_by_filter";
    }
    return "visible";
  }, [selectedLog, logs, filteredLogs]);

  const handleBlockIp = async (ip: string) => {
    try {
      await addBlocklistRule(ip, `Blocked from Packet Log Inspector (${ip})`);
    } catch (err) {
      console.error("[PacketLogTable] Failed to block IP:", err);
    }
  };

  const renderStatusPill = () => {
    if (!captureStatus) {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
          Checking...
        </span>
      );
    }
    const { state, iface, pid, engine_pid, started_at } = captureStatus;
    switch (state) {
      case "running":
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 flex items-center space-x-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[#2fb8a6] animate-pulse" />
            <span>
              Running on {iface || selectedIface} · PID {engine_pid || pid || "-"} ·{" "}
              {formatUptime(started_at)}
            </span>
          </span>
        );
      case "starting":
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#ffaa00]/20 text-[#ffaa00] border border-[#ffaa00]/40 flex items-center space-x-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[#ffaa00] animate-pulse" />
            <span>Starting</span>
          </span>
        );
      case "stopping":
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#ffaa00]/20 text-[#ffaa00] border border-[#ffaa00]/40 flex items-center space-x-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[#ffaa00] animate-pulse" />
            <span>Stopping</span>
          </span>
        );
      case "external":
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#8b9ac6]/20 text-[#a9b6da] border border-[#8b9ac6]/40 flex items-center space-x-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[#8b9ac6]" />
            <span>External engine{iface ? ` (${iface})` : ""}</span>
          </span>
        );
      case "stopped":
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
            Stopped
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] min-h-[640px] space-y-4">
      {/* Collapsible Capture Control Bar */}
      <div className="bg-[#101a38] border border-[#22305e] rounded-lg overflow-hidden shrink-0">
        <div
          onClick={() => setIsCaptureOpen(!isCaptureOpen)}
          className="p-3 bg-[#0c142e] border-b border-[#22305e] flex items-center justify-between cursor-pointer select-none hover:bg-[#121c3d] transition-colors"
        >
          <div className="flex items-center space-x-3">
            <Radio className="h-4 w-4 text-[#2fb8a6]" />
            <span className="text-xs font-mono font-bold text-[#eef1f8]">
              Packet Capture Engine
            </span>
            {renderStatusPill()}
          </div>
          <div className="flex items-center space-x-2 text-[#8b9ac6]">
            <span className="text-[11px] font-mono">
              {isCaptureOpen ? "Hide Controls" : "Show Controls"}
            </span>
            {isCaptureOpen ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </div>
        </div>

        {isCaptureOpen && (
          <div className="p-4 bg-[#101a38] space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center space-x-3">
                <label className="text-xs font-mono text-[#8b9ac6]">
                  Interface:
                </label>
                <select
                  value={selectedIface}
                  onChange={(e) => setSelectedIface(e.target.value)}
                  disabled={isRunning || isStarting || isStopping}
                  className="bg-[#0c142e] border border-[#22305e] rounded px-3 py-1.5 text-xs font-mono text-[#eef1f8] focus:outline-none focus:border-[#3a4a80] disabled:opacity-50"
                >
                  {interfaces.length > 0 ? (
                    interfaces.map((i) => {
                      const label =
                        i.name === "veth_lab"
                          ? `veth_lab (${i.ip || "10.10.0.1"}) – lab`
                          : `${i.name} (${i.ip})`;
                      return (
                        <option key={i.name} value={i.name}>
                          {label}
                        </option>
                      );
                    })
                  ) : (
                    <option value="">No network interfaces found</option>
                  )}
                </select>

                <Button
                  onClick={handleStartCapture}
                  disabled={isStartDisabled}
                  className="bg-[#2fb8a6] hover:bg-[#2fb8a6]/90 text-[#0a1128] font-bold text-xs font-mono px-3 py-1.5 h-auto flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Start</span>
                </Button>

                <Button
                  onClick={handleStopCapture}
                  disabled={isStopDisabled}
                  className="bg-[#ff5a2b] hover:bg-[#ff5a2b]/90 text-white font-bold text-xs font-mono px-3 py-1.5 h-auto flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Square className="h-3.5 w-3.5 fill-current" />
                  <span>Stop</span>
                </Button>
              </div>

              <div className="flex items-center space-x-2">
                <Button
                  onClick={() => setShowLogs(!showLogs)}
                  className="bg-[#0c142e] hover:bg-[#16204a] text-[#8b9ac6] border border-[#22305e] text-xs font-mono px-3 py-1.5 h-auto flex items-center space-x-1.5"
                >
                  <Terminal className="h-3.5 w-3.5" />
                  <span>{showLogs ? "Hide Engine Log" : "Show Engine Log"}</span>
                </Button>
              </div>
            </div>

            {/* Error or Disabled Notification */}
            {!controlEnabled && (
              <div className="text-[11px] font-mono text-[#8b9ac6] flex items-center space-x-1.5 bg-[#0c142e] border border-[#22305e] rounded p-2">
                <Info className="h-3.5 w-3.5 text-[#3a4a80] shrink-0" />
                <span>Capture control is disabled on this server</span>
              </div>
            )}

            {(actionError || captureStatus?.last_error) && (
              <div className="text-xs font-mono text-[#ff5a2b] flex items-center space-x-1.5 bg-[#ff5a2b]/10 border border-[#ff5a2b]/30 rounded p-2">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{actionError || captureStatus?.last_error}</span>
              </div>
            )}

            {/* Engine Log Terminal Drawer */}
            {showLogs && (
              <div className="mt-2 bg-[#081022] border border-[#22305e] rounded p-3 font-mono text-[11px] text-[#8b9ac6] max-h-48 overflow-y-auto space-y-1">
                <div className="text-[10px] uppercase font-bold text-[#3a4a80] pb-1 border-b border-[#16204a]">
                  Engine Standard Output / Error (Last{" "}
                  {captureStatus?.logs?.length || 0} lines)
                </div>
                {captureStatus?.logs && captureStatus.logs.length > 0 ? (
                  captureStatus.logs.map((line: string, idx: number) => (
                    <div
                      key={idx}
                      className="whitespace-pre-wrap leading-tight text-[#eef1f8]/90"
                    >
                      {line}
                    </div>
                  ))
                ) : (
                  <div className="text-[#8b9ac6] italic pt-1">
                    No engine log output recorded yet.
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Search & Filter Header Bar */}
      <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-start space-x-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-2.5 text-[#8b9ac6]" />
            <input
              type="text"
              placeholder="e.g. proto:tcp sni:google port:443"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#0c142e] border border-[#22305e] rounded px-9 py-1.5 text-xs font-mono text-[#eef1f8] placeholder-[#8b9ac6] focus:outline-none focus:border-[#3a4a80]"
            />
            <div className="text-[10px] font-mono text-[#8b9ac6] mt-1 pl-1">
              ip: src: dst: port: sni: proto: action:
            </div>
          </div>
          <span className="text-xs font-mono text-[#8b9ac6] whitespace-nowrap pt-2">
            {filteredLogs.length} of {logs.length} packets
          </span>
        </div>

        <div className="flex items-center space-x-4">
          {/* Action Filter */}
          <div className="flex items-center space-x-1.5 text-xs font-mono">
            <Filter className="h-3.5 w-3.5 text-[#8b9ac6]" />
            <span className="text-[#8b9ac6]">Action:</span>
            {["ALL", "FORWARD", "DROP", "UNHANDLED"].map((act) => (
              <button
                key={act}
                onClick={() => setActionFilter(act)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors ${
                  actionFilter === act
                    ? act === "DROP"
                      ? "bg-[#ff5a2b] text-white"
                      : act === "UNHANDLED"
                      ? "bg-[#8b9ac6] text-[#0a1128]"
                      : act === "FORWARD"
                      ? "bg-[#2fb8a6] text-[#0a1128]"
                      : "bg-[#3a4a80] text-white"
                    : "bg-[#0c142e] text-[#8b9ac6] border border-[#22305e] hover:border-[#3a4a80]"
                }`}
              >
                {act}
              </button>
            ))}
          </div>

          {/* Protocol Filter */}
          <div className="flex items-center space-x-1.5 text-xs font-mono">
            <span className="text-[#8b9ac6]">Proto:</span>
            {["ALL", ...availableProtos].map((p) => (
              <button
                key={p}
                onClick={() => setProtoFilter(p)}
                className={`px-2 py-1 rounded text-[11px] ${
                  protoFilter === p
                    ? "bg-[#3a4a80] text-white font-bold"
                    : "bg-[#0c142e] text-[#8b9ac6] border border-[#22305e] hover:border-[#3a4a80]"
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Split View: Virtualized Table + Side Detail Panel */}
      <div className="flex-1 min-h-0 flex flex-col 3xl:flex-row gap-4 min-w-0 items-stretch w-full">
        {/* Virtualized Table Container */}
        <div className="flex-1 min-h-[420px] bg-[#101a38] border border-[#22305e] rounded-lg overflow-hidden flex flex-col w-full">
          <div className="p-3 bg-[#0c142e] border-b border-[#22305e] flex items-center justify-between text-xs font-mono shrink-0">
            <div className="flex items-center space-x-2">
              <span className="text-[#eef1f8] font-bold">
                Inspected Packet Logs ({filteredLogs.length})
              </span>
              <span className="text-[10px] text-[#8b9ac6]">
                Virtualized via react-virtuoso
              </span>
            </div>
            <span className="text-[11px] text-[#2fb8a6]">
              Schema: dpi:logs stream
            </span>
          </div>

          <div className="flex-1 min-h-0 w-full overflow-hidden">
            <TableVirtuoso
              style={{ height: "100%" }}
              data={filteredLogs}
              className="h-full font-mono text-xs"
              fixedHeaderContent={() => (
                <tr className="bg-[#081022] text-[#8b9ac6] text-left border-b border-[#22305e]">
                  <th className="py-2.5 px-3 w-[100px] min-w-[100px] max-w-[100px] whitespace-nowrap">TIME</th>
                  <th className="py-2.5 px-3 w-[90px] min-w-[90px] max-w-[90px] whitespace-nowrap">ACTION</th>
                  <th className="py-2.5 px-3 w-[175px] min-w-[175px] max-w-[175px] whitespace-nowrap">SOURCE</th>
                  <th className="py-2.5 px-3 w-[175px] min-w-[175px] max-w-[175px] whitespace-nowrap">DESTINATION</th>
                  <th className="py-2.5 px-3 w-[70px] min-w-[70px] max-w-[70px] whitespace-nowrap">PROTO</th>
                  <th className="py-2.5 px-3 whitespace-nowrap min-w-0">SNI</th>
                  <th className="py-2.5 px-3 w-[120px] min-w-[120px] max-w-[120px] whitespace-nowrap">REASON</th>
                  <th className="py-2.5 px-3 w-[60px] min-w-[60px] max-w-[60px] text-center whitespace-nowrap" title="Worker Thread ID (FP[#])">THR</th>
                </tr>
              )}
              itemContent={(_index, log: DpiLogEntry) => {
                const srcStr = log.src_ip ? `${log.src_ip}${hasPort(log.protocol) ? `:${log.src_port}` : ""}` : (log.l3 === "ipv6" || log.protocol === "IPv6" ? "IPv6 frame" : "non-IP frame");
                const dstStr = log.dst_ip ? `${log.dst_ip}${hasPort(log.protocol) ? `:${log.dst_port}` : ""}` : "-";
                const sniStr = log.sni !== "-" ? log.sni : "-";
                return (
                  <>
                    <td className="py-2 px-3 text-[#8b9ac6] text-[11px] whitespace-nowrap w-[100px] min-w-[100px] max-w-[100px]">
                      {log.timestamp}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap w-[90px] min-w-[90px] max-w-[90px]">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          log.action === "DROP"
                            ? "bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40"
                            : log.action === "UNHANDLED"
                            ? "bg-[#8b9ac6]/20 text-[#a9b6da] border border-[#8b9ac6]/40"
                            : "bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40"
                        }`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[#eef1f8] whitespace-nowrap w-[175px] min-w-[175px] max-w-[175px]" title={srcStr}>
                      {log.src_ip ? (
                        <span className="whitespace-nowrap font-mono">
                          {log.src_ip}
                          {hasPort(log.protocol) && (
                            <span className="text-[#8b9ac6]">:{log.src_port}</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-[#8b9ac6] whitespace-nowrap font-mono">
                          {log.l3 === "ipv6" || log.protocol === "IPv6" ? "IPv6 frame" : "non-IP frame"}
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-[#eef1f8] whitespace-nowrap w-[175px] min-w-[175px] max-w-[175px]" title={dstStr}>
                      {log.dst_ip ? (
                        <span className="whitespace-nowrap font-mono">
                          {log.dst_ip}
                          {hasPort(log.protocol) && (
                            <span className="text-[#8b9ac6]">:{log.dst_port}</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-[#8b9ac6] whitespace-nowrap font-mono">-</span>
                      )}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap w-[70px] min-w-[70px] max-w-[70px]">
                      <span className="text-[#a9b6da] bg-[#16204a] px-1.5 py-0.5 rounded text-[10px]">
                        {log.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[#2fb8a6] truncate min-w-0" title={sniStr}>
                      <span className="truncate block font-mono">
                        {log.sni !== "-" ? log.sni : <span className="text-[#8b9ac6]">-</span>}
                      </span>
                    </td>
                    <td
                      className="py-2 px-3 text-[#8b9ac6] text-[11px] whitespace-nowrap w-[120px] min-w-[120px] max-w-[120px]"
                      title={log.reason}
                    >
                      {log.reason}
                    </td>
                    <td className="py-2 px-3 text-center text-[#a9b6da] text-[11px] whitespace-nowrap w-[60px] min-w-[60px] max-w-[60px]">
                      FP[{log.thread_id}]
                    </td>
                  </>
                );
              }}
              components={{
                Table: ({ style, ...props }) => (
                  <table
                    {...props}
                    style={{ ...style, width: "100%", tableLayout: "fixed" }}
                    className="table-fixed w-full"
                  />
                ),
                TableRow: ({ item, children, ...props }) => {
                  const isSelected = selectedLog?.id === item.id;
                  return (
                    <tr
                      {...props}
                      onClick={() => setSelectedLog(item)}
                      className={`cursor-pointer border-b border-[#16204a] transition-colors ${
                        isSelected
                          ? "bg-[#16204a] border-l-2 border-l-[#2fb8a6]"
                          : "hover:bg-[#0c142e]/80"
                      }`}
                    >
                      {children}
                    </tr>
                  );
                },
              }}
            />
          </div>
        </div>

        {/* Side Detail Panel for Selected Packet (fixed 380px on >= 3xl) */}
        <div className="hidden 3xl:flex 3xl:w-[380px] 3xl:shrink-0 bg-[#101a38] border border-[#22305e] rounded-lg flex-col min-h-[420px] overflow-hidden">
          {selectedLog ? (
            renderInspectorContent()
          ) : (
            <div className="p-5 flex flex-col items-center justify-center h-full text-center text-[#8b9ac6] font-mono text-xs space-y-2">
              <Info className="h-8 w-8 text-[#3a4a80]" />
              <span>Select any packet row to inspect full 5-tuple and L7 SNI metadata.</span>
            </div>
          )}
        </div>
      </div>

      {/* Slide-over Drawer for < 3xl (non-modal, top below header, 380px, close button + Esc) */}
      {selectedLog && (
        <aside
          aria-label="Packet Deep Inspector"
          className="3xl:hidden fixed top-[72px] right-0 bottom-0 w-[380px] max-w-[90vw] bg-[#101a38] border-l border-[#22305e] shadow-2xl shadow-black/80 flex flex-col overflow-hidden z-20 animate-in slide-in-from-right duration-200"
        >
          {renderInspectorContent(() => setSelectedLog(null))}
        </aside>
      )}
    </div>
  );

  function renderInspectorContent(onClose?: () => void) {
    if (!selectedLog) return null;
    const srcLocal = isLocalOrLoopback(selectedLog.src_ip, interfaces);
    const dstLocal = isLocalOrLoopback(selectedLog.dst_ip, interfaces);

    return (
      <div className="flex flex-col h-full overflow-hidden">
        {/* Sticky Header at top of panel */}
        <div className="p-5 pb-3.5 bg-[#101a38] border-b border-[#22305e] shrink-0 sticky top-0 z-10 flex items-center justify-between">
          <div className="min-w-0 pr-2">
            <h3 className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
              Packet Deep Inspector
            </h3>
            <div className="text-xs font-mono font-semibold text-[#eef1f8] mt-1 break-all leading-relaxed">
              <span className="text-[#8b9ac6] font-normal">Stream ID: </span>
              {selectedLog.stream_id || selectedLog.id}
            </div>
            <div className="text-xs font-mono text-[#8b9ac6] mt-0.5">
              Time seen:{" "}
              <span className="text-[#eef1f8] font-mono font-semibold">
                {selectedLog.timestamp}
              </span>
            </div>
          </div>
          <div className="flex items-center space-x-2 shrink-0">
            <span
              className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                selectedLog.action === "DROP"
                  ? "bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40"
                  : selectedLog.action === "UNHANDLED"
                  ? "bg-[#8b9ac6]/20 text-[#a9b6da] border border-[#8b9ac6]/40"
                  : "bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40"
              }`}
            >
              {selectedLog.action}
            </span>
            {onClose && (
              <button
                onClick={onClose}
                className="p-1 rounded text-[#8b9ac6] hover:text-[#eef1f8] hover:bg-[#16204a] transition-colors ml-1"
                title="Close Inspector (Esc)"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        {/* Scrollable Panel Body: scrolls under the sticky header */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {selectedLogFilterStatus === "hidden_by_filter" && (
            <div className="px-3 py-2 rounded bg-[#ff9900]/10 border border-[#ff9900]/30 text-[#ffb84d] text-xs font-mono flex items-center space-x-2">
              <Info className="h-4 w-4 shrink-0" />
              <span>Selected packet is hidden by the current filter.</span>
            </div>
          )}

          {selectedLogFilterStatus === "evicted" && (
            <div className="px-3 py-2 rounded bg-slate-500/10 border border-slate-500/30 text-slate-400 text-xs font-mono flex items-center space-x-2">
              <Info className="h-4 w-4 shrink-0" />
              <span>This packet is no longer in the live buffer (last 500 packets).</span>
            </div>
          )}

          {/* 5-Tuple Network Breakdown */}
          <div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-[#8b9ac6] mb-2">
              <Network className="h-3.5 w-3.5" />
              <span className="uppercase tracking-wider">L3 / L4 5-Tuple</span>
            </div>
            <div className="bg-[#0c142e] border border-[#22305e] rounded p-3 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-[#8b9ac6]">Source:</span>
                {selectedLog.src_ip ? (
                  <span className="text-[#eef1f8] font-bold">
                    {selectedLog.src_ip}
                    {hasPort(selectedLog.protocol) ? ` : ${selectedLog.src_port}` : ""}
                  </span>
                ) : (
                  <span className="text-[#8b9ac6] font-mono">
                    {selectedLog.l3 === "ipv6" || selectedLog.protocol === "IPv6" ? "IPv6 frame" : "non-IP frame"}
                  </span>
                )}
              </div>
              <div className="flex justify-between">
                <span className="text-[#8b9ac6]">Destination:</span>
                {selectedLog.dst_ip ? (
                  <span className="text-[#eef1f8] font-bold">
                    {selectedLog.dst_ip}
                    {hasPort(selectedLog.protocol) ? ` : ${selectedLog.dst_port}` : ""}
                  </span>
                ) : (
                  <span className="text-[#8b9ac6] font-mono">-</span>
                )}
              </div>
              <div className="flex justify-between">
                <span className="text-[#8b9ac6]">Protocol:</span>
                <span className="text-[#a9b6da]">{selectedLog.protocol}</span>
              </div>
              {selectedLog.protocol.toUpperCase() === "TCP" && selectedLog.tcp_flags !== undefined && (
                <div className="flex justify-between">
                  <span className="text-[#8b9ac6]">TCP flags:</span>
                  <span className="text-[#eef1f8] font-mono">
                    {formatTcpFlags(selectedLog.tcp_flags)}
                  </span>
                </div>
              )}
              {selectedLog.protocol.toUpperCase() === "ICMP" && selectedLog.icmp_type !== undefined && selectedLog.icmp_type >= 0 && (
                <div className="flex justify-between">
                  <span className="text-[#8b9ac6]">ICMP:</span>
                  <span className="text-[#eef1f8] font-mono">
                    {formatIcmpType(selectedLog.icmp_type)}
                  </span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-[#8b9ac6]">Thread Worker:</span>
                <span className="text-[#2fb8a6]">FP[{selectedLog.thread_id}]</span>
              </div>
            </div>
          </div>

          {/* L7 Metadata */}
          <div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-[#8b9ac6] mb-2">
              <Info className="h-3.5 w-3.5" />
              <span className="uppercase tracking-wider">L7 Inspection Attributes</span>
            </div>
            <div className="bg-[#0c142e] border border-[#22305e] rounded p-3 space-y-2 text-xs font-mono">
              <div>
                <span className="text-[#8b9ac6] block text-[10px]">EXTRACTED SNI / HOST:</span>
                {selectedLog.sni && selectedLog.sni !== "-" ? (
                  <span className="text-[#2fb8a6] font-bold break-all">
                    {selectedLog.sni}
                  </span>
                ) : (
                  <span className="text-[#8b9ac6] text-xs font-normal">
                    {selectedLog.protocol.toUpperCase() === "TCP"
                      ? "No SNI in this packet (hostname appears only in the TLS ClientHello, the first packet of a connection)"
                      : "N/A (not a TCP packet)"}
                  </span>
                )}
              </div>
              <div className="pt-2 border-t border-[#16204a]">
                <span className="text-[#8b9ac6] block text-[10px]">DECISION REASON:</span>
                <span className="text-[#eef1f8]">{selectedLog.reason}</span>
              </div>
              <div className="pt-2 border-t border-[#16204a]">
                <span className="text-[#8b9ac6] block text-[10px]">KERNEL ENFORCEMENT:</span>
                <span
                  className={
                    selectedLog.action === "DROP"
                      ? "text-[#ff5a2b]"
                      : selectedLog.action === "UNHANDLED"
                      ? "text-[#8b9ac6]"
                      : "text-[#2fb8a6]"
                  }
                >
                  {formatKernelEnforcement(selectedLog.action, selectedLog.reason, selectedLog.protocol, selectedLog.l3)}
                </span>
              </div>
            </div>
          </div>

          {/* Action Button with Self-block Protection */}
          {selectedLog.action === "FORWARD" && (() => {
            if (srcLocal && dstLocal) {
              return (
                <div className="pt-2">
                  <Button
                    disabled
                    title="local address"
                    className="w-full bg-[#16204a] text-[#8b9ac6] cursor-not-allowed text-xs font-mono flex items-center justify-center space-x-2 border border-[#22305e]"
                  >
                    <ShieldAlert className="h-4 w-4" />
                    <span>Block IP (local address)</span>
                  </Button>
                </div>
              );
            }

            if (srcLocal) {
              return (
                <div className="pt-2">
                  <Button
                    onClick={() => handleBlockIp(selectedLog.dst_ip)}
                    className="w-full bg-[#ff5a2b] hover:bg-[#ff5a2b]/90 text-white text-xs font-mono flex items-center justify-center space-x-2"
                  >
                    <ShieldAlert className="h-4 w-4" />
                    <span>Block Remote IP ({selectedLog.dst_ip})</span>
                  </Button>
                </div>
              );
            }

            return (
              <div className="pt-2">
                <Button
                  onClick={() => handleBlockIp(selectedLog.src_ip)}
                  className="w-full bg-[#ff5a2b] hover:bg-[#ff5a2b]/90 text-white text-xs font-mono flex items-center justify-center space-x-2"
                >
                  <ShieldAlert className="h-4 w-4" />
                  <span>Block Source IP ({selectedLog.src_ip})</span>
                </Button>
              </div>
            );
          })()}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#22305e] text-[10px] font-mono text-[#8b9ac6] flex justify-between items-center shrink-0 bg-[#101a38]">
          <span>Store Source: Redis dpi:logs</span>
          {isEngineLive ? (
            <span className="inline-flex items-center text-[#2fb8a6] font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2fb8a6] mr-1.5 animate-pulse" />
              Live
            </span>
          ) : (
            <span className="inline-flex items-center text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1.5" />
              Paused
            </span>
          )}
        </div>
      </div>
    );
  }
};
