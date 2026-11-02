import React from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Layers,
  Cpu,
  TrendingUp,
} from "lucide-react";
import { formatBandwidthRate, formatPacketRate } from "@/lib/utils";

function formatEndpoint(ip: string, port?: number): string {
  if (!port || port === 0) return ip;
  return `${ip}:${port}`;
}

export const StatsOverview: React.FC = () => {
  const { stats, threads, logs, chartHistory } = useAegisStore();
  const maxSeenPpsRef = React.useRef<number>(0);
  const isEngineLive = useIsEngineLive();

  if (!stats) {
    return (
      <div className="p-8 text-center font-mono text-[#8b9ac6]">
        Loading Aegis DPI Telemetry...
      </div>
    );
  }

  const forwardPct = ((stats.forwarded / (stats.total_packets || 1)) * 100).toFixed(1);
  const dropPct = ((stats.dropped / (stats.total_packets || 1)) * 100).toFixed(1);

  // Time window calculation for last 90 seconds
  const now = Math.max(Date.now(), stats.updated_at_ms || 0);
  const isStale = !isEngineLive;
  const currentPps = isStale ? 0 : stats.throughput_pps;
  const currentDroppedPps = isStale ? 0 : (stats.dropped_pps || 0);

  const windowMs = 90000;
  const t_min = now - windowMs;
  const visible = chartHistory.filter((s) => s.t >= t_min && s.t <= now);

  const allPpsValues = visible.map((s) => s.pps).concat([currentPps]);
  const highestCurrentPps = allPpsValues.length > 0 ? Math.max(...allPpsValues) : 0;
  if (highestCurrentPps > maxSeenPpsRef.current) {
    maxSeenPpsRef.current = highestCurrentPps;
  }
  const yCeiling = Math.max(50, Math.ceil(maxSeenPpsRef.current * 1.2));

  // Stable scale applied to both inspected and blocked lines
  const getY = (val: number) => 150 - (Math.min(Math.max(0, val), yCeiling) / yCeiling) * 130;
  const getX = (t: number) => Math.max(0, Math.min(500, ((t - t_min) / windowMs) * 500));

  const pointsList: Array<{ x: number; y_pps: number; y_drp: number }> = [];

  // Left boundary anchor if earliest visible sample is later than t_min
  if (visible.length === 0 || visible[0].t > t_min) {
    const initialY = visible.length > 0 ? getY(visible[0].pps) : getY(0);
    const initialDropY = visible.length > 0 ? getY(visible[0].dropped_pps) : getY(0);
    pointsList.push({ x: 0, y_pps: initialY, y_drp: initialDropY });
  }

  for (const s of visible) {
    pointsList.push({
      x: getX(s.t),
      y_pps: getY(s.pps),
      y_drp: getY(s.dropped_pps),
    });
  }

  // Right boundary at NOW (x = 500)
  pointsList.push({
    x: 500,
    y_pps: getY(currentPps),
    y_drp: getY(currentDroppedPps),
  });

  const ppsPoints = pointsList.map((pt) => `${pt.x.toFixed(1)},${pt.y_pps.toFixed(1)}`).join(" ");
  const droppedPoints = pointsList.map((pt) => `${pt.x.toFixed(1)},${pt.y_drp.toFixed(1)}`).join(" ");

  const ppsLinePath = pointsList
    .map((pt, i) => `${i === 0 ? "M" : "L"} ${pt.x.toFixed(1)} ${pt.y_pps.toFixed(1)}`)
    .join(" ");
  const ppsAreaPath = `${ppsLinePath} L 500 160 L 0 160 Z`;

  const droppedLinePath = pointsList
    .map((pt, i) => `${i === 0 ? "M" : "L"} ${pt.x.toFixed(1)} ${pt.y_drp.toFixed(1)}`)
    .join(" ");
  const droppedAreaPath = `${droppedLinePath} L 500 160 L 0 160 Z`;

  const lastPps = pointsList[pointsList.length - 1];
  const lastDropped = pointsList[pointsList.length - 1];

  const orderedThreads = [...threads].sort((a, b) => {
    if (a.role !== b.role) {
      return a.role === "LB" ? -1 : 1;
    }
    return a.thread_id - b.thread_id;
  });

  const lbTotal = threads.filter((t) => t.role === "LB").reduce((sum, t) => sum + t.packets_processed, 0);
  const fpTotal = threads.filter((t) => t.role === "FAST_PATH").reduce((sum, t) => sum + t.packets_processed, 0);

  return (
    <div className="space-y-6">
      {/* Top Stat Cards (4 columns >= 1280px, 2x2 below) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* Total Inspected */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6] whitespace-nowrap">
              TOTAL INSPECTED
            </span>
            <div className="flex items-center space-x-2 shrink-0">
              {isEngineLive ? (
                <span className="text-[10px] font-mono text-[#2fb8a6] flex items-center bg-[#2fb8a6]/10 border border-[#2fb8a6]/30 px-1.5 py-0.5 rounded whitespace-nowrap">
                  <TrendingUp className="h-3 w-3 mr-0.5 shrink-0" />
                  Live
                </span>
              ) : (
                <span className="text-[10px] font-mono text-[#8b9ac6] flex items-center bg-[#0c142e] border border-[#22305e] px-1.5 py-0.5 rounded whitespace-nowrap">
                  Last run
                </span>
              )}
              <div className="hidden 3xl:block p-1.5 rounded bg-[#16204a] text-[#a9b6da]">
                <Layers className="h-4 w-4" />
              </div>
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-[#eef1f8]">
              {stats.total_packets.toLocaleString()}
            </div>
          </div>
          <div className="mt-2 text-xs font-mono text-[#8b9ac6] flex items-center justify-between gap-4">
            <div className="flex items-center space-x-1">
              <span>Ring Drops:</span>
              <span className="text-[#eef1f8] font-semibold">
                {((stats.pcap_drop ?? 0) + (stats.pcap_ifdrop ?? 0)).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center space-x-1">
              <span>Kernel RX:</span>
              <span className="text-[#a9b6da] font-semibold">
                {(stats.pcap_recv ?? 0).toLocaleString()}
              </span>
            </div>
          </div>
        </div>

        {/* Forwarded */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
              FORWARDED
            </span>
            <div className="p-1.5 rounded bg-[#2fb8a6]/10 text-[#2fb8a6]">
              <ShieldCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <div className="text-2xl font-bold font-mono text-[#2fb8a6]">
              {stats.forwarded.toLocaleString()}
            </div>
            <span className="text-xs font-mono text-[#2fb8a6]">
              {forwardPct}%
            </span>
          </div>
          <div className="mt-2 text-xs font-mono text-[#8b9ac6] whitespace-nowrap truncate">
            No blocklist rule matched
          </div>
        </div>

        {/* Dropped Threats */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
              DROPPED
            </span>
            <div className="p-1.5 rounded bg-[#ff5a2b]/10 text-[#ff5a2b]">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <div className="text-2xl font-bold font-mono text-[#ff5a2b]">
              {stats.dropped.toLocaleString()}
            </div>
            <span className="text-xs font-mono text-[#ff5a2b]">
              {dropPct}%
            </span>
          </div>
          <div className="mt-2 text-xs font-mono text-[#8b9ac6]">
            blocklist or malformed
          </div>
        </div>

        {/* Live Throughput */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
              Throughput
            </span>
            <div className="p-1.5 rounded bg-[#3a4a80]/30 text-[#eef1f8]">
              <Activity className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <div className="text-2xl font-bold font-mono text-[#eef1f8]">
              {formatPacketRate(stats.throughput_pps)}
            </div>
            <span className="text-xs font-mono text-[#a9b6da]">
              {formatBandwidthRate(stats.throughput_bps ?? (stats.throughput_mbps * 1e6))}
            </span>
          </div>
          <div className="mt-2 text-xs font-mono text-[#8b9ac6] flex items-center">
            <span
              className={`inline-block w-2 h-2 rounded-full mr-1.5 ${
                isEngineLive ? "bg-[#2fb8a6] animate-pulse" : "bg-slate-500"
              }`}
            />
            NIC: {stats.interface || "offline"}
          </div>
        </div>
      </div>

      {/* Main Grid: Telemetry (Main Area) & Verdict Stream Sidebar (side by side >= 1280px, stacked below) */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-stretch">
        {/* Main Content Area (span 2 >= 1280px) */}
        <div className="xl:col-span-2 space-y-6">
          {/* Throughput Chart */}
          <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8] whitespace-nowrap">
                  Throughput Telemetry (PPS)
                </h2>
                <p className="text-xs text-[#8b9ac6] mt-0.5">
                  Real-time packet processing rate across{" "}
                  {threads.filter((t) => t.role === "FAST_PATH").length || 4} fast-path pipelines
                </p>
              </div>
              <div className="flex items-center space-x-5 text-xs font-mono whitespace-nowrap shrink-0">
                <div className="flex items-center space-x-2 whitespace-nowrap">
                  <span className="w-3.5 h-1 bg-[#2fb8a6] rounded-sm shrink-0" />
                  <span className="text-[#2fb8a6] whitespace-nowrap">Inspected pps</span>
                </div>
                <div className="flex items-center space-x-2 whitespace-nowrap">
                  <span className="w-3.5 h-1 bg-[#ff5a2b] rounded-sm shrink-0" />
                  <span className="text-[#ff5a2b] whitespace-nowrap">Blocked pps</span>
                </div>
              </div>
            </div>

            {/* SVG Sparkline Area Chart */}
            <div className="w-full h-48 relative">
              <svg
                className="w-full h-full overflow-visible"
                viewBox="0 0 500 160"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2fb8a6" stopOpacity="0.35" />
                    <stop offset="100%" stopColor="#2fb8a6" stopOpacity="0.0" />
                  </linearGradient>
                  <linearGradient id="mbpsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff5a2b" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#ff5a2b" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Grid Lines */}
                <line x1="0" y1="40" x2="500" y2="40" stroke="#16204a" strokeDasharray="3 3" />
                <line x1="0" y1="80" x2="500" y2="80" stroke="#16204a" strokeDasharray="3 3" />
                <line x1="0" y1="120" x2="500" y2="120" stroke="#16204a" strokeDasharray="3 3" />

                {/* Inspected Area & Straight Line */}
                <path
                  d={ppsAreaPath}
                  fill="url(#ppsGrad)"
                />
                <polyline
                  points={ppsPoints}
                  fill="none"
                  stroke="#2fb8a6"
                  strokeWidth="2"
                  strokeLinejoin="miter"
                />

                {/* Inspected Latest Point */}
                <circle
                  cx={lastPps.x.toFixed(1)}
                  cy={lastPps.y_pps.toFixed(1)}
                  r="4"
                  fill="#2fb8a6"
                />

                {/* Blocked / Dropped Area & Straight Line */}
                <path
                  d={droppedAreaPath}
                  fill="url(#mbpsGrad)"
                />
                <polyline
                  points={droppedPoints}
                  fill="none"
                  stroke="#ff5a2b"
                  strokeWidth="1.5"
                  strokeLinejoin="miter"
                />

                {/* Blocked Latest Point */}
                <circle
                  cx={lastDropped.x.toFixed(1)}
                  cy={lastDropped.y_drp.toFixed(1)}
                  r="3.5"
                  fill="#ff5a2b"
                />
              </svg>

              {/* Time markers plotted by timestamp across 90-second rolling window */}
              <div className="flex justify-between text-[10px] font-mono text-[#8b9ac6] mt-2">
                <span>-90s</span>
                <span>-75s</span>
                <span>-60s</span>
                <span>-45s</span>
                <span>-30s</span>
                <span>-15s</span>
                <span className="text-[#2fb8a6]">
                  NOW ({currentPps.toLocaleString()} pps)
                </span>
              </div>
            </div>
          </div>

          {/* Protocol Mix Bar */}
          <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
                  Protocol Classification Mix
                </h2>
                <p className="text-xs text-[#8b9ac6] mt-0.5">
                  Identified by L4-L7 Deep Packet Inspection
                </p>
              </div>
              <div className="text-[11px] font-mono text-[#8b9ac6] flex items-center space-x-3">
                <span>Parser: libpcap L2-L4 + TLS SNI</span>
                {isEngineLive ? (
                  <span className="text-[#2fb8a6]">SNI Extractor Active</span>
                ) : (
                  <span className="text-slate-400">SNI extractor idle</span>
                )}
              </div>
            </div>

            {/* Multi-segment bar */}
            <div className="mt-4 flex h-4 w-full rounded overflow-hidden bg-[#0c142e] border border-[#22305e]">
              {stats.protocols.map((proto) => (
                <div
                  key={proto.name}
                  style={{
                    width: `${proto.percentage}%`,
                    backgroundColor: proto.color,
                  }}
                  title={`${proto.name}: ${Number(proto.percentage).toFixed(1)}%`}
                  className="h-full transition-all duration-300"
                />
              ))}
            </div>

            {/* SNI identification callout */}
            <div className="mt-2.5 text-xs font-mono text-[#8b9ac6] flex items-center justify-between">
              <span>
                TLS handshakes identified via SNI:{" "}
                <strong className="text-[#2fb8a6] font-semibold">
                  {(stats.tls_sni_seen ?? 0).toLocaleString()}
                </strong>
              </span>
            </div>

            {/* Protocol legend breakdown (two-column grid, full wrapping labels, 1 decimal) */}
            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3">
              {stats.protocols.map((proto) => (
                <div key={proto.name} className="flex items-start justify-between text-xs font-mono gap-2">
                  <div className="flex items-start space-x-2 min-w-0 flex-1">
                    <span
                      className="w-2.5 h-2.5 rounded-sm shrink-0 mt-0.5"
                      style={{ backgroundColor: proto.color }}
                    />
                    <span className="text-[#eef1f8] leading-tight break-words" title={proto.name}>
                      {proto.name}
                    </span>
                  </div>
                  <div className="flex items-baseline space-x-2 shrink-0 ml-2 text-right">
                    <span className="text-[#8b9ac6] text-[11px] tabular-nums">
                      {proto.count.toLocaleString()}
                    </span>
                    <span className="text-[#a9b6da] font-semibold tabular-nums min-w-[44px] text-right">
                      {Number(proto.percentage).toFixed(1)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sidebar Column (span 1 >= 1280px) */}
        <div className="xl:col-span-1 flex flex-col min-h-0">
          {/* Packet Decisions Card */}
          <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 flex flex-col flex-1 min-h-[400px]">
            <div className="mb-4">
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8] whitespace-nowrap">
                Packet Decisions
              </h2>
              <p className="text-xs text-[#8b9ac6] mt-0.5">
                Latest packet decisions from the dpi:logs Redis stream
              </p>
              <div className="mt-2">
                {isEngineLive ? (
                  <span className="inline-flex items-center text-[11px] font-mono text-[#2fb8a6] bg-[#2fb8a6]/10 border border-[#2fb8a6]/30 px-2 py-0.5 rounded">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#2fb8a6] mr-1.5 animate-pulse" />
                    Live
                  </span>
                ) : (
                  <span className="inline-flex items-center text-[11px] font-mono text-slate-400 bg-slate-800/40 border border-slate-700/60 px-2 py-0.5 rounded">
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1.5" />
                    Paused - engine stopped
                  </span>
                )}
              </div>
            </div>

            <div className="flex-1 lg:relative">
              <div className="max-h-[400px] overflow-y-auto lg:absolute lg:inset-0 lg:max-h-none space-y-2 font-mono text-xs pr-1">
                {logs.slice(0, 30).map((log) => {
                  const displayReason = log.sni && log.sni !== "-" ? log.sni : log.reason;
                  return (
                    <div
                      key={log.id}
                      className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded hover:border-[#3a4a80] transition-colors font-mono text-xs"
                    >
                      {/* Line 1: action badge, protocol, reason */}
                      <div className="flex items-center justify-between text-[11px]">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                              log.action === "DROP"
                                ? "bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40"
                                : log.action === "UNHANDLED"
                                ? "bg-[#8b9ac6]/20 text-[#a9b6da] border border-[#8b9ac6]/40"
                                : "bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40"
                            }`}
                          >
                            {log.action}
                          </span>
                          <span className="text-[#a9b6da] bg-[#16204a] px-1.5 py-0.5 rounded text-[10px]">
                            {log.protocol}
                          </span>
                        </div>
                        <span className="text-[#8b9ac6] text-[10px] truncate ml-2">
                          {displayReason}
                        </span>
                      </div>

                      {/* Line 2: full src_ip:src_port -> dst_ip:dst_port (omit :0) */}
                      <div className="mt-1.5 text-[11px] font-mono text-[#eef1f8] flex flex-wrap items-center gap-x-1.5">
                        {log.src_ip ? (
                          <span className="whitespace-nowrap">{formatEndpoint(log.src_ip, log.src_port)}</span>
                        ) : (
                          <span className="text-[#8b9ac6] whitespace-nowrap">
                            {log.l3 === "ipv6" || log.protocol === "IPv6" ? "IPv6 frame" : "non-IP frame"}
                          </span>
                        )}
                        <span className="text-[#8b9ac6]">→</span>
                        {log.dst_ip ? (
                          <span className="whitespace-nowrap">{formatEndpoint(log.dst_ip, log.dst_port)}</span>
                        ) : (
                          <span className="text-[#8b9ac6] whitespace-nowrap">-</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Engine Pipeline Topology (Full-Width Pipeline) */}
      <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
              Engine Pipeline Topology
            </h2>
            <p className="text-xs text-[#8b9ac6] mt-0.5">
              2 Load Balancers & 4 Fast Paths
            </p>
          </div>
          <Cpu className="h-4 w-4 text-[#8b9ac6]" />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 font-mono text-xs">
          {orderedThreads.map((thread) => {
            const sumForType = thread.role === "LB" ? lbTotal : fpTotal;
            const loadShare = sumForType > 0 ? Math.round((thread.packets_processed / sumForType) * 100) : 0;

            return (
              <div
                key={thread.name}
                className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded hover:border-[#3a4a80] transition-colors"
              >
                <div className="flex items-center space-x-1.5 mb-1.5 whitespace-nowrap">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      thread.role === "LB" ? "bg-amber-400" : "bg-[#2fb8a6]"
                    }`}
                  />
                  <span className="text-[#eef1f8] font-bold text-xs whitespace-nowrap">
                    {thread.name} ({thread.role === "LB" ? "LB" : "FP"})
                  </span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-[#16204a] h-1.5 rounded overflow-hidden">
                  <div
                    className={`h-full ${
                      thread.role === "LB" ? "bg-amber-400" : "bg-[#2fb8a6]"
                    }`}
                    style={{ width: `${loadShare}%` }}
                  />
                </div>

                <div className="mt-1.5 font-mono text-[11px] text-[#8b9ac6] space-y-0.5">
                  <div>{thread.packets_processed.toLocaleString()} processed</div>
                  <div>{loadShare}% of packets</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
