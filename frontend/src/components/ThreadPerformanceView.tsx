import React from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import { formatBandwidthRate, formatPacketRate } from "@/lib/utils";
import { Cpu } from "lucide-react";

export const ThreadPerformanceView: React.FC = () => {
  const { threads, stats } = useAegisStore();
  const isEngineLive = useIsEngineLive();

  const lbTotal = threads.filter((t) => t.role === "LB").reduce((sum, t) => sum + t.packets_processed, 0);
  const fpTotal = threads.filter((t) => t.role === "FAST_PATH").reduce((sum, t) => sum + t.packets_processed, 0);
  const lbCount = threads.filter((t) => t.role === "LB").length || 2;
  const fpCount = threads.filter((t) => t.role === "FAST_PATH").length || 4;

  return (
    <div className="space-y-6">
      {/* Top Architecture Metric Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4">
          <div className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
            Thread Pipeline Concurrency
          </div>
          <div className="text-2xl font-bold font-mono text-[#eef1f8] mt-2">
            {threads.length}{" "}
            <span className="text-xs text-[#8b9ac6] font-normal">
              {isEngineLive ? "Active Workers" : "configured workers"}
            </span>
          </div>
          <div className="text-[11px] font-mono text-[#2fb8a6] mt-1">
            {lbCount} LBs + {fpCount} FPs (+ Reporter, RuleSubscriber)
          </div>
        </div>

        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4">
          <div className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
            Engine Throughput Rate
          </div>
          <div className="text-2xl font-bold font-mono text-[#2fb8a6] mt-2">
            {formatPacketRate(stats?.throughput_pps ?? 0)}
          </div>
          <div className="text-[11px] font-mono text-[#8b9ac6] mt-1">
            {formatBandwidthRate(stats?.throughput_bps ?? ((stats?.throughput_mbps ?? 0) * 1e6))}
          </div>
        </div>

        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4">
          <div className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
            Kernel Drops
          </div>
          <div className="text-2xl font-bold font-mono text-[#eef1f8] mt-2">
            {((stats?.pcap_drop ?? 0) + (stats?.pcap_ifdrop ?? 0)).toLocaleString()}
          </div>
          <div className="text-[11px] font-mono text-[#2fb8a6] mt-1">
            pcap_drop + pcap_ifdrop
          </div>
        </div>

        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4">
          <div className="text-xs font-mono uppercase tracking-wider text-[#8b9ac6]">
            Total Ingested By Workers
          </div>
          <div className="text-2xl font-bold font-mono text-[#eef1f8] mt-2">
            {fpTotal.toLocaleString()}
          </div>
          <div className="text-[11px] font-mono text-[#8b9ac6] mt-1">
            sum of Fast Path processed
          </div>
        </div>
      </div>

      {/* Grid of Thread Cards with Sparklines */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {threads.map((thread) => {
          const isLb = thread.role === "LB";
          const sumForType = isLb ? lbTotal : fpTotal;
          const loadPct = thread.load_pct ?? (sumForType > 0 ? Math.round((thread.packets_processed / sumForType) * 100) : 0);

          // Calculate SVG sparkline points from pps_history
          const minPps = Math.min(...(thread.pps_history || [0]));
          const maxPps = Math.max(...(thread.pps_history || [1])) || 1;
          const points = (thread.pps_history || [0])
            .map((val, idx) => {
              const histLen = thread.pps_history?.length || 1;
              const x = histLen > 1 ? (idx / (histLen - 1)) * 200 : 100;
              const y = 50 - ((val - minPps) / (maxPps - minPps || 1)) * 40;
              return `${x},${y}`;
            })
            .join(" ");

          return (
            <div
              key={thread.name || thread.thread_id}
              className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 flex flex-col justify-between hover:border-[#3a4a80] transition-colors"
            >
              <div>
                {/* Header */}
                <div className="flex items-center justify-between gap-2 pb-3 border-b border-[#22305e] whitespace-nowrap">
                  <div className="flex items-center space-x-2.5 min-w-0">
                    <div
                      className={`p-2 rounded shrink-0 ${
                        isLb
                          ? "bg-amber-400/10 text-amber-400"
                          : "bg-[#2fb8a6]/10 text-[#2fb8a6]"
                      }`}
                    >
                      <Cpu className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-sm font-bold font-mono text-[#eef1f8] truncate">
                        {thread.name}
                      </h3>
                      <span className="text-[10px] font-mono text-[#8b9ac6] block truncate">
                        {isLb ? "LB Dispatcher" : "Fast-Path"}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0 ml-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isLb
                          ? "bg-amber-400/20 text-amber-300 border border-amber-400/40"
                          : "bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40"
                      }`}
                    >
                      {isLb ? "LB" : "FP"}
                    </span>
                    <span className="text-xs font-mono font-bold text-[#a9b6da]">
                      {loadPct}% of packets
                    </span>
                  </div>
                </div>

                {/* Metrics */}
                <div className="mt-4 grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="bg-[#0c142e] border border-[#22305e] rounded p-2.5">
                    <span className="text-[10px] text-[#8b9ac6] block">
                      {isLb ? "DISPATCHED" : "PROCESSED"}
                    </span>
                    <span className="text-sm font-bold text-[#eef1f8] mt-0.5 block">
                      {thread.packets_processed.toLocaleString()}
                    </span>
                  </div>

                  <div className="bg-[#0c142e] border border-[#22305e] rounded p-2.5">
                    <span className="text-[10px] text-[#8b9ac6] block">PACKET SHARE</span>
                    <span className="text-sm font-bold text-[#2fb8a6] mt-0.5 block">
                      {loadPct}% of packets
                    </span>
                  </div>
                </div>

                {/* Verdict / Pipeline Summary Breakdown (same height for LB and FP) */}
                {isLb ? (
                  <div className="mt-3 bg-[#0c142e] border border-[#22305e] rounded p-2.5 text-xs font-mono space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Target pipeline:</span>
                      <span className="text-amber-300 font-semibold">
                        Fast-Path Workers
                      </span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Queue type:</span>
                      <span className="text-[#2fb8a6] font-semibold">
                        Thread-safe mutex
                      </span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Flow hashing:</span>
                      <span className="text-[#a9b6da] font-semibold">
                        Symmetric 5-tuple
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="mt-3 bg-[#0c142e] border border-[#22305e] rounded p-2.5 text-xs font-mono space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Forwarded:</span>
                      <span className="text-[#2fb8a6] font-semibold">
                        {thread.forwarded.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Dropped:</span>
                      <span className="text-[#ff5a2b] font-semibold">
                        {thread.dropped.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-[#8b9ac6]">Unhandled:</span>
                      <span className="text-[#8b9ac6]">
                        {thread.unhandled.toLocaleString()}
                      </span>
                    </div>
                  </div>
                )}

                {/* Throughput Sparkline */}
                <div className="mt-4">
                  <div className="flex items-center justify-between text-[10px] font-mono text-[#8b9ac6] mb-1">
                    <span>RATE HISTORY</span>
                    <span className="text-[#eef1f8]">
                      {isEngineLive && thread.pps_history && thread.pps_history.length > 0
                        ? thread.pps_history[thread.pps_history.length - 1]
                        : 0}{" "}
                      pps
                    </span>
                  </div>

                  <div className="w-full h-14 bg-[#0c142e] border border-[#22305e] rounded p-1.5 flex items-center justify-center">
                    <svg
                      className="w-full h-full overflow-visible"
                      viewBox="0 0 200 55"
                      preserveAspectRatio="none"
                    >
                      <polyline
                        fill="none"
                        stroke={isLb ? "#fbbf24" : "#2fb8a6"}
                        strokeWidth="2"
                        points={points}
                      />
                    </svg>
                  </div>
                </div>
              </div>

              {/* Footer status */}
              <div className="mt-4 pt-3 border-t border-[#22305e] flex items-center justify-between text-[10px] font-mono text-[#8b9ac6]">
                <span className="flex items-center">
                  <span
                    className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                      isEngineLive ? "bg-[#2fb8a6] animate-pulse" : "bg-slate-500"
                    }`}
                  />
                  <span className={isEngineLive ? "text-[#8b9ac6]" : "text-slate-400"}>
                    {isEngineLive ? "Running" : "Stopped"}
                  </span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
