import React, { useState } from "react";
import {
  Database,
  GitBranch,
  ShieldAlert,
  BrainCircuit,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  List,
  Eye,
} from "lucide-react";

export const ArchitectureView: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number>(0);
  const [showAllSteps, setShowAllSteps] = useState<boolean>(false);

  const captions = [
    "libpcap captures every packet on the selected interface.",
    "The engine parses, hashes the flow to a Fast Path thread, inspects it, and the Reporter writes it to Redis (dpi:logs via XADD, dpi:stats via HINCRBY/HSET).",
    "The middleware reads dpi:logs from Redis.",
    "It pushes entries to the dashboard in batches over Socket.io (log:batch).",
    "The ML service reads the same dpi:logs stream and scores each source IP over a 5-second window.",
    "At confidence >= 0.85 it calls POST /api/rules, and publishes the verdict on ml:verdicts (forwarded as anomaly:new) so the dashboard shows the alert.",
    "The middleware adds the IP to blocklist:ips and publishes ADD IP on blocklist:updates.",
    "The engine's Rule Subscriber receives the message.",
    "It adds the IP to the nftables set; the kernel drops its packets.",
  ];

  const getOpacity = (steps: number[]) => {
    if (showAllSteps || activeStep === 0) return 1;
    return steps.includes(activeStep) ? 1 : 0.4;
  };

  return (
    <div className="space-y-8">
      {/* SECTION 1: ARCHITECTURE PIPELINE */}
      <section className="bg-[#101a38] border border-[#22305e] rounded-lg p-6 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-[#22305e]">
          <div>
            <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
              1. System Pipeline
            </h2>
            <p className="font-sans text-[13px] leading-[1.6] text-[#8b9ac6] mt-0.5">
              Data ingestion path and closed-loop automated detection and mitigation flow.
            </p>
          </div>

          {/* Two-Item Legend */}
          <div className="flex items-center space-x-5 text-[11px] font-mono">
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#2fb8a6]" />
              <span className="text-[#eef1f8]">Data path</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ff5a2b]" />
              <span className="text-[#eef1f8]">Block path</span>
            </span>
          </div>
        </div>

        {/* 1A: Data Path (One Row) */}
        <div className="space-y-2">
          <div className="text-xs font-mono font-bold text-[#2fb8a6] uppercase tracking-wider flex items-center space-x-1.5">
            <span>1A. Data Path</span>
          </div>
          <div className="w-full overflow-x-auto">
            <svg
              viewBox="0 0 1180 100"
              className="w-full h-auto min-w-[950px]"
              style={{ display: "block" }}
            >
              <defs>
                <marker id="arr-teal" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill="#2fb8a6" />
                </marker>
              </defs>

              {/* Box 1: Network interface */}
              <g style={{ opacity: getOpacity([1]), transition: "opacity 0.2s" }}>
                <rect x="6" y="18" width="176" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="94" y="43" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Network interface
                </text>
                <text x="94" y="63" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  libpcap capture
                </text>
              </g>

              {/* Arrow 1 */}
              <g style={{ opacity: getOpacity([1]), transition: "opacity 0.2s" }}>
                <line x1="182" y1="50" x2="252" y2="50" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-teal)" />
                <circle cx="218" cy="50" r="10" fill="#101a38" stroke="#2fb8a6" strokeWidth="1.5" />
                <text x="218" y="54" fill="#2fb8a6" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  1
                </text>
              </g>

              {/* Box 2: C++ engine */}
              <g style={{ opacity: getOpacity([1, 2]), transition: "opacity 0.2s" }}>
                <rect x="254" y="18" width="176" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="342" y="43" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  C++ engine
                </text>
                <text x="342" y="63" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  LB &amp; Fast Path workers
                </text>
              </g>

              {/* Arrow 2 */}
              <g style={{ opacity: getOpacity([2]), transition: "opacity 0.2s" }}>
                <line x1="430" y1="50" x2="500" y2="50" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-teal)" />
                <circle cx="466" cy="50" r="10" fill="#101a38" stroke="#2fb8a6" strokeWidth="1.5" />
                <text x="466" y="54" fill="#2fb8a6" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  2
                </text>
              </g>

              {/* Box 3: Redis */}
              <g style={{ opacity: getOpacity([2, 3]), transition: "opacity 0.2s" }}>
                <rect x="502" y="18" width="176" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="590" y="43" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Redis
                </text>
                <text x="590" y="63" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  dpi:logs &amp; dpi:stats
                </text>
              </g>

              {/* Arrow 3 */}
              <g style={{ opacity: getOpacity([3]), transition: "opacity 0.2s" }}>
                <line x1="678" y1="50" x2="748" y2="50" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-teal)" />
                <circle cx="714" cy="50" r="10" fill="#101a38" stroke="#2fb8a6" strokeWidth="1.5" />
                <text x="714" y="54" fill="#2fb8a6" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  3
                </text>
              </g>

              {/* Box 4: Node middleware */}
              <g style={{ opacity: getOpacity([3, 4]), transition: "opacity 0.2s" }}>
                <rect x="750" y="18" width="176" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="838" y="43" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Node middleware
                </text>
                <text x="838" y="63" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  REST &amp; Socket.io
                </text>
              </g>

              {/* Arrow 4 */}
              <g style={{ opacity: getOpacity([4]), transition: "opacity 0.2s" }}>
                <line x1="926" y1="50" x2="996" y2="50" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-teal)" />
                <circle cx="962" cy="50" r="10" fill="#101a38" stroke="#2fb8a6" strokeWidth="1.5" />
                <text x="962" y="54" fill="#2fb8a6" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  4
                </text>
              </g>

              {/* Box 5: Dashboard */}
              <g style={{ opacity: getOpacity([4]), transition: "opacity 0.2s" }}>
                <rect x="998" y="18" width="176" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="1086" y="43" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Dashboard
                </text>
                <text x="1086" y="63" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  React web console
                </text>
              </g>
            </svg>
          </div>
        </div>

        {/* 1B: Detect & Block Loop (Two Rows) */}
        <div className="space-y-2 pt-4 border-t border-[#16204a]">
          <div className="text-xs font-mono font-bold text-[#ff5a2b] uppercase tracking-wider flex items-center space-x-1.5">
            <span>1B. Detect &amp; Block Loop</span>
          </div>
          <div className="w-full overflow-x-auto">
            <svg
              viewBox="0 0 1180 230"
              className="w-full h-auto min-w-[950px]"
              style={{ display: "block" }}
            >
              <defs>
                <marker id="arr-teal-loop" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill="#2fb8a6" />
                </marker>
                <marker id="arr-orange-loop" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill="#ff5a2b" />
                </marker>
              </defs>

              {/* ROW 1: Top (Left to Right) */}
              {/* Box 1B.1: Redis: dpi:logs */}
              <g style={{ opacity: getOpacity([5]), transition: "opacity 0.2s" }}>
                <rect x="15" y="20" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="160" y="45" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Redis: dpi:logs
                </text>
                <text x="160" y="65" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  Packet metadata stream
                </text>
              </g>

              {/* Arrow 5: Redis: dpi:logs -> ML service (teal) */}
              <g style={{ opacity: getOpacity([5]), transition: "opacity 0.2s" }}>
                <line x1="305" y1="52" x2="443" y2="52" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-teal-loop)" />
                <circle cx="375" cy="52" r="10" fill="#101a38" stroke="#2fb8a6" strokeWidth="1.5" />
                <text x="375" y="56" fill="#2fb8a6" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  5
                </text>
              </g>

              {/* Box 1B.2: ML service */}
              <g style={{ opacity: getOpacity([5, 6]), transition: "opacity 0.2s" }}>
                <rect x="445" y="20" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="590" y="45" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  ML service
                </text>
                <text x="590" y="65" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  Isolation Forest (5s window)
                </text>
              </g>

              {/* Arrow 6: ML service -> Node middleware (accent) */}
              <g style={{ opacity: getOpacity([6]), transition: "opacity 0.2s" }}>
                <line x1="735" y1="52" x2="873" y2="52" stroke="#ff5a2b" strokeWidth="2" markerEnd="url(#arr-orange-loop)" />
                <circle cx="805" cy="52" r="10" fill="#101a38" stroke="#ff5a2b" strokeWidth="1.5" />
                <text x="805" y="56" fill="#ff5a2b" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  6
                </text>
              </g>

              {/* Box 1B.3: Node middleware */}
              <g style={{ opacity: getOpacity([6, 7]), transition: "opacity 0.2s" }}>
                <rect x="875" y="20" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="1020" y="45" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Node middleware
                </text>
                <text x="1020" y="65" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  POST /api/rules endpoint
                </text>
              </g>

              {/* Arrow 7: Node middleware -> Redis: blocklist:updates (DOWN) */}
              <g style={{ opacity: getOpacity([7]), transition: "opacity 0.2s" }}>
                <line x1="1020" y1="84" x2="1020" y2="144" stroke="#ff5a2b" strokeWidth="2" markerEnd="url(#arr-orange-loop)" />
                <circle cx="1020" cy="115" r="10" fill="#101a38" stroke="#ff5a2b" strokeWidth="1.5" />
                <text x="1020" y="119" fill="#ff5a2b" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  7
                </text>
              </g>

              {/* ROW 2: Bottom (Right to Left) */}
              {/* Box 1B.4: Redis: blocklist:updates */}
              <g style={{ opacity: getOpacity([7, 8]), transition: "opacity 0.2s" }}>
                <rect x="875" y="146" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="1020" y="171" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Redis: blocklist:updates
                </text>
                <text x="1020" y="191" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  Pub/Sub control channel
                </text>
              </g>

              {/* Arrow 8: Redis: blocklist:updates -> Rule Subscriber (LEFT) */}
              <g style={{ opacity: getOpacity([8]), transition: "opacity 0.2s" }}>
                <line x1="875" y1="178" x2="737" y2="178" stroke="#ff5a2b" strokeWidth="2" markerEnd="url(#arr-orange-loop)" />
                <circle cx="805" cy="178" r="10" fill="#101a38" stroke="#ff5a2b" strokeWidth="1.5" />
                <text x="805" y="182" fill="#ff5a2b" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  8
                </text>
              </g>

              {/* Box 1B.5: Rule Subscriber */}
              <g style={{ opacity: getOpacity([8, 9]), transition: "opacity 0.2s" }}>
                <rect x="445" y="146" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="590" y="171" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  Rule Subscriber
                </text>
                <text x="590" y="191" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  Engine live listener thread
                </text>
              </g>

              {/* Arrow 9: Rule Subscriber -> nftables (kernel) (LEFT) */}
              <g style={{ opacity: getOpacity([9]), transition: "opacity 0.2s" }}>
                <line x1="445" y1="178" x2="307" y2="178" stroke="#ff5a2b" strokeWidth="2" markerEnd="url(#arr-orange-loop)" />
                <circle cx="375" cy="178" r="10" fill="#101a38" stroke="#ff5a2b" strokeWidth="1.5" />
                <text x="375" y="182" fill="#ff5a2b" fontFamily="monospace" fontSize="11" fontWeight="bold" textAnchor="middle">
                  9
                </text>
              </g>

              {/* Box 1B.6: nftables (kernel) */}
              <g style={{ opacity: getOpacity([9]), transition: "opacity 0.2s" }}>
                <rect x="15" y="146" width="290" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
                <text x="160" y="171" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                  nftables (kernel)
                </text>
                <text x="160" y="191" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                  inet aegis prerouting drop
                </text>
              </g>
            </svg>
          </div>
        </div>

        {/* Interactive Step-Through Controls & Caption */}
        <div className="pt-4 border-t border-[#16204a] space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center space-x-3">
              {showAllSteps ? (
                <span className="font-mono text-xs font-bold text-[#2fb8a6] px-2 py-1 rounded bg-[#2fb8a6]/10 border border-[#2fb8a6]/20">
                  All steps
                </span>
              ) : (
                <>
                  <button
                    onClick={() => setActiveStep((prev) => Math.max(0, prev - 1))}
                    disabled={activeStep === 0}
                    className="px-3 py-1.5 rounded bg-[#0c142e] border border-[#22305e] hover:border-[#3a4a80] text-xs font-mono text-[#eef1f8] disabled:opacity-30 disabled:cursor-not-allowed flex items-center space-x-1 transition-colors"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    <span>Prev</span>
                  </button>

                  <span className="font-mono text-xs font-bold text-[#eef1f8] px-2">
                    {activeStep === 0 ? "Overview" : `Step ${activeStep} / 9`}
                  </span>

                  <button
                    onClick={() => setActiveStep((prev) => Math.min(9, prev + 1))}
                    disabled={activeStep === 9}
                    className="px-3 py-1.5 rounded bg-[#0c142e] border border-[#22305e] hover:border-[#3a4a80] text-xs font-mono text-[#eef1f8] disabled:opacity-30 disabled:cursor-not-allowed flex items-center space-x-1 transition-colors"
                  >
                    <span>Next</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </>
              )}
            </div>

            <button
              onClick={() => setShowAllSteps(!showAllSteps)}
              className="px-3 py-1.5 rounded bg-[#0c142e] border border-[#22305e] hover:border-[#3a4a80] text-xs font-mono text-[#2fb8a6] flex items-center space-x-1.5 transition-colors"
            >
              {showAllSteps ? (
                <>
                  <Eye className="h-3.5 w-3.5" />
                  <span>Interactive step mode</span>
                </>
              ) : (
                <>
                  <List className="h-3.5 w-3.5" />
                  <span>Show all steps</span>
                </>
              )}
            </button>
          </div>

          {/* Caption Display */}
          {showAllSteps ? (
            <div className="space-y-2.5 bg-[#0c142e] border border-[#22305e] rounded p-4">
              {captions.map((c, i) => (
                <div key={i} className="font-sans text-[15px] leading-[1.6] text-[#eef1f8] flex items-start space-x-2.5">
                  <span className="font-mono font-bold text-[13px] text-[#2fb8a6] px-1.5 py-0.5 rounded bg-[#2fb8a6]/10 border border-[#2fb8a6]/20 shrink-0">
                    {i + 1}
                  </span>
                  <span>{c}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 flex items-start space-x-3">
              <span className="font-mono font-bold text-[13px] text-[#2fb8a6] px-2 py-0.5 rounded bg-[#2fb8a6]/10 border border-[#2fb8a6]/20 shrink-0">
                {activeStep === 0 ? "Overview" : `Step ${activeStep}`}
              </span>
              <p className="font-sans text-[15px] leading-[1.6] text-[#eef1f8]">
                {activeStep === 0
                  ? "Press Next to walk through the pipeline step by step."
                  : captions[activeStep - 1]}
              </p>
            </div>
          )}
        </div>
      </section>

      {/* SECTION 2: REDIS DATA MAP */}
      <section className="bg-[#101a38] border border-[#22305e] rounded-lg overflow-hidden">
        <div className="p-4 bg-[#0c142e] border-b border-[#22305e] flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <Database className="h-4 w-4 text-[#f97316]" />
            <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
              2. Redis Data Map
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[#8b9ac6]">
            Shared In-Memory State &amp; Pub/Sub Contracts
          </span>
        </div>

        <div className="p-4 overflow-x-auto">
          <table className="w-full min-w-[720px] text-left border-collapse">
            <thead>
              <tr className="border-b border-[#22305e] text-[#8b9ac6] font-mono text-[11px]">
                <th className="py-2.5 px-3">REDIS KEY / CHANNEL</th>
                <th className="py-2.5 px-3">TYPE</th>
                <th className="py-2.5 px-3">WRITTEN BY</th>
                <th className="py-2.5 px-3">READ BY</th>
                <th className="py-2.5 px-3">PURPOSE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#16204a] font-mono text-[11px]">
              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#2fb8a6]">dpi:logs</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
                    stream
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">C++ DPI Engine (Reporter)</td>
                <td className="py-3 px-3 text-[#eef1f8]">
                  Node Middleware (redis_consumer), ML Service
                </td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Carries 5-tuple, protocol, SNI, decision action, reason, and worker thread ID. Trimmed to ~20,000 entries every 30 s by Node middleware.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#2fb8a6]">dpi:stats</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
                    hash
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">C++ DPI Engine (Reporter)</td>
                <td className="py-3 px-3 text-[#eef1f8]">
                  Node Middleware (stats route, engine manager)
                </td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  System-wide telemetry: pcap drop counters, per-thread processed totals, engine PID, and updated_at_ms heartbeat. Flushed every 1 s by the engine.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#ff5a2b]">blocklist:ips</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
                    set
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">Node Middleware (/api/rules)</td>
                <td className="py-3 px-3 text-[#eef1f8]">
                  Node Middleware, ML Service, C++ Engine (startup seed)
                </td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Persistent set of active blocked IPv4 addresses. Read at startup by the C++ engine to seed nftables, and queried by the ML service to skip already-blocked hosts.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#ff5a2b]">blocklist:meta</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
                    hash
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">Node Middleware (/api/rules)</td>
                <td className="py-3 px-3 text-[#eef1f8]">
                  Node Middleware (/api/rules, session report)
                </td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Persistent metadata for blocked IPs: <code className="text-[#eef1f8]">added_by</code>, <code className="text-[#eef1f8]">source</code> (manual vs ml_auto), <code className="text-[#eef1f8]">added_at</code> timestamp, and attribution reason, stored as JSON per IP field.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#ff5a2b]">blocklist:updates</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/30">
                    pub/sub
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">Node Middleware (/api/rules)</td>
                <td className="py-3 px-3 text-[#eef1f8]">C++ DPI Engine (Rule Subscriber)</td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Real-time control channel publishing <code className="text-[#eef1f8]">ADD IP &lt;ip&gt;</code> or <code className="text-[#eef1f8]">DEL IP &lt;ip&gt;</code> for live kernel enforcer updates without engine restart.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#a855f7]">ml:verdicts</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#a855f7]/20 text-[#a855f7] border border-[#a855f7]/30">
                    pub/sub
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">Python ML Service</td>
                <td className="py-3 px-3 text-[#eef1f8]">Node Middleware (redis_consumer)</td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Broadcast channel emitting evaluated ANOMALOUS verdict payloads with calibrated confidence scores and feature contributions for live Socket.io alert relay.
                </td>
              </tr>

              <tr className="hover:bg-[#0c142e]/60 transition-colors">
                <td className="py-3 px-3 font-bold text-[#a855f7]">ml:verdict_history</td>
                <td className="py-3 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e]">
                    stream
                  </span>
                </td>
                <td className="py-3 px-3 text-[#eef1f8]">Python ML Service</td>
                <td className="py-3 px-3 text-[#eef1f8]">Node Middleware (/api/anomalies)</td>
                <td className="py-3 px-3 font-sans text-[12px] leading-[1.5] text-[#a9b6da]">
                  Bounded stream (capped at 500 entries) archiving historical anomaly verdicts to ensure the UI retains anomaly history across page reloads.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* SECTION 3: HOW A PACKET IS DECIDED */}
      <section className="bg-[#101a38] border border-[#22305e] rounded-lg p-6 space-y-6">
        <div className="flex items-center space-x-2.5 pb-3 border-b border-[#22305e]">
          <GitBranch className="h-4 w-4 text-[#2fb8a6]" />
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
            3. How a Packet is Decided
          </h2>
        </div>

        {/* Small single-row diagram of engine internals */}
        <div className="space-y-2">
          <div className="text-xs font-mono font-bold text-[#8b9ac6] uppercase tracking-wider">
            Engine Thread Pipeline Internals
          </div>
          <div className="w-full overflow-x-auto">
            <svg
              viewBox="0 0 1100 84"
              className="w-full h-auto min-w-[850px]"
              style={{ display: "block" }}
            >
              <defs>
                <marker id="arr-engine" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill="#2fb8a6" />
                </marker>
              </defs>

              {/* Box 1: libpcap */}
              <rect x="10" y="10" width="205" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
              <text x="112" y="35" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                libpcap
              </text>
              <text x="112" y="55" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                Raw packet capture
              </text>

              {/* Arrow 1 -> 2 */}
              <line x1="215" y1="42" x2="285" y2="42" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-engine)" />

              {/* Box 2: Load Balancer threads */}
              <rect x="295" y="10" width="235" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
              <text x="412" y="35" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                Load Balancer threads
              </text>
              <text x="412" y="55" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                Symmetric 5-tuple hash (--lbs)
              </text>

              {/* Arrow 2 -> 3 */}
              <line x1="530" y1="42" x2="600" y2="42" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-engine)" />

              {/* Box 3: Fast Path threads */}
              <rect x="610" y="10" width="235" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
              <text x="727" y="35" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                Fast Path threads
              </text>
              <text x="727" y="55" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                Payload inspect &amp; SNI (--fps)
              </text>

              {/* Arrow 3 -> 4 */}
              <line x1="845" y1="42" x2="915" y2="42" stroke="#2fb8a6" strokeWidth="2" markerEnd="url(#arr-engine)" />

              {/* Box 4: Reporter */}
              <rect x="925" y="10" width="165" height="64" rx="6" fill="#101a38" stroke="#22305e" strokeWidth="1.5" />
              <text x="1007" y="35" fill="#eef1f8" fontFamily="monospace" fontSize="14" fontWeight="bold" textAnchor="middle">
                Reporter
              </text>
              <text x="1007" y="55" fill="#8b9ac6" fontFamily="'Public Sans', sans-serif" fontSize="13" textAnchor="middle">
                XADD logs &amp; flush stats
              </text>
            </svg>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2">
            <div className="text-xs font-mono font-bold text-[#2fb8a6] uppercase tracking-wider">
              Symmetric 5-Tuple Flow Hashing
            </div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              TCP/UDP flows are hashed on a symmetric 5-tuple so both directions of a connection go to the same Fast Path thread (N threads, set by <code className="font-mono text-[12px] bg-[#081022] px-1 py-0.5 rounded text-[#eef1f8]">--fps</code>).
            </p>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              ICMP and ARP have no ports and are distributed round-robin across worker queues using the Load Balancer thread's dispatched counter (N threads, set by <code className="font-mono text-[12px] bg-[#081022] px-1 py-0.5 rounded text-[#eef1f8]">--lbs</code>).
            </p>
          </div>

          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-3">
            <div className="text-xs font-mono font-bold text-[#eef1f8] uppercase tracking-wider">
              Terminal Packet Outcomes
            </div>
            <div className="space-y-2 font-sans text-[13px] leading-[1.5]">
              <div className="flex items-start space-x-2">
                <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 shrink-0">
                  FORWARDED
                </span>
                <span className="text-[#a9b6da]">
                  Clean TCP packets that pass inspection without matching any blocklist rule. Classified by payload into TLS, HTTP, or TCP control.
                </span>
              </div>

              <div className="flex items-start space-x-2">
                <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40 shrink-0">
                  DROPPED
                </span>
                <span className="text-[#a9b6da]">
                  Packets from a blocked IP (kept in Redis <code className="font-mono text-[11px] text-[#eef1f8]">blocklist:ips</code> and mirrored into the nftables set <code className="font-mono text-[11px] text-[#eef1f8]">blocklist</code>), or malformed frames (truncated ethernet, IP, or TCP headers).
                </span>
              </div>

              <div className="flex items-start space-x-2">
                <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-[#8b9ac6]/20 text-[#a9b6da] border border-[#8b9ac6]/40 shrink-0">
                  UNHANDLED
                </span>
                <span className="text-[#a9b6da]">
                  Non-TCP protocols (UDP, ICMP) and non-IPv4 frames that are not deep-inspected.
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 4: ENFORCEMENT */}
      <section className="bg-[#101a38] border border-[#22305e] rounded-lg p-6 space-y-4">
        <div className="flex items-center space-x-2.5 pb-3 border-b border-[#22305e]">
          <ShieldAlert className="h-4 w-4 text-[#ff5a2b]" />
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
            4. Kernel Enforcement
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2">
            <div className="text-xs font-mono font-bold text-[#ff5a2b] uppercase tracking-wider">
              Linux Nftables Structure
            </div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              Linux nftables table <code className="font-mono text-[12px] bg-[#081022] px-1 py-0.5 rounded text-[#eef1f8]">inet aegis</code> with an IP set <code className="font-mono text-[12px] bg-[#081022] px-1 py-0.5 rounded text-[#eef1f8]">blocklist</code> and a drop rule in the prerouting chain (hooked at priority -300).
            </p>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              Rules are added and removed live via Redis pub/sub; the table is removed on clean shutdown (SIGINT).
            </p>
          </div>

          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2">
            <div className="text-xs font-mono font-bold text-[#ffaa00] uppercase tracking-wider">
              Detect-Then-Block Mechanics
            </div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              Enforcement is detect-then-block, not inline: a flood is blocked after it has been detected.
            </p>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              Detection takes about one evaluation cycle (1 s) on a 5-second sliding window before the drop rule is installed into kernel space.
            </p>
          </div>
        </div>
      </section>

      {/* SECTION 5: ML ANOMALY DETECTION */}
      <section className="bg-[#101a38] border border-[#22305e] rounded-lg p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-[#22305e]">
          <div className="flex items-center space-x-2.5">
            <BrainCircuit className="h-4 w-4 text-[#a855f7]" />
            <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
              5. ML Anomaly Detection
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[#8b9ac6]">
            Scikit-Learn IsolationForest
          </span>
        </div>

        {/* 5 Features as a Row of Small Chips */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-mono text-[#8b9ac6] uppercase font-bold">
            Features Evaluated Per Source IP (5-second Sliding Window):
          </div>
          <div className="flex flex-wrap gap-2">
            {["packets/s", "unique destination ports", "unique destination IPs", "dropped ratio", "protocol diversity"].map((f) => (
              <span
                key={f}
                className="px-2.5 py-1 rounded bg-[#0c142e] border border-[#22305e] text-xs font-mono text-[#eef1f8]"
              >
                {f}
              </span>
            ))}
          </div>
        </div>

        {/* Three Equal-Height Cards with Short Text */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="text-xs font-mono font-bold text-[#a855f7] uppercase tracking-wider">
                Isolation Forest Model
              </div>
              <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
                Scores the 5 aggregated features per source IP over a 5-second sliding window. Calibrated sigmoid confidence determines anomalous traffic (&ge; 0.85).
              </p>
            </div>
          </div>

          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="text-xs font-mono font-bold text-[#2fb8a6] uppercase tracking-wider">
                Direction-Aware Flow Tracking
              </div>
              <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
                The initiator comes from TCP SYN / ICMP type, falling back to arrival order for UDP. Responses to connections this machine initiated are never scored. Already-blocked IPs are skipped.
              </p>
            </div>
          </div>

          <div className="bg-[#0c142e] border border-[#22305e] rounded p-4 space-y-2 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="text-xs font-mono font-bold text-[#eef1f8] uppercase tracking-wider">
                Baseline Deviation Attribution
              </div>
              <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
                Feature explanation is &quot;Deviation from baseline&quot;, not SHAP. Relative baseline deviations pinpoint the anomalous dimension.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 6: KNOWN LIMITATIONS */}
      <section className="bg-[#101a38] border border-amber-500/30 rounded-lg p-6 space-y-4">
        <div className="flex items-center space-x-2.5 pb-3 border-b border-[#22305e]">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-[#eef1f8]">
            6. Known Limitations (Honest List)
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Feature Limitations</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              The engine does not log packet length, so the ML uses 5 features.
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Training Baseline</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              The model is trained on synthetic normal traffic rather than long-term enterprise captures.
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Stream Reassembly</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              No TCP stream reassembly (a TLS hello split across packets is not reassembled).
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Initiator Inference</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              UDP flow initiator is still inferred from arrival order; TCP uses the SYN flag and ICMP uses the message type.
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Capture Interfaces</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              One capture interface at a time; multi-interface aggregation is not supported.
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Elevation Method</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              The capture button relies on a restricted sudo rule; production would use Linux capabilities and a service account.
            </p>
          </div>

          <div className="bg-[#0c142e] border border-amber-500/20 rounded p-4 space-y-1.5">
            <div className="text-xs font-mono font-bold text-amber-300">Session Management</div>
            <p className="font-sans text-[13px] leading-[1.6] text-[#a9b6da]">
              Sessions use JWTs that are not revoked on sign-out; they expire after 8 h.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
