import React, { useState, useEffect } from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import {
  RefreshCw,
  Clock,
  Pause,
  Play,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";

export const Header: React.FC = () => {
  const {
    navSection,
    socketConnected,
    stats,
    initializeData,
    isPaused,
    bufferedCount,
    togglePause,
    setIsReportOpen,
  } = useAegisStore();

  const [timeString, setTimeString] = useState<string>(() => {
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  });

  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, "0");
      setTimeString(`${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const getSectionTitle = () => {
    switch (navSection) {
      case "stats":
        return "Telemetry Overview";
      case "packets":
        return "Packet Inspection Log";
      case "blocklist":
        return "Kernel Blocklist Rules";
      case "anomalies":
        return "ML Anomaly Detection";
      case "threads":
        return "Engine Thread Performance";
      case "architecture":
        return "System Architecture";
      default:
        return "Security Operations Console";
    }
  };

  const getFullSectionTitle = () => {
    switch (navSection) {
      case "stats":
        return "Telemetry Overview & Packet Classification";
      case "packets":
        return "Packet Inspection Log Stream (dpi:logs)";
      case "blocklist":
        return "Kernel Blocklist Rules & Pub/Sub Updates";
      case "anomalies":
        return "ML Real-Time Anomaly Detection & Feature Explainability";
      case "threads":
        return "C++ Multi-Threaded Engine Performance (LBs + Fast-Paths)";
      case "architecture":
        return "System Architecture, Pipeline Flow & Redis Data Map";
      default:
        return "Security Operations Console";
    }
  };

  const isEngineLive = useIsEngineLive();

  return (
    <header className="bg-[#101a38] border-b border-[#22305e] px-8 h-[72px] flex items-center justify-between sticky top-0 z-30 font-mono">
      <div className="flex-1 min-w-0 mr-4">
        <div className="flex items-center space-x-2 text-[11px] text-[#8b9ac6] uppercase tracking-wider whitespace-nowrap truncate">
          <span>Aegis Operations</span>
          <span>/</span>
          <span className="text-[#ff5a2b] font-bold">{navSection}</span>
        </div>
        <h1
          className="text-base font-bold text-[#eef1f8] tracking-wide mt-0.5 whitespace-nowrap truncate"
          title={getFullSectionTitle()}
        >
          {getSectionTitle()}
        </h1>
      </div>

      <div className="flex items-center gap-2 shrink-0 whitespace-nowrap">
        {/* Rate indicator when live, single grey pill when engine stopped */}
        {isEngineLive ? (
          <div
            className="flex items-center h-9 px-3 bg-[#0c142e] border border-[#22305e] rounded text-xs gap-1.5"
            title="Inspected packet throughput"
          >
            <span className="text-[#8b9ac6]">RATE</span>
            <span className="text-[#2fb8a6] font-bold">
              {stats ? `${stats.throughput_pps.toLocaleString()} pps` : "0 pps"}
            </span>
          </div>
        ) : (
          <div
            className="flex items-center h-9 px-3 bg-[#0c142e] border border-slate-700/60 rounded text-xs text-slate-400 font-semibold gap-2"
            title="Engine process is stopped"
          >
            <span className="w-2 h-2 rounded-full bg-slate-500" />
            <span>ENGINE STOPPED</span>
          </div>
        )}

        {/* Socket Link Status */}
        <div
          className="flex items-center h-9 px-3 bg-[#0c142e] border border-[#22305e] rounded text-xs gap-2 cursor-default"
          title={socketConnected ? "Socket.io connected" : "Socket.io disconnected"}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              socketConnected ? "bg-[#2fb8a6] animate-engine-tick" : "bg-[#ff5a2b]"
            }`}
          />
          <span className="text-[#a9b6da]">WS 4000</span>
        </div>

        {/* Live Clock (hidden below 1400px) */}
        <div className="hidden min-[1400px]:flex items-center h-9 px-3 bg-[#0c142e] border border-[#22305e] rounded text-xs gap-1.5">
          <Clock className="h-3.5 w-3.5 text-[#8b9ac6]" />
          <span className="font-mono text-xs text-[#eef1f8] tracking-wider tabular-nums font-semibold">
            {timeString}
          </span>
        </div>

        {/* Hold / Resume Stream Toggle (icon-only below 1600px) */}
        <Button
          variant="outline"
          size="sm"
          onClick={togglePause}
          className={`h-9 px-3 text-xs font-mono justify-center transition-colors ${
            isPaused
              ? "border-[#ff5a2b] bg-[#ff5a2b]/10 text-[#ff5a2b] hover:bg-[#ff5a2b]/20"
              : "border-[#22305e] bg-[#0c142e] hover:bg-[#16204a] text-[#a9b6da] hover:text-[#eef1f8]"
          }`}
          title={isPaused ? `Resume packet log stream (${bufferedCount} buffered)` : "Hold / freeze packet log stream"}
        >
          {isPaused ? (
            <>
              <Play className="h-3.5 w-3.5 fill-current" />
              <span className="hidden min-[1600px]:inline ml-1.5">
                RESUME ({bufferedCount} buffered)
              </span>
            </>
          ) : (
            <>
              <Pause className="h-3.5 w-3.5 fill-current" />
              <span className="hidden min-[1600px]:inline ml-1.5">
                HOLD STREAM
              </span>
            </>
          )}
        </Button>

        {/* Manual Refresh / Resync (icon-only below 1600px) */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => initializeData()}
          className="border-[#22305e] bg-[#0c142e] hover:bg-[#16204a] text-[#eef1f8] text-xs font-mono h-9 px-3 flex items-center justify-center"
          title="Re-fetch all summary endpoints"
        >
          <RefreshCw className="h-3.5 w-3.5 text-[#8b9ac6]" />
          <span className="hidden min-[1600px]:inline ml-1.5">Sync</span>
        </Button>

        {/* Export Session Report (icon-only below 1600px) */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setIsReportOpen(true)}
          className="border-[#22305e] bg-[#0c142e] hover:bg-[#16204a] text-[#eef1f8] text-xs font-mono h-9 px-3 flex items-center justify-center"
          title="Open session report export view"
        >
          <FileText className="h-3.5 w-3.5 text-[#2fb8a6]" />
          <span className="hidden min-[1600px]:inline ml-1.5">Export report</span>
        </Button>
      </div>
    </header>
  );
};
