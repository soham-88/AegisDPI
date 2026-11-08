import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertOctagon, Zap, X } from "lucide-react";
import { useAegisStore } from "@/hooks/useAegisStore";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { HealthBanner } from "@/components/HealthBanner";
import { StatsOverview } from "@/components/StatsOverview";
import { PacketLogTable } from "@/components/PacketLogTable";
import { BlocklistManager } from "@/components/BlocklistManager";
import { AnomalyAlertPanel } from "@/components/AnomalyAlertPanel";
import { ThreadPerformanceView } from "@/components/ThreadPerformanceView";
import { ArchitectureView } from "@/components/ArchitectureView";
import { SessionReportView } from "@/components/SessionReportView";
import { initializeSocket, disconnectSocket } from "@/lib/socket";
import { formatDateTime } from "@/lib/utils";

export const Dashboard: React.FC = () => {
  const {
    navSection,
    initializeData,
    tickHistory,
    activeAlert,
    dismissAlert,
    isReportOpen,
    setIsReportOpen,
  } = useAegisStore();

  useEffect(() => {
    // Initial fetch of telemetry and state
    initializeData();

    // Wire real-time socket events with authenticated handshake
    const token = sessionStorage.getItem("aegis_token") || "";
    initializeSocket(token);

    // 250ms rolling history ticker (4x sampling rate, 360 points for 90s window)
    const timer = setInterval(() => {
      tickHistory();
    }, 250);

    return () => {
      clearInterval(timer);
      disconnectSocket();
    };
  }, [initializeData, tickHistory]);

  const renderActiveSection = () => {
    switch (navSection) {
      case "stats":
        return <StatsOverview />;
      case "packets":
        return <PacketLogTable />;
      case "blocklist":
        return <BlocklistManager />;
      case "anomalies":
        return <AnomalyAlertPanel />;
      case "threads":
        return <ThreadPerformanceView />;
      case "architecture":
        return <ArchitectureView />;
      default:
        return <StatsOverview />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a1128] text-[#eef1f8] font-sans flex print:block print:bg-white print:text-black">
      {/* Session Report View (loaded from /api/report) */}
      {isReportOpen && (
        <SessionReportView onClose={() => setIsReportOpen(false)} />
      )}

      {/* Sidebar Navigation */}
      <div className={isReportOpen ? "print:hidden" : ""}>
        <Sidebar />
      </div>

      {/* Main Content Area */}
      <div className={`flex-1 flex flex-col min-w-0 ${isReportOpen ? "print:hidden" : ""}`}>
        <Header />
        <HealthBanner />

        {/* Global Anomaly Flash Banner */}
        <AnimatePresence>
          {activeAlert && (
            <motion.div
              initial={{ opacity: 0, y: -25, scale: 0.97 }}
              animate={{
                opacity: 1,
                y: 0,
                scale: 1,
                boxShadow: [
                  "0 0 0 rgba(255, 90, 43, 0)",
                  "0 0 25px rgba(255, 90, 43, 0.45)",
                  "0 0 10px rgba(255, 90, 43, 0.2)",
                ],
              }}
              exit={{ opacity: 0, y: -25, scale: 0.97 }}
              transition={{ duration: 0.45, ease: "easeOut" }}
              className="mx-8 mt-6 bg-[#101a38] border-2 border-[#ff5a2b] rounded-lg p-5 relative overflow-hidden"
            >
              <div className="absolute top-0 left-0 w-1.5 h-full bg-[#ff5a2b]" />

              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3.5">
                  <div className="p-2.5 rounded-lg bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40 animate-pulse">
                    <AlertOctagon className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <span className="text-xs font-mono font-bold bg-[#ff5a2b] text-white px-2 py-0.5 rounded uppercase">
                        CRITICAL ANOMALY VERDICT
                      </span>
                      {activeAlert.is_simulated ? (
                        <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 rounded">
                          [SIMULATED TRIGGER]
                        </span>
                      ) : (
                        <span className="text-[9px] font-mono bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/30 px-1.5 py-0.5 rounded whitespace-nowrap">
                          REAL
                        </span>
                      )}
                      <span className="text-xs font-mono text-[#8b9ac6]">
                        {formatDateTime(activeAlert.timestamp)}
                      </span>
                      {activeAlert.auto_mitigated && (
                        <span className="text-xs font-mono text-[#2fb8a6] flex items-center">
                          <Zap className="h-3.5 w-3.5 mr-1 text-[#2fb8a6]" />
                          Auto-blocked via nftables
                        </span>
                      )}
                      {activeAlert.telegram_alert === "sent" && (
                        <span className="text-[10px] font-mono bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 px-1.5 py-0.5 rounded whitespace-nowrap">
                          Telegram: sent
                        </span>
                      )}
                      {activeAlert.telegram_alert === "suppressed_cooldown" && (
                        <span className="text-[10px] font-mono bg-slate-800/40 text-slate-400 border border-slate-700/60 px-1.5 py-0.5 rounded whitespace-nowrap">
                          Telegram: suppressed (cooldown)
                        </span>
                      )}
                      {activeAlert.telegram_alert === "failed" && (
                        <span className="text-[10px] font-mono bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40 px-1.5 py-0.5 rounded whitespace-nowrap">
                          Telegram: failed
                        </span>
                      )}
                      {(activeAlert.telegram_alert === "disabled" || activeAlert.telegram_alert === "attempted") && (
                        <span className="text-[10px] font-mono bg-slate-800/40 text-slate-400 border border-slate-700/60 px-1.5 py-0.5 rounded whitespace-nowrap">
                          Telegram: {activeAlert.telegram_alert}
                        </span>
                      )}
                    </div>

                    <h2 className="text-base font-bold font-mono text-[#eef1f8] mt-1.5">
                      Attacker Stream <span className="whitespace-nowrap font-mono">{activeAlert.source_ip}</span> → <span className="whitespace-nowrap font-mono">{activeAlert.dest_ip}</span> Flagged
                    </h2>
                    <p className="text-xs text-[#a9b6da] mt-1 font-sans max-w-2xl">
                      {activeAlert.description}
                    </p>

                    <div className="mt-3 flex items-center space-x-4 text-xs font-mono">
                      <span className="text-[#8b9ac6]">
                        Confidence Score:{" "}
                        <span className="text-[#ff5a2b] font-bold">
                          {(activeAlert.confidence * 100).toFixed(1)}%
                        </span>
                      </span>
                      <span className="text-[#8b9ac6]">
                        Mitigation Target:{" "}
                        <span className="text-[#2fb8a6] font-bold">
                          {activeAlert.source_ip}
                        </span>
                      </span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={dismissAlert}
                  className="p-1 rounded text-[#8b9ac6] hover:text-[#eef1f8] hover:bg-[#16204a]"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <main className="p-8 flex-1 min-w-0 overflow-x-hidden overflow-y-auto">
          {renderActiveSection()}
        </main>
      </div>
    </div>
  );
};
