import React, { useState, useEffect } from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import { NavSection } from "@/types/aegis";
import {
  Activity,
  Table,
  Ban,
  AlertOctagon,
  Cpu,
  Layers,
} from "lucide-react";

interface NavItem {
  id: NavSection;
  label: string;
  icon: React.ElementType;
  badge?: string;
}

function formatUptime(startedAt?: number, isStale?: boolean, updatedAtMs?: number): string {
  if (!startedAt || startedAt <= 0) return "00:00:00";
  const endSec = isStale && updatedAtMs && updatedAtMs > 0
    ? Math.floor(updatedAtMs / 1000)
    : Math.floor(Date.now() / 1000);
  const diffSec = Math.max(0, endSec - startedAt);
  const hours = Math.floor(diffSec / 3600);
  const minutes = Math.floor((diffSec % 3600) / 60);
  const seconds = diffSec % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

export const Sidebar: React.FC = () => {
  const {
    navSection,
    setNavSection,
    socketConnected,
    blocklist,
    anomalies,
    stats,
    currentUser,
    logout,
  } = useAegisStore();

  const isEngineLive = useIsEngineLive();
  const isStale = !isEngineLive;

  const [, setTick] = useState(0);
  useEffect(() => {
    if (isStale) return;
    const timer = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(timer);
  }, [isStale]);

  const navItems: NavItem[] = [
    {
      id: "stats",
      label: "Stats & Telemetry",
      icon: Activity,
    },
    {
      id: "packets",
      label: "Packet Flow Logs",
      icon: Table,
    },
    {
      id: "blocklist",
      label: "Blocklist Rules",
      icon: Ban,
      badge: blocklist.length > 0 ? String(blocklist.length) : undefined,
    },
    {
      id: "anomalies",
      label: "ML Verdicts",
      icon: AlertOctagon,
      badge: anomalies.length > 0 ? String(anomalies.length) : undefined,
    },
    {
      id: "threads",
      label: "Thread Performance",
      icon: Cpu,
    },
    {
      id: "architecture",
      label: "Architecture",
      icon: Layers,
    },
  ];

  return (
    <aside className="w-64 bg-[#081022] border-r border-[#22305e] flex flex-col justify-between shrink-0 h-screen sticky top-0 font-mono select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-[#22305e]">
          <div className="flex items-center space-x-3">
            <img src="/aegisdpi-mark.svg" alt="AegisDPI" className="h-9 w-9 shrink-0" />
            <div>
              <div className="text-base font-bold tracking-wider text-[#eef1f8] uppercase flex items-center space-x-1.5">
                <span>AEGIS</span>
                <span className="text-[#ff5a2b]">DPI</span>
              </div>
              <p className="text-[10px] text-[#8b9ac6] uppercase tracking-widest mt-0.5">
                SOC Core Console
              </p>
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = navSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setNavSection(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-[#101a38] text-[#eef1f8] border-l-2 border-l-[#ff5a2b] shadow-sm"
                    : "text-[#8b9ac6] hover:bg-[#0c142e] hover:text-[#a9b6da]"
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon
                    className={`h-4 w-4 ${
                      isActive ? "text-[#ff5a2b]" : "text-[#8b9ac6]"
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      item.id === "anomalies"
                        ? "bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40"
                        : "bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Status Card */}
      <div className="p-4 border-t border-[#22305e] bg-[#0c142e]/60 text-[11px] space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-[#8b9ac6]">SOCKET FEED</span>
          <span
            className={`flex items-center space-x-1.5 font-bold ${
              socketConnected ? "text-[#2fb8a6]" : "text-[#ff5a2b]"
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                socketConnected ? "bg-[#2fb8a6] animate-engine-tick" : "bg-[#ff5a2b]"
              }`}
            />
            <span>{socketConnected ? "ONLINE" : "WAITING"}</span>
          </span>
        </div>

        <div className="flex items-center justify-between text-[#8b9ac6]">
          <span>INTERFACE</span>
          <span className="text-[#eef1f8] font-bold">{stats?.interface || "offline"}</span>
        </div>

        <div className="flex items-center justify-between text-[#8b9ac6]">
          <span>ENGINE</span>
          {isStale ? (
            <span className="text-[#8b9ac6]">stopped</span>
          ) : (
            <span className="text-[#a9b6da]">PID {stats?.engine_pid || 0}</span>
          )}
        </div>

        <div className="pt-2 border-t border-[#16204a] text-[10px] text-[#8b9ac6] flex items-center justify-between whitespace-nowrap">
          <span>{isStale ? "Uptime -" : `Uptime ${formatUptime(stats?.started_at)}`}</span>
          <span className={isStale ? "text-[#8b9ac6]" : "text-[#2fb8a6]"}>
            {isStale ? "nftables: off" : "nftables active"}
          </span>
        </div>

        {/* User Account / Sign Out */}
        <div className="pt-2 border-t border-[#16204a] text-[11px] flex items-center justify-between">
          <span className="text-[#8b9ac6] truncate">
            Signed in as <span className="text-[#eef1f8] font-bold">{currentUser || "admin"}</span>
          </span>
          <button
            onClick={() => logout()}
            className="text-[#ff5a2b] hover:text-[#ff7a54] text-[11px] hover:underline cursor-pointer font-bold ml-2 shrink-0 transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>
    </aside>
  );
};
