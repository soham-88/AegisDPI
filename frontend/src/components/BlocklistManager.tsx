import React, { useState, useEffect } from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import {
  Ban,
  Plus,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Radio,
  Clock,
  ShieldAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";
import { AllowlistPanel } from "./AllowlistPanel";
import { AuditLogPanel } from "./AuditLogPanel";

function formatTtlCountdown(expiresAt: string | null | undefined, nowMs: number): string {
  if (!expiresAt) return "Permanent";
  const expMs = new Date(expiresAt).getTime();
  const diffSec = Math.floor((expMs - nowMs) / 1000);
  if (diffSec <= 0) return "Expiring...";
  const hours = Math.floor(diffSec / 3600);
  const minutes = Math.floor((diffSec % 3600) / 60);
  const seconds = diffSec % 60;
  if (hours > 0) {
    return `expires in ${hours}h ${minutes}m ${seconds}s`;
  }
  return `expires in ${minutes}m ${seconds}s`;
}

export const BlocklistManager: React.FC = () => {
  const { blocklist, addBlocklistRule, removeBlocklistRule } =
    useAegisStore();
  const isEngineLive = useIsEngineLive();

  const [inputIp, setInputIp] = useState("");
  const [inputReason, setInputReason] = useState("");
  const [selectedDuration, setSelectedDuration] = useState("0");
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [nowMs, setNowMs] = useState(Date.now());

  // 1-second interval for real-time countdown
  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");

    const trimmedIp = inputIp.trim();
    if (!trimmedIp) {
      setErrorMessage("IP address is required.");
      return;
    }

    // Basic IPv4 format validation
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Regex.test(trimmedIp)) {
      setErrorMessage("Please enter a valid IPv4 address (e.g., 10.10.0.2).");
      return;
    }

    try {
      const ttl = selectedDuration !== "0" ? parseInt(selectedDuration, 10) : null;
      await addBlocklistRule(
        trimmedIp,
        inputReason.trim() || "Manual Admin Block",
        "manual",
        ttl
      );
      setInputIp("");
      setInputReason("");
      setSelectedDuration("0");
      setSuccessMessage(`Rule published for ${trimmedIp}`);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to publish rule");
    }
  };

  const handleRemove = async (ip: string) => {
    await removeBlocklistRule(ip);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Form */}
      <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5">
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2 rounded bg-[#ff5a2b]/10 text-[#ff5a2b]">
            <Ban className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
              Active Blocklist & Safe Blocking Enforcement
            </h2>
            <p className="text-xs text-[#8b9ac6] mt-0.5">
              Rules are saved to Redis (blocklist:ips, blocklist:expiry, audit:log) and published on blocklist:updates live to the C++ engine.
            </p>
          </div>
        </div>

        {/* Add IP Form */}
        <form onSubmit={handleAddRule} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-[11px] font-mono text-[#8b9ac6] mb-1">
                TARGET IP ADDRESS (IPv4)
              </label>
              <input
                type="text"
                placeholder="e.g. 10.10.0.2"
                value={inputIp}
                onChange={(e) => {
                  setInputIp(e.target.value);
                  if (errorMessage) setErrorMessage("");
                  if (successMessage) setSuccessMessage("");
                }}
                className={`w-full bg-[#0c142e] border ${
                  errorMessage ? "border-[#ff5a2b]" : "border-[#22305e]"
                } rounded px-3 py-2 text-xs font-mono text-[#eef1f8] placeholder-[#8b9ac6] focus:outline-none focus:border-[#3a4a80]`}
              />
              {errorMessage && (
                <div className="mt-1 text-xs font-mono text-[#ff5a2b] flex items-center space-x-1">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}
              {successMessage && (
                <div className="mt-1 text-xs font-mono text-[#2fb8a6] flex items-center space-x-1">
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                  <span>{successMessage}</span>
                </div>
              )}
            </div>

            <div>
              <label className="block text-[11px] font-mono text-[#8b9ac6] mb-1">
                DURATION / TTL
              </label>
              <select
                value={selectedDuration}
                onChange={(e) => setSelectedDuration(e.target.value)}
                className="w-full bg-[#0c142e] border border-[#22305e] rounded px-3 py-2 text-xs font-mono text-[#eef1f8] focus:outline-none focus:border-[#3a4a80]"
              >
                <option value="0">Permanent (default)</option>
                <option value="600">10 minutes (600s)</option>
                <option value="3600">1 hour (3600s)</option>
                <option value="86400">24 hours (86400s)</option>
              </select>
            </div>

            <div className="md:col-span-2 flex items-end space-x-3">
              <div className="flex-1">
                <label className="block text-[11px] font-mono text-[#8b9ac6] mb-1">
                  REASON / ATTRIBUTION TAG
                </label>
                <input
                  type="text"
                  placeholder="e.g. High-PPS Flood from attacker namespace"
                  value={inputReason}
                  onChange={(e) => {
                    setInputReason(e.target.value);
                    if (errorMessage) setErrorMessage("");
                    if (successMessage) setSuccessMessage("");
                  }}
                  className="w-full bg-[#0c142e] border border-[#22305e] rounded px-3 py-2 text-xs font-mono text-[#eef1f8] placeholder-[#8b9ac6] focus:outline-none focus:border-[#3a4a80]"
                />
              </div>

              <Button
                type="submit"
                className="bg-[#ff5a2b] hover:bg-[#ff5a2b]/90 text-white font-mono text-xs px-4 py-2 flex items-center space-x-1.5 shrink-0"
              >
                <Plus className="h-4 w-4" />
                <span>Publish Block Rule</span>
              </Button>
            </div>
          </div>
        </form>
      </div>

      {/* Main Grid: Active Rules + How a rule reaches the kernel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Rules List */}
        <div className="lg:col-span-2 bg-[#101a38] border border-[#22305e] rounded-lg p-5">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
                BLOCKED IPS ({blocklist.length})
              </h3>
              <p className="text-xs text-[#8b9ac6] mt-0.5">
                Entries in blocklist:ips (enforced by nftables while the engine runs)
              </p>
              <div className="mt-2">
                {isEngineLive ? (
                  <span className="inline-flex items-center text-[11px] font-mono text-[#2fb8a6] bg-[#2fb8a6]/10 border border-[#2fb8a6]/30 px-2 py-0.5 rounded">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#2fb8a6] mr-1.5 animate-pulse" />
                    nftables active
                  </span>
                ) : (
                  <span className="inline-flex items-center text-[11px] font-sans text-slate-400 bg-slate-800/40 border border-slate-700/60 px-2 py-0.5 rounded">
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1.5 shrink-0" />
                    {"nftables off (applied from blocklist:ips on next start)"}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {blocklist.length === 0 ? (
              <div className="p-8 text-center text-[#8b9ac6]">
                No active blocklist rules. Add an IP above to enforce kernel drop.
              </div>
            ) : (
              blocklist.map((rule) => {
                const ttlDisplay = formatTtlCountdown(rule.expires_at, nowMs);
                const isPermanent = !rule.expires_at;

                return (
                  <div
                    key={rule.ip}
                    className="p-3.5 bg-[#0c142e] border border-[#22305e] rounded-lg flex items-center justify-between hover:border-[#3a4a80] transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="text-sm font-bold text-[#eef1f8]">
                          {rule.ip}
                        </span>

                        {/* Status chip */}
                        {isEngineLive ? (
                          <span className="bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 px-2 py-0.5 rounded text-[10px] font-bold flex items-center space-x-1">
                            <CheckCircle2 className="h-3 w-3" />
                            <span>ENFORCED</span>
                          </span>
                        ) : (
                          <span className="bg-slate-800/40 text-slate-400 border border-slate-700/60 px-2 py-0.5 rounded text-[10px] font-bold flex items-center space-x-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1 shrink-0" />
                            <span>SAVED</span>
                          </span>
                        )}

                        {/* Source chip */}
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border bg-[#101a38] border-[#22305e] text-[#8b9ac6] uppercase">
                          {rule.source === "ml_auto" ? "ML Auto" : "Manual"}
                        </span>

                        {/* TTL / Countdown chip */}
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center space-x-1 ${
                            isPermanent
                              ? "bg-slate-800/40 text-slate-400 border-slate-700/60"
                              : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                          }`}
                        >
                          <Clock className="h-3 w-3 mr-0.5" />
                          <span>{ttlDisplay}</span>
                        </span>

                        {/* Strikes chip if repeat offender */}
                        {rule.strikes_24h !== undefined && rule.strikes_24h > 0 && (
                          <span className="text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30 px-1.5 py-0.5 rounded flex items-center space-x-1">
                            <ShieldAlert className="h-3 w-3 mr-0.5" />
                            <span>{rule.strikes_24h} strike{rule.strikes_24h > 1 ? "s" : ""} (24h)</span>
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-[#8b9ac6] break-words">
                        Reason: {rule.reason}
                      </div>

                      <div className="text-[11px] text-[#8b9ac6] whitespace-nowrap">
                        By {rule.source === "ml_auto" ? "ML auto-mitigation" : (rule.added_by || "unknown")} · {formatDateTime(rule.added_at)}
                      </div>
                    </div>

                    <div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleRemove(rule.ip)}
                        className="border-[#ff5a2b]/30 bg-[#ff5a2b]/10 text-[#ff5a2b] hover:bg-[#ff5a2b] hover:text-white text-xs font-mono"
                      >
                        <Trash2 className="h-3.5 w-3.5 mr-1" />
                        Remove
                      </Button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* How a rule reaches the kernel */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
                  How a rule reaches the kernel
                </h3>
                <p className="text-xs text-[#8b9ac6] mt-0.5">
                  Dynamic safe blocking pipeline
                </p>
              </div>
              <Radio className={`h-4 w-4 ${isEngineLive ? "text-[#ff5a2b]" : "text-slate-500"}`} />
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#ff5a2b]/20 text-[#ff5a2b] flex items-center justify-center text-[10px] font-bold">1</span>
                  <span className="text-[#eef1f8] font-bold text-[11px]">POST /api/rules</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  Validated against allowlist, host-local addresses, and TTL policy
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#2fb8a6]/20 text-[#2fb8a6] flex items-center justify-center text-[10px] font-bold">2</span>
                  <span className="text-[#2fb8a6] font-bold text-[11px]">SADD, ZADD & XADD</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  Saved in blocklist:ips, blocklist:expiry, and persistent audit:log stream
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#3a4a80]/30 text-[#8b9ac6] flex items-center justify-center text-[10px] font-bold">3</span>
                  <span className="text-[#eef1f8] font-bold text-[11px]">Engine Rule Subscriber</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  C++ engine background thread consumes blocklist:updates pub/sub message
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#2fb8a6]/20 text-[#2fb8a6] flex items-center justify-center text-[10px] font-bold">4</span>
                  <span className="text-[#2fb8a6] font-bold text-[11px]">Automatic TTL Sweeper</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  Expired blocks are automatically unblocked and audited on schedule
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#22305e] text-[10px] font-mono">
            {isEngineLive ? (
              <span className="text-[#2fb8a6] flex items-start">
                <span className="w-1.5 h-1.5 rounded-full bg-[#2fb8a6] mr-1.5 mt-0.5 shrink-0 animate-pulse" />
                <span>Engine listening on blocklist:updates</span>
              </span>
            ) : (
              <span className="text-slate-400 flex items-start">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1.5 mt-0.5 shrink-0" />
                <span>Engine stopped – rules are loaded from blocklist:ips at startup</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Allowlist Panel */}
      <AllowlistPanel />

      {/* Audit Log Panel */}
      <AuditLogPanel />
    </div>
  );
};
