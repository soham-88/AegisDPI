import React, { useState } from "react";
import { useAegisStore, useIsEngineLive } from "@/hooks/useAegisStore";
import {
  Ban,
  Plus,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Radio,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";

export const BlocklistManager: React.FC = () => {
  const { blocklist, addBlocklistRule, removeBlocklistRule } =
    useAegisStore();
  const isEngineLive = useIsEngineLive();

  const [inputIp, setInputIp] = useState("");
  const [inputReason, setInputReason] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

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
      await addBlocklistRule(trimmedIp, inputReason.trim() || "Manual Admin Block");
      setInputIp("");
      setInputReason("");
      setSuccessMessage(`Rule published for ${trimmedIp}`);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to publish rule");
      // Keep inputIp and inputReason intact on failure
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
              Active Blocklist & Kernel Rule Enforcement
            </h2>
            <p className="text-xs text-[#8b9ac6] mt-0.5">
              Saved to the Redis set blocklist:ips and published on blocklist:updates, so rules apply live without restarting the engine.
            </p>
          </div>
        </div>

        {/* Add IP Form */}
        <form onSubmit={handleAddRule} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
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
              blocklist.map((rule) => (
                <div
                  key={rule.ip}
                  className="p-3.5 bg-[#0c142e] border border-[#22305e] rounded-lg flex items-center justify-between hover:border-[#3a4a80] transition-colors"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="text-sm font-bold text-[#eef1f8]">
                        {rule.ip}
                      </span>
                      {isEngineLive ? (
                        <span className="bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 px-2 py-0.5 rounded text-[10px] font-bold flex items-center space-x-1">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>ENFORCED</span>
                        </span>
                      ) : (
                        <span className="bg-slate-800/40 text-slate-400 border border-slate-700/60 px-2 py-0.5 rounded text-[10px] font-bold flex items-center space-x-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1 shrink-0" />
                          <span>SAVED – applies on next start</span>
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
              ))
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
                  Dynamic enforcement pipeline
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
                  REST endpoint receives rule payload from admin console or ML auto-mitigation
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#2fb8a6]/20 text-[#2fb8a6] flex items-center justify-center text-[10px] font-bold">2</span>
                  <span className="text-[#2fb8a6] font-bold text-[11px]">SADD + PUBLISH</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  Saved to Redis set blocklist:ips and published on blocklist:updates
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#3a4a80]/30 text-[#8b9ac6] flex items-center justify-center text-[10px] font-bold">3</span>
                  <span className="text-[#eef1f8] font-bold text-[11px]">Engine Rule Subscriber</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  C++ engine background thread consumes pub/sub message without stopping workers
                </p>
              </div>

              <div className="p-2.5 bg-[#0c142e] border border-[#22305e] rounded space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-4 h-4 rounded bg-[#2fb8a6]/20 text-[#2fb8a6] flex items-center justify-center text-[10px] font-bold">4</span>
                  <span className="text-[#2fb8a6] font-bold text-[11px]">nft add element</span>
                </div>
                <p className="text-[11px] text-[#8b9ac6] pl-6 font-sans">
                  Directly inserted into kernel nftables set inet aegis blocklist
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
    </div>
  );
};
