import React, { useState, useEffect } from "react";
import { ScrollText, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { socket } from "@/lib/socket";
import { AuditLogEntry } from "@/types/aegis";
import { formatDateTime } from "@/lib/utils";

export const AuditLogPanel: React.FC = () => {
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchAudit = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLog(100);
      setAuditLogs(data);
    } catch (err) {
      console.error("[AUDIT-LOG-PANEL] Failed to fetch audit log:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();

    // 10s polling interval
    const interval = setInterval(() => {
      fetchAudit();
    }, 10000);

    // Refresh immediately on blocklist:changed socket events
    const handleBlocklistChanged = () => {
      fetchAudit();
    };
    socket.on("blocklist:changed", handleBlocklistChanged);

    return () => {
      clearInterval(interval);
      socket.off("blocklist:changed", handleBlocklistChanged);
    };
  }, []);

  const getActionBadge = (action: string) => {
    const act = action.toLowerCase();
    if (act === "block") {
      return (
        <span className="bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          BLOCK
        </span>
      );
    }
    if (act === "extend") {
      return (
        <span className="bg-purple-500/20 text-purple-300 border border-purple-500/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          EXTEND
        </span>
      );
    }
    if (act === "unblock") {
      return (
        <span className="bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          UNBLOCK
        </span>
      );
    }
    if (act === "expire") {
      return (
        <span className="bg-amber-500/20 text-amber-300 border border-amber-500/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          EXPIRE
        </span>
      );
    }
    if (act === "block_rejected") {
      return (
        <span className="bg-red-600/20 text-red-400 border border-red-500/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          REJECTED
        </span>
      );
    }
    if (act.startsWith("allowlist")) {
      return (
        <span className="bg-blue-500/20 text-blue-300 border border-blue-500/40 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">
          {action.toUpperCase()}
        </span>
      );
    }
    return (
      <span className="bg-[#3a4a80]/30 text-[#8b9ac6] border border-[#22305e] px-1.5 py-0.5 rounded text-[10px] font-mono uppercase">
        {action}
      </span>
    );
  };

  return (
    <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 space-y-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded bg-indigo-500/10 text-indigo-400">
            <ScrollText className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
              Security & Blocklist Audit Trail (audit:log)
            </h3>
            <p className="text-xs text-[#8b9ac6] mt-0.5">
              Persistent event stream recording all block lifecycle actions, allowlist updates, and rejections.
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchAudit}
          disabled={loading}
          className="border-[#22305e] text-[#8b9ac6] hover:text-[#eef1f8] font-mono text-xs"
        >
          <RefreshCw className={`h-3.5 w-3.5 mr-1 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <div className="overflow-x-auto rounded border border-[#22305e]">
        <table className="w-full text-left font-mono text-xs text-[#8b9ac6]">
          <thead className="bg-[#0c142e] text-[#eef1f8] uppercase text-[10px] border-b border-[#22305e]">
            <tr>
              <th className="p-2.5">Time</th>
              <th className="p-2.5">Actor (Role)</th>
              <th className="p-2.5">Action</th>
              <th className="p-2.5">Target</th>
              <th className="p-2.5">Reason / Detail</th>
              <th className="p-2.5">TTL / Expiry</th>
              <th className="p-2.5">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#22305e] bg-[#101a38]">
            {auditLogs.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-6 text-center text-[#8b9ac6]">
                  No audit log records recorded yet.
                </td>
              </tr>
            ) : (
              auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#0c142e]/60 transition-colors">
                  <td className="p-2.5 whitespace-nowrap text-[#eef1f8]">
                    {formatDateTime(log.ts)}
                  </td>
                  <td className="p-2.5 whitespace-nowrap">
                    <span className="text-[#eef1f8] font-bold">{log.actor}</span>{" "}
                    <span className="text-[10px] text-[#8b9ac6]">({log.role})</span>
                  </td>
                  <td className="p-2.5 whitespace-nowrap">
                    {getActionBadge(log.action)}
                  </td>
                  <td className="p-2.5 font-bold text-[#eef1f8] whitespace-nowrap">
                    {log.target || "-"}
                  </td>
                  <td className="p-2.5 max-w-xs truncate" title={log.detail || log.reason}>
                    {log.detail || log.reason || "-"}
                  </td>
                  <td className="p-2.5 whitespace-nowrap text-[11px]">
                    {log.action === "block" || log.action === "extend" ? (
                      log.expires_at ? (
                        <span title={`Expires: ${log.expires_at}`}>
                          {log.ttl_s ? `${log.ttl_s}s` : formatDateTime(log.expires_at)}
                        </span>
                      ) : log.ttl_s ? (
                        `${log.ttl_s}s`
                      ) : (
                        "permanent"
                      )
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="p-2.5 whitespace-nowrap">
                    <span className="font-semibold text-[#eef1f8]">{log.result}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
