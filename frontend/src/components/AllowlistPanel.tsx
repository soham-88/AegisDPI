import React, { useState, useEffect } from "react";
import { ShieldCheck, Plus, Trash2, CheckCircle2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { AllowlistEntry } from "@/types/aegis";
import { formatDateTime } from "@/lib/utils";

export const AllowlistPanel: React.FC = () => {
  const [entries, setEntries] = useState<AllowlistEntry[]>([]);
  const [inputEntry, setInputEntry] = useState("");
  const [inputNote, setInputNote] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const fetchAllowlist = async () => {
    try {
      const data = await api.getAllowlist();
      setEntries(data);
    } catch (err: any) {
      console.error("[ALLOWLIST] Failed to fetch allowlist:", err);
    }
  };

  useEffect(() => {
    fetchAllowlist();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");

    const trimmed = inputEntry.trim();
    if (!trimmed) {
      setErrorMessage("IP address or CIDR range is required.");
      return;
    }

    setLoading(true);
    try {
      await api.addAllowlistEntry(trimmed, inputNote.trim());
      setInputEntry("");
      setInputNote("");
      setSuccessMessage(`Allowlisted ${trimmed} (any active blocks unblocked)`);
      await fetchAllowlist();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to add allowlist entry");
    } finally {
      setLoading(false);
    }
  };

  const handleRemove = async (entry: string) => {
    try {
      await api.removeAllowlistEntry(entry);
      await fetchAllowlist();
    } catch (err: any) {
      console.error("[ALLOWLIST] Failed to remove entry:", err);
    }
  };

  return (
    <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 space-y-4">
      <div className="flex items-center space-x-3 mb-2">
        <div className="p-2 rounded bg-[#2fb8a6]/10 text-[#2fb8a6]">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
            Allowlist & Subnet Exemptions ({entries.length})
          </h3>
          <p className="text-xs text-[#8b9ac6] mt-0.5">
            IPs or CIDR ranges (/0–/32) that can never be blocked by manual rules or ML auto-mitigation.
          </p>
        </div>
      </div>

      {/* Add Form */}
      <form onSubmit={handleAdd} className="space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-[#8b9ac6] mb-1">
              IP OR CIDR RANGE
            </label>
            <input
              type="text"
              placeholder="e.g. 192.0.2.0/29 or 10.10.0.1"
              value={inputEntry}
              onChange={(e) => {
                setInputEntry(e.target.value);
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
                NOTE / JUSTIFICATION
              </label>
              <input
                type="text"
                placeholder="e.g. Critical management subnet"
                value={inputNote}
                onChange={(e) => setInputNote(e.target.value)}
                className="w-full bg-[#0c142e] border border-[#22305e] rounded px-3 py-2 text-xs font-mono text-[#eef1f8] placeholder-[#8b9ac6] focus:outline-none focus:border-[#3a4a80]"
              />
            </div>

            <Button
              type="submit"
              disabled={loading}
              className="bg-[#2fb8a6] hover:bg-[#2fb8a6]/90 text-white font-mono text-xs px-4 py-2 flex items-center space-x-1.5 shrink-0"
            >
              <Plus className="h-4 w-4" />
              <span>Allowlist Entry</span>
            </Button>
          </div>
        </div>
      </form>

      {/* Entries List */}
      <div className="space-y-2 pt-2">
        {entries.length === 0 ? (
          <div className="p-4 text-center text-xs text-[#8b9ac6] bg-[#0c142e] rounded border border-[#22305e]">
            No allowlisted ranges. Add a subnet or IP above to protect it from all blocks.
          </div>
        ) : (
          entries.map((item) => (
            <div
              key={item.entry}
              className="p-3 bg-[#0c142e] border border-[#22305e] rounded flex items-center justify-between font-mono text-xs hover:border-[#3a4a80] transition-colors"
            >
              <div className="space-y-0.5">
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-[#eef1f8]">{item.entry}</span>
                  <span className="text-[10px] bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/30 px-1.5 py-0.2 rounded font-mono">
                    PROTECTED
                  </span>
                </div>
                {item.note && (
                  <div className="text-[11px] text-[#8b9ac6]">Note: {item.note}</div>
                )}
                <div className="text-[10px] text-[#8b9ac6]">
                  Added by {item.added_by} · {formatDateTime(item.added_at)}
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleRemove(item.entry)}
                className="border-[#ff5a2b]/30 bg-[#ff5a2b]/10 text-[#ff5a2b] hover:bg-[#ff5a2b] hover:text-white text-xs font-mono"
              >
                <Trash2 className="h-3.5 w-3.5 mr-1" />
                Remove
              </Button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

