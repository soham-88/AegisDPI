import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { SessionReportData } from "@/types/aegis";
import { Download, Printer, X, RefreshCw, AlertCircle, CheckCircle2, XCircle } from "lucide-react";

interface SessionReportViewProps {
  onClose: () => void;
}

export const SessionReportView: React.FC<SessionReportViewProps> = ({ onClose }) => {
  const [data, setData] = useState<SessionReportData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getSessionReport();
      setData(res);
    } catch (err: any) {
      setError(err?.message || "Failed to load session report");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handleDownloadJson = () => {
    if (!data) return;
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = data.generated_at
      ? new Date(data.generated_at).getTime()
      : Date.now();
    link.href = url;
    link.download = `aegis-report-${timestamp}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  const formatSecToHms = (sec: number) => {
    const s = Math.max(0, sec || 0);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const remSec = s % 60;
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(h)}:${pad(m)}:${pad(remSec)}`;
  };

  // Format date/time to unambiguous local format: "11 Oct 2026, 11:38:51 PM IST"
  const formatDateTime = (val: string | number | null | undefined): string => {
    if (!val || val === 0) return "N/A";
    let d: Date;
    if (typeof val === "number") {
      // If epoch seconds (< 1e11), convert to milliseconds
      d = new Date(val > 1e11 ? val : val * 1000);
    } else {
      d = new Date(val);
    }
    if (isNaN(d.getTime())) return "N/A";

    const formatted = d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
      timeZoneName: "short",
    });
    // Ensure AM/PM is uppercase: "11 Oct 2026, 11:38:51 PM IST"
    return formatted.replace(/\b(am|pm)\b/g, (m) => m.toUpperCase());
  };

  // Bandwidth rate formatting:
  // >= 1 Mbps -> Mbps (2 decimals), >= 1 kbps -> kbps (1 decimal), else bps. Never round non-zero to 0.
  const formatBandwidth = (bytes: number, sec: number): string => {
    if (bytes === 0) return "0 bps";
    const duration = sec > 0 ? sec : 1;
    const bps = (bytes * 8) / duration;
    if (bps >= 1_000_000) {
      return `${(bps / 1_000_000).toFixed(2)} Mbps`;
    }
    if (bps >= 1_000) {
      return `${(bps / 1_000).toFixed(1)} kbps`;
    }
    const rounded = Math.round(bps);
    if (rounded > 0) {
      return `${rounded.toLocaleString()} bps`;
    }
    const f1 = bps.toFixed(1);
    if (parseFloat(f1) > 0) {
      return `${f1} bps`;
    }
    return `${bps.toFixed(2)} bps`;
  };

  // Packet rate formatting: 1 decimal when < 10 pps. Never round non-zero to 0.
  const formatPacketRate = (packets: number, sec: number): string => {
    if (packets === 0) return "0 pps";
    const duration = sec > 0 ? sec : 1;
    const pps = packets / duration;
    if (pps >= 10) {
      return `${Math.round(pps).toLocaleString()} pps`;
    }
    const f1 = pps.toFixed(1);
    if (parseFloat(f1) > 0) {
      return `${f1} pps`;
    }
    const f2 = pps.toFixed(2);
    if (parseFloat(f2) > 0) {
      return `${f2} pps`;
    }
    return `${pps.toPrecision(2)} pps`;
  };

  // Integrity checks count: count only PASS/FAIL rows, not INFO
  const passFailChecks = data?.checks?.filter((c) => !c.is_info) || [];
  const totalChecks = passFailChecks.length;
  const passedCount = passFailChecks.filter((c) => c.pass === true).length;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/80 backdrop-blur-sm print:static print:bg-white print:overflow-visible">
      {/* Scoped Print CSS */}
      <style>{`
        @page {
          margin: 14mm;
          size: auto;
        }
        @media print {
          body {
            background: #ffffff !important;
            color: #000000 !important;
          }
          section, table, .report-section, .report-table {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
          }
          h1, h2, h3, h4, .report-heading {
            break-after: avoid !important;
            page-break-after: avoid !important;
          }
          header, footer {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
          }
        }
      `}</style>

      {/* Top action bar - HIDDEN WHEN PRINTING */}
      <div className="sticky top-0 z-10 bg-slate-800 border-b border-slate-700 px-6 py-3 flex items-center justify-between shadow-md print:hidden">
        <div className="flex items-center space-x-3">
          <span className="font-mono text-sm font-bold text-white tracking-wide">
            Session Report Export
          </span>
          {data && (
            <span
              className={`text-xs px-2 py-0.5 rounded font-mono font-semibold ${
                data.engine.state === "running"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                  : "bg-slate-700 text-slate-300 border border-slate-600"
              }`}
            >
              Engine: {data.engine.state.toUpperCase()}
            </span>
          )}
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchReport}
            disabled={isLoading}
            className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-mono flex items-center space-x-1.5 transition-colors disabled:opacity-50"
            title="Refresh snapshot from Redis"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Reload</span>
          </button>

          <button
            onClick={handleDownloadJson}
            disabled={!data}
            className="px-3 py-1.5 rounded bg-teal-700 hover:bg-teal-600 text-white text-xs font-mono flex items-center space-x-1.5 shadow transition-colors disabled:opacity-50"
            title="Download complete raw JSON snapshot"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download JSON</span>
          </button>

          <button
            onClick={handlePrint}
            disabled={!data}
            className="px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-600 text-white text-xs font-mono flex items-center space-x-1.5 shadow transition-colors disabled:opacity-50"
            title="Trigger browser print to save as PDF or print on A4"
          >
            <Printer className="h-3.5 w-3.5" />
            <span>Print / Save as PDF</span>
          </button>

          <button
            onClick={onClose}
            className="p-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-colors ml-2"
            title="Close report view"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Main Report Container - PRINT-FRIENDLY A4 */}
      <div className="p-4 sm:p-6 md:p-8 flex justify-center print:p-0 print:m-0">
        {isLoading && !data ? (
          <div className="w-full max-w-4xl bg-white text-slate-700 rounded-lg shadow-xl p-12 text-center font-mono">
            <RefreshCw className="h-8 w-8 animate-spin mx-auto text-slate-400 mb-3" />
            <p className="text-sm">Generating session report snapshot from Redis...</p>
          </div>
        ) : error ? (
          <div className="w-full max-w-4xl bg-white text-slate-900 rounded-lg shadow-xl p-8 text-center">
            <AlertCircle className="h-8 w-8 text-rose-500 mx-auto mb-2" />
            <p className="font-semibold text-rose-600">Failed to load report</p>
            <p className="text-xs text-slate-500 mt-1 font-mono">{error}</p>
            <button
              onClick={fetchReport}
              className="mt-4 px-4 py-2 bg-slate-800 text-white text-xs font-mono rounded hover:bg-slate-700"
            >
              Try Again
            </button>
          </div>
        ) : data ? (
          <article className="w-full max-w-[210mm] bg-white text-slate-900 rounded-lg shadow-xl p-8 sm:p-10 font-sans print:shadow-none print:rounded-none print:p-0 print:max-w-none print:text-black">
            {/* Document Header */}
            <header className="border-b-2 border-slate-900 pb-5 mb-6">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-slate-900 font-sans uppercase report-heading">
                    Aegis DPI &middot; Session Report
                  </h1>
                  <p className="text-xs font-mono text-slate-600 mt-1">
                    Deep Packet Inspection & Automated Threat Mitigation Telemetry
                  </p>
                </div>
                <div className="text-right">
                  <span className="inline-block px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border border-slate-400 bg-slate-100 text-slate-800">
                    State: {data.engine.state}
                  </span>
                </div>
              </div>

              {/* Header Note: always show live note; when stopped, show session note as second line below it */}
              <div className="mt-4 p-2.5 bg-slate-100 rounded border border-slate-300 text-xs font-mono text-slate-800 space-y-1">
                <div>
                  Generated <strong className="whitespace-nowrap">{formatDateTime(data.generated_at)}</strong> from live Redis data
                </div>
                {data.engine.state === "stopped" && (
                  <div className="text-slate-600">
                    Engine stopped &ndash; figures are from the last session (
                    <strong className="whitespace-nowrap">{formatDateTime(data.engine.started_at)}</strong> to{" "}
                    <strong className="whitespace-nowrap">{formatDateTime(data.engine.last_update)}</strong>)
                  </div>
                )}
              </div>
            </header>

            <div className="space-y-6 text-sm">
              {/* SECTION 1: ENGINE SESSION */}
              <section className="space-y-2.5 report-section">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 border-b border-slate-300 pb-1 report-heading">
                  1. Engine Session
                </h2>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">INTERFACE</span>
                    <strong className="text-slate-900 text-sm font-semibold">{data.engine.interface}</strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">ENGINE PID</span>
                    <strong className="text-slate-900 text-sm font-semibold">{data.engine.engine_pid || "N/A"}</strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">SESSION DURATION</span>
                    <strong className="text-slate-900 text-sm font-semibold">
                      {data.engine.session_seconds}s ({formatSecToHms(data.engine.session_seconds)})
                    </strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">STARTED AT</span>
                    <span className="text-slate-900 text-xs whitespace-nowrap">{formatDateTime(data.engine.started_at)}</span>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded col-span-2">
                    <span className="text-slate-500 block text-[11px]">LAST TELEMETRY UPDATE</span>
                    <span className="text-slate-900 text-xs whitespace-nowrap">{formatDateTime(data.engine.last_update)}</span>
                  </div>
                </div>
              </section>

              {/* SECTION 2: TRAFFIC TOTALS */}
              <section className="space-y-2.5 report-section">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 border-b border-slate-300 pb-1 report-heading">
                  2. Traffic Totals
                </h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">TOTAL INSPECTED</span>
                    <strong className="text-slate-900 text-base font-bold">
                      {data.traffic.total_inspected.toLocaleString()}
                    </strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">FORWARDED</span>
                    <strong className="text-emerald-700 text-base font-bold">
                      {data.traffic.forwarded.toLocaleString()}
                    </strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">DROPPED</span>
                    <strong className="text-rose-700 text-base font-bold">
                      {data.traffic.dropped.toLocaleString()}
                    </strong>
                    <span className="text-slate-500 block text-[10px] mt-0.5 font-sans">
                      blocklist or malformed
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">UNHANDLED</span>
                    <strong className="text-slate-700 text-base font-bold">
                      {data.traffic.unhandled.toLocaleString()}
                    </strong>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">TOTAL VOLUME</span>
                    <strong className="text-slate-900 text-sm font-semibold block whitespace-nowrap">
                      {(data.traffic.bytes_total / 1_000_000).toFixed(2)} MB
                    </strong>
                    <span className="text-slate-500 block text-[10px] mt-0.5 whitespace-nowrap">
                      {data.traffic.bytes_total.toLocaleString()} bytes
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">KERNEL RX (PCAP)</span>
                    <strong className="text-slate-900 text-xs">{data.traffic.pcap_recv.toLocaleString()}</strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">RING / IF DROPS</span>
                    <strong className="text-slate-900 text-xs">
                      {(data.traffic.pcap_drop + data.traffic.pcap_ifdrop).toLocaleString()}
                    </strong>
                  </div>
                  <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                    <span className="text-slate-500 block text-[11px]">AVERAGE RATES (SESSION)</span>
                    <strong className="text-slate-900 text-xs whitespace-nowrap block">
                      {formatPacketRate(data.traffic.total_inspected, data.engine.session_seconds)} &middot;{" "}
                      {formatBandwidth(data.traffic.bytes_total, data.engine.session_seconds)}
                    </strong>
                  </div>
                </div>
              </section>

              {/* SECTION 3: PROTOCOL MIX */}
              <section className="space-y-2.5 report-section">
                <div className="flex items-center justify-between border-b border-slate-300 pb-1">
                  <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 report-heading">
                    3. Protocol Classification Mix
                  </h2>
                  <span className="font-mono text-xs text-slate-600">
                    SNI Identified: <strong>{data.protocol_mix.tls_sni_seen.toLocaleString()}</strong>
                  </span>
                </div>
                <table className="w-full text-left border-collapse border border-slate-300 font-mono text-xs report-table">
                  <thead>
                    <tr className="bg-slate-100 text-slate-700 border-b border-slate-300">
                      <th className="py-2 px-3">PROTOCOL CLASS</th>
                      <th className="py-2 px-3 text-right">PACKET COUNT</th>
                      <th className="py-2 px-3 text-right">PERCENTAGE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {data.protocol_mix.classes.map((cls) => (
                      <tr key={cls.name} className="hover:bg-slate-50">
                        <td className="py-1.5 px-3 font-semibold text-slate-800">{cls.name}</td>
                        <td className="py-1.5 px-3 text-right text-slate-700">{cls.count.toLocaleString()}</td>
                        <td className="py-1.5 px-3 text-right font-semibold text-slate-900">
                          {cls.percentage.toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>

              {/* SECTION 4: THREADS */}
              <section className="space-y-2.5 report-section">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 border-b border-slate-300 pb-1 report-heading">
                  4. Engine Thread Workload
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                  {/* Load Balancers */}
                  <div>
                    <div className="flex justify-between items-center mb-1 text-slate-700 font-bold">
                      <span>LOAD BALANCERS</span>
                      <span>Total: {data.threads.lb_total.toLocaleString()}</span>
                    </div>
                    <table className="w-full text-left border-collapse border border-slate-300 report-table">
                      <thead>
                        <tr className="bg-slate-100 text-slate-700 border-b border-slate-300">
                          <th className="py-1.5 px-2.5">THREAD</th>
                          <th className="py-1.5 px-2.5 text-right">DISPATCHED</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {data.threads.lbs.map((lb) => (
                          <tr key={lb.name}>
                            <td className="py-1.5 px-2.5 font-semibold text-slate-800">{lb.name}</td>
                            <td className="py-1.5 px-2.5 text-right">{lb.dispatched.toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Fast Paths */}
                  <div>
                    <div className="flex justify-between items-center mb-1 text-slate-700 font-bold">
                      <span>FAST PATH WORKERS</span>
                      <span>Total: {data.threads.fp_total.toLocaleString()}</span>
                    </div>
                    <table className="w-full text-left border-collapse border border-slate-300 report-table">
                      <thead>
                        <tr className="bg-slate-100 text-slate-700 border-b border-slate-300">
                          <th className="py-1.5 px-2">THREAD</th>
                          <th className="py-1.5 px-2 text-right">PROCESSED</th>
                          <th className="py-1.5 px-2 text-right">FORWARDED</th>
                          <th className="py-1.5 px-2 text-right">DROPPED</th>
                          <th className="py-1.5 px-2 text-right">UNHANDLED</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {data.threads.fps.map((fp) => (
                          <tr key={fp.name}>
                            <td className="py-1.5 px-2 font-semibold text-slate-800">{fp.name}</td>
                            <td className="py-1.5 px-2 text-right">{fp.processed.toLocaleString()}</td>
                            <td className="py-1.5 px-2 text-right text-emerald-700">{fp.forwarded.toLocaleString()}</td>
                            <td className="py-1.5 px-2 text-right text-rose-700">{fp.dropped.toLocaleString()}</td>
                            <td className="py-1.5 px-2 text-right text-slate-600">{fp.unhandled.toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>

              {/* SECTION 5: CONSISTENCY CHECKS */}
              <section className="space-y-2.5 report-section">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 border-b border-slate-300 pb-1 report-heading">
                  5. Engine Telemetry Consistency Checks
                </h2>
                <table className="w-full text-left border-collapse border border-slate-300 font-mono text-xs report-table">
                  <thead>
                    <tr className="bg-slate-100 text-slate-700 border-b border-slate-300">
                      <th className="py-2 px-3">INVARIANT CHECK</th>
                      <th className="py-2 px-3 text-right">LEFT VALUE</th>
                      <th className="py-2 px-3 text-right">RIGHT VALUE</th>
                      <th className="py-2 px-3 text-center">VERDICT</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {data.checks.map((c) => (
                      <tr key={c.name} className="hover:bg-slate-50">
                        <td className="py-2 px-3">
                          <div className="font-semibold text-slate-800">{c.name}</div>
                          {c.note && (
                            <div className="text-[11px] text-slate-500 font-sans font-normal mt-0.5">
                              {c.note}
                            </div>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right">{c.left.toLocaleString()}</td>
                        <td className="py-2 px-3 text-right">{c.right.toLocaleString()}</td>
                        <td className="py-2 px-3 text-center">
                          {c.is_info ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-blue-100 text-blue-800 border border-blue-300 whitespace-nowrap">
                              INFO {c.diff !== undefined ? `(diff: ${c.diff > 0 ? `+${c.diff.toLocaleString()}` : c.diff.toLocaleString()})` : ""}
                            </span>
                          ) : c.pass ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                              PASS
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-rose-100 text-rose-800 border border-rose-300">
                              <XCircle className="h-3 w-3 mr-1" />
                              FAIL
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>

              {/* SECTION 6: BLOCKED IPS */}
              <section className="space-y-2.5 report-section">
                <div className="flex items-center justify-between border-b border-slate-300 pb-1">
                  <div className="flex items-center space-x-2">
                    <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 report-heading">
                      6. BLOCKED IPS
                    </h2>
                    <code className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-700 lowercase font-normal">
                      blocklist:ips
                    </code>
                  </div>
                  <span className="font-mono text-xs text-slate-600">
                    Active Entries: <strong>{data.blocklist.length}</strong>
                  </span>
                </div>
                {data.blocklist.length > 0 ? (
                  <div className="flex flex-wrap gap-2 pt-1 font-mono text-xs">
                    {data.blocklist.map((ip) => (
                      <span
                        key={ip}
                        className="px-2.5 py-1 rounded bg-slate-100 border border-slate-300 text-slate-800 font-semibold"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="font-sans text-xs text-slate-500 italic py-2">
                    No active blocked IPs in <code className="font-mono lowercase text-[11px]">blocklist:ips</code>.
                  </p>
                )}
              </section>

              {/* SECTION 7: ANOMALIES THIS SESSION */}
              <section className="space-y-2.5 report-section">
                <div className="border-b border-slate-300 pb-1.5">
                  <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 report-heading">
                    7. Anomalies This Session
                  </h2>
                  <div className="text-[11px] font-mono text-slate-600 mt-0.5">
                    This session: <strong>{data.anomalies.this_session_count}</strong> &middot; All verdicts in history (all sessions):{" "}
                    <strong>{data.anomalies.total_history_count}</strong>
                  </div>
                </div>
                {data.anomalies.list.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse border border-slate-300 font-mono text-xs report-table">
                      <thead>
                        <tr className="bg-slate-100 text-slate-700 border-b border-slate-300">
                          <th className="py-2 px-2.5">TIME</th>
                          <th className="py-2 px-2.5">SRC IP</th>
                          <th className="py-2 px-2.5">DST IP</th>
                          <th className="py-2 px-2.5">VERDICT</th>
                          <th className="py-2 px-2.5 text-right">CONFIDENCE</th>
                          <th className="py-2 px-2.5 text-center">MITIGATED</th>
                          <th className="py-2 px-2.5 text-center">TELEGRAM</th>
                          <th className="py-2 px-2.5">TOP FEATURE</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {data.anomalies.list.map((anom, idx) => (
                          <tr key={idx} className="hover:bg-slate-50">
                            <td className="py-1.5 px-2.5 text-[11px] text-slate-600 whitespace-nowrap">
                              {formatDateTime(anom.time)}
                            </td>
                            <td className="py-1.5 px-2.5 font-semibold text-slate-900">{anom.src}</td>
                            <td className="py-1.5 px-2.5 text-slate-700">{anom.dst}</td>
                            <td className="py-1.5 px-2.5">
                              <span className="font-bold text-rose-700">{anom.verdict}</span>
                            </td>
                            <td className="py-1.5 px-2.5 text-right font-semibold">
                              {(anom.confidence * 100).toFixed(1)}%
                            </td>
                            <td className="py-1.5 px-2.5 text-center">
                              {anom.mitigated ? (
                                <span className="text-emerald-700 font-bold">YES</span>
                              ) : (
                                <span className="text-slate-400">NO</span>
                              )}
                            </td>
                            <td className="py-1.5 px-2.5 text-center text-[11px] whitespace-nowrap">
                              {anom.telegram_alert === "sent" ? (
                                <span className="text-emerald-700 font-semibold">sent</span>
                              ) : anom.telegram_alert === "suppressed_cooldown" ? (
                                <span className="text-slate-500">suppressed</span>
                              ) : anom.telegram_alert === "failed" ? (
                                <span className="text-rose-600 font-semibold">failed</span>
                              ) : anom.telegram_alert === "disabled" ? (
                                <span className="text-slate-400">disabled</span>
                              ) : anom.telegram_alert === "attempted" ? (
                                <span className="text-slate-500">attempted</span>
                              ) : (
                                <span className="text-slate-400">—</span>
                              )}
                            </td>
                            <td className="py-1.5 px-2.5 text-slate-700">{anom.top_feature}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="font-sans text-xs text-slate-500 italic py-2">
                    No anomalies detected this session.
                  </p>
                )}
              </section>

              {/* SECTION 8: ML MODEL - 3 + 2 layout */}
              <section className="space-y-2.5 report-section">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 border-b border-slate-300 pb-1 report-heading">
                  8. ML Anomaly Detection Model
                </h2>
                <div className="space-y-3 font-mono text-xs">
                  {/* Row 1: 3 cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                      <span className="text-slate-500 block text-[11px]">SERVICE STATUS</span>
                      <strong
                        className={`text-sm font-bold ${
                          data.ml.online ? "text-emerald-700" : "text-rose-700"
                        }`}
                      >
                        {data.ml.online ? "ONLINE" : "OFFLINE"}
                      </strong>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                      <span className="text-slate-500 block text-[11px]">MODEL TYPE</span>
                      <strong className="text-slate-900 text-sm font-semibold whitespace-normal break-words">
                        {data.ml.model_type}
                      </strong>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                      <span className="text-slate-500 block text-[11px]">FEATURES EVALUATED</span>
                      <strong className="text-slate-900 text-sm font-semibold">{data.ml.feature_count} features</strong>
                    </div>
                  </div>

                  {/* Row 2: 2 cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                      <span className="text-slate-500 block text-[11px]">AUTO-MITIGATION</span>
                      <strong className="text-slate-900 text-sm font-semibold">
                        {data.ml.auto_mitigate ? "ENABLED" : "DISABLED"}
                      </strong>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                      <span className="text-slate-500 block text-[11px]">ANOMALY THRESHOLD</span>
                      <strong className="text-slate-900 text-sm font-semibold">&ge; {data.ml.threshold}</strong>
                    </div>
                  </div>
                </div>
              </section>
            </div>

            {/* Document Footer */}
            <footer className="mt-8 pt-4 border-t border-slate-300 text-center font-mono text-[11px] text-slate-500 space-y-1">
              <div>
                Aegis DPI Automated System &middot; Generated{" "}
                <span className="whitespace-nowrap">{formatDateTime(data.generated_at)}</span>
              </div>
              <div className="whitespace-nowrap">
                Consistency checks: {passedCount} of {totalChecks} passed
              </div>
            </footer>
          </article>
        ) : null}
      </div>
    </div>
  );
};
