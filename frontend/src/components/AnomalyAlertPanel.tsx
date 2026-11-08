import React, { useState, useEffect } from "react";
import { useAegisStore } from "@/hooks/useAegisStore";
import { AnomalyAlert, MlStatusResponse } from "@/types/aegis";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";
import {
  BarChart3,
  Cpu,
  Info,
  CheckCircle2,
  XCircle,
} from "lucide-react";

const renderTelegramChip = (status?: string | null) => {
  if (!status || status === "not_applicable") return null;
  if (status === "sent") {
    return (
      <span className="text-[9px] font-mono bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/30 px-1.5 py-0.5 rounded whitespace-nowrap">
        Telegram: sent
      </span>
    );
  }
  if (status === "suppressed_cooldown") {
    return (
      <span className="text-[9px] font-mono bg-slate-800/40 text-slate-400 border border-slate-700/60 px-1.5 py-0.5 rounded whitespace-nowrap">
        Telegram: suppressed (cooldown)
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="text-[9px] font-mono bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/30 px-1.5 py-0.5 rounded whitespace-nowrap">
        Telegram: failed
      </span>
    );
  }
  if (status === "disabled" || status === "attempted") {
    return (
      <span className="text-[9px] font-mono bg-slate-800/40 text-slate-400 border border-slate-700/60 px-1.5 py-0.5 rounded whitespace-nowrap">
        Telegram: {status}
      </span>
    );
  }
  return null;
};

export const AnomalyAlertPanel: React.FC = () => {
  const { anomalies, injectSimulatedAnomaly } = useAegisStore();
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyAlert | null>(null);
  const [mlStatus, setMlStatus] = useState<MlStatusResponse>({ online: false });

  useEffect(() => {
    let mounted = true;
    const pollStatus = async () => {
      const s = await api.getMlStatus();
      if (mounted) setMlStatus(s);
    };
    pollStatus();
    const timer = setInterval(pollStatus, 10000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const displayAnomaly = (selectedAnomaly && anomalies.some((a) => a.id === selectedAnomaly.id))
    ? selectedAnomaly
    : anomalies[0] || null;

  return (
    <div className="space-y-6">
      {/* Real Status Banner */}
      <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div
            className={`p-2 rounded border ${
              mlStatus.online
                ? "bg-[#2fb8a6]/10 border-[#2fb8a6]/30 text-[#2fb8a6]"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            }`}
          >
            {mlStatus.online ? (
              <CheckCircle2 className="h-5 w-5" />
            ) : (
              <XCircle className="h-5 w-5" />
            )}
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <span
                className={`text-xs font-mono font-bold uppercase tracking-wider ${
                  mlStatus.online ? "text-[#2fb8a6]" : "text-red-400"
                }`}
              >
                {mlStatus.online ? "ML ENGINE ONLINE" : "ML ENGINE OFFLINE"}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-[#0c142e] border-[#22305e] text-[#eef1f8]">
                {mlStatus.model_type || "Isolation Forest"}
              </span>
              {mlStatus.online && (
                <>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-[#0c142e] border-[#22305e] text-[#8b9ac6]">
                    {mlStatus.feature_schema?.length ?? 5} features
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      mlStatus.auto_mitigate
                        ? "bg-[#2fb8a6]/15 border-[#2fb8a6]/30 text-[#2fb8a6]"
                        : "bg-amber-500/15 border-amber-500/30 text-amber-300"
                    }`}
                  >
                    Auto-mitigation: {mlStatus.auto_mitigate ? "ON" : "OFF"}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-[#0c142e] border-[#22305e] text-[#8b9ac6]">
                    Alert cooldown {mlStatus.alert_cooldown_s ?? 600}s · re-block {mlStatus.mitigation_cooldown_s ?? 10}s
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-[#0c142e] border-[#22305e] text-[#8b9ac6]">
                    Trained on {mlStatus.training_sample_count ? mlStatus.training_sample_count.toLocaleString() : "1,000"} samples
                  </span>
                </>
              )}
            </div>
            <p className="text-xs text-[#8b9ac6] mt-0.5 font-mono">
              {mlStatus.online
                ? `Tracking ${mlStatus.flow_table_size ?? 0} active flows across ${mlStatus.tracked_source_ips ?? 0} source IP window(s). Polled every 10s.`
                : "ML inference service is unreachable at http://127.0.0.1:8000. Reconnect service to resume scoring."}
            </p>
          </div>
        </div>

        <button
          onClick={injectSimulatedAnomaly}
          className="text-[11px] font-mono px-3 py-1.5 rounded border border-[#22305e] bg-[#0c142e] text-[#8b9ac6] hover:text-[#eef1f8] hover:border-[#3a4a80] transition-colors"
        >
          Inject simulated verdict (test)
        </button>
      </div>

      {/* Main Content Split: Flagged Event List + Feature Contribution Bars */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
        {/* Flagged Event List */}
        <div className="bg-[#101a38] border border-[#22305e] rounded-lg p-5 flex flex-col h-full min-h-0">
          <div className="flex items-center justify-between mb-4 shrink-0">
            <div>
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
                ML Anomaly Verdicts ({anomalies.length})
              </h3>
              <p className="text-xs text-[#8b9ac6] mt-0.5">
                {mlStatus.model_type || "IsolationForest + EnvelopeGuard"} · {mlStatus.feature_schema?.length ?? 10} features · 5-s window per source IP{mlStatus.model_version ? ` · model ${mlStatus.model_version}` : ""}
              </p>
            </div>
            <Cpu className="h-4 w-4 text-[#8b9ac6]" />
          </div>

          <div className="relative flex-1 min-h-0">
            <div className="space-y-3 font-mono text-xs max-h-[600px] overflow-y-auto lg:max-h-none lg:absolute lg:inset-0 lg:overflow-y-auto lg:overscroll-contain pr-1">
              {anomalies.length === 0 ? (
                <div className="p-8 text-center text-[#8b9ac6]">
                  <p>No anomalies detected yet. Verdicts appear here in real time.</p>
                </div>
              ) : (
                anomalies.map((anom) => {
                  const isSelected = displayAnomaly?.id === anom.id;
                  return (
                    <div
                      key={anom.id}
                      onClick={() => setSelectedAnomaly(anom)}
                      className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? "bg-[#0c142e] border-[#2fb8a6] ring-1 ring-[#2fb8a6]/40 shadow-sm"
                          : "bg-[#0c142e]/60 border-[#22305e] hover:border-[#3a4a80]"
                      }`}
                    >
                      {/* Line 1: IP + REAL/SIMULATED chip left, confidence right (one line, nowrap). No chip in header row. */}
                      <div className="flex items-center justify-between mb-2 gap-2 whitespace-nowrap">
                        <div className="flex items-center space-x-2 shrink-0 whitespace-nowrap">
                          <span className="text-xs font-bold text-[#eef1f8] whitespace-nowrap font-mono">
                            {anom.source_ip}
                          </span>
                          {anom.is_simulated ? (
                            <span className="text-[9px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 rounded whitespace-nowrap">
                              SIMULATED
                            </span>
                          ) : (
                            <span className="text-[9px] font-mono bg-[#2fb8a6]/20 text-[#2fb8a6] border border-[#2fb8a6]/30 px-1.5 py-0.5 rounded whitespace-nowrap">
                              REAL
                            </span>
                          )}
                          {anom.trigger && (
                            <span className="text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 px-1.5 py-0.5 rounded uppercase whitespace-nowrap">
                              {anom.trigger.toUpperCase()}
                            </span>
                          )}
                        </div>
                        <span
                          title={anom.model_version === "v3" ? "percentile vs normal traffic windows" : undefined}
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#ff5a2b]/20 text-[#ff5a2b] border border-[#ff5a2b]/40 whitespace-nowrap shrink-0 cursor-default"
                        >
                          {(anom.confidence * 100).toFixed(1)}% confidence
                        </span>
                      </div>

                      {/* Line 2: description */}
                      <div className="text-[11px] text-[#8b9ac6] whitespace-normal break-words mt-1">
                        {anom.description}
                      </div>

                      {/* Footer: three short lines: "Target ...", "Detected ...", and the Telegram chip */}
                      <div className="mt-2.5 pt-2 border-t border-[#16204a] space-y-1 text-[10px] text-[#8b9ac6]">
                        <div>
                          Target <span className="text-[#eef1f8] font-mono whitespace-nowrap">{anom.dest_ip}</span>
                        </div>
                        <div>
                          Detected <span className="text-[#a9b6da] font-mono whitespace-nowrap">{formatDateTime(anom.timestamp)}</span>
                        </div>
                        {anom.model_version && (
                          <div>
                            Model <span className="text-[#a9b6da] font-mono whitespace-nowrap uppercase">{anom.model_version}</span>
                          </div>
                        )}
                        <div>
                          {renderTelegramChip(anom.telegram_alert)}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Feature Contribution Bars (Feature Deviation / ML Explainability) */}
        <div className="lg:col-span-2 bg-[#101a38] border border-[#22305e] rounded-lg p-5">
          <div className="flex items-start justify-between gap-4 mb-4">
            <div>
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#eef1f8]">
                ML Feature Attribution & Transparency
              </h3>
              {displayAnomaly && (
                <div className="text-xs text-[#2fb8a6] font-mono mt-0.5 flex items-center space-x-2 flex-wrap gap-y-1">
                  <span>
                    Explaining: <span className="whitespace-nowrap font-bold text-[#eef1f8]">{displayAnomaly.source_ip}</span> · <span className="whitespace-nowrap text-[#a9b6da]">{formatDateTime(displayAnomaly.timestamp)}</span>
                  </span>
                  {displayAnomaly.model_version && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border bg-[#0c142e] border-[#22305e] text-[#8b9ac6] uppercase">
                      Model {displayAnomaly.model_version}
                    </span>
                  )}
                  {displayAnomaly.trigger && (
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border bg-purple-500/20 text-purple-300 border-purple-500/30 uppercase">
                      {displayAnomaly.trigger}
                    </span>
                  )}
                </div>
              )}
              <p className="text-xs text-[#8b9ac6] mt-1 font-sans">
                {displayAnomaly?.model_version === "v1"
                  ? "Share of each feature's relative deviation from its baseline: |observed - baseline| / baseline, normalised to 100%."
                  : "Share of each feature's robust deviation from the normal median: |observed - median| / IQR, normalised to 100%."}
              </p>
            </div>
            <div className="flex items-center space-x-1 text-xs font-mono text-[#2fb8a6] whitespace-nowrap shrink-0">
              <BarChart3 className="h-4 w-4 mr-1 shrink-0" />
              <span className="whitespace-nowrap">Deviation from Baseline</span>
            </div>
          </div>

          {displayAnomaly ? (
            <div className="space-y-6">
              {/* Envelope Guard Checks Table (when guard entries present) */}
              {displayAnomaly.guard && displayAnomaly.guard.length > 0 && (
                <div className="bg-[#0c142e] border border-[#22305e] rounded-lg p-3.5 font-mono text-xs">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-[#eef1f8]">
                      Envelope Guard Checks
                    </span>
                    <span className="text-[10px] text-[#8b9ac6]">
                      Limit = max(3× normal max, normal max + 10)
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="border-b border-[#22305e] text-[#8b9ac6] text-[11px]">
                          <th className="pb-2 font-medium">Feature</th>
                          <th className="pb-2 font-medium text-right">Observed</th>
                          <th className="pb-2 font-medium text-right">Normal Max</th>
                          <th className="pb-2 font-medium text-right">Limit</th>
                          <th className="pb-2 font-medium text-right">Ratio</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#16204a]">
                        {displayAnomaly.guard.map((g) => {
                          const exceeded = g.ratio > 1.0;
                          return (
                            <tr
                              key={g.feature}
                              className={
                                exceeded
                                  ? "bg-rose-500/15 text-rose-200 font-semibold"
                                  : "text-[#a9b6da]"
                              }
                            >
                              <td className="py-1.5 pr-2">
                                <span>{g.human_name || g.feature}</span>
                                <span className="text-[10px] text-[#8b9ac6] ml-1.5 font-mono">
                                  ({g.feature})
                                </span>
                              </td>
                              <td className="py-1.5 px-2 text-right">
                                {Number(g.raw_value).toFixed(1)}
                              </td>
                              <td className="py-1.5 px-2 text-right">
                                {Number(g.normal_max).toFixed(1)}
                              </td>
                              <td className="py-1.5 px-2 text-right">
                                {Number(g.limit).toFixed(1)}
                              </td>
                              <td className="py-1.5 pl-2 text-right">
                                <span
                                  className={
                                    exceeded
                                      ? "text-rose-400 font-bold"
                                      : "text-[#8b9ac6]"
                                  }
                                >
                                  {Number(g.ratio).toFixed(2)}x
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Feature Bars */}
              <div className="space-y-4">
                {displayAnomaly.features.map((feat) => {
                  const isRatio = feat.name.toLowerCase().includes("ratio");
                  let effectiveBase = feat.baseline;
                  if (feat.name === "dropped_ratio" && effectiveBase === 0) {
                    effectiveBase = 0.0048; // never show baseline as 0 when non-zero (from baselines.json)
                  }
                  const formattedValue = isRatio ? Number(feat.value).toFixed(4) : Number(feat.value).toFixed(2);
                  const formattedBase = isRatio ? Number(effectiveBase).toFixed(4) : Number(effectiveBase).toFixed(2);
                  const diff = feat.value - effectiveBase;
                  const direction =
                    Math.abs(diff) < 0.00001
                      ? "at baseline"
                      : diff > 0
                      ? "above baseline"
                      : "below baseline";

                  return (
                    <div key={feat.name} className="bg-[#0c142e] border border-[#22305e] rounded-lg p-3.5 font-mono text-xs">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-[#eef1f8] font-bold">
                            {feat.name}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-[#ff5a2b] font-bold">
                            {feat.contribution_pct}% of total deviation
                          </span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                              direction === "above baseline"
                                ? "bg-rose-500/15 text-rose-300 border border-rose-500/30"
                                : direction === "below baseline"
                                ? "bg-blue-500/15 text-blue-300 border border-blue-500/30"
                                : "bg-slate-500/15 text-slate-300 border border-slate-500/30"
                            }`}
                          >
                            {direction}
                          </span>
                        </div>
                      </div>

                      {/* Progress Bar */}
                      <div className="w-full bg-[#16204a] h-2 rounded overflow-hidden mb-2">
                        <div
                          className="bg-gradient-to-r from-[#2fb8a6] to-[#ff5a2b] h-full"
                          style={{ width: `${feat.contribution_pct}%` }}
                        />
                      </div>

                      <div className="flex justify-between text-[11px] text-[#8b9ac6]">
                        <span>
                          Observed:{" "}
                          <span className="text-[#eef1f8] font-semibold">
                            {formattedValue}
                          </span>
                        </span>
                        <span>
                          Baseline Normal:{" "}
                          <span className="text-[#a9b6da]">{formattedBase}</span>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Explanatory Info Card */}
              <div className="p-4 bg-[#0c142e] border border-[#22305e] rounded-lg flex items-start space-x-3">
                <Info className="h-5 w-5 text-[#2fb8a6] shrink-0 mt-0.5" />
                <div className="text-xs font-sans text-[#a9b6da] space-y-1">
                  <p className="font-semibold text-[#eef1f8]">
                    How This Detection Works:
                  </p>
                  {mlStatus.model_version === "v1" ? (
                    <p>
                      The ML service reads every packet record from dpi:logs, builds
                      5 features per source IP over a 5-second window, and scores them
                      with an Isolation Forest once per second. At 0.85 confidence or
                      above the verdict is ANOMALOUS: the service calls POST /api/rules
                      to block the source, publishes the verdict to this page, and
                      sends a Telegram alert (at most one per IP every 10 minutes).
                      Blocking happens after detection, not inline.
                    </p>
                  ) : (
                    <p>
                      The ML service reads packet records from dpi:logs and builds 10
                      traffic-shape features per source IP over a 5-s window, scored
                      every second by an IsolationForest trained only on normal traffic,
                      plus a per-feature envelope guard (limit = max(3x normal max, normal max + 10)).
                      A verdict is ANOMALOUS if traffic is more unusual than every normal
                      validation window or if any guard limit is exceeded. Blocks expire
                      (10 min → 1 h → 24 h for repeat offenders), and allowlisted IPs are
                      never blocked. Blocking happens after detection, not inline.
                    </p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-[#8b9ac6] font-mono text-xs">
              Select an anomaly event to view feature contribution breakdown.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
