import { create } from "zustand";
import {
  NavSection,
  SystemStats,
  DpiLogEntry,
  BlocklistRule,
  BlocklistEvent,
  WorkerThreadStats,
  AnomalyAlert,
  ChartSample,
} from "@/types/aegis";
import { api, setAuthErrorHandler } from "@/lib/api";

interface PrevStatsSnapshot {
  total: number;
  dropped: number;
  bytes_total: number;
  per_thread: Record<string, number>;
  updated_at_ms: number;
  started_at: number;
}

let prevStatsSnapshot: PrevStatsSnapshot | null = null;
let currentRates = {
  pps: 0,
  dropped_pps: 0,
  mbps: 0,
  bps: 0,
  perThread: {} as Record<string, number>,
};

function normalizeAnomaly(item: any): AnomalyAlert {
  let rawFeatures = item.features;
  if (typeof rawFeatures === "string") {
    try {
      rawFeatures = JSON.parse(rawFeatures);
    } catch {
      rawFeatures = [];
    }
  }

  let rawGuard = item.guard;
  if (typeof rawGuard === "string") {
    try {
      rawGuard = JSON.parse(rawGuard);
    } catch {
      rawGuard = undefined;
    }
  }

  return {
    id: String(item.id || `anom_${Date.now()}`),
    timestamp: String(item.timestamp || new Date().toISOString()),
    source_ip: String(item.source_ip || ""),
    dest_ip: String(item.dest_ip || ""),
    confidence: Number(item.confidence) || 0,
    verdict: item.verdict === "SUSPICIOUS" ? "SUSPICIOUS" : "ANOMALOUS",
    auto_mitigated: Boolean(item.auto_mitigated),
    description: String(item.description || ""),
    features: Array.isArray(rawFeatures)
      ? rawFeatures.map((f: any) => ({
          name: String(f.name || ""),
          value: Number(f.value) || 0,
          baseline: Number(f.baseline) || 0,
          contribution_pct: Number(f.contribution_pct) || 0,
        }))
      : [],
    is_simulated: Boolean(item.is_simulated),
    telegram_alert: item.telegram_alert,
    model_version: item.model_version ? String(item.model_version) : undefined,
    trigger: item.trigger ? String(item.trigger) : undefined,
    guard: Array.isArray(rawGuard)
      ? rawGuard.map((g: any) => ({
          feature: String(g.feature || ""),
          human_name: String(g.human_name || g.feature || ""),
          raw_value: Number(g.raw_value) || 0,
          normal_max: Number(g.normal_max) || 0,
          limit: Number(g.limit) || 0,
          ratio: Number(g.ratio) || 0,
        }))
      : undefined,
  };
}

interface AegisStoreState {
  navSection: NavSection;
  socketConnected: boolean;
  isPaused: boolean;
  bufferedCount: number;
  pausedLogBuffer: DpiLogEntry[];
  stats: SystemStats | null;
  ppsHistory: number[];
  droppedHistory: number[];
  chartHistory: ChartSample[];
  isEngineNoData: boolean;
  logs: DpiLogEntry[];
  selectedLog: DpiLogEntry | null;
  blocklist: BlocklistRule[];
  blocklistEvents: BlocklistEvent[];
  threads: WorkerThreadStats[];
  anomalies: AnomalyAlert[];
  activeAlert: AnomalyAlert | null;
  isLoading: boolean;
  isReportOpen: boolean;
  isAuthenticated: boolean;
  currentUser: string | null;
  authError: string | null;

  login: (username: string, password: string) => Promise<boolean>;
  logout: (reason?: string) => void;

  setNavSection: (section: NavSection) => void;
  setSocketConnected: (connected: boolean) => void;
  setIsReportOpen: (open: boolean) => void;
  togglePause: () => void;
  setIsPaused: (paused: boolean) => void;
  setSelectedLog: (log: DpiLogEntry | null) => void;
  dismissAlert: () => void;

  // Real data actions wired to backend
  fetchStatsSummary: () => Promise<void>;
  fetchLogs: () => Promise<void>;
  addLog: (log: DpiLogEntry) => void;
  addLogBatch: (batch: any) => void;
  fetchBlocklist: () => Promise<void>;
  addBlocklistRule: (
    ip: string,
    reason?: string,
    source?: string,
    ttl_s?: number | null
  ) => Promise<void>;
  removeBlocklistRule: (ip: string) => Promise<void>;
  fetchThreads: () => Promise<void>;
  fetchAnomalies: () => Promise<void>;
  initializeData: () => Promise<void>;

  // Continuous client-side ticker action
  tickHistory: () => void;

  // Real-time ML anomaly event from Socket.io
  addAnomaly: (alert: AnomalyAlert) => void;

  // Phase 5 Placeholder: Inject simulated anomaly for testing UI mitigation pipeline
  injectSimulatedAnomaly: () => void;
}
function formatStreamTimestamp(streamId?: string): string {
  if (!streamId) return "--:--:--.---";
  const msPart = parseInt(streamId.split("-")[0], 10);
  if (isNaN(msPart) || msPart <= 0) return "--:--:--.---";
  const d = new Date(msPart);
  const pad = (n: number, z = 2) => String(n).padStart(z, "0");
  const hh = pad(d.getHours());
  const mm = pad(d.getMinutes());
  const ss = pad(d.getSeconds());
  const mmm = pad(d.getMilliseconds(), 3);
  return `${hh}:${mm}:${ss}.${mmm}`;
}

function compareStreamIds(a: string, b: string): number {
  const [msAStr, seqAStr] = a.split("-");
  const [msBStr, seqBStr] = b.split("-");
  const msA = Number(msAStr) || 0;
  const msB = Number(msBStr) || 0;
  if (msA !== msB) return msB - msA; // newest first
  const seqA = Number(seqAStr) || 0;
  const seqB = Number(seqBStr) || 0;
  return seqB - seqA;
}

function normalizeDpiLog(raw: any): DpiLogEntry {
  const rawAction = String(raw.action || "").toUpperCase().trim();
  let normalizedAction: "FORWARD" | "DROP" | "UNHANDLED" = "FORWARD";
  if (rawAction.includes("DROP")) {
    normalizedAction = "DROP";
  } else if (rawAction.includes("UNHANDLED")) {
    normalizedAction = "UNHANDLED";
  } else {
    normalizedAction = "FORWARD";
  }

  const rawL3 = String(raw.l3 || "").toLowerCase().trim();
  let l3: "ipv4" | "arp" | "ipv6" | "other" = "other";
  if (rawL3 === "ipv4" || rawL3 === "arp" || rawL3 === "ipv6") {
    l3 = rawL3;
  } else if (raw.protocol === "0" && raw.src_ip && raw.dst_ip) {
    l3 = "arp";
  }

  const rawProto = String(raw.protocol || "").trim();
  let protoLabel = rawProto.toUpperCase();
  if (l3 === "arp") {
    protoLabel = "ARP";
  } else if (l3 === "ipv6") {
    protoLabel = "IPv6";
  } else if (protoLabel === "1" || protoLabel === "ICMP") {
    protoLabel = "ICMP";
  } else if (protoLabel === "6" || protoLabel === "TCP") {
    protoLabel = "TCP";
  } else if (protoLabel === "17" || protoLabel === "UDP") {
    protoLabel = "UDP";
  } else {
    protoLabel = "OTHER";
  }

  const threadId = Number(raw.thread_id) || 0;
  const streamId = String(raw.stream_id || raw.id || "");

  const tcpFlags = raw.tcp_flags !== undefined && raw.tcp_flags !== null && raw.tcp_flags !== ""
    ? Number(raw.tcp_flags)
    : undefined;
  const icmpType = raw.icmp_type !== undefined && raw.icmp_type !== null && raw.icmp_type !== ""
    ? Number(raw.icmp_type)
    : undefined;

  return {
    ...raw,
    id: streamId,
    stream_id: streamId,
    action: normalizedAction,
    timestamp: formatStreamTimestamp(streamId),
    protocol: protoLabel,
    l3,
    src_port: Number(raw.src_port) || 0,
    dst_port: Number(raw.dst_port) || 0,
    sni: raw.sni || "-",
    reason: raw.reason || "clean",
    thread_id: threadId,
    tcp_flags: tcpFlags,
    icmp_type: icmpType,
  };
}

export const useAegisStore = create<AegisStoreState>((set, get) => ({
  navSection: "stats",
  socketConnected: false,
  isPaused: false,
  bufferedCount: 0,
  pausedLogBuffer: [],
  stats: null,
  ppsHistory: [],
  droppedHistory: [],
  chartHistory: [],
  isEngineNoData: false,
  logs: [],
  selectedLog: null,
  blocklist: [],
  blocklistEvents: [],
  threads: [],
  anomalies: [],
  activeAlert: null,
  isLoading: false,
  isReportOpen: false,
  isAuthenticated: Boolean(sessionStorage.getItem("aegis_token")),
  currentUser: sessionStorage.getItem("aegis_user") || null,
  authError: null,

  login: async (username: string, password: string) => {
    try {
      const data = await api.login(username, password);
      set({
        isAuthenticated: true,
        currentUser: data.username || username,
        authError: null,
      });
      return true;
    } catch (err: any) {
      set({ authError: err.message || "Invalid credentials" });
      return false;
    }
  },

  logout: (reason?: string) => {
    const user = get().currentUser || sessionStorage.getItem("aegis_user") || undefined;
    api.logout(user).catch(() => {});
    sessionStorage.removeItem("aegis_token");
    sessionStorage.removeItem("aegis_user");
    set({
      isAuthenticated: false,
      currentUser: null,
      authError: reason || null,
      socketConnected: false,
    });
  },

  setNavSection: (section) => set({ navSection: section }),
  setSocketConnected: (connected) => set({ socketConnected: connected }),
  setIsReportOpen: (open) => set({ isReportOpen: open }),
  togglePause: () => {
    set((state) => {
      const nextPaused = !state.isPaused;
      if (!nextPaused && state.pausedLogBuffer.length > 0) {
        const combined = [...state.pausedLogBuffer, ...state.logs].slice(0, 500);
        return {
          isPaused: false,
          bufferedCount: 0,
          logs: combined,
          pausedLogBuffer: [],
          selectedLog: state.selectedLog,
        };
      }
      return {
        isPaused: nextPaused,
        bufferedCount: nextPaused ? state.bufferedCount : 0,
      };
    });
  },
  setIsPaused: (paused) => {
    set((state) => {
      if (!paused && state.pausedLogBuffer.length > 0) {
        const combined = [...state.pausedLogBuffer, ...state.logs].slice(0, 500);
        return {
          isPaused: false,
          bufferedCount: 0,
          logs: combined,
          pausedLogBuffer: [],
          selectedLog: state.selectedLog,
        };
      }
      return {
        isPaused: paused,
        bufferedCount: paused ? state.bufferedCount : 0,
      };
    });
  },
  setSelectedLog: (log) => set({ selectedLog: log }),
  dismissAlert: () => set({ activeAlert: null }),

  // Signal-only trigger: socket "stats:update" arrives -> re-fetch /api/stats/summary
  fetchStatsSummary: async () => {
    try {
      const stats = await api.getStatsSummary();
      const updated_at_ms = stats.updated_at_ms || 0;
      const started_at = stats.started_at || 0;
      const total = stats.total_packets;
      const dropped = stats.dropped;
      const bytes_total = stats.bytes_total || 0;

      const currentThreadCounts: Record<string, number> = {};
      (stats.threads || []).forEach((t) => {
        currentThreadCounts[`${t.role}_${t.thread_id}`] = t.packets_processed;
      });

      let shouldAppendChart = false;
      const isLive = updated_at_ms > 0 && Date.now() - updated_at_ms <= 5000;

      if (!isLive) {
        currentRates = { pps: 0, dropped_pps: 0, mbps: 0, bps: 0, perThread: {} };
        shouldAppendChart = false;
        // Still update snapshot baseline if available
        if (total > 0) {
          prevStatsSnapshot = {
            total,
            dropped,
            bytes_total,
            per_thread: currentThreadCounts,
            updated_at_ms,
            started_at,
          };
        }
      } else if (!prevStatsSnapshot) {
        // First snapshot after page load: seed previous counter values, never compute pps from 0
        prevStatsSnapshot = {
          total,
          dropped,
          bytes_total,
          per_thread: currentThreadCounts,
          updated_at_ms,
          started_at,
        };
        currentRates = { pps: 0, dropped_pps: 0, mbps: 0, bps: 0, perThread: {} };
        shouldAppendChart = false;
      } else {
        const dt = updated_at_ms - prevStatsSnapshot.updated_at_ms;
        if (dt > 0) {
          const anyCounterDecreased =
            total < prevStatsSnapshot.total ||
            dropped < prevStatsSnapshot.dropped ||
            bytes_total < prevStatsSnapshot.bytes_total ||
            Object.entries(currentThreadCounts).some(
              ([key, count]) => count < (prevStatsSnapshot!.per_thread[key] ?? 0)
            );

          if (started_at !== prevStatsSnapshot.started_at || anyCounterDecreased) {
            // Engine restarted: reset baseline, rates = 0
            prevStatsSnapshot = {
              total,
              dropped,
              bytes_total,
              per_thread: currentThreadCounts,
              updated_at_ms,
              started_at,
            };
            currentRates = { pps: 0, dropped_pps: 0, mbps: 0, bps: 0, perThread: {} };
          } else {
            const dropped_pps = Math.max(0, Math.round(((dropped - prevStatsSnapshot.dropped) * 1000) / dt));
            const bps = Math.max(0, ((bytes_total - prevStatsSnapshot.bytes_total) * 8) / (dt / 1000));
            const mbps = Math.max(0, +(bps / 1e6).toFixed(2));

            const perThread: Record<string, number> = {};
            const fpKeys = Object.keys(currentThreadCounts).filter((k) => k.startsWith("FAST_PATH_"));
            const lbKeys = Object.keys(currentThreadCounts).filter((k) => k.startsWith("LB_"));

            // Real per-thread LB deltas: rate_i = (lb_i_dispatched_now - lb_i_dispatched_prev) / dt
            for (const key of lbKeys) {
              const prevCount = prevStatsSnapshot.per_thread[key] ?? currentThreadCounts[key];
              const delta = Math.max(0, currentThreadCounts[key] - prevCount);
              perThread[key] = Math.max(0, Math.round((delta * 1000) / dt));
            }

            // Real per-thread FP deltas: rate_i = (fp_i_processed_now - fp_i_processed_prev) / dt
            let totalFpRate = 0;
            for (const key of fpKeys) {
              const prevCount = prevStatsSnapshot.per_thread[key] ?? currentThreadCounts[key];
              const delta = Math.max(0, currentThreadCounts[key] - prevCount);
              const rate = Math.max(0, Math.round((delta * 1000) / dt));
              perThread[key] = rate;
              totalFpRate += rate;
            }

            // Header pps = sum of FP deltas / dt, so they match exactly by construction
            const pps = totalFpRate;

            currentRates = { pps, dropped_pps, mbps, bps, perThread };
            prevStatsSnapshot = {
              total,
              dropped,
              bytes_total,
              per_thread: currentThreadCounts,
              updated_at_ms,
              started_at,
            };
            shouldAppendChart = true;
          }
        }
      }

      set((state) => {
        const rawThreads = stats.threads && stats.threads.length > 0 ? stats.threads : state.threads;

        const lbSum = rawThreads.filter((t) => t.role === "LB").reduce((sum, t) => sum + t.packets_processed, 0);
        const fpSum = rawThreads.filter((t) => t.role === "FAST_PATH").reduce((sum, t) => sum + t.packets_processed, 0);

        const updatedThreads = rawThreads.map((newT) => {
          const sumProcessed = newT.role === "LB" ? lbSum : fpSum;
          const load_pct = sumProcessed > 0 ? Math.round((newT.packets_processed / sumProcessed) * 100) : 0;
          const threadRate = isLive ? (currentRates.perThread[`${newT.role}_${newT.thread_id}`] ?? 0) : 0;

          const existing = state.threads.find(
            (et) => et.thread_id === newT.thread_id && et.role === newT.role
          );
          const existingHistory = existing?.pps_history || [];
          const newPpsHistory = shouldAppendChart && isLive
            ? [...existingHistory.slice(-39), threadRate]
            : existingHistory;

          return {
            ...newT,
            load_pct,
            pps_history: newPpsHistory,
          };
        });

        let chartHistory = state.chartHistory;
        if (shouldAppendChart && isLive) {
          const cutoff = updated_at_ms - 100000;
          chartHistory = [
            ...chartHistory.filter((s) => s.t >= cutoff),
            {
              t: updated_at_ms,
              pps: currentRates.pps,
              dropped_pps: currentRates.dropped_pps,
            },
          ];
        }

        return {
          stats: {
            ...stats,
            throughput_pps: currentRates.pps,
            throughput_mbps: currentRates.mbps,
            throughput_bps: currentRates.bps,
            dropped_pps: currentRates.dropped_pps,
            threads: updatedThreads,
          },
          threads: updatedThreads,
          chartHistory,
          isEngineNoData: !isLive,
        };
      });
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to fetch stats summary:", err);
    }
  },

  fetchLogs: async () => {
    try {
      const rawLogs = await api.getRecentLogs(200);
      const mappedLogs = rawLogs.map(normalizeDpiLog);

      set((state) => {
        // Merge with existing logs in case live packets arrived during fetch
        const map = new Map<string, DpiLogEntry>();
        for (const item of state.logs) {
          if (item.id) map.set(item.id, item);
        }
        for (const item of mappedLogs) {
          if (item.id && !map.has(item.id)) {
            map.set(item.id, item);
          }
        }
        const merged = Array.from(map.values())
          .sort((a, b) => compareStreamIds(a.id, b.id))
          .slice(0, 500);

        if (state.isPaused) {
          return { pausedLogBuffer: merged };
        }
        return {
          logs: merged,
          selectedLog: state.selectedLog,
        };
      });
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to fetch logs:", err);
    }
  },

  addLogBatch: (rawBatch: any) => {
    const list = Array.isArray(rawBatch) ? rawBatch : (rawBatch?.logs || rawBatch?.batch || []);
    if (!Array.isArray(list) || list.length === 0) return;

    const normalizedList: DpiLogEntry[] = [];
    for (const raw of list) {
      const norm = normalizeDpiLog(raw);
      if (norm.id) normalizedList.push(norm);
    }
    if (normalizedList.length === 0) return;

    set((state) => {
      if (state.isPaused) {
        const existingMap = new Map<string, DpiLogEntry>();
        for (const l of state.pausedLogBuffer) {
          if (l.id) existingMap.set(l.id, l);
        }
        let addedCount = 0;
        for (const l of normalizedList) {
          if (!existingMap.has(l.id)) {
            existingMap.set(l.id, l);
            addedCount++;
          }
        }
        const updatedPaused = Array.from(existingMap.values())
          .sort((a, b) => compareStreamIds(a.id, b.id))
          .slice(0, 500);

        return {
          pausedLogBuffer: updatedPaused,
          bufferedCount: state.bufferedCount + addedCount,
        };
      }

      const existingMap = new Map<string, DpiLogEntry>();
      for (const l of state.logs) {
        if (l.id) existingMap.set(l.id, l);
      }
      for (const l of normalizedList) {
        if (!existingMap.has(l.id)) {
          existingMap.set(l.id, l);
        }
      }
      const merged = Array.from(existingMap.values())
        .sort((a, b) => compareStreamIds(a.id, b.id))
        .slice(0, 500);

      return {
        logs: merged,
        selectedLog: state.selectedLog,
      };
    });
  },

  addLog: (newLog: any) => {
    get().addLogBatch([newLog]);
  },

  fetchBlocklist: async () => {
    try {
      const blocklist = await api.getBlocklist();
      set({ blocklist });
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to fetch blocklist:", err);
    }
  },

  addBlocklistRule: async (ip, reason, source = "manual", ttl_s = null) => {
    try {
      const res = await api.addBlocklistRule(ip, reason, source, ttl_s);
      await get().fetchBlocklist();
      set((state) => ({
        blocklistEvents: [res.event, ...state.blocklistEvents],
      }));
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to add rule:", err);
      throw err;
    }
  },

  removeBlocklistRule: async (ip) => {
    try {
      const res = await api.removeBlocklistRule(ip);
      set((state) => ({
        blocklist: state.blocklist.filter((r) => r.ip !== ip),
        blocklistEvents: [res.event, ...state.blocklistEvents],
      }));
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to remove rule:", err);
    }
  },

  fetchThreads: async () => {
    // Deprecated: Thread counters are fetched atomically via /api/stats/summary
    await get().fetchStatsSummary();
  },

  fetchAnomalies: async () => {
    try {
      const rawList = await api.getAnomalies(100);
      const mappedList: AnomalyAlert[] = rawList.map((a) => ({
        ...normalizeAnomaly(a),
        is_simulated: false,
      }));

      set((state) => {
        const simulated = state.anomalies.filter((a) => a.is_simulated);
        const seenIds = new Set<string>();
        const combined: AnomalyAlert[] = [];

        for (const item of simulated) {
          if (!seenIds.has(item.id)) {
            seenIds.add(item.id);
            combined.push(item);
          }
        }
        for (const item of mappedList) {
          if (!seenIds.has(item.id)) {
            seenIds.add(item.id);
            combined.push(item);
          }
        }

        return {
          anomalies: combined,
          activeAlert: state.activeAlert || combined[0] || null,
        };
      });
    } catch (err) {
      console.error("[AEGIS-STORE] Failed to fetch anomalies:", err);
    }
  },

  initializeData: async () => {
    set({ isLoading: true });
    await Promise.allSettled([
      get().fetchStatsSummary(),
      get().fetchLogs(),
      get().fetchBlocklist(),
      get().fetchAnomalies(),
    ]);
    set({ isLoading: false });
  },

  tickHistory: () => {
    const stats = get().stats;
    const now = Date.now();
    const lastUpdate = stats?.updated_at_ms || 0;
    const isStale = lastUpdate === 0 || now - lastUpdate > 5000;

    if (isStale) {
      currentRates = { pps: 0, dropped_pps: 0, mbps: 0, bps: 0, perThread: {} };
      if (!get().isEngineNoData || (stats && (stats.throughput_pps > 0 || stats.throughput_mbps > 0))) {
        set((state) => ({
          isEngineNoData: true,
          stats: state.stats
            ? {
                ...state.stats,
                throughput_pps: 0,
                throughput_mbps: 0,
                throughput_bps: 0,
                dropped_pps: 0,
              }
            : null,
        }));
      }
    } else {
      if (get().isEngineNoData) {
        set({ isEngineNoData: false });
      }
    }
  },

  addAnomaly: (alert: AnomalyAlert) => {
    set((state) => {
      if (state.anomalies.some((a) => a.id === alert.id)) {
        return state;
      }
      const liveAlert: AnomalyAlert = {
        ...normalizeAnomaly(alert),
        is_simulated: false,
      };
      return {
        anomalies: [liveAlert, ...state.anomalies],
        activeAlert: liveAlert,
      };
    });
  },

  // Manual trigger for testing UI mitigation until Phase 5 ML service is online
  injectSimulatedAnomaly: () => {
    const simulatedAlert: AnomalyAlert = {
      id: `sim_anom_${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      source_ip: "10.10.0.2",
      dest_ip: "10.10.0.1",
      confidence: 0.984,
      verdict: "ANOMALOUS",
      auto_mitigated: true,
      description: "Simulated: 4,800 pkts/s from one source across 1 destination (ICMP flood pattern)",
      features: [
        { name: "Packets Per Sec (PPS)", value: 4800, baseline: 180, contribution_pct: 42 },
        { name: "SYN / ACK Ratio", value: 0.96, baseline: 0.08, contribution_pct: 35 },
        { name: "Target Port Entropy", value: 0.02, baseline: 0.74, contribution_pct: 15 },
        { name: "Payload Length Variance", value: 0, baseline: 420, contribution_pct: 8 },
      ],
      is_simulated: true,
    };

    set((state) => ({
      anomalies: [simulatedAlert, ...state.anomalies],
      activeAlert: simulatedAlert,
    }));
  },
}));

// Automatically logout and display session expiration banner on 401s
setAuthErrorHandler((msg) => {
  useAegisStore.getState().logout(msg);
});

/**
 * Global single source of truth for engine liveness.
 * True ONLY when the engine is actively emitting telemetry within the last 5 seconds
 * and isEngineNoData is false.
 */
export const selectIsEngineLive = (state: AegisStoreState): boolean => {
  if (state.isEngineNoData || !state.stats || !state.stats.updated_at_ms) {
    return false;
  }
  return Date.now() - state.stats.updated_at_ms <= 5000;
};

export const useIsEngineLive = (): boolean => {
  return useAegisStore(selectIsEngineLive);
};
