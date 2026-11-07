import {
  SystemStats,
  BlocklistRule,
  BlocklistEvent,
  AllowlistEntry,
  AuditLogEntry,
  WorkerThreadStats,
  AnomalyAlert,
  MlStatusResponse,
  SessionReportData,
} from "@/types/aegis";

const API_BASE_URL = import.meta.env.VITE_API_URL || "";

type AuthErrorHandler = (message: string) => void;
let authErrorHandler: AuthErrorHandler | null = null;

export function setAuthErrorHandler(handler: AuthErrorHandler | null) {
  authErrorHandler = handler;
}

export function getAuthToken(): string | null {
  return sessionStorage.getItem("aegis_token");
}

export function setAuthToken(token: string, username?: string) {
  sessionStorage.setItem("aegis_token", token);
  if (username) {
    sessionStorage.setItem("aegis_user", username);
  }
}

export function clearAuthToken() {
  sessionStorage.removeItem("aegis_token");
  sessionStorage.removeItem("aegis_user");
}

async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(url, { ...init, headers });
  if (res.status === 401) {
    clearAuthToken();
    if (authErrorHandler) {
      authErrorHandler("Session expired - please sign in again");
    }
    throw new Error("Session expired - please sign in again");
  }
  return res;
}

/**
 * API service for Aegis DPI middleware.
 */
export const api = {
  async login(username: string, password: string): Promise<{ token: string; username: string; role?: string }> {
    const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      if (res.status === 429) {
        throw new Error("Too many failed attempts - wait 60 seconds");
      }
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || "Invalid credentials");
    }
    const data = await res.json();
    setAuthToken(data.token, data.username || username);
    return data;
  },

  async logout(username?: string): Promise<void> {
    try {
      await authFetch(`${API_BASE_URL}/api/auth/logout`, {
        method: "POST",
        body: JSON.stringify({ username }),
      });
    } catch (e) {
      // Ignore network errors during logout
    } finally {
      clearAuthToken();
    }
  },

  async getStatsSummary(): Promise<SystemStats> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/stats/summary`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const forwarded = Number(data.forwarded) || 0;
      const dropped = Number(data.dropped) || 0;
      const unhandled = Number(data.unhandled) || 0;
      const total = forwarded + dropped + unhandled;

      return {
        total_packets: total,
        forwarded,
        dropped,
        unhandled,
        throughput_pps: 0,
        throughput_mbps: 0,
        q_drops: 0,
        interface: data.interface || "offline",
        engine_pid: Number(data.engine_pid) || 0,
        started_at: Number(data.started_at) || 0,
        bytes_total: Number(data.bytes_total) || 0,
        pcap_recv: Number(data.pcap_recv) || 0,
        pcap_drop: Number(data.pcap_drop) || 0,
        pcap_ifdrop: Number(data.pcap_ifdrop) || 0,
        updated_at_ms: Number(data.updated_at_ms) || 0,
        proto_tls: Number(data.proto_tls) || 0,
        proto_http: Number(data.proto_http) || 0,
        proto_tcp_ctrl: Number(data.proto_tcp_ctrl) || 0,
        proto_tcp_other: Number(data.proto_tcp_other) || 0,
        tls_sni_seen: Number(data.tls_sni_seen) || 0,
        protocols: [
          {
            name: "TLS records",
            count: Number(data.proto_tls) || 0,
            percentage: total > 0 ? +(((Number(data.proto_tls) || 0) / total) * 100).toFixed(1) : 0,
            color: "#2fb8a6",
          },
          {
            name: "HTTP",
            count: Number(data.proto_http) || 0,
            percentage: total > 0 ? +(((Number(data.proto_http) || 0) / total) * 100).toFixed(1) : 0,
            color: "#38bdf8",
          },
          {
            name: "TCP control (no payload)",
            count: Number(data.proto_tcp_ctrl) || 0,
            percentage: total > 0 ? +(((Number(data.proto_tcp_ctrl) || 0) / total) * 100).toFixed(1) : 0,
            color: "#818cf8",
          },
          {
            name: "TCP other payload",
            count: Number(data.proto_tcp_other) || 0,
            percentage: total > 0 ? +(((Number(data.proto_tcp_other) || 0) / total) * 100).toFixed(1) : 0,
            color: "#c084fc",
          },
          {
            name: "Non-TCP",
            count: unhandled,
            percentage: total > 0 ? +((unhandled / total) * 100).toFixed(1) : 0,
            color: "#8b9ac6",
          },
        ],
        threads: Array.isArray(data.threads) ? data.threads : [],
      };
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
      return {
        total_packets: 0,
        forwarded: 0,
        dropped: 0,
        unhandled: 0,
        throughput_pps: 0,
        throughput_mbps: 0,
        q_drops: 0,
        interface: "offline",
        engine_pid: 0,
        started_at: 0,
        bytes_total: 0,
        pcap_recv: 0,
        pcap_drop: 0,
        pcap_ifdrop: 0,
        updated_at_ms: 0,
        proto_tls: 0,
        proto_http: 0,
        proto_tcp_ctrl: 0,
        proto_tcp_other: 0,
        tls_sni_seen: 0,
        protocols: [
          { name: "TLS records", count: 0, percentage: 0, color: "#2fb8a6" },
          { name: "HTTP", count: 0, percentage: 0, color: "#38bdf8" },
          { name: "TCP control", count: 0, percentage: 0, color: "#818cf8" },
          { name: "TCP other", count: 0, percentage: 0, color: "#c084fc" },
          { name: "Non-TCP", count: 0, percentage: 0, color: "#8b9ac6" },
        ],
        threads: [],
      };
    }
  },

  async getRecentLogs(limit = 200): Promise<any[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/logs?limit=${limit}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
      return [];
    }
  },

  async getBlocklist(): Promise<BlocklistRule[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/rules`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const ips: string[] = Array.isArray(data.ips) ? data.ips : [];
      const meta: Record<string, any> = data.meta || {};

      return ips.map((ip) => {
        const item = meta[ip];
        return {
          ip,
          added_at: item?.added_at || new Date().toISOString(),
          added_by: item?.added_by || "admin",
          source: item?.source,
          reason: item?.reason || "Active block rule",
          ttl_s: item?.ttl_s !== undefined ? item.ttl_s : null,
          expires_at: item?.expires_at || null,
          strikes_24h: item?.strikes_24h || 0,
        };
      });
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
      return [];
    }
  },

  async addBlocklistRule(
    ip: string,
    reason = "Manual Admin Block",
    source = "manual",
    ttl_s: number | null = null
  ): Promise<{ success: boolean; event: BlocklistEvent }> {
    const payload: any = {
      type: "ip",
      value: ip,
      reason,
      source,
    };
    if (ttl_s !== null && ttl_s !== undefined && ttl_s > 0) {
      payload.ttl_s = ttl_s;
    }

    const res = await authFetch(`${API_BASE_URL}/api/rules`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const iso = new Date().toISOString();
    return {
      success: true,
      event: {
        id: `evt_${Date.now()}`,
        timestamp: iso,
        action: "ADD",
        ip,
        channel: "blocklist:updates",
        raw_payload: `ADD IP ${ip}`,
      },
    };
  },

  async getAllowlist(): Promise<AllowlistEntry[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/allowlist`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return Array.isArray(data.entries) ? data.entries : [];
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
      return [];
    }
  },

  async addAllowlistEntry(entry: string, note = ""): Promise<{ success: boolean; entry?: AllowlistEntry }> {
    const res = await authFetch(`${API_BASE_URL}/api/allowlist`, {
      method: "POST",
      body: JSON.stringify({ entry, note }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async removeAllowlistEntry(entry: string): Promise<{ success: boolean }> {
    const res = await authFetch(`${API_BASE_URL}/api/allowlist`, {
      method: "DELETE",
      body: JSON.stringify({ entry }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async getAuditLog(limit = 200): Promise<AuditLogEntry[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/audit?limit=${limit}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return Array.isArray(data.audit) ? data.audit : [];
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
      return [];
    }
  },

  async removeBlocklistRule(ip: string): Promise<{ success: boolean; event: BlocklistEvent }> {
    const res = await authFetch(`${API_BASE_URL}/api/rules`, {
      method: "DELETE",
      body: JSON.stringify({
        type: "ip",
        value: ip,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const iso = new Date().toISOString();
    return {
      success: true,
      event: {
        id: `evt_${Date.now()}`,
        timestamp: iso,
        action: "DEL",
        ip,
        channel: "blocklist:updates",
        raw_payload: `DEL IP ${ip}`,
      },
    };
  },

  async getThreads(): Promise<WorkerThreadStats[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/threads`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (Array.isArray(data)) {
        return data.map((t) => ({
          thread_id: Number(t.thread_id) || 0,
          name: t.name || `Thread-${t.thread_id}`,
          role: t.role === "LB" ? "LB" : "FAST_PATH",
          packets_processed: Number(t.packets_processed) || 0,
          forwarded: Number(t.forwarded) || 0,
          dropped: Number(t.dropped) || 0,
          unhandled: Number(t.unhandled) || 0,
          load_pct: 0,
          pps_history: Array.isArray(t.pps_history) ? t.pps_history : [],
        }));
      }
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
    }
    return [];
  },

  async getAnomalies(limit = 100): Promise<AnomalyAlert[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/anomalies?limit=${limit}`);
      if (res.ok) {
        return await res.json();
      }
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
    }
    return [];
  },

  async getMlStatus(): Promise<MlStatusResponse> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/ml/status`);
      if (res.ok) {
        return await res.json();
      }
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
    }
    return { online: false };
  },

  async getCaptureInterfaces(): Promise<{ name: string; ip: string }[]> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/capture/interfaces`);
      if (res.ok) return await res.json();
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
    }
    return [];
  },

  async getCaptureStatus(): Promise<any> {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/capture/status`);
      if (res.ok) return await res.json();
    } catch (err: any) {
      if (err.message === "Session expired - please sign in again") throw err;
    }
    return null;
  },

  async startCapture(iface: string): Promise<any> {
    const res = await authFetch(`${API_BASE_URL}/api/capture/start`, {
      method: "POST",
      body: JSON.stringify({ interface: iface }),
    });
    return await res.json();
  },

  async stopCapture(): Promise<any> {
    const res = await authFetch(`${API_BASE_URL}/api/capture/stop`, {
      method: "POST",
    });
    return await res.json();
  },

  async getSessionReport(): Promise<SessionReportData> {
    const res = await authFetch(`${API_BASE_URL}/api/report`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  },
};
