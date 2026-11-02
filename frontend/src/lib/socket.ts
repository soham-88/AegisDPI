import { io, Socket } from "socket.io-client";
import { useAegisStore } from "@/hooks/useAegisStore";

export const socket: Socket = io({
  autoConnect: false,
  transports: ["websocket"],
  reconnectionDelay: 1000,
  reconnectionAttempts: 50,
});

let isInitialized = false;

export function initializeSocket(token?: string) {
  const authToken = token || sessionStorage.getItem("aegis_token");
  if (!authToken) {
    console.warn("[SOCKET] No token available, skipping socket connection");
    return;
  }

  socket.auth = { token: authToken };

  if (!isInitialized) {
    isInitialized = true;

    socket.on("connect", () => {
      console.log("[SOCKET] Connected to Aegis DPI middleware:", socket.id);
      useAegisStore.getState().setSocketConnected(true);
      // Re-sync on reconnect: re-fetch /api/anomalies, /api/rules and stats summary
      useAegisStore.getState().fetchAnomalies();
      useAegisStore.getState().fetchBlocklist();
      useAegisStore.getState().fetchStatsSummary();
    });

    socket.on("connect_error", (err) => {
      console.warn("[SOCKET] Connection error:", err.message);
      if (
        err.message &&
        (err.message.includes("Authentication error") ||
          err.message.includes("Session expired") ||
          err.message.includes("token"))
      ) {
        useAegisStore.getState().logout("Session expired - please sign in again");
      }
    });

    socket.on("disconnect", (reason) => {
      console.warn("[SOCKET] Disconnected from Aegis DPI middleware:", reason);
      useAegisStore.getState().setSocketConnected(false);
    });

    // Signal-only event: triggers a GET /api/stats/summary re-fetch
    socket.on("stats:update", () => {
      console.log("[SOCKET] 'stats:update' signal received -> re-fetching /api/stats/summary");
      useAegisStore.getState().fetchStatsSummary();
    });

    // Real-time packet batched relay: prepends batch of up to 200 entries every 250ms
    socket.on("log:batch", (payload: any) => {
      useAegisStore.getState().addLogBatch(payload);
    });

    // Live blocklist changes from middleware
    socket.on("blocklist:changed", (data) => {
      console.log("[SOCKET] 'blocklist:changed' signal received -> re-fetching /api/rules:", data);
      useAegisStore.getState().fetchBlocklist();
    });

    // Backward compatibility for blocklist update channel
    socket.on("blocklist:update", () => {
      useAegisStore.getState().fetchBlocklist();
    });

    // Real-time ML anomaly verdicts
    socket.on("anomaly:new", (verdict) => {
      useAegisStore.getState().addAnomaly(verdict);
    });
  }

  if (!socket.connected) {
    socket.connect();
  }
}

export function disconnectSocket() {
  socket.disconnect();
}
