import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Unambiguous local format: "11 Oct 2026, 11:38:51 PM IST" (en-IN, Asia/Kolkata, month as word)
export function formatDateTime(val: string | number | null | undefined): string {
  if (!val || val === 0) return "N/A";
  let d: Date;
  if (typeof val === "number") {
    d = new Date(val > 1e11 ? val : val * 1000);
  } else {
    d = new Date(val);
  }
  if (isNaN(d.getTime())) return String(val);

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
  return formatted.replace(/\b(am|pm)\b/g, (m) => m.toUpperCase());
}

// Bandwidth rate formatting:
// >= 1 Mbps -> Mbps (2 decimals), >= 1 kbps -> kbps (1 decimal), else bps. Never round non-zero to 0.
export function formatBandwidthRate(bps: number): string {
  if (!bps || bps <= 0) return "0 bps";
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
}

// Packet rate formatting: 1 decimal when < 10 pps. Never round non-zero to 0.
export function formatPacketRate(pps: number): string {
  if (!pps || pps <= 0) return "0 pps";
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
}

