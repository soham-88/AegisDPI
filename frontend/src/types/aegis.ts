export interface DpiLogEntry {
  id: string;
  stream_id?: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  sni: string;
  action: "FORWARD" | "DROP" | "UNHANDLED";
  reason: string;
  thread_id: number;
  tcp_flags?: number;
  icmp_type?: number;
  l3?: "ipv4" | "arp" | "ipv6" | "other";
}

export interface ProtocolMix {
  name: string;
  count: number;
  percentage: number;
  color: string;
}

export interface ThroughputDataPoint {
  time: string;
  pps: number;
  mbps: number;
  blocked?: number;
}

export interface ThroughputHistoryPoint {
  time: string;
  pps: number;
  blocked: number;
}

export interface ChartSample {
  t: number;
  pps: number;
  dropped_pps: number;
}

export interface SystemStats {
  total_packets: number;
  forwarded: number;
  dropped: number;
  unhandled: number;
  throughput_pps: number;
  throughput_mbps: number;
  throughput_bps?: number;
  dropped_pps?: number;
  q_drops: number;
  interface?: string;
  engine_pid?: number;
  started_at?: number;
  bytes_total?: number;
  pcap_recv?: number;
  pcap_drop?: number;
  pcap_ifdrop?: number;
  updated_at_ms?: number;
  proto_tls?: number;
  proto_http?: number;
  proto_tcp_ctrl?: number;
  proto_tcp_other?: number;
  tls_sni_seen?: number;
  protocols: ProtocolMix[];
  history?: ThroughputDataPoint[];
  threads?: WorkerThreadStats[];
}

export interface WorkerThreadStats {
  thread_id: number;
  name: string;
  role: "LB" | "FAST_PATH";
  packets_processed: number;
  forwarded: number;
  dropped: number;
  unhandled: number;
  load_pct: number;
  pps_history: number[];
}

export interface BlocklistRule {
  ip: string;
  added_at: string;
  added_by: string;
  source?: string;
  reason: string;
}

export interface BlocklistEvent {
  id: string;
  timestamp: string;
  action: "ADD" | "DEL";
  ip: string;
  channel: string;
  raw_payload: string;
}

export interface FeatureContribution {
  name: string;
  value: number;
  baseline: number;
  contribution_pct: number;
}

export interface AnomalyAlert {
  id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  confidence: number;
  verdict: "ANOMALOUS" | "SUSPICIOUS";
  auto_mitigated: boolean;
  description: string;
  features: FeatureContribution[];
  is_simulated?: boolean;
  telegram_alert?: "sent" | "suppressed_cooldown" | "failed" | "disabled" | "attempted" | "not_applicable" | string;
  model_version?: string;
  trigger?: "guard" | "iforest" | "both" | string;
  guard?: Array<{
    feature: string;
    human_name: string;
    raw_value: number;
    normal_max: number;
    limit: number;
    ratio: number;
  }>;
}

export type NavSection =
  | "stats"
  | "packets"
  | "blocklist"
  | "anomalies"
  | "threads"
  | "architecture";

export interface MlStatusResponse {
  online: boolean;
  model_loaded?: boolean;
  model_version?: string;
  model_type?: string;
  n_estimators?: number;
  contamination?: number | string;
  training_sample_count?: number | null;
  trained_at?: string;
  feature_schema?: string[];
  baselines?: Record<string, number>;
  auto_mitigate?: boolean;
  alert_cooldown_s?: number;
  num_local_ips?: number;
  flow_table_size?: number;
  tracked_source_ips?: number;
}

export interface SessionReportData {
  generated_at: string;
  engine: {
    interface: string;
    engine_pid: number;
    started_at: number;
    last_update: number;
    state: "running" | "stopped";
    session_seconds: number;
  };
  traffic: {
    total_inspected: number;
    forwarded: number;
    dropped: number;
    unhandled: number;
    bytes_total: number;
    pcap_recv: number;
    pcap_drop: number;
    pcap_ifdrop: number;
    avg_pps: number;
    avg_mbps: number;
  };
  protocol_mix: {
    classes: Array<{
      name: string;
      count: number;
      percentage: number;
    }>;
    tls_sni_seen: number;
  };
  threads: {
    lbs: Array<{
      thread_id: number;
      name: string;
      dispatched: number;
    }>;
    fps: Array<{
      thread_id: number;
      name: string;
      processed: number;
      forwarded: number;
      dropped: number;
      unhandled: number;
    }>;
    lb_total: number;
    fp_total: number;
  };
  checks: Array<{
    name: string;
    left: number;
    right: number;
    pass?: boolean | null;
    is_info?: boolean;
    diff?: number;
    note?: string;
  }>;
  blocklist: string[];
  anomalies: {
    this_session_count: number;
    total_history_count: number;
    list: Array<{
      time: string;
      src: string;
      dst: string;
      verdict: string;
      confidence: number;
      mitigated: boolean;
      top_feature: string;
      telegram_alert?: string | null;
    }>;
  };
  ml: {
    model_type: string;
    feature_count: number;
    auto_mitigate: boolean;
    threshold: number;
    online: boolean;
  };
}
