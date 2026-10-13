export type ToastType = "success" | "error" | "warning" | "info";

export interface ToastItem {
  id: string;
  type: ToastType;
  title: string;
  message: string;
}

export interface PcapFile {
  id: string;
  filename: string;
  original_filename: string;
  file_size: number;
  status: "uploaded" | "parsing" | "parsed" | "failed";
  packet_count: number;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PacketSummary {
  index: number;
  timestamp: number | null;
  length: number;
  protocol: string;
  src_mac?: string | null;
  dst_mac?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  summary: string;
  anomalies?: string | null;
}

export interface PacketLayer {
  name: string;
  fields: Record<string, unknown>;
}

export interface ProtocolInsight {
  protocol: string;
  title: string;
  fields: Record<string, unknown>;
}

export interface PacketDetail {
  index: number;
  summary: string;
  length: number;
  layers: PacketLayer[];
  hex: string;
  protocol_insights: ProtocolInsight[];
}

export interface PacketListResponse {
  items: PacketSummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface StatsData {
  total_packets: number;
  protocol_distribution: Record<string, number>;
  top_src_ips: Array<{ ip: string; count: number }>;
  top_dst_ips: Array<{ ip: string; count: number }>;
  top_dst_ports: Array<{ port: number; count: number }>;
}

export interface LayerSpec {
  name: string;
  fields: Record<string, string>;
}

export interface BuilderFieldOption {
  label: string;
  value: string;
}

export interface BuilderFieldSpec {
  key: string;
  label: string;
  type: "text" | "number" | "select";
  default?: string | null;
  placeholder?: string | null;
  options?: BuilderFieldOption[] | null;
  wide: boolean;
  advanced: boolean;
  auto: boolean;
}

export interface BuilderLayerSpec {
  name: string;
  label: string;
  fields: BuilderFieldSpec[];
}

export interface BuilderSchema {
  layers: BuilderLayerSpec[];
}

export interface BuilderPacket {
  layers: LayerSpec[];
  summary: string;
}

export interface PacketPreviewResponse {
  summary: string;
  layers: PacketLayer[];
  hex: string;
  warnings: string[];
}

export interface PcapBuildResponse {
  pcap_id: string;
  download_url: string;
}

export interface PacketFilters {
  protocol: string;
  srcIp: string;
  dstIp: string;
  port: string;
}

export interface StreamChunk {
  direction: "client" | "server";
  packet_index: number;
  start_packet_index: number;
  end_packet_index: number;
  byte_count: number;
  data: string;
}

export interface FollowStreamResponse {
  protocol: string;
  client_ip: string;
  server_ip: string;
  client_port: number;
  server_port: number;
  packet_count: number;
  byte_count: number;
  chunks: StreamChunk[];
}
