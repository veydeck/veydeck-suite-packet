import type {
  BuilderPacket,
  BuilderSchema,
  PacketDetail,
  PacketFilters,
  PacketListResponse,
  PacketPreviewResponse,
  PcapBuildResponse,
  PcapFile,
  StatsData,
  FollowStreamResponse,
} from "./types";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function parseError(response: Response) {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      return body.detail
        .map((item: { msg?: string }) => item.msg)
        .filter(Boolean)
        .join("; ");
    }
  } catch {
    // Ignore JSON parsing failure and fall through to generic message.
  }
  return `Request failed with status ${response.status}`;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(toApiUrl(url), init);
  if (!response.ok) {
    throw new ApiError(await parseError(response), response.status);
  }
  return response.json() as Promise<T>;
}

export function toApiUrl(path: string) {
  if (/^https?:\/\//i.test(path)) return path;
  const base = import.meta.env.BASE_URL || "./";
  const normalizedBase = base.endsWith("/") ? base : `${base}/`;
  return `${normalizedBase}${path.replace(/^\/+/, "")}`;
}

export const packetApi = {
  listPcaps() {
    return requestJson<PcapFile[]>("/api/pcaps");
  },

  uploadPcap(file: File) {
    const form = new FormData();
    form.append("file", file);
    return requestJson<PcapFile>("/api/pcaps", {
      method: "POST",
      body: form,
    });
  },

  deletePcap(pcapId: string) {
    return requestJson<{ message: string }>(`/api/pcaps/${encodeURIComponent(pcapId)}`, {
      method: "DELETE",
    });
  },

  listPackets(pcapId: string, page: number, pageSize: number, filters: PacketFilters) {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (filters.protocol) params.set("protocol", filters.protocol);
    if (filters.srcIp) params.set("src_ip", filters.srcIp);
    if (filters.dstIp) params.set("dst_ip", filters.dstIp);
    if (filters.port) params.set("port", filters.port);
    return requestJson<PacketListResponse>(
      `/api/pcaps/${encodeURIComponent(pcapId)}/packets?${params.toString()}`,
    );
  },

  getPacketDetail(pcapId: string, packetIndex: number) {
    return requestJson<PacketDetail>(
      `/api/pcaps/${encodeURIComponent(pcapId)}/packets/${packetIndex}`,
    );
  },

  getStats(pcapId: string) {
    return requestJson<StatsData>(`/api/pcaps/${encodeURIComponent(pcapId)}/stats`);
  },

  followStream(pcapId: string, packetIndex: number) {
    return requestJson<FollowStreamResponse>(
      `/api/pcaps/${encodeURIComponent(pcapId)}/packets/${packetIndex}/follow-stream`,
    );
  },

  getBuilderSchema() {
    return requestJson<BuilderSchema>("/api/packets/builder/schema");
  },

  previewPacket(layers: BuilderPacket["layers"]) {
    return requestJson<PacketPreviewResponse>("/api/packets/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ layers }),
    });
  },

  buildPcap(filename: string, packets: BuilderPacket[]) {
    return requestJson<PcapBuildResponse>("/api/pcaps/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename,
        packets: packets.map((packet) => ({ layers: packet.layers })),
      }),
    });
  },

  downloadUrl(pcapId: string) {
    return toApiUrl(`/api/pcaps/${encodeURIComponent(pcapId)}/download`);
  },
};
