import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { VeyGlassProvider, VeyModal, VeyTabs, VeyToast } from "@veydeck/react";
import { packetApi, toApiUrl } from "./api";
import { BuilderPanel } from "./components/BuilderPanel";
import { PacketDetailDrawer } from "./components/PacketDetailDrawer";
import { PcapExplorer } from "./components/PcapExplorer";
import { StatsDialog } from "./components/StatsDialog";
import { FollowStreamDialog } from "./components/FollowStreamDialog";
import { useToasts } from "./hooks/useToasts";
import { useLocale } from "./i18n";
import { suiteBridge } from "./suiteBridge";
import type {
  BuilderPacket,
  BuilderLayerSpec,
  LayerSpec,
  PacketDetail,
  PacketFilters,
  PacketPreviewResponse,
  PacketSummary,
  PcapFile,
  StatsData,
  FollowStreamResponse,
} from "./types";

const pageSize = 50;

const tcpSynLayers: LayerSpec[] = [
  { name: "Ether", fields: { src: "", dst: "" } },
  {
    name: "IP",
    fields: { src: "192.168.1.10", dst: "192.168.1.20", ttl: "64" },
  },
  { name: "TCP", fields: { sport: "12345", dport: "80", flags: "S" } },
];

function triggerDownload(url: string, filename: string) {
  const downloadName = filename.toLowerCase().endsWith(".pcap")
    ? filename
    : `${filename}.pcap`;
  const link = document.createElement("a");
  link.href = url;
  link.download = downloadName;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

const defaultFields: Record<string, Record<string, string>> = {
  Ether: { src: "", dst: "" },
  IP: { src: "192.168.1.10", dst: "192.168.1.20", ttl: "64" },
  IPv6: { src: "", dst: "" },
  TCP: { sport: "12345", dport: "80", flags: "S" },
  UDP: { sport: "12345", dport: "53" },
  ICMP: { type: "8", code: "0", id: "1", seq: "1" },
  DNS: { id: "4660", qr: "0", rd: "1" },
  DNSQR: { qname: "example.com", qtype: "A" },
  Raw: { load: "Hello Packet!" },
};

const arpOpDefaults: Record<string, Record<string, string>> = {
  "who-has": {
    op: "who-has",
    hwsrc: "00:11:22:33:44:55",
    hwdst: "00:00:00:00:00:00",
    psrc: "192.168.1.10",
    pdst: "192.168.1.1",
  },
  "is-at": {
    op: "is-at",
    hwsrc: "66:77:88:99:aa:bb",
    hwdst: "00:11:22:33:44:55",
    psrc: "192.168.1.1",
    pdst: "192.168.1.10",
  },
};

const httpRequestLayers: LayerSpec[] = [
  { name: "Ether", fields: { src: "", dst: "" } },
  {
    name: "IP",
    fields: { src: "192.168.1.10", dst: "93.184.216.34", ttl: "64" },
  },
  {
    name: "TCP",
    fields: { sport: "49152", dport: "80", flags: "PA", seq: "1" },
  },
  {
    name: "Raw",
    fields: {
      load: "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Veydeck-Packet/0.1.0-alpha.1\\r\\nAccept: */*\\r\\nConnection: close\\r\\n\\r\\n",
    },
  },
];

const httpResponseLayers: LayerSpec[] = [
  { name: "Ether", fields: { src: "", dst: "" } },
  {
    name: "IP",
    fields: { src: "93.184.216.34", dst: "192.168.1.10", ttl: "64" },
  },
  {
    name: "TCP",
    fields: { sport: "80", dport: "49152", flags: "PA", seq: "1", ack: "1" },
  },
  {
    name: "Raw",
    fields: {
      load: 'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: 34\\r\\nConnection: close\\r\\n\\r\\n{"status":"ok","source":"veydeck"}',
    },
  },
];

const templates: Record<string, LayerSpec[]> = {
  tcp_syn: tcpSynLayers,
  udp_dns: [
    { name: "Ether", fields: { src: "", dst: "" } },
    { name: "IP", fields: { src: "192.168.1.10", dst: "8.8.8.8", ttl: "128" } },
    { name: "UDP", fields: { sport: "51234", dport: "53" } },
    { name: "DNS", fields: { id: "1234", qr: "0", rd: "1" } },
    { name: "DNSQR", fields: { qname: "example.com", qtype: "A" } },
  ],
  dns_aaaa: [
    { name: "Ether", fields: { src: "", dst: "" } },
    { name: "IP", fields: { src: "192.168.1.10", dst: "8.8.8.8", ttl: "128" } },
    { name: "UDP", fields: { sport: "51234", dport: "53" } },
    { name: "DNS", fields: { id: "1234", qr: "0", rd: "1" } },
    { name: "DNSQR", fields: { qname: "example.com", qtype: "AAAA" } },
  ],
  icmp_ping: [
    { name: "Ether", fields: { src: "", dst: "" } },
    {
      name: "IP",
      fields: { src: "192.168.1.10", dst: "192.168.1.1", ttl: "64" },
    },
    { name: "ICMP", fields: { type: "8", code: "0", id: "1", seq: "1" } },
    { name: "Raw", fields: { load: "PING_REQUEST" } },
  ],
  http_request: httpRequestLayers,
  http_response: httpResponseLayers,
  tls_client_hello: [
    { name: "Ether", fields: { src: "", dst: "" } },
    {
      name: "IP",
      fields: { src: "192.168.1.10", dst: "104.244.42.1", ttl: "64" },
    },
    {
      name: "TCP",
      fields: { sport: "49152", dport: "443", flags: "PA", seq: "1" },
    },
    {
      name: "Raw",
      fields: {
        load: "\\x16\\x03\\x01\\x00\\xba\\x01\\x00\\x00\\xb6\\x03\\x03\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x00\\x00\\x1a\\xc0\\x2b\\xc0\\x2f\\xc0\\x0a\\xc0\\x09\\xc0\\x13\\xc0\\x14\\x00\\x9c\\x00\\x9d\\x00\\x2f\\x00\\x35\\x00\\x0a\\x01\\x00\\x00\\x73\\x00\\x00\\x00\\x0e\\x00\\x0c\\x00\\x00\\x09\\x6c\\x6f\\x63\\x61\\x6c\\x68\\x6f\\x73\\x74\\x00\\x0b\\x00\\x04\\x03\\x00\\x01\\x02\\x00\\x0a\\x00\\x0c\\x00\\x0a\\x00\\x1d\\x00\\x17\\x00\\x18\\x00\\x19\\x00\\x1e\\x00\\x23\\x00\\x00\\x00\\x16\\x00\\x00\\x00\\x17\\x00\\x00\\x00\\x0d\\x00\\x1e\\x00\\x1c\\x04\\x03\\x05\\x03\\x06\\x03\\x08\\x07\\x08\\x08\\x08\\x09\\x08\\x0a\\x08\\x0b\\x08\\x04\\x08\\x05\\x08\\x06\\x04\\x01\\x05\\x01\\x06\\x01\\x03\\x01\\x00\\x2b\\x00\\x03\\x02\\x03\\x04",
      },
    },
  ],
};

const layerNameMap: Record<string, string> = {
  Ethernet: "Ether",
  "802.1Q": "Dot1Q",
  ARP: "ARP",
  IP: "IP",
  IPv6: "IPv6",
  TCP: "TCP",
  UDP: "UDP",
  ICMP: "ICMP",
  DNS: "DNS",
  "DNS Question Record": "DNSQR",
  Raw: "Raw",
};

const allowedFields: Record<string, string[]> = {
  Ether: ["src", "dst"],
  Dot1Q: ["vlan", "prio", "type"],
  ARP: ["op", "hwsrc", "hwdst", "psrc", "pdst"],
  IP: ["src", "dst", "ttl"],
  IPv6: ["src", "dst"],
  TCP: ["sport", "dport", "flags", "seq", "ack"],
  UDP: ["sport", "dport"],
  ICMP: ["type", "code", "id", "seq"],
  DNS: ["id", "qr", "rd"],
  DNSQR: ["qname", "qtype"],
  Raw: ["load"],
};

const arpOpAliases: Record<string, string> = {
  "1": "who-has",
  "who-has": "who-has",
  "2": "is-at",
  "is-at": "is-at",
};

const dnsQtypeAliases: Record<string, string> = {
  "1": "A",
  A: "A",
  "5": "CNAME",
  CNAME: "CNAME",
  "15": "MX",
  MX: "MX",
  "16": "TXT",
  TXT: "TXT",
  "28": "AAAA",
  AAAA: "AAAA",
};

const tcpFlagsByBit: Array<[number, string]> = [
  [0x01, "F"],
  [0x02, "S"],
  [0x04, "R"],
  [0x08, "P"],
  [0x10, "A"],
  [0x20, "U"],
  [0x40, "E"],
  [0x80, "C"],
];

function normalizeTcpFlags(value: string) {
  const numeric = Number(value);
  if (!Number.isInteger(numeric)) return value;
  const flags = tcpFlagsByBit
    .filter(([bit]) => (numeric & bit) !== 0)
    .map(([, flag]) => flag)
    .join("");
  return flags || "";
}

function normalizeBuilderField(
  layerName: string,
  field: string,
  value: unknown,
) {
  const text = String(value);
  if (layerName === "ARP" && field === "op") {
    return arpOpAliases[text] ?? text;
  }
  if (layerName === "DNSQR" && field === "qtype") {
    return dnsQtypeAliases[text.toUpperCase()] ?? text;
  }
  if (layerName === "TCP" && field === "flags") {
    return normalizeTcpFlags(text);
  }
  return text;
}

function bytesToEscapedString(bytes: number[]): string {
  return bytes
    .map((byte) => {
      if (byte === 9) return "\\t";
      if (byte === 10) return "\\n";
      if (byte === 13) return "\\r";
      if (byte === 92) return "\\\\";
      if (byte >= 32 && byte < 127) return String.fromCharCode(byte);
      return `\\x${byte.toString(16).padStart(2, "0")}`;
    })
    .join("");
}

function hexToBytes(hex: string): number[] {
  const normalized = hex.replace(/[^0-9a-f]/gi, "");
  const bytes: number[] = [];
  for (let i = 0; i + 1 < normalized.length; i += 2) {
    bytes.push(parseInt(normalized.slice(i, i + 2), 16));
  }
  return bytes;
}

function numberField(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function extractTransportPayload(detail: PacketDetail): string | null {
  const bytes = hexToBytes(detail.hex);
  if (bytes.length === 0) return null;

  let offset = 0;
  if (detail.layers[0]?.name === "Ethernet") {
    offset += 14;
  }

  for (const layer of detail.layers) {
    if (layer.name === "802.1Q") {
      offset += 4;
    }
  }

  const networkOffset = offset;
  let packetEnd = bytes.length;
  const ipLayer = detail.layers.find((layer) => layer.name === "IP");
  const ipv6Layer = detail.layers.find((layer) => layer.name === "IPv6");
  if (ipLayer) {
    const ipTotalLength = numberField(ipLayer.fields.len);
    if (ipTotalLength !== null) {
      packetEnd = Math.min(packetEnd, networkOffset + ipTotalLength);
    }
    offset += (numberField(ipLayer.fields.ihl) ?? 5) * 4;
  } else if (ipv6Layer) {
    const ipv6PayloadLength = numberField(ipv6Layer.fields.plen);
    if (ipv6PayloadLength !== null) {
      packetEnd = Math.min(packetEnd, networkOffset + 40 + ipv6PayloadLength);
    }
    offset += 40;
  } else {
    return null;
  }

  const tcpLayer = detail.layers.find((layer) => layer.name === "TCP");
  const udpLayer = detail.layers.find((layer) => layer.name === "UDP");
  if (tcpLayer) {
    offset += (numberField(tcpLayer.fields.dataofs) ?? 5) * 4;
  } else if (udpLayer) {
    offset += 8;
  } else {
    return null;
  }

  if (offset >= packetEnd) return null;
  return bytesToEscapedString(bytes.slice(offset, packetEnd));
}

function mapDetailToBuilderLayers(detail: PacketDetail): {
  layers: LayerSpec[];
  skippedLayers: string[];
} {
  const skippedLayers: string[] = [];
  const mapped = detail.layers
    .map((dl) => {
      const name = layerNameMap[dl.name] || dl.name;
      if (!allowedFields[name]) {
        skippedLayers.push(dl.name);
        return null;
      }

      const fields: Record<string, string> = {};
      const fieldsToKeep = allowedFields[name];
      for (const field of fieldsToKeep) {
        if (dl.fields[field] !== undefined && dl.fields[field] !== null) {
          fields[field] = normalizeBuilderField(name, field, dl.fields[field]);
        }
      }
      return { name, fields };
    })
    .filter(Boolean) as LayerSpec[];

  const hasRawPayload = mapped.some(
    (layer) => layer.name === "Raw" && layer.fields.load,
  );
  if (!hasRawPayload) {
    const payload = extractTransportPayload(detail);
    if (payload) {
      mapped.push({ name: "Raw", fields: { load: payload } });
    }
  }

  return { layers: mapped, skippedLayers };
}

function cloneLayers(layers: LayerSpec[]) {
  return layers.map((layer) => ({
    name: layer.name,
    fields: { ...layer.fields },
  }));
}

function defaultFieldsForLayer(schema: BuilderLayerSpec[], layerName: string) {
  if (layerName === "ARP") return { ...arpOpDefaults["who-has"] };

  const layer = schema.find((item) => item.name === layerName);
  if (!layer) return { ...(defaultFields[layerName] ?? {}) };

  const fields: Record<string, string> = {};
  for (const field of layer.fields) {
    if (field.default) {
      fields[field.key] = field.default;
    }
  }
  return fields;
}

export default function App() {
  const { dict, t } = useLocale();
  const { toasts, addToast, removeToast } = useToasts();
  const [suiteTheme, setSuiteTheme] = useState(() =>
    suiteBridge.getThemeSnapshot(),
  );

  const [activeTab, setActiveTab] = useState("pcaps");
  const [pcaps, setPcaps] = useState<PcapFile[]>([]);
  const [loadingPcaps, setLoadingPcaps] = useState(false);
  const [pcapListError, setPcapListError] = useState<string | null>(null);
  // 主控导入入口只在首次成功加载列表时消费，后续刷新保留用户选择。
  const pendingImportedPcap = useRef(
    new URLSearchParams(window.location.search).get("pcapId"),
  );
  const [selectedPcap, setSelectedPcap] = useState<PcapFile | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [deletePcapId, setDeletePcapId] = useState<string | null>(null);

  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [loadingPackets, setLoadingPackets] = useState(false);
  const [totalPackets, setTotalPackets] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<PacketFilters>({
    protocol: "",
    srcIp: "",
    dstIp: "",
    port: "",
  });

  const [packetDetail, setPacketDetail] = useState<PacketDetail | null>(null);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number | null>(
    null,
  );
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailVisible, setDetailVisible] = useState(false);

  const [stats, setStats] = useState<StatsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [statsVisible, setStatsVisible] = useState(false);

  const [builderLayers, setBuilderLayers] = useState<LayerSpec[]>([]);
  const [builderSchema, setBuilderSchema] = useState<BuilderLayerSpec[]>([]);
  const [builderPackets, setBuilderPackets] = useState<BuilderPacket[]>([]);
  const [editingPacketIndex, setEditingPacketIndex] = useState<number | null>(
    null,
  );
  const [selectedTemplate, setSelectedTemplate] = useState("");
  const [preview, setPreview] = useState<PacketPreviewResponse | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [outputFilename, setOutputFilename] = useState("generated.pcap");
  const [buildingPcap, setBuildingPcap] = useState(false);
  const [exportVisible, setExportVisible] = useState(false);

  const [streamVisible, setStreamVisible] = useState(false);
  const [streamLoading, setStreamLoading] = useState(false);
  const [streamData, setStreamData] = useState<FollowStreamResponse | null>(
    null,
  );
  const [streamProto, setStreamProto] = useState("TCP");

  useEffect(
    () =>
      suiteBridge.subscribeTheme((theme) => {
        setSuiteTheme(theme);
      }),
    [],
  );

  const fetchPcaps = useCallback(async () => {
    setLoadingPcaps(true);
    try {
      const data = await packetApi.listPcaps();
      setPcaps(data);
      setPcapListError(null);
      const importedPcap = data.find(
        (pcap) => pcap.id === pendingImportedPcap.current,
      );
      if (importedPcap) {
        pendingImportedPcap.current = null;
        setSelectedPcap(importedPcap);
        setActiveTab("pcaps");
        setPage(1);
      } else {
        setSelectedPcap((current) => {
          if (!current) return current;
          return data.find((pcap) => pcap.id === current.id) ?? null;
        });
      }
    } catch (error) {
      setPcapListError((error as Error).message);
    } finally {
      setLoadingPcaps(false);
    }
  }, []);

  useEffect(() => {
    void fetchPcaps();
  }, [fetchPcaps]);

  useEffect(() => {
    if (
      !pcaps.some(
        (pcap) => pcap.status === "uploaded" || pcap.status === "parsing",
      )
    )
      return;
    const timer = window.setInterval(() => void fetchPcaps(), 2000);
    return () => window.clearInterval(timer);
  }, [fetchPcaps, pcaps]);

  const fetchPackets = useCallback(async () => {
    if (!selectedPcap || selectedPcap.status !== "parsed") {
      setPackets([]);
      setTotalPackets(0);
      return;
    }

    setLoadingPackets(true);
    try {
      const data = await packetApi.listPackets(
        selectedPcap.id,
        page,
        pageSize,
        filters,
      );
      setPackets(data.items);
      setTotalPackets(data.total);
    } catch (error) {
      addToast("error", dict.pcaps.uploadFailed, (error as Error).message);
    } finally {
      setLoadingPackets(false);
    }
  }, [addToast, dict.pcaps.uploadFailed, filters, page, selectedPcap]);

  useEffect(() => {
    void fetchPackets();
  }, [fetchPackets]);

  useEffect(() => {
    let cancelled = false;
    async function fetchBuilderSchema() {
      try {
        const schema = await packetApi.getBuilderSchema();
        if (!cancelled) setBuilderSchema(schema.layers);
      } catch (error) {
        addToast("error", dict.builder.invalid, (error as Error).message);
      }
    }

    void fetchBuilderSchema();
    return () => {
      cancelled = true;
    };
  }, [addToast, dict.builder.invalid]);

  useEffect(() => {
    if (activeTab !== "builder") return;
    if (builderLayers.length === 0) {
      setPreview(null);
      setPreviewError(null);
      setPreviewLoading(false);
      return;
    }

    const timer = window.setTimeout(async () => {
      setPreviewLoading(true);
      setPreviewError(null);
      try {
        setPreview(await packetApi.previewPacket(builderLayers));
      } catch (error) {
        setPreview(null);
        setPreviewError((error as Error).message);
      } finally {
        setPreviewLoading(false);
      }
    }, 350);

    return () => window.clearTimeout(timer);
  }, [activeTab, builderLayers]);

  const uploadPcap = async (file: File) => {
    setUploading(true);
    setUploadError(null);
    try {
      const uploaded = await packetApi.uploadPcap(file);
      setPcaps((current) => [uploaded, ...current]);
      setSelectedPcap(uploaded);
      setPage(1);
      addToast("success", dict.pcaps.uploadedOk, dict.pcaps.uploadedMsg);
    } catch (error) {
      const message = (error as Error).message;
      setUploadError(message);
      addToast("error", dict.pcaps.uploadFailed, message);
    } finally {
      setUploading(false);
    }
  };

  const confirmDeletePcap = async () => {
    if (!deletePcapId) return;
    try {
      await packetApi.deletePcap(deletePcapId);
      setPcaps((current) => current.filter((pcap) => pcap.id !== deletePcapId));
      if (selectedPcap?.id === deletePcapId) {
        setSelectedPcap(null);
        setPackets([]);
        setTotalPackets(0);
      }
      addToast("success", dict.pcaps.deleteOk, dict.pcaps.deleteMsg);
    } catch (error) {
      addToast("error", dict.pcaps.deleteTitle, (error as Error).message);
    } finally {
      setDeletePcapId(null);
    }
  };

  const openPacketDetail = async (packetIndex: number) => {
    if (!selectedPcap) return;
    setSelectedPacketIndex(packetIndex);
    setPacketDetail(null);
    setLoadingDetail(true);
    setDetailVisible(true);
    try {
      setPacketDetail(
        await packetApi.getPacketDetail(selectedPcap.id, packetIndex),
      );
    } catch (error) {
      addToast(
        "error",
        dict.detail.title.replace("{index}", String(packetIndex)),
        (error as Error).message,
      );
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleSendToBuilder = (detail: PacketDetail) => {
    try {
      const { layers, skippedLayers } = mapDetailToBuilderLayers(detail);
      setBuilderLayers(layers);
      setEditingPacketIndex(null);
      setActiveTab("builder");
      setDetailVisible(false);
      addToast("success", dict.actions.sendToBuilder, dict.builder.savedMsg);
      if (skippedLayers.length > 0) {
        addToast(
          "warning",
          dict.actions.sendToBuilder,
          `${dict.builder.skippedLayers} ${[...new Set(skippedLayers)].join(", ")}`,
        );
      }
    } catch (error) {
      addToast("error", dict.builder.invalid, (error as Error).message);
    }
  };

  const handleFollowStream = async (packetIndex: number) => {
    if (!selectedPcap) return;
    const pkt = packets.find((p) => p.index === packetIndex);
    const proto = (pkt?.protocol || "TCP").toUpperCase();
    setStreamProto(proto);
    setStreamVisible(true);
    setStreamLoading(true);
    setStreamData(null);
    try {
      const data = await packetApi.followStream(selectedPcap.id, packetIndex);
      setStreamData(data);
    } catch (error) {
      addToast("error", dict.actions.followStream, (error as Error).message);
      setStreamVisible(false);
    } finally {
      setStreamLoading(false);
    }
  };

  const openStats = async () => {
    if (!selectedPcap) return;
    setStatsVisible(true);
    setLoadingStats(true);
    try {
      setStats(await packetApi.getStats(selectedPcap.id));
    } catch (error) {
      addToast("error", dict.stats.title, (error as Error).message);
    } finally {
      setLoadingStats(false);
    }
  };

  const addLayer = (name: string) => {
    setBuilderLayers((current) => [
      ...current,
      { name, fields: defaultFieldsForLayer(builderSchema, name) },
    ]);
  };

  const updateLayerField = (layerIndex: number, key: string, value: string) => {
    setBuilderLayers((current) =>
      current.map((layer, index) => {
        if (index !== layerIndex) return layer;
        if (layer.name === "ARP" && key === "op" && arpOpDefaults[value]) {
          return { ...layer, fields: { ...arpOpDefaults[value] } };
        }
        return { ...layer, fields: { ...layer.fields, [key]: value } };
      }),
    );
  };

  const saveBuilderPacket = () => {
    if (!preview || previewError) {
      addToast("error", dict.builder.invalid, dict.builder.invalidMsg);
      return;
    }

    const packet = {
      layers: cloneLayers(builderLayers),
      summary: preview.summary,
    };
    if (editingPacketIndex === null) {
      setBuilderPackets((current) => [...current, packet]);
      addToast("success", dict.builder.saved, dict.builder.savedMsg);
    } else {
      setBuilderPackets((current) =>
        current.map((item, index) =>
          index === editingPacketIndex ? packet : item,
        ),
      );
      setEditingPacketIndex(null);
      addToast("success", dict.builder.updated, dict.builder.updatedMsg);
    }

    setBuilderLayers([]);
    setSelectedTemplate("");
  };

  const copyBuilderPacket = (index: number) => {
    setBuilderPackets((current) => {
      const packet = current[index];
      if (!packet) return current;
      const next = [...current];
      next.splice(index + 1, 0, {
        summary: packet.summary,
        layers: cloneLayers(packet.layers),
      });
      return next;
    });
  };

  const moveBuilderPacket = (index: number, direction: -1 | 1) => {
    setBuilderPackets((current) => {
      const target = index + direction;
      if (target < 0 || target >= current.length) return current;
      const next = [...current];
      const [packet] = next.splice(index, 1);
      next.splice(target, 0, packet);
      return next;
    });
  };

  const compilePcap = async () => {
    if (builderPackets.length === 0) {
      addToast("warning", dict.builder.emptyList, dict.builder.emptyListMsg);
      return;
    }

    setExportVisible(false);
    setBuildingPcap(true);
    try {
      const result = await packetApi.buildPcap(outputFilename, builderPackets);
      triggerDownload(
        toApiUrl(result.download_url),
        outputFilename || "generated.pcap",
      );
      addToast("success", dict.builder.buildOk, outputFilename);
    } catch (error) {
      addToast("error", dict.builder.buildFailed, (error as Error).message);
    } finally {
      setBuildingPcap(false);
    }
  };

  const handleTabChange = (name: string) => {
    setActiveTab(name);
    if (name === "pcaps") {
      void fetchPcaps();
    }
  };

  const pcapLabels = useMemo(
    () => ({
      refresh: dict.actions.refresh,
      upload: dict.actions.upload,
      reset: dict.actions.reset,
      stats: dict.actions.stats,
      downloadRaw: dict.actions.downloadRaw,
      delete: dict.actions.delete,
      uploaded: dict.pcaps.uploaded,
      empty: dict.pcaps.empty,
      select: dict.pcaps.select,
      loadingList: dict.pcaps.loadingList,
      listLoadFailed: dict.pcaps.listLoadFailed,
      loadingPackets: dict.pcaps.loadingPackets,
      uploading: dict.pcaps.uploading,
      status: dict.pcaps.status,
      meta: dict.pcaps.meta,
      protocol: dict.filters.protocol,
      allProtocols: dict.filters.allProtocols,
      srcIp: dict.filters.srcIp,
      dstIp: dict.filters.dstIp,
      port: dict.filters.port,
      table: dict.table,
    }),
    [dict],
  );

  return (
    <VeyGlassProvider glass={suiteTheme.glassEnabled}>
      <div className="view-shell" data-page="packet-suite">
        <div className="view-toolbar" data-ui="toolbar">
          <div className="toolbar-left">
            <VeyTabs
              value={activeTab}
              onChange={handleTabChange}
              tabs={[
                { name: "pcaps", label: dict.tabs.pcaps },
                { name: "builder", label: dict.tabs.builder },
              ]}
            />
          </div>
        </div>

        <div className="view-content" data-slot="content">
          {activeTab === "pcaps" ? (
            <PcapExplorer
              pcaps={pcaps}
              loadingPcaps={loadingPcaps}
              pcapListError={pcapListError}
              uploading={uploading}
              uploadError={uploadError}
              selectedPcap={selectedPcap}
              packets={packets}
              loadingPackets={loadingPackets}
              totalPackets={totalPackets}
              page={page}
              pageSize={pageSize}
              filters={filters}
              labels={pcapLabels}
              onRefresh={fetchPcaps}
              onUpload={uploadPcap}
              onSelectPcap={(pcap) => {
                setSelectedPcap(pcap);
                setPage(1);
              }}
              onDeletePcap={setDeletePcapId}
              onChangePage={setPage}
              onChangeFilters={(nextFilters) => {
                setFilters(nextFilters);
                setPage(1);
              }}
              onOpenStats={openStats}
              onOpenPacket={openPacketDetail}
              onCloseUploadError={() => setUploadError(null)}
            />
          ) : (
            <BuilderPanel
              schema={builderSchema}
              layers={builderLayers}
              pendingPackets={builderPackets}
              editingPacketIndex={editingPacketIndex}
              selectedTemplate={selectedTemplate}
              preview={preview}
              previewError={previewError}
              previewLoading={previewLoading}
              outputFilename={outputFilename}
              building={buildingPcap}
              labels={{
                ...dict.builder,
                remove: dict.actions.remove,
                edit: dict.actions.edit,
                copy: dict.actions.copy,
                moveUp: dict.actions.moveUp,
                moveDown: dict.actions.moveDown,
                savePacket: dict.actions.savePacket,
                saveEdit: dict.actions.saveEdit,
                compile: dict.actions.compile,
                noHex: dict.detail.noHex,
              }}
              onAddLayer={addLayer}
              onRemoveLayer={(index) =>
                setBuilderLayers((current) =>
                  current.filter((_, itemIndex) => itemIndex !== index),
                )
              }
              onUpdateLayerField={updateLayerField}
              onLoadTemplate={(template) => {
                setSelectedTemplate(template);
                if (templates[template])
                  setBuilderLayers(cloneLayers(templates[template]));
              }}
              onSavePacket={saveBuilderPacket}
              onEditPacket={(index) => {
                setBuilderLayers(cloneLayers(builderPackets[index].layers));
                setEditingPacketIndex(index);
              }}
              onCopyPacket={copyBuilderPacket}
              onMovePacket={moveBuilderPacket}
              onDeletePacket={(index) => {
                setBuilderPackets((current) =>
                  current.filter((_, itemIndex) => itemIndex !== index),
                );
                addToast("info", dict.builder.removed, dict.builder.removedMsg);
              }}
              onChangeOutputFilename={setOutputFilename}
              onCompile={() => setExportVisible(true)}
            />
          )}
        </div>

        <PacketDetailDrawer
          visible={detailVisible}
          title={t(dict.detail.title, { index: selectedPacketIndex ?? "-" })}
          loading={loadingDetail}
          detail={packetDetail}
          anomalies={
            packets.find((p) => p.index === selectedPacketIndex)?.anomalies
          }
          labels={{
            empty: dict.detail.empty,
            summary: dict.detail.summary,
            insights: dict.detail.insights,
            insightsEmpty: dict.detail.insightsEmpty,
            protocolTree: dict.detail.protocolTree,
            hex: dict.detail.hex,
            noHex: dict.detail.noHex,
            close: dict.actions.close,
            sendToBuilder: dict.actions.sendToBuilder,
            followStream: dict.actions.followStream,
            anomaliesLabel: dict.detail.anomalies,
          }}
          onClose={() => {
            setDetailVisible(false);
            setSelectedPacketIndex(null);
            setPacketDetail(null);
          }}
          onSendToBuilder={handleSendToBuilder}
          onFollowStream={handleFollowStream}
        />

        <StatsDialog
          visible={statsVisible}
          loading={loadingStats}
          stats={stats}
          themeKey={`${suiteTheme.resolvedTheme}:${suiteTheme.glassEnabled}`}
          labels={{ ...dict.stats, close: dict.actions.close }}
          onClose={() => setStatsVisible(false)}
        />

        <FollowStreamDialog
          visible={streamVisible}
          loading={streamLoading}
          proto={streamProto}
          data={streamData}
          labels={{
            ...dict.stream,
            close: dict.actions.close,
          }}
          onClose={() => setStreamVisible(false)}
        />

        <VeyModal
          visible={Boolean(deletePcapId)}
          title={dict.pcaps.deleteTitle}
          message={dict.pcaps.deleteConfirm}
          confirmText={dict.actions.confirmDelete}
          cancelText={dict.actions.cancel}
          type="danger"
          onConfirm={confirmDeletePcap}
          onCancel={() => setDeletePcapId(null)}
        />

        <VeyModal
          visible={exportVisible}
          title={dict.builder.exportTitle}
          message={t(dict.builder.exportConfirm, { name: outputFilename })}
          confirmText={dict.actions.confirmExport}
          cancelText={dict.actions.cancel}
          onConfirm={compilePcap}
          onCancel={() => setExportVisible(false)}
        />

        <VeyToast toasts={toasts} onClose={removeToast} />
      </div>
    </VeyGlassProvider>
  );
}
