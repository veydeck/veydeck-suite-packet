import {
  VeyAlert,
  VeyButton,
  VeyEmpty,
  VeyGlassSurface,
  VeyInput,
  VeyLoading,
  VeyPagination,
  VeySelect,
  VeyTable,
  VeyTag,
  type VeyTableColumn,
} from "@veydeck/react";
import { packetApi } from "../api";
import type { PacketFilters, PacketSummary, PcapFile } from "../types";
import {
  endpoint,
  formatBytes,
  formatDateTime,
  formatPacketTime,
} from "../utils";
import { ResizableWorkspace } from "./ResizableWorkspace";

interface PcapExplorerProps {
  pcaps: PcapFile[];
  loadingPcaps: boolean;
  pcapListError: string | null;
  uploading: boolean;
  uploadError: string | null;
  selectedPcap: PcapFile | null;
  packets: PacketSummary[];
  loadingPackets: boolean;
  totalPackets: number;
  page: number;
  pageSize: number;
  filters: PacketFilters;
  labels: {
    refresh: string;
    upload: string;
    reset: string;
    stats: string;
    downloadRaw: string;
    delete: string;
    uploaded: string;
    empty: string;
    select: string;
    loadingList: string;
    listLoadFailed: string;
    loadingPackets: string;
    uploading: string;
    status: Record<PcapFile["status"], string>;
    meta: string;
    protocol: string;
    allProtocols: string;
    srcIp: string;
    dstIp: string;
    port: string;
    table: Record<string, string>;
  };
  onRefresh: () => void;
  onUpload: (file: File) => void;
  onSelectPcap: (pcap: PcapFile) => void;
  onDeletePcap: (pcapId: string) => void;
  onChangePage: (page: number) => void;
  onChangeFilters: (filters: PacketFilters) => void;
  onOpenStats: () => void;
  onOpenPacket: (packetIndex: number) => void;
  onCloseUploadError: () => void;
}

const statusTagType: Record<
  PcapFile["status"],
  "default" | "primary" | "success" | "danger"
> = {
  uploaded: "default",
  parsing: "primary",
  parsed: "success",
  failed: "danger",
};

const protocolOptions = [
  "HTTP",
  "TCP",
  "UDP",
  "DNS",
  "ICMP",
  "ARP",
  "TLS",
  "SSH",
  "FTP",
  "MQTT",
  "HTTP/2",
].map((value) => ({
  label: value,
  value,
}));

export function PcapExplorer({
  pcaps,
  loadingPcaps,
  pcapListError,
  uploading,
  uploadError,
  selectedPcap,
  packets,
  loadingPackets,
  totalPackets,
  page,
  pageSize,
  filters,
  labels,
  onRefresh,
  onUpload,
  onSelectPcap,
  onDeletePcap,
  onChangePage,
  onChangeFilters,
  onOpenStats,
  onOpenPacket,
  onCloseUploadError,
}: PcapExplorerProps) {
  const columns: VeyTableColumn<PacketSummary>[] = [
    { prop: "index", label: labels.table.index, width: 76, align: "center" },
    {
      prop: "timestamp",
      label: labels.table.time,
      width: 132,
      renderCell: (row) => formatPacketTime(row.timestamp),
    },
    {
      prop: "protocol",
      label: labels.table.protocol,
      width: 108,
      align: "center",
      renderCell: (row) => (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "4px",
          }}
        >
          <span>{row.protocol}</span>
          {row.anomalies ? (
            <span
              title={row.anomalies.split(",").join("\n")}
              style={{
                cursor: "help",
                display: "inline-flex",
                fontSize: "12px",
              }}
            >
              ⚠️
            </span>
          ) : null}
        </div>
      ),
    },
    {
      prop: "source",
      label: labels.table.source,
      minWidth: 180,
      renderCell: (row) => endpoint(row.src_ip, row.src_port, row.src_mac),
    },
    {
      prop: "destination",
      label: labels.table.destination,
      minWidth: 180,
      renderCell: (row) => endpoint(row.dst_ip, row.dst_port, row.dst_mac),
    },
    { prop: "length", label: labels.table.length, width: 104, align: "right" },
    { prop: "summary", label: labels.table.summary, minWidth: 260 },
  ];

  return (
    <ResizableWorkspace
      dataUi="pcap-explorer"
      storageKey="packet-explorer-split"
      left={
        <VeyGlassSurface className="packet-side-panel" data-slot="pcap-library">
          <div className="packet-panel-title-row">
            <h3 className="packet-panel-title">{labels.uploaded}</h3>
            <div className="packet-actions">
              <VeyButton type="secondary" size="small" onClick={onRefresh}>
                {labels.refresh}
              </VeyButton>
              <VeyGlassSurface
                as="label"
                profile="control"
                className={`packet-upload-button vl-button vl-button--secondary vl-button--small ${
                  uploading ? "is-disabled" : ""
                }`}
              >
                <span className="vl-button-content">{labels.upload}</span>
                <input
                  className="file-input-cover"
                  type="file"
                  accept=".pcap,.pcapng"
                  disabled={uploading}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) onUpload(file);
                    event.currentTarget.value = "";
                  }}
                />
              </VeyGlassSurface>
            </div>
          </div>

          {uploadError ? (
            <VeyAlert
              type="error"
              description={uploadError}
              closable
              onClose={onCloseUploadError}
            />
          ) : null}
          {uploading ? (
            <VeyAlert type="info" description={labels.uploading} />
          ) : null}
          {pcapListError ? (
            <VeyAlert
              type="warning"
              description={`${labels.listLoadFailed} (${pcapListError})`}
            />
          ) : null}

          <div className="packet-file-list">
            {loadingPcaps && pcaps.length === 0 ? (
              <VeyLoading loading text={labels.loadingList} />
            ) : pcaps.length === 0 ? (
              <VeyEmpty description={labels.empty} />
            ) : (
              pcaps.map((pcap) => (
                <div
                  className={`packet-file-item ${selectedPcap?.id === pcap.id ? "is-active" : ""}`}
                  aria-disabled={pcap.status !== "parsed"}
                  key={pcap.id}
                  role="button"
                  tabIndex={pcap.status === "parsed" ? 0 : -1}
                  onClick={() => {
                    if (pcap.status === "parsed") onSelectPcap(pcap);
                  }}
                  onKeyDown={(event) => {
                    if (pcap.status !== "parsed") return;
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelectPcap(pcap);
                    }
                  }}
                >
                  <div className="packet-file-main">
                    <span className="packet-file-name">
                      {pcap.original_filename}
                    </span>
                    <span className="packet-file-meta">
                      {labels.meta
                        .replace("{size}", formatBytes(pcap.file_size))
                        .replace("{count}", String(pcap.packet_count))
                        .replace("{time}", formatDateTime(pcap.created_at))}
                    </span>
                    {pcap.error_message ? (
                      <span className="packet-file-error">
                        {pcap.error_message}
                      </span>
                    ) : null}
                  </div>
                  <div className="packet-file-actions">
                    <VeyTag type={statusTagType[pcap.status]}>
                      {labels.status[pcap.status]}
                    </VeyTag>
                    <VeyButton
                      type="danger"
                      size="small"
                      onClick={(event) => {
                        event.stopPropagation();
                        onDeletePcap(pcap.id);
                      }}
                    >
                      {labels.delete}
                    </VeyButton>
                  </div>
                </div>
              ))
            )}
          </div>
        </VeyGlassSurface>
      }
      right={
        <VeyGlassSurface className="packet-main-panel" data-slot="packet-list">
          {!selectedPcap ? (
            <div className="packet-empty-wrap">
              <VeyEmpty description={labels.select} />
            </div>
          ) : (
            <>
              <div className="packet-filter-bar">
                <VeySelect
                  value={filters.protocol}
                  onChange={(value) =>
                    onChangeFilters({
                      ...filters,
                      protocol: String(value ?? ""),
                    })
                  }
                  placeholder={labels.protocol}
                  options={[
                    { label: labels.allProtocols, value: "" },
                    ...protocolOptions,
                  ]}
                />
                <VeyInput
                  value={filters.srcIp}
                  onChange={(value) =>
                    onChangeFilters({ ...filters, srcIp: value })
                  }
                  placeholder={labels.srcIp}
                />
                <VeyInput
                  value={filters.dstIp}
                  onChange={(value) =>
                    onChangeFilters({ ...filters, dstIp: value })
                  }
                  placeholder={labels.dstIp}
                />
                <VeyInput
                  value={filters.port}
                  onChange={(value) =>
                    onChangeFilters({ ...filters, port: value })
                  }
                  placeholder={labels.port}
                />
                <VeyButton
                  type="secondary"
                  size="small"
                  onClick={() =>
                    onChangeFilters({
                      protocol: "",
                      srcIp: "",
                      dstIp: "",
                      port: "",
                    })
                  }
                >
                  {labels.reset}
                </VeyButton>
                <div className="packet-filter-actions">
                  <VeyButton
                    type="secondary"
                    size="small"
                    onClick={onOpenStats}
                  >
                    {labels.stats}
                  </VeyButton>
                  <VeyButton
                    type="secondary"
                    size="small"
                    onClick={() =>
                      window.open(packetApi.downloadUrl(selectedPcap.id))
                    }
                  >
                    {labels.downloadRaw}
                  </VeyButton>
                </div>
              </div>

              <div
                className="packet-table-shell"
                onClick={(event) => {
                  const rowElement = (event.target as HTMLElement).closest(
                    ".vl-table-row",
                  );
                  if (!rowElement?.parentElement) return;
                  const rowIndex = Array.from(
                    rowElement.parentElement.children,
                  ).indexOf(rowElement);
                  const packet = packets[rowIndex];
                  if (packet) onOpenPacket(packet.index);
                }}
              >
                {loadingPackets ? (
                  <VeyLoading loading text={labels.loadingPackets} />
                ) : (
                  <VeyTable
                    data={packets}
                    columns={columns}
                    border
                    glass={false}
                  />
                )}
              </div>

              <div className="packet-pagination">
                <VeyPagination
                  currentPage={page}
                  totalPages={Math.ceil(totalPackets / pageSize) || 1}
                  onPageChange={onChangePage}
                />
              </div>
            </>
          )}
        </VeyGlassSurface>
      }
    />
  );
}
