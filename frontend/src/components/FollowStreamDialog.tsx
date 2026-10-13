import { useState } from "react";
import {
  VeyButton,
  VeyDialog,
  VeyLoading,
  VeyEmpty,
  VeySelect,
} from "@veydeck/react";
import type { FollowStreamResponse } from "../types";

interface FollowStreamDialogProps {
  visible: boolean;
  loading: boolean;
  proto: string;
  data: FollowStreamResponse | null;
  labels: {
    title: string;
    client: string;
    server: string;
    empty: string;
    format: string;
    ascii: string;
    escaped: string;
    hex: string;
    packets: string;
    bytes: string;
    close: string;
  };
  onClose: () => void;
}

function formatEndpoint(ip: string, port: number): string {
  return `${ip}:${port}`;
}

function parseEscapedToBytes(escapedStr: string): number[] {
  const bytes: number[] = [];
  let i = 0;
  while (i < escapedStr.length) {
    const char = escapedStr[i];
    if (char === "\\" && i + 1 < escapedStr.length) {
      const next = escapedStr[i + 1];
      if (next === "x" && i + 3 < escapedStr.length) {
        const hex = escapedStr.substring(i + 2, i + 4);
        bytes.push(parseInt(hex, 16));
        i += 4;
      } else if (next === "r") {
        bytes.push(13);
        i += 2;
      } else if (next === "n") {
        bytes.push(10);
        i += 2;
      } else if (next === "t") {
        bytes.push(9);
        i += 2;
      } else if (next === "\\") {
        bytes.push(92);
        i += 2;
      } else {
        bytes.push(char.charCodeAt(0));
        i++;
      }
    } else {
      bytes.push(char.charCodeAt(0));
      i++;
    }
  }
  return bytes;
}

function formatBytesToHex(bytes: number[]): string {
  return bytes
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join(" ");
}

function renderText(escapedStr: string): string {
  return escapedStr
    .replaceAll("\\r\\n", "\n")
    .replaceAll("\\n", "\n")
    .replaceAll("\\t", "\t")
    .replaceAll("\\\\", "\\");
}

function renderAsciiDot(escapedStr: string): string {
  const bytes = parseEscapedToBytes(escapedStr);
  return bytes
    .map((b) => {
      if (b === 10 || b === 13 || b === 9) {
        return String.fromCharCode(b);
      }
      if (b >= 32 && b <= 126) {
        return String.fromCharCode(b);
      }
      return ".";
    })
    .join("");
}

export function FollowStreamDialog({
  visible,
  loading,
  proto,
  data,
  labels,
  onClose,
}: FollowStreamDialogProps) {
  const [viewMode, setViewMode] = useState<"ascii" | "escaped" | "hex">(
    "ascii",
  );

  if (!visible) return null;

  const renderChunkContent = (escapedData: string) => {
    if (viewMode === "hex") {
      const bytes = parseEscapedToBytes(escapedData);
      return formatBytesToHex(bytes);
    }
    if (viewMode === "ascii") {
      return renderAsciiDot(escapedData);
    }
    return renderText(escapedData);
  };
  const displayProto = data?.protocol || proto;

  const getFullCopyText = () => {
    if (!data) return "";
    return data.chunks
      .map((chunk) => {
        const prefix =
          chunk.direction === "client"
            ? "[Client -> Server]"
            : "[Server -> Client]";
        const text = renderChunkContent(chunk.data);
        return `${prefix}\n${text}\n`;
      })
      .join("\n");
  };

  const handleCopy = () => {
    const text = getFullCopyText();
    void navigator.clipboard.writeText(text);
  };

  return (
    <VeyDialog
      visible={visible}
      title={labels.title.replace("{proto}", displayProto)}
      width="min(880px, calc(100vw - 48px))"
      data-ui="follow-stream-dialog"
      onClose={onClose}
      footer={
        <div className="packet-actions">
          <VeyButton type="secondary" size="small" onClick={onClose}>
            {labels.close}
          </VeyButton>
        </div>
      }
    >
      <div className="packet-stream-body">
        {data && (
          <div className="packet-stream-subtitle">
            {labels.client.replace(
              "{ip}",
              formatEndpoint(data.client_ip, data.client_port),
            )}{" "}
            ↔{" "}
            {labels.server.replace(
              "{ip}",
              formatEndpoint(data.server_ip, data.server_port),
            )}
          </div>
        )}

        {loading ? (
          <VeyLoading loading text="Loading stream..." />
        ) : !data || data.chunks.length === 0 ? (
          <VeyEmpty description={labels.empty} />
        ) : (
          <>
            <div className="packet-stream-toolbar">
              <div className="packet-stream-controls">
                <span>{labels.format}</span>
                <div className="packet-stream-select-wrap">
                  <VeySelect
                    value={viewMode}
                    onChange={(value) =>
                      setViewMode(value as "ascii" | "escaped" | "hex")
                    }
                    options={[
                      { label: labels.ascii, value: "ascii" },
                      { label: labels.escaped, value: "escaped" },
                      { label: labels.hex, value: "hex" },
                    ]}
                  />
                </div>
                <span className="packet-stream-meta">
                  {data.packet_count} {labels.packets} / {data.byte_count}{" "}
                  {labels.bytes}
                </span>
              </div>
              <VeyButton type="secondary" size="small" onClick={handleCopy}>
                Copy All
              </VeyButton>
            </div>

            <div className="packet-stream-content" data-ui="stream-content">
              {data.chunks.map((chunk, index) => {
                const isClient = chunk.direction === "client";
                return (
                  <div
                    key={index}
                    className={`packet-stream-chunk packet-stream-chunk-${chunk.direction}`}
                  >
                    <div className="packet-stream-chunk-header">
                      {isClient ? "Client" : "Server"} [Frame #
                      {chunk.start_packet_index}
                      {chunk.end_packet_index !== chunk.start_packet_index
                        ? `-${chunk.end_packet_index}`
                        : ""}
                      , {chunk.byte_count} {labels.bytes}]
                    </div>
                    <div className="packet-stream-chunk-data">
                      {renderChunkContent(chunk.data)}
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </VeyDialog>
  );
}
