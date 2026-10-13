import { useState } from "react";
import {
  VeyAlert,
  VeyButton,
  VeyEmpty,
  VeyGlassSurface,
  VeyInput,
  VeyLoading,
  VeySelect,
} from "@veydeck/react";
import type {
  BuilderLayerSpec,
  BuilderPacket,
  LayerSpec,
  PacketPreviewResponse,
} from "../types";
import { HexDump } from "./HexDump";
import { ResizableWorkspace } from "./ResizableWorkspace";

interface BuilderPanelProps {
  schema: BuilderLayerSpec[];
  layers: LayerSpec[];
  pendingPackets: BuilderPacket[];
  editingPacketIndex: number | null;
  selectedTemplate: string;
  preview: PacketPreviewResponse | null;
  previewError: string | null;
  previewLoading: boolean;
  outputFilename: string;
  building: boolean;
  labels: {
    addTitle: string;
    editTitle: string;
    template: string;
    selectTemplate: string;
    layer: string;
    previewTitle: string;
    previewLoading: string;
    previewHint: string;
    previewHex: string;
    summary: string;
    pending: string;
    pendingEmpty: string;
    output: string;
    remove: string;
    edit: string;
    savePacket: string;
    saveEdit: string;
    compile: string;
    noHex: string;
    advanced: string;
    copy: string;
    moveUp: string;
    moveDown: string;
    warnings: string;
    templates: Record<string, string>;
  };
  onAddLayer: (name: string) => void;
  onRemoveLayer: (index: number) => void;
  onUpdateLayerField: (layerIndex: number, key: string, value: string) => void;
  onLoadTemplate: (template: string) => void;
  onSavePacket: () => void;
  onEditPacket: (index: number) => void;
  onCopyPacket: (index: number) => void;
  onMovePacket: (index: number, direction: -1 | 1) => void;
  onDeletePacket: (index: number) => void;
  onChangeOutputFilename: (value: string) => void;
  onCompile: () => void;
}

export function BuilderPanel({
  schema,
  layers,
  pendingPackets,
  editingPacketIndex,
  selectedTemplate,
  preview,
  previewError,
  previewLoading,
  outputFilename,
  building,
  labels,
  onAddLayer,
  onRemoveLayer,
  onUpdateLayerField,
  onLoadTemplate,
  onSavePacket,
  onEditPacket,
  onCopyPacket,
  onMovePacket,
  onDeletePacket,
  onChangeOutputFilename,
  onCompile,
}: BuilderPanelProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const schemaByName = new Map(schema.map((layer) => [layer.name, layer]));

  return (
    <ResizableWorkspace
      className="packet-builder-workspace"
      dataUi="packet-builder"
      defaultLeftPercent={52}
      minLeftPercent={34}
      minRightPercent={30}
      storageKey="packet-builder-split"
      left={
        <VeyGlassSurface
          className="packet-main-panel"
          data-slot="builder-editor"
        >
          <div className="packet-panel-title-row">
            <h3 className="packet-panel-title">
              {editingPacketIndex === null
                ? labels.addTitle
                : labels.editTitle.replace(
                    "{index}",
                    String(editingPacketIndex + 1),
                  )}
            </h3>
            <div className="packet-template-picker">
              <span className="packet-template-label">{labels.template}</span>
              <VeySelect
                value={selectedTemplate}
                placeholder={labels.selectTemplate}
                onChange={(value) => onLoadTemplate(String(value ?? ""))}
                options={[
                  { label: labels.templates.tcp_syn, value: "tcp_syn" },
                  { label: labels.templates.udp_dns, value: "udp_dns" },
                  { label: labels.templates.dns_aaaa, value: "dns_aaaa" },
                  { label: labels.templates.icmp_ping, value: "icmp_ping" },
                  {
                    label: labels.templates.http_request,
                    value: "http_request",
                  },
                  {
                    label: labels.templates.http_response,
                    value: "http_response",
                  },
                  {
                    label: labels.templates.tls_client_hello,
                    value: "tls_client_hello",
                  },
                ]}
              />
            </div>
          </div>

          <div className="packet-builder-toolbar">
            {schema.map((layer) => (
              <VeyButton
                type="secondary"
                size="small"
                key={layer.name}
                onClick={() => onAddLayer(layer.name)}
              >
                + {layer.name}
              </VeyButton>
            ))}
            <VeyButton
              type="secondary"
              size="small"
              onClick={() => setShowAdvanced((current) => !current)}
            >
              {labels.advanced}
            </VeyButton>
          </div>

          <div className="packet-layer-list">
            {layers.map((layer, index) => (
              <div className="packet-layer-card" key={`${layer.name}-${index}`}>
                <div className="packet-layer-title-row">
                  <h4>
                    {labels.layer
                      .replace("{index}", String(index + 1))
                      .replace("{name}", layer.name)}
                  </h4>
                  <VeyButton
                    type="danger"
                    size="small"
                    onClick={() => onRemoveLayer(index)}
                  >
                    {labels.remove}
                  </VeyButton>
                </div>
                <div className="packet-field-grid">
                  {(schemaByName.get(layer.name)?.fields ?? [])
                    .filter((field) => showAdvanced || !field.advanced)
                    .map((field) => (
                      <label
                        className={`packet-form-field ${field.wide ? "is-wide" : ""}`}
                        key={field.key}
                      >
                        <span>
                          {field.label}
                          {field.auto ? " (auto)" : ""}
                        </span>
                        {field.type === "select" ? (
                          <VeySelect
                            value={String(layer.fields[field.key] ?? "")}
                            placeholder={field.placeholder ?? undefined}
                            options={(field.options ?? []).map((option) => ({
                              label: option.label,
                              value: option.value,
                            }))}
                            onChange={(value) =>
                              onUpdateLayerField(
                                index,
                                field.key,
                                String(value ?? ""),
                              )
                            }
                          />
                        ) : (
                          <VeyInput
                            value={String(layer.fields[field.key] ?? "")}
                            placeholder={field.placeholder ?? undefined}
                            onChange={(value) =>
                              onUpdateLayerField(index, field.key, value)
                            }
                          />
                        )}
                      </label>
                    ))}
                </div>
              </div>
            ))}
          </div>

          <div className="packet-form-footer">
            <VeyButton type="primary" onClick={onSavePacket}>
              {editingPacketIndex === null
                ? labels.savePacket
                : labels.saveEdit}
            </VeyButton>
          </div>
        </VeyGlassSurface>
      }
      right={
        <VeyGlassSurface
          className="packet-side-panel"
          data-slot="builder-preview"
        >
          <div className="packet-panel-title-row">
            <h3 className="packet-panel-title">{labels.previewTitle}</h3>
          </div>
          <div className="packet-preview-area">
            {previewLoading ? (
              <VeyLoading loading text={labels.previewLoading} />
            ) : previewError ? (
              <VeyAlert type="error" description={previewError} />
            ) : preview ? (
              <>
                {preview.warnings.length > 0 ? (
                  <VeyAlert
                    type="warning"
                    description={`${labels.warnings} ${preview.warnings.join("; ")}`}
                  />
                ) : null}
                <div className="packet-preview-block">
                  <div className="packet-preview-label">{labels.summary}</div>
                  <div className="packet-summary-box">{preview.summary}</div>
                </div>
                <div className="packet-preview-block is-hex">
                  <div className="packet-preview-label">
                    {labels.previewHex}
                  </div>
                  <HexDump hex={preview.hex} emptyText={labels.noHex} />
                </div>
              </>
            ) : (
              <VeyEmpty description={labels.previewHint} />
            )}
          </div>

          <div className="packet-pending-section">
            <h3 className="packet-panel-title">
              {labels.pending.replace("{count}", String(pendingPackets.length))}
            </h3>
            {pendingPackets.length === 0 ? (
              <VeyEmpty description={labels.pendingEmpty} />
            ) : (
              <div className="packet-pending-list">
                {pendingPackets.map((packet, index) => (
                  <div
                    className="packet-pending-item"
                    key={`${packet.summary}-${index}`}
                  >
                    <div>
                      <strong>#{index + 1}</strong>
                      <span>{packet.summary}</span>
                    </div>
                    <div className="packet-actions">
                      <VeyButton
                        type="secondary"
                        size="small"
                        onClick={() => onEditPacket(index)}
                      >
                        {labels.edit}
                      </VeyButton>
                      <VeyButton
                        type="secondary"
                        size="small"
                        onClick={() => onCopyPacket(index)}
                      >
                        {labels.copy}
                      </VeyButton>
                      <VeyButton
                        type="secondary"
                        size="small"
                        onClick={() => onMovePacket(index, -1)}
                      >
                        {labels.moveUp}
                      </VeyButton>
                      <VeyButton
                        type="secondary"
                        size="small"
                        onClick={() => onMovePacket(index, 1)}
                      >
                        {labels.moveDown}
                      </VeyButton>
                      <VeyButton
                        type="danger"
                        size="small"
                        onClick={() => onDeletePacket(index)}
                      >
                        {labels.remove}
                      </VeyButton>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {pendingPackets.length > 0 ? (
              <div className="packet-export-area">
                <label className="packet-form-field is-wide">
                  <span>{labels.output}</span>
                  <VeyInput
                    value={outputFilename}
                    onChange={onChangeOutputFilename}
                  />
                </label>
                <VeyButton
                  type="primary"
                  loading={building}
                  onClick={onCompile}
                >
                  {labels.compile}
                </VeyButton>
              </div>
            ) : null}
          </div>
        </VeyGlassSurface>
      }
    />
  );
}
