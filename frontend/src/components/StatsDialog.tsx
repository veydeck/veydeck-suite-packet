import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import {
  VeyButton,
  VeyDialog,
  VeyEmpty,
  VeyLoading,
  VeyTable,
  type VeyTableColumn,
} from "@veydeck/react";
import type { StatsData } from "../types";

interface StatsDialogProps {
  visible: boolean;
  loading: boolean;
  stats: StatsData | null;
  labels: {
    title: string;
    loading: string;
    chartTitle: string;
    seriesName: string;
    topSrc: string;
    topDst: string;
    topPorts: string;
    total: string;
    ip: string;
    count: string;
    port: string;
    connections: string;
    empty: string;
    close: string;
  };
  themeKey: string;
  onClose: () => void;
}

export function StatsDialog({
  visible,
  loading,
  stats,
  labels,
  themeKey,
  onClose,
}: StatsDialogProps) {
  const chartRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!visible || !stats || !chartRef.current) return;

    const styles = getComputedStyle(chartRef.current);
    const token = (name: string) => styles.getPropertyValue(name).trim();
    const chart = echarts.init(chartRef.current);
    chart.setOption({
      backgroundColor: "transparent",
      title: {
        text: labels.chartTitle,
        left: "center",
        textStyle: { color: token("--vdl-text-primary"), fontSize: 15 },
      },
      tooltip: { trigger: "item" },
      legend: {
        orient: "horizontal",
        bottom: 0,
        textStyle: { color: token("--vdl-text-secondary") },
      },
      series: [
        {
          name: labels.seriesName,
          type: "pie",
          radius: "56%",
          center: ["50%", "46%"],
          data: Object.entries(stats.protocol_distribution).map(
            ([name, value]) => ({
              name,
              value,
            }),
          ),
        },
      ],
    });

    const resize = () => chart.resize();
    window.addEventListener("resize", resize);
    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [labels.chartTitle, labels.seriesName, stats, themeKey, visible]);

  if (!visible) return null;

  const ipColumns: VeyTableColumn<{ ip: string; count: number }>[] = [
    { prop: "ip", label: labels.ip },
    { prop: "count", label: labels.count, width: 120, align: "right" },
  ];
  const portColumns: VeyTableColumn<{ port: number; count: number }>[] = [
    { prop: "port", label: labels.port },
    { prop: "count", label: labels.connections, width: 120, align: "right" },
  ];

  return (
    <VeyDialog
      visible={visible}
      title={labels.title}
      width="min(980px, calc(100vw - 48px))"
      data-ui="stats-dialog"
      onClose={onClose}
      footer={
        <div className="packet-actions">
          <VeyButton type="secondary" size="small" onClick={onClose}>
            {labels.close}
          </VeyButton>
        </div>
      }
    >
      <div className="packet-stats-body">
        {loading ? (
          <VeyLoading loading text={labels.loading} />
        ) : !stats ? (
          <VeyEmpty description={labels.empty} />
        ) : (
          <>
            <div className="packet-total-line">
              {labels.total} <strong>{stats.total_packets}</strong>
            </div>
            <div className="chart-container" ref={chartRef} />
            <div className="packet-stats-grid">
              <div className="packet-card">
                <h4>{labels.topSrc}</h4>
                <div className="packet-card-table">
                  <VeyTable
                    data={stats.top_src_ips}
                    columns={ipColumns}
                    border
                    glass={false}
                  />
                </div>
              </div>
              <div className="packet-card">
                <h4>{labels.topDst}</h4>
                <div className="packet-card-table">
                  <VeyTable
                    data={stats.top_dst_ips}
                    columns={ipColumns}
                    border
                    glass={false}
                  />
                </div>
              </div>
              <div className="packet-card">
                <h4>{labels.topPorts}</h4>
                <div className="packet-card-table">
                  <VeyTable
                    data={stats.top_dst_ports}
                    columns={portColumns}
                    border
                    glass={false}
                  />
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </VeyDialog>
  );
}
