export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const base = 1024;
  const units = ["Bytes", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(base)), units.length - 1);
  return `${Number((bytes / base ** index).toFixed(Math.max(0, decimals)))} ${units[index]}`;
}

export function formatPacketTime(timestamp: number | null) {
  if (!timestamp) return "-";
  return new Date(timestamp * 1000).toISOString().split("T")[1]?.slice(0, -1) ?? "-";
}

export function formatDateTime(value: string, locale = "zh-CN") {
  return new Date(value).toLocaleString(locale);
}

export function endpoint(ip?: string | null, port?: number | null, mac?: string | null) {
  return ip ? `${ip}${port ? `:${port}` : ""}` : mac || "-";
}
