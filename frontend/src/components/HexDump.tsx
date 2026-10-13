import { useState } from "react";

interface HexDumpProps {
  hex?: string;
  emptyText: string;
}

export function HexDump({ hex, emptyText }: HexDumpProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (!hex) {
    return <div className="packet-muted">{emptyText}</div>;
  }

  const cleanHex = hex.replace(/\s+/g, "").toUpperCase();
  const bytesCount = Math.floor(cleanHex.length / 2);
  const rows = [];

  for (let i = 0; i < bytesCount; i += 16) {
    const bytes: Array<{ index: number; value: string }> = [];
    const ascii: Array<{ index: number; value: string }> = [];

    for (let j = 0; j < 16; j += 1) {
      const index = i + j;
      if (index >= bytesCount) break;
      const value = cleanHex.slice(index * 2, index * 2 + 2);
      const code = Number.parseInt(value, 16);
      bytes.push({ index, value });
      ascii.push({
        index,
        value: code >= 32 && code <= 126 ? String.fromCharCode(code) : ".",
      });
    }

    rows.push({
      offset: i.toString(16).padStart(4, "0").toUpperCase(),
      bytes,
      ascii,
    });
  }

  return (
    <div className="hex-dump-panel hex-monospace" data-ui="hex-dump">
      {rows.map((row) => (
        <div className="hex-dump-row" key={row.offset}>
          <span className="hex-offset">{row.offset}</span>
          <div className="hex-byte-group">
            {Array.from({ length: 16 }, (_, index) => row.bytes[index]).map((byte, index) =>
              byte ? (
              <span
                className={`hex-byte ${hoveredIndex === byte.index ? "is-active" : ""}`}
                key={byte.index}
                onMouseEnter={() => setHoveredIndex(byte.index)}
                onMouseLeave={() => setHoveredIndex(null)}
              >
                {byte.value}
              </span>
              ) : (
                <span className="hex-byte is-empty" key={`empty-${row.offset}-${index}`} />
              ),
            )}
          </div>
          <span className="hex-divider">|</span>
          <div className="hex-ascii-group">
            {Array.from({ length: 16 }, (_, index) => row.ascii[index]).map((item, index) =>
              item ? (
              <span
                className={`hex-ascii ${hoveredIndex === item.index ? "is-active" : ""}`}
                key={item.index}
                onMouseEnter={() => setHoveredIndex(item.index)}
                onMouseLeave={() => setHoveredIndex(null)}
              >
                {item.value}
              </span>
              ) : (
                <span className="hex-ascii is-empty" key={`empty-ascii-${row.offset}-${index}`} />
              ),
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
