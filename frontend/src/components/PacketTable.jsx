import { FixedSizeList as List } from "react-window";

function Row({ index, style, data }) {
  const row = data[index];
  if (!row) return null;
  const cls = row.status === "failed_auth" ? "row failed" : row.protocol === "ICMP" ? "row icmp" : "row";
  return (
    <div className={cls} style={style}>
      <span>{index + 1}</span>
      <span>{new Date(row.timestamp).toLocaleTimeString()}</span>
      <span>{row.direction === "INBOUND" ? "▼IN" : "▲OUT"}</span>
      <span>{row.src_ip}:{row.src_port || "-"}</span>
      <span>{row.dst_ip}:{row.dst_port || "-"}</span>
      <span>{row.protocol}</span>
      <span>{row.packet_size}</span>
      <span>{row.flags || "-"}</span>
      <span>{row.status}</span>
    </div>
  );
}

export default function PacketTable({ packets, filters, setFilters }) {
  const filtered = packets.filter((p) => {
    if (filters.protocol && p.protocol !== filters.protocol) return false;
    if (filters.direction && p.direction !== filters.direction) return false;
    if (filters.src_ip && !p.src_ip.includes(filters.src_ip)) return false;
    if (filters.port && !(String(p.src_port).includes(filters.port) || String(p.dst_port).includes(filters.port))) return false;
    if (filters.threats_only && p.status === "normal") return false;
    return true;
  });
  return (
    <section className="packet-pane">
      <div className="filter-bar">
        <select onChange={(e) => setFilters((f) => ({ ...f, protocol: e.target.value }))}><option value="">Protocol</option><option>TCP</option><option>UDP</option><option>ICMP</option></select>
        <select onChange={(e) => setFilters((f) => ({ ...f, direction: e.target.value }))}><option value="">Direction</option><option>INBOUND</option><option>OUTBOUND</option></select>
        <input placeholder="Src IP" onChange={(e) => setFilters((f) => ({ ...f, src_ip: e.target.value }))} />
        <input placeholder="Port" onChange={(e) => setFilters((f) => ({ ...f, port: e.target.value }))} />
        <label><input type="checkbox" onChange={(e) => setFilters((f) => ({ ...f, threats_only: e.target.checked }))} /> threats only</label>
      </div>
      <div className="table-header row">
        <span>#</span><span>Timestamp</span><span>Direction</span><span>Src</span><span>Dst</span><span>Proto</span><span>Size</span><span>Flags</span><span>Status</span>
      </div>
      <List height={260} width={"100%"} itemCount={filtered.length} itemSize={28} itemData={filtered}>
        {Row}
      </List>
    </section>
  );
}