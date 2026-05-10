import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, ReferenceLine } from "recharts";

const colorMap = { LOW: "#ffe066", MEDIUM: "#ff922b", HIGH: "#ff4d4f", CRITICAL: "#ff1744" };
const spikeHeight = (score) => (score <= 30 ? 30 : score <= 60 ? 60 : score <= 85 ? 85 : 100);

export default function PacketGraph({ points, alerts }) {
  return (
    <div className="graph-pane">
      <ResponsiveContainer width="100%" height={320}>
        <LineChart data={points}>
          <XAxis dataKey="time" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="inbound" stroke="#00d4ff" dot={false} name="Inbound" />
          <Line type="monotone" dataKey="outbound" stroke="#4c6fff" dot={false} name="Outbound" />
          <Line type="monotone" dataKey="total" stroke="#8e8e93" strokeDasharray="4 4" dot={false} name="Total" />
          {alerts.slice(-60).map((a) => (
            <ReferenceLine
              key={a.alert_id}
              x={new Date(a.timestamp).toLocaleTimeString()}
              stroke={colorMap[a.severity]}
              strokeWidth={2}
              ifOverflow="extendDomain"
              label={{ value: `⚡${spikeHeight(a.risk_score)}`, fill: colorMap[a.severity], position: "top" }}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      <div className="timeline">
        {(alerts || []).slice(-100).map((a) => <span key={a.alert_id} style={{ background: colorMap[a.severity] }} title={`${a.threat_type} ${a.src_ip} ${a.risk_score}`} />)}
      </div>
    </div>
  );
}