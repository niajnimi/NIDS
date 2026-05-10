const cls = { LOW: "low", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical" };

export default function AlertsFeed({ alerts, onViewPackets }) {
  return (
    <section className="alerts-pane">
      <h3>Alerts Feed</h3>
      {alerts.map((a) => (
        <article key={a.alert_id} className={`alert-card ${cls[a.severity]}`}>
          <div className="alert-head">
            <span className={`badge ${cls[a.severity]}`}>{a.severity}</span>
            <strong>{a.threat_type}</strong> - {a.src_ip}
          </div>
          <div>{a.detail_message}</div>
          <div>Risk Score: {a.risk_score}/100</div>
          <small>{new Date(a.timestamp).toLocaleString()} | {a.alert_id}</small>
          <button onClick={() => onViewPackets(a.src_ip)}>View Packets</button>
        </article>
      ))}
    </section>
  );
}