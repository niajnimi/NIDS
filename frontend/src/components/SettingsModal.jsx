import { useEffect, useState } from "react";
const API = "http://localhost:5000";

export default function SettingsModal({ open, onClose }) {
  const [settings, setSettings] = useState(null);
  useEffect(() => {
    if (open) fetch(`${API}/api/settings`).then((r) => r.json()).then(setSettings);
  }, [open]);
  if (!open || !settings) return null;
  const update = (k, v) => setSettings((s) => ({ ...s, [k]: v }));
  const save = async () => {
    await fetch(`${API}/api/settings`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings) });
    onClose();
  };
  return (
    <div className="modal">
      <div className="modal-card">
        <h3>Detection Settings</h3>
        {Object.entries(settings).map(([k, v]) => (
          <label key={k}>{k}
            <input value={String(v)} onChange={(e) => update(k, typeof v === "number" ? Number(e.target.value) : (typeof v === "boolean" ? e.target.value === "true" : e.target.value))} />
          </label>
        ))}
        <button onClick={save}>Save</button>
        <button onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
}