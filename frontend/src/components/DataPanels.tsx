import { useState } from "react";
import type { StateSummary } from "../types";
import styles from "./DataPanels.module.css";

const TABS = ["Findings", "Secrets", "Hosts & Footholds"] as const;

export default function DataPanels({ summary }: { summary: StateSummary }) {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Findings");
  const capped = (v: unknown) =>
    v && typeof v === "object" && "count" in (v as Record<string, unknown>)
      ? `${(v as { count: number }).count} items (full list via state inspector)`
      : null;

  return (
    <div className={styles.panels}>
      <div className={styles.tabs}>
        {TABS.map((t) => (
          <button key={t} className={tab === t ? styles.on : ""} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>
      {tab === "Findings" && (
        <table className={styles.table}>
          <thead><tr><th>Title</th><th>Severity</th><th>Host</th></tr></thead>
          <tbody>
            {summary.findings.map((f, i) => (
              <tr key={i}><td>{f.title}</td><td>{f.severity}</td><td>{f.host}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "Secrets" && (
        <table className={styles.table}>
          <thead><tr><th>Type</th><th>Source</th><th>Value</th></tr></thead>
          <tbody>
            {summary.harvested_secrets.map((s, i) => (
              <tr key={i}><td>{s.secret_type}</td><td>{s.source}</td><td><code>{s.secret_value}</code></td></tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "Hosts & Footholds" && (
        <table className={styles.table}>
          <thead><tr><th>Host</th><th>Foothold</th><th>Access</th></tr></thead>
          <tbody>
            {summary.footholds.map((f, i) => (
              <tr key={i}><td>{f.host_ip}</td><td>{f.method}</td><td>{f.access_type}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {capped(summary.findings) && <p className={styles.dim}>{capped(summary.findings)}</p>}
    </div>
  );
}
