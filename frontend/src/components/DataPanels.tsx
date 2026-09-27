import { useState } from "react";
import type { StateSummary } from "../types";
import AttackGraph from "./AttackGraph";
import styles from "./DataPanels.module.css";

const TABS = ["Findings", "Secrets", "Hosts & Footholds", "Attack Graph"] as const;

// WS summaries (spec §4) cap long lists as {"count": N} — only render tables
// when the list is actually an array; otherwise show the capped count.
const asArray = <T,>(v: T[] | { count: number } | undefined): v is T[] =>
  Array.isArray(v);

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
        asArray(summary.findings) ? (
          <table className={styles.table}>
            <thead><tr><th>Title</th><th>Severity</th><th>Host</th></tr></thead>
            <tbody>
              {summary.findings.map((f, i) => (
                <tr key={i}><td>{f.title}</td><td>{f.severity}</td><td>{f.host}</td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className={styles.dim}>{capped(summary.findings) ?? "no findings yet"}</p>
        )
      )}
      {tab === "Secrets" && (
        asArray(summary.harvested_secrets) ? (
          <table className={styles.table}>
            <thead><tr><th>Type</th><th>Source</th><th>Value</th></tr></thead>
            <tbody>
              {summary.harvested_secrets.map((s, i) => (
                <tr key={i}><td>{s.secret_type}</td><td>{s.source}</td><td><code>{s.secret_value}</code></td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className={styles.dim}>{capped(summary.harvested_secrets) ?? "no secrets yet"}</p>
        )
      )}
      {tab === "Hosts & Footholds" && (
        asArray(summary.footholds) ? (
          <table className={styles.table}>
            <thead><tr><th>Host</th><th>Foothold</th><th>Access</th></tr></thead>
            <tbody>
              {summary.footholds.map((f, i) => (
                <tr key={i}><td>{f.host_ip}</td><td>{f.method}</td><td>{f.access_type}</td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className={styles.dim}>{capped(summary.footholds) ?? "no footholds yet"}</p>
        )
      )}
      {tab === "Attack Graph" && <AttackGraph summary={summary} />}
    </div>
  );
}
