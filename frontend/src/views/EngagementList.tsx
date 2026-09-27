import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listEngagements } from "../api";
import type { EngagementRow } from "../types";
import styles from "./EngagementList.module.css";

export default function EngagementList() {
  const [rows, setRows] = useState<EngagementRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      listEngagements()
        .then((r) => alive && (setRows(r), setError(null)))
        .catch((e) => alive && setError(String(e)));
    tick();
    const h = setInterval(tick, 10_000); // spec §7.1: 10 s poll, no WS here
    return () => { alive = false; clearInterval(h); };
  }, []);

  return (
    <div className={styles.page}>
      <h1>AutoRed Engagements</h1>
      {error && <p className={styles.error}>{error}</p>}
      <table className={styles.table}>
        <thead>
          <tr>
            <th>ID</th><th>Target</th><th>Phase</th><th>Started</th><th>Operator</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.engagement_id}>
              <td>
                {r.phase === "running" || !isTerminal(r.phase) ? (
                  <Link to={`/engagements/${r.engagement_id}`}>{r.engagement_id}</Link>
                ) : (
                  r.engagement_id
                )}
              </td>
              <td>{r.target}</td>
              <td><span className={styles[`phase_${r.phase}`] ?? styles.badge}>{r.phase}</span></td>
              <td>{r.started_at}</td>
              <td>{r.operator}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isTerminal(phase: string): boolean {
  return phase === "done" || phase === "failed" || phase === "aborted";
}
