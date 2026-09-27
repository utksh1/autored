import type { EventFrame } from "../socket";
import styles from "./ActivityLog.module.css";

export default function ActivityLog({ events }: { events: EventFrame[] }) {
  return (
    <div className={styles.log}>
      <h3>Activity</h3>
      {events.length === 0 && <p className={styles.dim}>waiting for events…</p>}
      {events.map((f) => (
        <div key={`${f.seq}`} className={styles.line}>
          <span className={styles.seq}>#{f.seq}</span>
          <span className={styles.type}>{String(f.event.type)}</span>
          <span>{describe(f.event)}</span>
        </div>
      ))}
    </div>
  );
}

function describe(e: Record<string, unknown> & { type: string }): string {
  if (e.type === "hitl_gate") return `gate ${(e.gate_id as string) ?? ""} — ${String(e.command ?? "")}`;
  if (e.type === "phase_change") return `→ ${String(e.phase ?? e.node ?? "")}`;
  if (typeof e.tool === "string") return e.tool;
  if (typeof e.message === "string") return e.message;
  return JSON.stringify(e).slice(0, 120);
}
