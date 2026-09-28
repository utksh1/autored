import { useEffect, useState } from "react";
import { resolveHitl } from "../api";
import type { EventFrame } from "../socket";
import type { HitlGate, StateSummary } from "../types";
import styles from "./HitLModal.module.css";

interface Props {
  engagementId: string;
  summary: StateSummary;
  events: EventFrame[];
}

export default function HitLModal({ engagementId, summary, events }: Props) {
  // Visibility source of truth is the state snapshot's pending_hitl_gates
  // (spec §7.1): event frames persist in the client's history after a gate
  // is resolved, so deriving visibility from them would render a resolved
  // gate behind a full-screen overlay forever. The newest frame (by seq —
  // the socket reducer prepends, so scan order is already newest-first)
  // only ENRICHES the preview when its gate_id matches a still-pending entry.
  const gateFrames = events.filter((f) => f.event.type === "hitl_gate");
  const newestFrame = gateFrames.length > 0
    ? gateFrames.reduce((a, b) => (b.seq > a.seq ? b : a))
    : null;
  const pending: HitlGate[] = summary.pending_hitl_gates.map((g) => {
    if (newestFrame && String(newestFrame.event.gate_id) === g.gate_id) {
      return {
        ...g,
        gate_type: String(newestFrame.event.gate_type ?? g.gate_type),
        target: String(newestFrame.event.target ?? g.target),
        command: String(newestFrame.event.command ?? g.command),
        risks: (newestFrame.event.risks as string[]) ?? g.risks,
      };
    }
    return g;
  });

  const [error, setError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);
  const [dismissedId, setDismissedId] = useState<string | null>(null);

  useEffect(() => { setError(null); }, [pending[0]?.gate_id]);

  if (pending.length === 0) return null;
  const gate = pending[0];
  // Dismissed after our own decision (or a 409 telling us someone else
  // resolved it) — stays hidden until a NEW gate id appears. The bridge
  // pushes a state frame right after resolution that empties
  // pending_hitl_gates, so this only gates the gap before that frame lands.
  if (gate.gate_id === dismissedId) return null;

  async function decide(approved: boolean) {
    setDeciding(true);
    try {
      await resolveHitl(engagementId, gate.gate_id, approved);
      setDismissedId(gate.gate_id);
    } catch (e) {
      if (String(e).includes("already-resolved")) {
        setDismissedId(gate.gate_id);
      } else {
        setError(String(e));
      }
    } finally {
      setDeciding(false);
    }
  }

  return (
    <div className={styles.overlay} role="dialog" aria-label="HitL approval">
      <div className={styles.modal}>
        <h3>⚠ Approval required — {gate.gate_type}</h3>
        <p>target: {gate.target}</p>
        <pre className={styles.cmd}>{gate.command || "(no command preview)"}</pre>
        {gate.risks.length > 0 && (
          <ul className={styles.risks}>
            {gate.risks.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        )}
        {error && <p className={styles.err}>{error}</p>}
        <div className={styles.buttons}>
          <button className={styles.approve} disabled={deciding} onClick={() => void decide(true)}>Approve</button>
          <button className={styles.reject} disabled={deciding} onClick={() => void decide(false)}>Reject</button>
        </div>
      </div>
    </div>
  );
}
