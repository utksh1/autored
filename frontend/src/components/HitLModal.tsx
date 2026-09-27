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
  // Live gate frames win (they carry command preview); pending list from the
  // state summary keeps the modal sticky across reconnects (spec §7.1). The
  // NEWEST frame wins, picked by seq rather than scan order: the socket
  // reducer prepends frames (newest first), so a plain find/reverse-find
  // would silently lock onto a stale, already-resolved gate.
  const gateFrames = events.filter((f) => f.event.type === "hitl_gate");
  const gateFromEvent = gateFrames.length > 0
    ? gateFrames.reduce((a, b) => (b.seq > a.seq ? b : a))
    : null;
  const pending: HitlGate[] = gateFromEvent
    ? [{
        gate_id: String(gateFromEvent.event.gate_id),
        gate_type: String(gateFromEvent.event.gate_type ?? "gate"),
        target: String(gateFromEvent.event.target ?? ""),
        command: String(gateFromEvent.event.command ?? ""),
        risks: (gateFromEvent.event.risks as string[]) ?? [],
      }]
    : summary.pending_hitl_gates;

  const [error, setError] = useState<string | null>(null);
  const [decided, setDecided] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);

  useEffect(() => { setDecided(null); setError(null); }, [pending[0]?.gate_id]);

  if (pending.length === 0) return null;
  const gate = pending[0];

  async function decide(approved: boolean) {
    setDeciding(true);
    try {
      await resolveHitl(engagementId, gate.gate_id, approved);
      setDecided(approved ? "approved" : "rejected");
    } catch (e) {
      if (String(e).includes("already-resolved")) {
        setDecided("already resolved by another operator");
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
        {decided ? (
          <p className={styles.decided}>{decided}</p>
        ) : (
          <div className={styles.buttons}>
            <button className={styles.approve} disabled={deciding} onClick={() => void decide(true)}>Approve</button>
            <button className={styles.reject} disabled={deciding} onClick={() => void decide(false)}>Reject</button>
          </div>
        )}
      </div>
    </div>
  );
}
