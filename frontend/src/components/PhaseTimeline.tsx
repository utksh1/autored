import { PHASES } from "../socket";
import styles from "./PhaseTimeline.module.css";

export default function PhaseTimeline({ phase }: { phase: string }) {
  const activeIdx = PHASES.indexOf(phase);
  return (
    <div className={styles.bar}>
      {PHASES.map((p, i) => (
        <span
          key={p}
          className={[
            styles.step,
            i < activeIdx ? styles.done : "",
            i === activeIdx ? styles.active : "",
          ].join(" ")}
        >
          {i < activeIdx ? "✓ " : ""}{p}
        </span>
      ))}
    </div>
  );
}
