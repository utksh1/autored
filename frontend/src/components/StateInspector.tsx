import { useState } from "react";
import type { StateSummary } from "../types";
import styles from "./StateInspector.module.css";

export default function StateInspector({ summary }: { summary: StateSummary }) {
  const [open, setOpen] = useState(false);
  return (
    <details className={styles.inspector} open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary>State inspector</summary>
      <pre>{JSON.stringify(summary, null, 2)}</pre>
    </details>
  );
}
