// (HitLModal is added to this file in Task 9 — it does not exist yet here.)
import { useEffect, useState } from "react";
import { useParams } from "react-router";
import ActivityLog from "../components/ActivityLog";
import DataPanels from "../components/DataPanels";
import PhaseTimeline from "../components/PhaseTimeline";
import RoeCard from "../components/RoeCard";
import StateInspector from "../components/StateInspector";
import { fetchRoe } from "../api";
import { useEngagementSocket } from "../socket";
import styles from "./EngagementDetail.module.css";

export default function EngagementDetail() {
  const { id = "" } = useParams();
  const { summary, events, connected } = useEngagementSocket(id);
  const [roe, setRoe] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    fetchRoe(id).then(setRoe).catch(() => setRoe(null));
  }, [id]);

  if (!summary) {
    return <p className={styles.loading}>Loading engagement {id}… (or not found)</p>;
  }

  return (
    <div className={styles.page}>
      <PhaseTimeline phase={summary.phase} />
      <p className={styles.conn}>
        {connected ? "live" : "reconnecting…"} · target {summary.target_scope.join(", ")}
      </p>
      <div className={styles.columns}>
        <ActivityLog events={events} />
        <DataPanels summary={summary} />
      </div>
      <StateInspector summary={summary} />
      {roe && <RoeCard roe={roe} />}
    </div>
  );
}
