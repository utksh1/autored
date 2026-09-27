import {
  Background, Controls, ReactFlow, type Edge, type Node,
} from "@xyflow/react";
import { useMemo } from "react";
import type { StateSummary } from "../types";
import "@xyflow/react/dist/style.css";
import styles from "./AttackGraph.module.css";

// WS summaries (spec §4) cap long lists as {"count": N} — mirror DataPanels'
// asArray guard so capped fields degrade to empty instead of crashing the graph.
const asArray = <T,>(v: T[] | { count: number } | undefined): T[] =>
  Array.isArray(v) ? v : [];

export default function AttackGraph({ summary }: { summary: StateSummary }) {
  const { nodes, edges } = useMemo(() => {
    const scope = asArray(summary.target_scope);
    const hosts = asArray(summary.hosts);
    const footholds = asArray(summary.footholds);
    const pivots = asArray(summary.pivots);
    const paths = asArray(summary.movement_paths);

    const ips = new Set<string>(scope);
    for (const h of hosts) ips.add(h.ip);
    for (const f of footholds) ips.add(f.host_ip);
    for (const m of paths) { ips.add(m.from_host); ips.add(m.to_host); }

    const footholdIps = new Set(footholds.map((f) => f.host_ip));
    const pivotTargets = new Set(pivots.map((p) => (p as { target_host: string }).target_host));

    const nodes: Node[] = [...ips].map((ip, i) => ({
      id: ip,
      position: { x: 80 + (i % 4) * 220, y: 80 + Math.floor(i / 4) * 120 },
      data: { label: ip },
      style: {
        background: footholdIps.has(ip) ? "#166534" : "#3f3f46",
        color: "#f4f4f5", border: pivotTargets.has(ip) ? "2px solid #f59e0b" : "1px solid #71717a",
        borderRadius: 8,
      },
    }));
    const edges: Edge[] = paths.map((m, i) => ({
      id: `e${i}`, source: m.from_host, target: m.to_host,
      label: m.method, animated: true, style: { stroke: "#f59e0b" },
    }));
    return { nodes, edges };
  }, [summary]);

  if (asArray(summary.movement_paths).length === 0) {
    return <p className={styles.empty}>No movement yet — the graph appears after the first pivot.</p>;
  }
  return (
    <div className={styles.canvas}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
