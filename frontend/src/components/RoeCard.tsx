import styles from "./RoeCard.module.css";

export default function RoeCard({ roe }: { roe: Record<string, unknown> }) {
  return (
    <div className={styles.card}>
      <h3>Rules of Engagement (read-only)</h3>
      <ul>
        <li>name: {String(roe.engagement_name)}</li>
        <li>operator: {String(roe.operator)}</li>
        <li>allowed_ips: {JSON.stringify(roe.allowed_ips)}</li>
        <li>allowed_techniques: {JSON.stringify(roe.allowed_techniques)}</li>
        <li>hitl_mode: {String(roe.hitl_mode)}</li>
      </ul>
    </div>
  );
}
