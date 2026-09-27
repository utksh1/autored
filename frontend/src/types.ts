export interface EngagementRow {
  engagement_id: string;
  target: string;
  phase: string;
  started_at: string;
  operator: string;
}

export interface HitlGate {
  gate_id: string;
  gate_type: string;
  target: string;
  command: string;
  risks: string[];
}

export interface StateSummary {
  phase: string;
  engagement_id: string;
  target_scope: string[];
  hosts: HostRow[];
  services: ServiceRow[];
  findings: FindingRow[];
  footholds: FootholdRow[];
  harvested_secrets: SecretRow[];
  pivots: unknown[];
  movement_paths: MovementPath[];
  sub_engagements: unknown[];
  cleanup_results: unknown[];
  attack_hypotheses: unknown;
  pending_hitl_gates: HitlGate[];
}

export interface HostRow { ip: string; hostname: string | null; os: string | null; }
export interface ServiceRow { host_ip: string; port: number; protocol: string; service: string; }
export interface FindingRow { title: string; severity: string; host: string; }
export interface FootholdRow { host_ip: string; method: string; access_type: string; }
export interface SecretRow { secret_type: string; source: string; secret_value: string; }
export interface MovementPath { from_host: string; to_host: string; method: string; credential_used: string; }
