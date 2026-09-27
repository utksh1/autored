import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { StateSummary } from "../types";
import DataPanels from "./DataPanels";

const base = {
  phase: "recon",
  engagement_id: "eng_1",
  target_scope: [],
  hosts: [],
  services: [],
  footholds: [],
  harvested_secrets: [],
  pivots: [],
  movement_paths: [],
  sub_engagements: [],
  cleanup_results: [],
  attack_hypotheses: null,
  pending_hitl_gates: [],
};

describe("DataPanels", () => {
  it("renders the capped message when the ws summary caps findings", () => {
    const summary = {
      ...base,
      findings: { count: 250 },
    } as unknown as StateSummary;
    render(<DataPanels summary={summary} />);
    expect(screen.getByText(/250 items/)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("renders findings rows when the list is a plain array", () => {
    const summary = {
      ...base,
      findings: [{ title: "SQLi", severity: "high", host: "10.0.0.1" }],
    } as unknown as StateSummary;
    render(<DataPanels summary={summary} />);
    expect(screen.getByText("SQLi")).toBeTruthy();
    expect(screen.getByRole("table")).toBeTruthy();
  });
});
