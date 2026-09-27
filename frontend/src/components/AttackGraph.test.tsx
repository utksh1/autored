import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { StateSummary } from "../types";
import AttackGraph from "./AttackGraph";

vi.mock("@xyflow/react", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  ReactFlow: ({ nodes, edges }: { nodes: unknown[]; edges: unknown[] }) => (
    <div data-testid="rf">{nodes.length} nodes {edges.length} edges</div>
  ),
  Background: () => null,
  Controls: () => null,
}));

const summary = {
  target_scope: ["10.0.0.1"],
  hosts: [{ ip: "10.0.0.2", hostname: null, os: null }],
  footholds: [],
  pivots: [],
  movement_paths: [
    { from_host: "10.0.0.1", to_host: "10.0.0.2", method: "wmiexec", credential_used: "s1" },
  ],
} as unknown as StateSummary;

describe("AttackGraph", () => {
  it("renders placeholder before any movement", () => {
    render(<AttackGraph summary={{ ...summary, movement_paths: [] } as StateSummary} />);
    expect(screen.getByText(/No movement yet/)).toBeTruthy();
  });

  it("renders nodes and labelled edges from movement_paths", () => {
    render(<AttackGraph summary={summary} />);
    expect(screen.getByTestId("rf")).toHaveTextContent("2 nodes 1 edges");
  });
});
