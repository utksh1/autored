import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { StateSummary } from "../types";
import HitLModal from "./HitLModal";

const resolveHitl = vi.fn();
vi.mock("../api", () => ({
  resolveHitl: (...args: unknown[]) => resolveHitl(...args),
}));

const baseSummary = {
  pending_hitl_gates: [],
} as unknown as StateSummary;

const gateEvent = {
  seq: 12,
  event: {
    type: "hitl_gate", gate_id: "12", gate_type: "exploit",
    target: "10.0.0.1", command: "msfconsole -x eternalblue",
    risks: ["crashes host"],
  },
};

describe("HitLModal", () => {
  // Braced body on purpose: `() => resolveHitl.mockReset()` would return the
  // mock, which vitest treats as a beforeEach cleanup hook and calls after the
  // test — producing an unhandled rejection when the last impl is mockRejectedValue.
  beforeEach(() => {
    resolveHitl.mockReset();
  });

  it("renders gate fields from the event frame and posts approve", async () => {
    resolveHitl.mockResolvedValue(undefined);
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    expect(screen.getByText(/msfconsole -x eternalblue/)).toBeTruthy();
    expect(screen.getByText("crashes host")).toBeTruthy();
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenCalledWith("eng_1", "12", true),
    );
  });

  it("closes with a note on 409 (already resolved)", async () => {
    resolveHitl.mockRejectedValue(new Error("already-resolved"));
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    await userEvent.click(screen.getByText("Reject"));
    await waitFor(() =>
      expect(screen.getByText(/already resolved/)).toBeTruthy(),
    );
  });

  it("renders nothing when no gate is pending", () => {
    const { container } = render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
